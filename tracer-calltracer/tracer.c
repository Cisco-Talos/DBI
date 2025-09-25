/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group

tracer.c - DynamoRio client which tries to resolve names and print out the 
           target addresse of all call instructions found in the target app

           This works with 32 bit and 64 bit target apps

Example:
drrun.exe" -c "./bin/Release/tracer64.dll" -- "../testsamples/anti_x/x64/Release/anti_x.exe"

Output:
a CSV logfile like this:
pc, target_address, target_apiname
0x00401b0a,0x76d9ba60,IsProcessorFeaturePresent


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"
#include "drreg.h"

#include <windows.h>
#include <winnt.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

/*
 * This DynamoRIO client logs CALL instructions and their target address.
 * It builds, at module load time, a map (hash table) from the import names (DLL!Function)
 * using the Import Address Table (IAT). It logs all call informations to a log csv file
 * 
 * Sample CSV content is: 
 * Addr of Call instr, Addr of target   ,Function name
 * 0x0000000140002a3a,0x00007ffbfaf6b450,GetModuleHandleW       # 64 bit
 * 0x00401034,0x76855060,__stdio_common_vfwprintf               # 32 bit
 */

/* Init */
typedef struct {
    app_pc addr;                                    // Key: target address of a CALL (pointer to function)
    char  *dll;                                     // DLL name (e.g., "kernel32.dll")
    char  *name;                                    // Function name (e.g. "NtTerminateProcess") or "dll#ordinal"
} map_entry_t;

// log filename
char gLogfile[MAXIMUM_PATH];

// hash table init
#define MAP_CAP (1u << 16)                          // Capacity of hash table: 65,536 entries
static map_entry_t *g_map;                          // The table (open addressing, linear probing)
static const size_t g_mask = MAP_CAP - 1;           // Bitmask for fast modulo (since size is power of 2)

// Global vars for logging
static file_t g_log = INVALID_FILE;                 // NEW: log file handle
static void *g_log_mutex = NULL;                    // NEW: mutex for thread-safe writes

// Allocation wrappers for nicer code 
static void *g_alloc(size_t n) { return dr_global_alloc(n); }
static void  g_free(void *p, size_t n) { dr_global_free(p, n); }

// Duplicate a string using DR global allocator (with NULL terminator) 
static char *dupstr(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = (char *)g_alloc(n);
    memcpy(d, s, n);
    return d;
}

// Reduce collisions in hashtable
// - Hash function for pointer keys.
// - Mixes the pointer bits using XOR-shifts and multiplications
// - with constants from MurmurHash3’s finalizer.
static size_t hkey(app_pc k) {
#if INTPTR_MAX == INT64_MAX
    /* 64-bit mix (MurmurHash3 finalizer) */
    uint64_t x = (uint64_t)(uintptr_t)k;
    x ^= x >> 33; x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 33; x *= UINT64_C(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    return (size_t)(x & (uint64_t)g_mask);
#else
    /* 32-bit mix (MurmurHash3 32-bit finalizer) */
    uint32_t x = (uint32_t)(uintptr_t)k;
    x ^= x >> 16; x *= UINT32_C(0x85ebca6b);
    x ^= x >> 13; x *= UINT32_C(0xc2b2ae35);
    x ^= x >> 16;
    return (size_t)(x & (uint32_t)g_mask);
#endif
}

// Insert (key -> (dll, name)) into the open-addressing hash table.
static void map_put(app_pc key, const char *dll, const char *name) {
    if (!key || !name) return;
    size_t i = hkey(key);
    for (size_t n = 0; n < MAP_CAP; ++n, i = (i + 1) & g_mask) {
        if (g_map[i].addr == NULL || g_map[i].addr == key) {
            g_map[i].addr = key;
            g_map[i].dll  = dupstr(dll ? dll : "");
            g_map[i].name = dupstr(name);
            return;
        }
    }
}

// Lookup an entry by key
static map_entry_t *map_get(app_pc key) {
    if (!key) return NULL;
    size_t i = hkey(key);
    for (size_t n = 0; n < MAP_CAP; ++n, i = (i + 1) & g_mask) {
        if (g_map[i].addr == key) return &g_map[i];
        if (g_map[i].addr == NULL) return NULL;
    }
    return NULL;
}

// Parse IAT and fill hashtable 
// - Parse the PE headers of a module, locate its Import Directory,
// - iterate over all imported DLLs and their functions, and record
// - each IAT entry in the map as (target address -> "dll!name").
static void build_iat_map_for_module(const module_data_t *mod) {
    byte *base = (byte *)mod->start;
    if (!base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY impdir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impdir.VirtualAddress == 0 || impdir.Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR desc =
        (PIMAGE_IMPORT_DESCRIPTOR)(base + impdir.VirtualAddress);

    // Iterate all import descriptors (one per imported DLL)
    for (; desc->Name != 0; ++desc) {
        const char *dllname = (const char *)(base + desc->Name);

#ifdef _WIN64
        // 64-bit import thunks
        PIMAGE_THUNK_DATA64 oft = (PIMAGE_THUNK_DATA64)(base +
            (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        PIMAGE_THUNK_DATA64 ft  = (PIMAGE_THUNK_DATA64)(base + desc->FirstThunk);
        for (; oft->u1.AddressOfData != 0; ++oft, ++ft) {
            app_pc target = (app_pc)(uintptr_t)ft->u1.Function;     // resolved function address
            const char *fname = NULL;
            char tmp[128];
            if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) {
                // Import by ordinal
                unsigned ord = (unsigned)IMAGE_ORDINAL64(oft->u1.Ordinal);
                dr_snprintf(tmp, sizeof(tmp), "%s#%u", dllname, ord);
                fname = tmp;
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(base + oft->u1.AddressOfData);
                fname = (const char *)ibn->Name;
            }
            map_put(target, dllname, fname); // add to hashtable
        }
#else
        // 32-bit import thunks
        PIMAGE_THUNK_DATA32 oft = (PIMAGE_THUNK_DATA32)(base +
            (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        PIMAGE_THUNK_DATA32 ft  = (PIMAGE_THUNK_DATA32)(base + desc->FirstThunk);
        for (; oft->u1.AddressOfData != 0; ++oft, ++ft) {
            app_pc target = (app_pc)(uintptr_t)ft->u1.Function;
            const char *fname = NULL;
            char tmp[128];
            if (IMAGE_SNAP_BY_ORDINAL32(oft->u1.Ordinal)) {
                unsigned ord = (unsigned)IMAGE_ORDINAL32(oft->u1.Ordinal);
                dr_snprintf(tmp, sizeof(tmp), "%s#%u", dllname, ord);
                fname = tmp;
            } else {
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(base + oft->u1.AddressOfData);
                fname = (const char *)ibn->Name;
            }
            map_put(target, dllname, fname); // add to hashtable
        }
#endif
    }
}


/* ===== Logging functions ===== */

// log filename helper 
static char *get_app_name_woext(void) {
    const char *full = dr_get_application_name();
    if (full == NULL)
        return NULL;

    const char *base = strrchr(full, '\\');
    if (base)
        base++;
    else {
        base = strrchr(full, '/');
        base = base ? base + 1 : full;
    }

    size_t len = strlen(base);
    const char *dot = strrchr(base, '.');
    if (dot != NULL && dot > base) {
        len = (size_t)(dot - base); // length up to dot
    }

    char *name = (char *)dr_global_alloc(len + 1);
    memcpy(name, base, len);
    name[len] = '\0';
    return name; // caller must dr_global_free(name, len+1)
}

// log helper function
static void log_line(const char *fmt, ...)
{
    if (g_log == INVALID_FILE)
        return;

    va_list ap;
    va_start(ap, fmt);

    dr_mutex_lock(g_log_mutex);              
    dr_vfprintf(g_log, fmt, ap);             
    dr_fprintf(g_log, "\n");                 
    dr_flush_file(g_log);                    
    dr_mutex_unlock(g_log_mutex);            

    va_end(ap);
}

// log to file
static void logger(app_pc call_pc, app_pc target_pc, const char *info) {

    /*
    // If speed is important no resolution for function names
    dr_printf("%p,%p\n", call_pc, target_pc); 
    return;
    */

    map_entry_t *e = map_get(target_pc);
    if (e) {
        //log_line("[%s] %p call %p (%s)", info, call_pc, target_pc, e->name);   
        log_line("%p,%p,%s", call_pc, target_pc, e->name); 
    } else {
        //log_line("[%s] %p call %p", info, call_pc, target_pc);
        log_line("%p,%p,none", call_pc, target_pc);                
    }                 
}

// Check if the address(pc) belongs to the target app
static bool addr_is_in_app(app_pc pc) {
    module_data_t *mainm = dr_get_main_module();
    bool in_app = (mainm != NULL) && dr_module_contains_addr(mainm, pc);
    if (mainm) dr_free_module_data(mainm);
    return in_app;
}

/* ===== Instrumenting functions ===== */

// Identify to which module the address (pc) belongs
static char *classify_address_str(app_pc pc) {
    char buf[256]; // temporary buffer

    if (dr_memory_is_dr_internal(pc) || dr_memory_is_in_client(pc)) {
        dr_snprintf(buf, sizeof(buf), "DynamoRIO/Client internal");

    } else if (addr_is_in_app(pc)) {
        dr_snprintf(buf, sizeof(buf), "%s", dr_get_application_name());

    } else {
        module_data_t *md = dr_lookup_module(pc);
        if (md != NULL) {
            const char *name = dr_module_preferred_name(md); // directly here
            dr_snprintf(buf, sizeof(buf), "%s", name ? name : "(unknown)");
            dr_free_module_data(md);

        } else {
            dr_snprintf(buf, sizeof(buf), "n.a. (heap/JIT/stack/anon)");
        }
    }
    size_t len = strlen(buf) + 1;
    char *out = (char *)dr_global_alloc(len);
    memcpy(out, buf, len);
    return out;
}

// event_app_instruction is called for each application instruction.
// - We filter for CALL instructions.
// - Direct CALLs: target known statically -> log directly.
// - Indirect CALLs: must compute/resolve target at runtime.
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_app(inst) || !instr_is_call(inst))
        return DR_EMIT_DEFAULT;

    app_pc call_pc = instr_get_app_pc(inst);

    // remove this if you want to see all calls, even the once in libraries
    if (!addr_is_in_app(call_pc)) 
        return DR_EMIT_DEFAULT;

    // get call_pc module name
    char *info = classify_address_str(call_pc);  // we do this here (instrumentation phase) 
                                                 // and not at runtime for speed e.g. loops
                                                 // for stability it will also not be free'ed
                                                 // There are cleaner solutions, but should be
                                                 // fine for our usecase 
    // Direct calls
    if (instr_is_call_direct(inst)) {
        app_pc dst = instr_get_branch_target_pc(inst);
        dr_insert_clean_call(drcontext, bb, inst, (void *)logger, false,
                             3,
                             OPND_CREATE_INTPTR(call_pc),
                             OPND_CREATE_INTPTR(dst),
                             OPND_CREATE_INTPTR(info));
        return DR_EMIT_DEFAULT;
    }

    // Indirect CALL: must resolve target dynamically
    opnd_t tgt = instr_get_target(inst);

    if (opnd_is_reg(tgt)) {
        // Example: call rax — target is register value.Pass register directly to clean call.
        reg_id_t r = opnd_get_reg(tgt);
        dr_insert_clean_call(drcontext, bb, inst, (void *)logger, false,
                             3,
                             OPND_CREATE_INTPTR(call_pc),
                             opnd_create_reg(r),
                             OPND_CREATE_INTPTR(info));
        return DR_EMIT_DEFAULT;
    }

    if (opnd_is_memory_reference(tgt)) {
        // Example: call [mem] — must compute effective address and load pointer.
        reg_id_t reg_addr, reg_val;
        if (drreg_reserve_register(drcontext, bb, inst, NULL, &reg_addr) != DRREG_SUCCESS ||
            drreg_reserve_register(drcontext, bb, inst, NULL, &reg_val)  != DRREG_SUCCESS) {
            /* Fallback: wenn keine Register verfügbar, logge ohne Ziel */
            dr_insert_clean_call(drcontext, bb, inst, (void *)logger, false,
                                 3, 
                                 OPND_CREATE_INTPTR(call_pc), 
                                 OPND_CREATE_INTPTR(NULL),
                                 OPND_CREATE_INTPTR(info));
            return DR_EMIT_DEFAULT;
        }

        // Compute effective address into reg_addr
        bool ok = drutil_insert_get_mem_addr(drcontext, bb, inst, tgt, reg_addr, reg_val);
        if (!ok) {
            drreg_unreserve_register(drcontext, bb, inst, reg_val);
            drreg_unreserve_register(drcontext, bb, inst, reg_addr);
            dr_insert_clean_call(drcontext, bb, inst, (void *)logger, false,
                                 3, 
                                 OPND_CREATE_INTPTR(call_pc), 
                                 OPND_CREATE_INTPTR(NULL),
                                 OPND_CREATE_INTPTR(info));
            return DR_EMIT_DEFAULT;
        }

#ifdef _WIN64
        instrlist_meta_preinsert(bb, inst,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_val),
                          OPND_CREATE_MEM64(reg_addr, 0)));
#else
        instrlist_meta_preinsert(bb, inst,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_val),
                          OPND_CREATE_MEM32(reg_addr, 0)));
#endif
        // Clean call with (call_pc, loaded target address)
        dr_insert_clean_call(drcontext, bb, inst, (void *)logger, false,
                             3,
                             OPND_CREATE_INTPTR(call_pc),
                             opnd_create_reg(reg_val),
                             OPND_CREATE_INTPTR(info));

        // Release reserved registers
        drreg_unreserve_register(drcontext, bb, inst, reg_val);
        drreg_unreserve_register(drcontext, bb, inst, reg_addr);
        return DR_EMIT_DEFAULT;
    }

    // Other exotic operand types: log without target
    dr_insert_clean_call(drcontext, bb, inst, (void *)logger, false,
                         3, 
                         OPND_CREATE_INTPTR(call_pc), 
                         OPND_CREATE_INTPTR(NULL),
                         OPND_CREATE_INTPTR(info));
    return DR_EMIT_DEFAULT;
}

// builds IAT map for each newly loaded module
static void event_module_load(void *drcontext, const module_data_t *mod, bool loaded) {
    build_iat_map_for_module(mod); // build addr/name hashtable 
}

// frees all allocations and shuts down DR helpers.
static void event_exit(void) {

    dr_printf("[tracer-calltracer] Logged to: %s\n", gLogfile);

    if (g_map) {
        // Free strings inside map entries
        for (size_t i = 0; i < MAP_CAP; ++i) {
            if (g_map[i].addr) {
                if (g_map[i].dll)  dr_global_free(g_map[i].dll,  strlen(g_map[i].dll) + 1);
                if (g_map[i].name) dr_global_free(g_map[i].name, strlen(g_map[i].name) + 1);
            }
        }
        // Free the table itself
        g_free(g_map, MAP_CAP * sizeof(map_entry_t));
        g_map = NULL;
    }

    // Close log file and destroy log file mutex
    if (g_log != INVALID_FILE) {
        dr_close_file(g_log);
        g_log = INVALID_FILE;
    }
    if (g_log_mutex) {
        dr_mutex_destroy(g_log_mutex);
        g_log_mutex = NULL;
    }

    // Shutdown extentions
    drutil_exit();
    drreg_exit();
    drmgr_exit();
}



// --- DynamoRIo Main function ----
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("call-logger", "hunterbr@cisco.com");
    DR_ASSERT_MSG(drmgr_init(), "drmgr_init failed");
    DR_ASSERT_MSG(drutil_init(), "drutil_init failed");
    drreg_options_t ropts = { sizeof(ropts), 3 /*max slots*/, false };
    DR_ASSERT_MSG(drreg_init(&ropts) == DRREG_SUCCESS, "drreg_init failed");

    // Allocate + clear the hashtable 
    g_map = (map_entry_t *)g_alloc(MAP_CAP * sizeof(map_entry_t));
    memset(g_map, 0, MAP_CAP * sizeof(map_entry_t));

    // Create logging mutex
    g_log_mutex = dr_mutex_create();

    // create loggin file
    dr_time_t now;
    dr_get_time(&now);  

    char *appname_wo_ext = get_app_name_woext();

    if (appname_wo_ext == NULL) appname_wo_ext = dupstr("unknown_app");

    dr_snprintf(gLogfile, sizeof(gLogfile),
            "log_%s-%02d-%02d-%02d_%02d-%02d-%02d.csv",
            appname_wo_ext,
            (now.year % 100), now.month, now.day,
            now.hour, now.minute, now.second); 

    dr_printf("[tracer-calltracer] Logging to: %s\n", gLogfile); 
    dr_global_free(appname_wo_ext, strlen(appname_wo_ext) + 1);

    g_log = dr_open_file(gLogfile, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE); // NEW
    dr_fprintf(g_log, "pc, target_address, target_apiname\n"); 
    DR_ASSERT(g_log != INVALID_FILE);        

    // Register instrumentation event callbacks
    dr_register_exit_event(event_exit);
    DR_ASSERT_MSG(drmgr_register_module_load_event(event_module_load), "module event failed"); // built IAT map
    DR_ASSERT_MSG(drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL),
                  "bb event failed");
}
    