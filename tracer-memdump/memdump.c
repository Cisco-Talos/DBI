/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group


memdump.c - DynamoRio client to dump memory the source operand of an instruction is pointing to
            e.g. lea eax, [ecx+3]  -> dump the bytes at the address [ecx+3] is pointing to

It is either generating a CSV file like the one below, or a binary file with the raw data.

(Fast version - save time at runtime - default)
pc,hex
0x0000000140001084,"37 A9 F1 A1 0F 2C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "

or

(a slower version - use the -v command line arg)
pc,op_index,memaddr,hex,ascii
0x000000014000190d,0,0x0000000140004708,5B 41 4E 54 49 2D 58 5D 20 50 72 6F 63 65 73 73 20 49 44 20 69 73 3A 20 25 6C 75 0A 00 00 00 00 ,"[ANTI-X] Process ID is: %lu....."

Example:
<DR_INSTALL_DIR>\bin32\drrun.exe -c "<PATH_TO_CLIENT>\memdump32.dll" -start 0x401040    -end 0x401174 -n 64 -- "<PATH>\app32.exe"
<DR_INSTALL_DIR>\bin64\drrun.exe -c "<PATH_TO_CLIENT>\memdump64.dll" -start 0x1400018F0 -end 0x140001983    -- "<PATH>\app64.exe"

<DR_INSTALL_DIR>\bin32\drrun.exe -c "<PATH_TO_CLIENT>\memdump32.dll" -start 0x401040    -end 0x401174 -n 64 -b -- "<PATH>\app32.exe"

For help:
<DR_INSTALL_DIR>\bin64\drrun.exe -c "<PATH_TO_CLIENT>\memdump64.dll" -h -- "<PATH>\app64.exe"

Example:

See "run_tracerXX.sh" scripts.

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
#include "dr_tools.h"
#include "drmgr.h"
#include "drutil.h"
#include "drreg.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>   

// Number of bytes per row in logfile
#define BYTES_PER_ROW_DEFAULT 32

/* -------- Globals -------- */

static file_t g_log = INVALID_FILE;
static void *g_log_mutex = NULL;

static app_pc g_start = NULL;
static app_pc g_end   = (app_pc)(~(uintptr_t)0);

static bool g_verbose = false;
static bool g_bin_dump_only = false;
static bool g_end_set = false;
 
char g_logfile[MAXIMUM_PATH];

static uintptr_t g_bytes_to_dump = BYTES_PER_ROW_DEFAULT;


/* ---------- Helper functions ---------- */

static void usage(void) {
    dr_printf("memdump options:\n");
    dr_printf("  -start <addr>   Begin instrumenting at absolute address (mandatory)\n");
    dr_printf("  -end   <addr>   End   instrumenting at absolute address (optional)\n");
    dr_printf("  -n <number>     Number of bytes to dump (optional - default is 32)\n");
    dr_printf("  -b              Dump memory to binary file, default is CSV file (optional)\n");
    dr_printf("  -v              Verbose mode. Print more details to CSV file, including ASCII values (optional)\n");
#ifdef X86_64
    dr_printf("  Example: drrun.exe -c memdump64.dll -start 0x140001000 -end 0x140010000 -- app.exe\n");
#else
    dr_printf("  Example: drrun.exe -c memdump32.dll -start 0x401000 -end 0x410000 -- app.exe\n");
#endif
}

// Parse 64-bit unsigned integer from hex (0x...) or decimal.
static bool parse_u64(const char *s, uint64_t *out) {
    if (s == NULL || out == NULL) return false;
    while (*s == ' ' || *s == '\t') s++;
#ifdef _MSC_VER
    unsigned long long v = _strtoui64(s, NULL, 0);
#else
    unsigned long long v = strtoull(s, NULL, 0);
#endif
    *out = (uint64_t)v;
    return true;
}

// Parse address string into app_pc safely for 32/64. 
static bool parse_address(const char *s, app_pc *out) {
    uint64_t v = 0;
    if (!parse_u64(s, &v)) return false;
    *out = (app_pc)(uintptr_t)v;
    return true;
}

// Print line to log file
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

// Dump memory region to log file
static void dump_region_to_file(app_pc addr, size_t length) {
    byte buf[4096];
    size_t done = 0;

    dr_printf("[memdump_client] [INFO] Dumping %d bytes from " PFX ".\n", length , addr);

    while (done < length) {
        size_t to_read = (length - done > 4096) ? 4096 : (length - done);
        size_t got = 0;
        if (!dr_safe_read(addr + done, to_read, buf, &got) || got == 0)
            break; // unreadable -> done.
        dr_write_file(g_log, buf, got);
        done += got;
    }
}

// Clean-call callback function: dump starting at addr for num_bytes_read.
static void dump_src_mem(app_pc pc, int op_index, byte *addr, size_t num_bytes_read)
{
    if (num_bytes_read == 0) {
        dr_printf("[memdump_client] [ERROR] Number of bytes to read not set for PC " PFX ".\n", pc);
        dr_abort();
        return;
    }

    size_t bytes_per_row = (size_t)num_bytes_read;

    // Memory address (addr) calculation failed in event_app_instruction() 
    if (addr == NULL) {
        dr_printf("[memdump_client] [WARNING] Target address of src operand is NULL: " PFX ",%d," PFX ",<null>,<null>\n",
                  pc, op_index, addr);
        return;
    }

    // Do we only want to binary dump the memory region at addr?
    if (g_bin_dump_only) {
        dump_region_to_file(addr, num_bytes_read);
        return;
    }

    size_t remaining = num_bytes_read;

    byte *buf = (byte *)dr_global_alloc(bytes_per_row * sizeof(byte));
    if (buf == NULL) {
        dr_printf("[memdump_client] [ERROR] failed to allocate memory for data buffer.\n");
        dr_abort();
    }

    size_t size_hex = bytes_per_row * 3 + 1;
    size_t size_asc = bytes_per_row + 1;
    char *hex = (char *)dr_global_alloc(size_hex);
    char *asc = (char *)dr_global_alloc(size_asc);

    size_t off = 0;
    while (remaining > 0) {
        size_t want = (remaining > bytes_per_row ? bytes_per_row : remaining);

        size_t got = 0;
        bool ok = dr_safe_read(addr + off, want, buf, &got);

        char *h = hex;
        for (size_t i = 0; i < bytes_per_row; ++i) {
            if (i < got && ok)
                h += dr_snprintf(h, 4, "%02X ", buf[i]);
            else if (i < want && !ok)
                h += dr_snprintf(h, 4, "?? ");
            else if (i < want)
                h += dr_snprintf(h, 4, "   ");
            else
                h += dr_snprintf(h, 4, "   ");
        }
        *h = '\0';

        if (g_verbose) {
            for (size_t i = 0; i < bytes_per_row; ++i) {
                if (i < got && ok) {
                    unsigned char c = buf[i];
                    asc[i] = (c >= 32 && c <= 126) ? (char)c : '.';
                } else if (i < want && !ok) {
                    asc[i] = '?';
                } else {
                    asc[i] = ' ';
                }
            }
            asc[bytes_per_row] = '\0';

            log_line(PFX ",%d," PFX ",%s,\"%s\"",
                     pc, op_index, (app_pc)(addr + off), hex, asc);
        } else {
            log_line(PFX ",\"%s\"", pc, hex);
        }

        if (!ok || got == 0) {
            break; // could not read further
        }

        off += got;
        if (remaining <= got) break;
        remaining -= got;
    }

    dr_global_free(hex, size_hex);
    dr_global_free(asc, size_asc);
    dr_global_free(buf, bytes_per_row);
}



/* -------- Instrumentation -------- */

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_app(inst))
        return DR_EMIT_DEFAULT;

    app_pc pc = instr_get_app_pc(inst);

    if (!(pc >= g_start && pc <= g_end))
        return DR_EMIT_DEFAULT;

    const int nsrcs = instr_num_srcs(inst);
    if (nsrcs <= 0)
        return DR_EMIT_DEFAULT;

    for (int i = 0; i < nsrcs; ++i) {
        opnd_t src = instr_get_src(inst, i);
        if (!opnd_is_memory_reference(src))
            continue;

        // Allocate temp. registers 
        reg_id_t reg_addr = DR_REG_NULL, reg_scratch = DR_REG_NULL;

        // reg_addr = temp. register to store effective address (EA) of src oprand 
        bool have_reg_addr = (drreg_reserve_register(drcontext, bb, inst, NULL, &reg_addr) == DRREG_SUCCESS);

        // reg_scratch = helper temp. register, used if a more complex address computation is required in drutil_insert_get_mem_addr().
        bool have_scratch = (drreg_reserve_register(drcontext, bb, inst, NULL, &reg_scratch) == DRREG_SUCCESS);

        // Did one of the register reservations fail ?
        // Yes -> hand over NULL as address parameter to dump_src_mem()
        if (!have_reg_addr || !have_scratch) {
            dr_insert_clean_call(drcontext, bb, inst, (void *)dump_src_mem, false,
                                 4,
                                 OPND_CREATE_INTPTR(pc),
                                 OPND_CREATE_INT32(i),
                                 OPND_CREATE_INTPTR(NULL),
                                 OPND_CREATE_INTPTR((void*)(uintptr_t)g_bytes_to_dump));
            if (have_scratch)  drreg_unreserve_register(drcontext, bb, inst, reg_scratch);
            if (have_reg_addr) drreg_unreserve_register(drcontext, bb, inst, reg_addr);
            continue;
        }

        // Inserts instructions into the basic block that compute the effective address of 
        // a memory reference at runtime and store it in a register. 
        // e.g. lea reg_addr, [ebx + esi*4 + 0x10]
        // If this fails -> hand over NULL as address parameter to dump_src_mem()
        if (!drutil_insert_get_mem_addr(drcontext, bb, inst, src, reg_addr, reg_scratch)) {
            drreg_unreserve_register(drcontext, bb, inst, reg_scratch);
            drreg_unreserve_register(drcontext, bb, inst, reg_addr);

            dr_insert_clean_call(drcontext, bb, inst, (void *)dump_src_mem, false,
                                 4,
                                 OPND_CREATE_INTPTR(pc),
                                 OPND_CREATE_INT32(i),
                                 OPND_CREATE_INTPTR(NULL),
                                 OPND_CREATE_INTPTR((void*)(uintptr_t)g_bytes_to_dump));
            continue;
        }

        // Normal case, we successfully got to registers and got the memory address (reg_addr)
        // and we hand it over to dump_src_mem()  
        dr_insert_clean_call(drcontext, bb, inst, (void *)dump_src_mem, false,
                             4,
                             OPND_CREATE_INTPTR(pc),
                             OPND_CREATE_INT32(i),
                             opnd_create_reg(reg_addr),
                             OPND_CREATE_INTPTR((void*)(uintptr_t)g_bytes_to_dump));

        // release temp regs 
        drreg_unreserve_register(drcontext, bb, inst, reg_scratch);
        drreg_unreserve_register(drcontext, bb, inst, reg_addr);
    }

    return DR_EMIT_DEFAULT;
}

/* -------- End of lifecycle -------- */

static void event_exit(void)
{
    if (g_log != INVALID_FILE) {
        dr_close_file(g_log);
        g_log = INVALID_FILE;
    }
    if (g_log_mutex) {
        dr_mutex_destroy(g_log_mutex);
        g_log_mutex = NULL;
    }
    drutil_exit();
    drreg_exit();
    drmgr_exit();
}



/* -------- Main -------- */

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("tracer-memdump client", "memdump@example");
    DR_ASSERT_MSG(drmgr_init(), "drmgr_init failed");
    DR_ASSERT_MSG(drutil_init(), "drutil_init failed");
    drreg_options_t ropts = { sizeof(ropts), 3 /*max slots*/, false };
    DR_ASSERT_MSG(drreg_init(&ropts) == DRREG_SUCCESS, "drreg_init failed");

    /* Defaults: whole address space */
    g_start = (app_pc)(uintptr_t)0;
    g_end   = (app_pc)(~(uintptr_t)0);

    /* parse client args */
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (a == NULL) continue;

        if (strcmp(a, "-v") == 0) {
            g_verbose = true;
        }
        else if (strcmp(a, "-b") == 0) {
            g_bin_dump_only = true;
        }
        else if (strcmp(a, "-n") == 0 && i + 1 < argc) {
            uint64_t v = 0;
            if (parse_u64(argv[++i], &v) && v > 0) {
                if (v > (uint64_t)(~(uintptr_t)0))
                    v = (uint64_t)(~(uintptr_t)0);
                g_bytes_to_dump = (uintptr_t)v;
            } else {
                dr_printf("[memdump_client] [ERROR] invalid -n value: %s\n", argv[i]);
                usage();
                dr_abort();
            }
        }
        else if (strcmp(a, "-start") == 0 && i + 1 < argc) {
            app_pc v;
            if (parse_address(argv[i + 1], &v)) {
                g_start = v;
                i++;
            } else {
                dr_printf("[memdump_client] [ERROR] invalid -start value: %s\n", argv[i + 1]);
                usage();
                dr_abort();
            }
        } else if (strcmp(a, "-end") == 0 && i + 1 < argc) {
            app_pc v;
            if (parse_address(argv[i + 1], &v)) {
                g_end = v;
                i++;
                g_end_set = true;
            } else {
                dr_printf("[memdump_client] [ERROR] invalid -end value: %s\n", argv[i + 1]);
                usage();
                dr_abort();
            }
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0 || strcmp(a, "/?") == 0) {
            usage();
            dr_abort();
        }
    }

    if (!g_end_set) {
        g_end = g_start;
    }

    // Ensure range makes sense 
    if (!(g_end >= g_start)) {
        dr_printf("[memdump_client] [ERROR] Start address should be smaller or equal than end address.\n");
        dr_abort();
    }

    g_log_mutex = dr_mutex_create();

    // open log file
    dr_time_t now; dr_get_time(&now);
    unsigned int pid = (unsigned int)dr_get_process_id();
    
    if (g_bin_dump_only) {
        dr_snprintf(g_logfile, sizeof(g_logfile),
                "dump_%02d-%02d-%02d_%02d-%02d-%02d_pid%u.bin",
                (now.year % 100), now.month, now.day,
                now.hour, now.minute, now.second, pid);
    }
    else {
        dr_snprintf(g_logfile, sizeof(g_logfile),
                "dump_%02d-%02d-%02d_%02d-%02d-%02d_pid%u.csv",
                (now.year % 100), now.month, now.day,
                now.hour, now.minute, now.second, pid);
    }

    g_log = dr_open_file(g_logfile, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(g_log != INVALID_FILE);

    if (!g_bin_dump_only) {
        if (g_verbose) {
            log_line("pc,op_index,memaddr,hex,ascii");
        } else {
            log_line("pc,hex");
        }
    }

    // Register instrumentation callbacks
    dr_register_exit_event(event_exit);
    DR_ASSERT_MSG(drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL), "bb event failed");

    // Print out some info
    dr_printf("[memdump_client] [INFO] Dumping PC range: " PFX "-" PFX "\n", g_start, g_end);
    dr_printf("[memdump_client] [INFO] Dump length limit: %zu bytes\n", (size_t)g_bytes_to_dump);
    dr_printf("[memdump_client] [INFO] Writing to logfile: %s\n", g_logfile);
}
