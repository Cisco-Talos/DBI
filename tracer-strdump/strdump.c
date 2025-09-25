/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group

strdump.c — Simple DynamoRIO client to dump all strings the source operand
            of an instruction is pointing to into a csv

            For speed, it prints either only the PC and the memory bytes
            to the CSV, or additional information like the decode ascii 
            bytes and the operand address.  

Example:

drrun.exe -c "./bin/Release/strdump32.dll" -start 0x401040    -end 0x401174    -n 32 -- "../testsamples/strDecode_x32.exe"
drrun.exe -c "./bin/Release/strdump64.dll" -start 0x1400018F0 -end 0x140001983 -n 32 -- "../testsamples/anti_x/x64/Release/anti_x.exe"

Helper script:

This Python scripts decodes the dumped bytes to human readable strings

python ./decode_strings.py memdump_25-09-24_14-50-35.csv

Output:
$ cat memdump_25-09-24_14-50-35.csv
pc,hex
0x00000001400018ff,"E0 36 F2 8D F9 7F 00 00 10 35 F2 8D F9 7F 00 00 F0 C6 F3 8D F9 7F 00 00 90 3C F3 8D F9 7F 00 00 "


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

#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>   /* strtoull */
//#include <ctype.h>

#define BYTES_TO_DUMP_DEFAULT 16
#define BYTES_TO_DUMP_MAX 256

/* -------- globals -------- */
static file_t g_log = INVALID_FILE;
static void *g_log_mutex = NULL;

/* address filter: [g_start, g_end) */
static app_pc g_start = NULL;
static app_pc g_end   = (app_pc)(~(uintptr_t)0);

bool g_verbose = false;
static int g_bytes_to_dump = BYTES_TO_DUMP_DEFAULT;
/* -------- utilities -------- */

static void usage(void) {
    dr_printf("\nmemdump_client options:\n");
    dr_printf("  -start <addr>   begin instrumenting at absolute address\n");
    dr_printf("  -end   <addr>   end   instrumenting at absolute address\n");
    dr_printf("  -n <number>           number of bytes to dump. Range is 0-256\n");
    dr_printf("  -verbose              print more details\n\n");
#ifdef X86_64
    dr_printf("  drrun -c memdump_client64.dll -start 0x140001000 -end 0x140010000 -- app.exe\n");
#else
    dr_printf("  drrun -c memdump_client32.dll -start 0x401000 -end 0x410000 -- app.exe\n");
#endif
}

/* Parse address string (hex with 0x or decimal) into app_pc safely for 32/64. */
static bool parse_address(const char *s, app_pc *out) {
    if (s == NULL || out == NULL) return false;

    /* skip leading spaces */
    while (*s == ' ' || *s == '\t') s++;

    /* strtoull handles 0x... or decimal with base 0 */
#ifdef _MSC_VER
    unsigned long long v = _strtoui64(s, NULL, 0);
#else
    unsigned long long v = strtoull(s, NULL, 0);
#endif
    /* cast through uintptr_t to truncate appropriately on 32-bit clients */
    *out = (app_pc)(uintptr_t)v;
    return true;
}

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

static void dump_src_mem(app_pc pc, int op_index, byte *addr, int nbytes)
{
    if (addr == NULL || nbytes <= 0) {
        if (g_verbose) log_line(PFX ",%d," PFX ",<null>,<null>", pc, op_index, addr);
        return;
    }

    byte buf[BYTES_TO_DUMP_MAX]; /* max */
    if (nbytes > (int)sizeof(buf)) nbytes = (int)sizeof(buf);

    size_t got = 0;
    if (!dr_safe_read(addr, nbytes, buf, &got) || got == 0) {
        if (g_verbose) log_line(PFX ",%d," PFX ",<unreadable>,<unreadable>", pc, op_index, addr);
        return;
    }

    char hex[BYTES_TO_DUMP_MAX * 3 + 1];
    char *h = hex;
    for (size_t i = 0; i < (size_t)nbytes; ++i) {
        if (i < got)
            h += dr_snprintf(h, 4, "%02X ", buf[i]);
        else
            h += dr_snprintf(h, 4, "   ");
    }
    *h = '\0';

    char asc[BYTES_TO_DUMP_MAX + 1];
    for (size_t i = 0; i < (size_t)nbytes; ++i) {
        if (i < got) {
            unsigned char c = buf[i];
            asc[i] = (c >= 32 && c <= 126) ? (char)c : '.';
        } else asc[i] = ' ';
    }
    asc[nbytes] = '\0';

    if (g_verbose) { 
        log_line(PFX ",%d," PFX ",%s,\"%s\"", pc, op_index, addr, hex, asc);
    }
    else
        log_line(PFX ",\"%s\"", pc, hex);
}


/* -------- instrumentation -------- */

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_app(inst))
        return DR_EMIT_DEFAULT;

    app_pc pc = instr_get_app_pc(inst);

    // address filter: instrument only when pc in (g_start, g_end) 
    // If we instrument every instruction in the target app it will
    // cost too much time
    if (!(pc >= g_start && pc < g_end))
        return DR_EMIT_DEFAULT;

    const int nsrcs = instr_num_srcs(inst);   // Returns the number of source operands of instr
    if (nsrcs <= 0)
        return DR_EMIT_DEFAULT;

    for (int i = 0; i < nsrcs; ++i) {
        opnd_t src = instr_get_src(inst, i);  // Returns instr's source operand at position pos (0-based)
        if (!opnd_is_memory_reference(src))
            continue; 

        reg_id_t reg_addr = DR_REG_NULL, reg_scratch = DR_REG_NULL;
        int have_addr = 0, have_scratch = 0;

        // reserve two temporaries regs
        if (drreg_reserve_register(drcontext, bb, inst, NULL, &reg_addr) == DRREG_SUCCESS)
            have_addr = 1;
        if (drreg_reserve_register(drcontext, bb, inst, NULL, &reg_scratch) == DRREG_SUCCESS)
            have_scratch = 1;

        if (!have_addr || !have_scratch) {
            /* fallback: no EA */
            dr_insert_clean_call(drcontext, bb, inst, (void *)dump_src_mem, false,
                                 4,
                                 OPND_CREATE_INTPTR(pc),
                                 OPND_CREATE_INT32(i),
                                 OPND_CREATE_INTPTR(NULL),
                                 OPND_CREATE_INT32(g_bytes_to_dump));
            if (have_scratch)
                drreg_unreserve_register(drcontext, bb, inst, reg_scratch);
            if (have_addr)
                drreg_unreserve_register(drcontext, bb, inst, reg_addr);
            continue;
        }

        /* compute effective address into reg_addr */
        if (!drutil_insert_get_mem_addr(drcontext, bb, inst, src, reg_addr, reg_scratch)) {
            /* cleanup + fallback */
            drreg_unreserve_register(drcontext, bb, inst, reg_scratch);
            drreg_unreserve_register(drcontext, bb, inst, reg_addr);

            dr_insert_clean_call(drcontext, bb, inst, (void *)dump_src_mem, false,
                                 4,
                                 OPND_CREATE_INTPTR(pc),
                                 OPND_CREATE_INT32(i),
                                 OPND_CREATE_INTPTR(NULL),
                                 OPND_CREATE_INT32(g_bytes_to_dump));
            continue;
        }

        /* pass EA via register to clean call */
        dr_insert_clean_call(drcontext, bb, inst, (void *)dump_src_mem, false,
                             4,
                             OPND_CREATE_INTPTR(pc),
                             OPND_CREATE_INT32(i),
                             opnd_create_reg(reg_addr),
                             OPND_CREATE_INT32(g_bytes_to_dump));

        /* release temps */
        drreg_unreserve_register(drcontext, bb, inst, reg_scratch);
        drreg_unreserve_register(drcontext, bb, inst, reg_addr);
    }

    return DR_EMIT_DEFAULT;
}

/* -------- lifecycle -------- */

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

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("src-memdump (DR 11.3.0)", "hunterbr@cisco.com");
    DR_ASSERT_MSG(drmgr_init(), "drmgr_init failed");
    DR_ASSERT_MSG(drutil_init(), "drutil_init failed");
    drreg_options_t ropts = { sizeof(ropts), 3 /*max slots*/, false };
    DR_ASSERT_MSG(drreg_init(&ropts) == DRREG_SUCCESS, "drreg_init failed");

    // Defaults: whole address space
    g_start = (app_pc)(uintptr_t)0;
    g_end   = (app_pc)(~(uintptr_t)0);

    // parse client args
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (a == NULL) continue;

        if (strcmp(a, "-verbose") == 0) {
            g_verbose = true;
        }
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            g_bytes_to_dump = atoi(argv[++i]);
            if (g_bytes_to_dump <= 0 || g_bytes_to_dump > 256)
                g_bytes_to_dump = BYTES_TO_DUMP_DEFAULT;
        }
        else if (strcmp(a, "-start") == 0 && i + 1 < argc) {
            app_pc v;
            if (parse_address(argv[i + 1], &v)) {
                g_start = v;
                i++;
            } else {
                dr_printf("[memdump_client] invalid -start value: %s\n", argv[i + 1]);
                usage();
            }
        } else if (strcmp(a, "-end") == 0 && i + 1 < argc) {
            app_pc v;
            if (parse_address(argv[i + 1], &v)) {
                g_end = v;
                i++;
            } else {
                dr_printf("[memdump_client] invalid -end value: %s\n", argv[i + 1]);
                usage();
            }
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0 || strcmp(a, "/?") == 0) {
            usage();
            dr_abort();
        }
    }

    // Ensure range makes sense
    if (!(g_end > g_start)) {
        dr_printf("[memdump_client] Start address should be smaller than end address.\n");
        dr_abort();
    }

    g_log_mutex = dr_mutex_create();

    /* open log file */
    dr_time_t now; dr_get_time(&now);
    char logfile[MAXIMUM_PATH];
    dr_snprintf(logfile, sizeof(logfile),
                "memdump_%02d-%02d-%02d_%02d-%02d-%02d.csv",
                (now.year % 100), now.month, now.day,
                now.hour, now.minute, now.second);
    g_log = dr_open_file(logfile, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(g_log != INVALID_FILE);

    if(g_verbose) {
        log_line("pc,op_index,memaddr,hex,ascii");
    }
    else {
        log_line("pc,hex");
    }

    /* register instrumentation */
    dr_register_exit_event(event_exit);
    DR_ASSERT_MSG(drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL),
                  "bb event failed");

    /* info */
    dr_printf("[memdump_client] Dumping range:" PFX "-" PFX ")\n", g_start, g_end);
    dr_printf("[memdump_client] Writing to logfile: %s\n", logfile);
}
