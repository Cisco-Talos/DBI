/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group

client3 - Simple DynamoRio x64 client which prints out loaded DLLs and 
          disassembles all instructions in a certain range at runtime
          going into branches like calls, jmp, etc.

          Use this client only with the x64 anti-x test target app, it is 
          changing the return value of the function always_return_true() 
          at 0x140001190 in anti-x. This shows how to use drwrap to manipulate 
          the target apps code at runtime.

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

#pragma once
#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"
#include "drreg.h"
#include "drx.h"
#include "drwrap.h"
#include "dr_tools.h"
#include "dr_ir_opnd.h"

#include <stdio.h>

#define UNUSED(x) (void)(x)   // Used to avoid compiler warnings about unused local variables from functions
#define MAX_INSTR 500         // Max number of instructions to instrument

// --- Structs ---
typedef struct s_argv_para {
  size_t start;
  size_t end;
  char* module;
} S_ARGV_PARA;


// --- Globals ---
client_id_t my_id;
void* my_buffer;
size_t buffer_size = 30 * 1024;
S_ARGV_PARA* trace_para = NULL;
bool start_reached = FALSE;
bool end_reached   = FALSE;
unsigned long long instr_instructions_counter = 0;
unsigned long long loop_start_end_counter=0;
size_t next_pc = 0;
bool call_called = FALSE;
bool first_call = FALSE;



// --- Functions ---
char* toLower(char* s) {
  for(char *p=s; *p; p++) *p=(char)tolower((unsigned char)*p);
  return s;
}

void wrap_post_function(void *wrapcxt, void *user_data)
{
  UNUSED(user_data);
    dr_printf("[SIMPLECLIENT] [DEBUG] [wrap_post_function] Setting function post wrap\n");
    drwrap_set_retval(wrapcxt, (void *)0);
    dr_printf("[SIMPLECLIENT] [DEBUG] [wrap_post_function] Return value set to FALSE\n");
}

void event_module_load_trace_instr(void* drcontext, const module_data_t* info, bool loaded)
// executed for every module (e.g. DLL) loaded 
{
  UNUSED(loaded);     
  UNUSED(drcontext);    

  char* pref_name = __wrap_strdup(dr_module_preferred_name(info));

  if (!pref_name) {
    dr_printf("[SIMPLECLIENT] [DEBUG] [event_module_load_trace_instr] [ERROR] failed to duplicate string.");
    __wrap_free(pref_name);
    dr_exit_process(1);
  }

  // Patch a function:
  if (!strcmp(pref_name, trace_para->module)) {

    dr_printf("[SIMPLECLIENT] [DEBUG] [event_module_load_trace_instr] Process PID %u (%s) module loaded: %s:  <-- [instrumented]\n", dr_get_process_id(), dr_get_application_name(), pref_name);

    // Function in target application (anti-x.exe):
    // bool always_return_true() {
    //    printf("[ANTI-X] This function always returns TRUE\n");
    //    return true;
    // }

    // Set address of always_return_true()
    app_pc func_addr = (app_pc)0x140001190; // for imported functions "use func_addr = (app_pc)dr_get_proc_address(info->handle, "ImportedFunction");"
    
    if (func_addr >= info->start && func_addr < info->end) {
          bool success = drwrap_wrap(func_addr, NULL, wrap_post_function);
          if (success) {
              dr_printf("[SIMPLECLIENT] [DEBUG] [event_module_load_trace_instr] Successfully wrapped function at %p\n", func_addr);
          } else {
              dr_printf("[SIMPLECLIENT] [DEBUG] [event_module_load_trace_instr] Failed to wrap function at %p\n", func_addr);
          }
      }
  }
  else {
    dr_printf("[SIMPLECLIENT] [DEBUG] [event_module_load_trace_instr] Process PID %u (%s) module loaded: %s:\n", dr_get_process_id(), dr_get_application_name(), pref_name);
  }
}

void event_exit(void)
// executed when process exits
{
  dr_printf("[SIMPLECLIENT] [DEBUG] [event_exit] Number of instrumented instructions: %d\n", instr_instructions_counter); 
  dr_global_free(my_buffer, buffer_size); // free allocated buffer 
  dr_global_free(trace_para, sizeof(S_ARGV_PARA));
  drwrap_exit();
  drmgr_exit();
}

void usage()
{
  // -no_follow_children = drrun does not follow into any child processes
  dr_printf("\n");
  dr_printf("Usage:\n");
  dr_printf("drrun.exe [-no_follow_children] -c <TRACER.DLL> <OPTIONS> -- <SAMPLE.EXE>\n");
  dr_printf("-no_follow_children              drrun option: don't follow child processes [optional]\n");
  dr_printf("-s <ADDR>                        Trace start address in hex e.g. 140003000\n");
  dr_printf("-e <ADDR>                        Trace end address in hex e.g. 14000A000\n");
  dr_printf("-m <MOD1>                        Module to instrument. This avoids tracing into standard libraries\n");
  dr_printf("<SAMPLE.EXE>                     PE file to analyse\n\n");
  dr_printf("Example:\n");
  dr_printf("\"C:\\dynamorio_install\\bin64\\drrun.exe\" -c \"C:\\somedir\\simpleclient.dll\" -s 140001000 -e 140001000 -m \"sample1_64.exe\" -- \"C:\\samples\\sample1_64.exe\"\n\n");
}

void parse_cmd_opt() {
  // Parse the commandline arguments of the client library
  int argc;
  int i = 0;
  char** argv; 

  bool start_set  = FALSE;
  bool end_set  = FALSE;
  bool mod_set  = FALSE;

  size_t start = 0;
  size_t end   = 0;

  // Get cmd args from client
  dr_get_option_array(my_id, &argc, &argv);

  // init global trace_para structure
  trace_para = dr_global_alloc(sizeof(S_ARGV_PARA));    

  // parse arguments
  while (++i < argc)  
  {
    argv++;
    if (argv[0][0] == '-') {
      switch (argv[0][1]) {
      case 's':
        sscanf_s(argv[1], "%zx", &start);
        dr_printf("[SIMPLECLIENT] [DEBUG] [parse_cmd_opt] Start adress set to : 0x%llx\n", start);
        trace_para->start = start;
        start_set = TRUE;
        break;
      case 'e':
        sscanf_s(argv[1], "%zx", &end);
        dr_printf("[SIMPLECLIENT] [DEBUG] [parse_cmd_opt] End address set to  : 0x%llx\n", end);
        trace_para->end = end;
        end_set = TRUE;
        break;
      case 'm':
        trace_para->module = (argv[1]);
        dr_printf("[SIMPLECLIENT] [DEBUG] [parse_cmd_opt] Module to instrument : %s\n", trace_para->module);
        mod_set = TRUE;
        break;
      // Help
      case 'h':
        usage();
        dr_exit_process(1);
      // Should not happen
      default:
        dr_printf("[SIMPLECLIENT] [ERROR] Unknown option -%c.\n", argv[0][1]);
        usage();
        dr_exit_process(1);
      }
    }
  }

  if (start_set == FALSE || end_set == FALSE || mod_set == FALSE) {
    usage();
    dr_exit_process(1);
  }
}

// This gets executed as many times as the code is executed (e.g. in a loop of 3, it is executed 3 times)
void process_instr_trace_instr(app_pc instr_addr_tmp)
{ 
  void* drcontext;
  size_t  instr_addr = (size_t) instr_addr_tmp;

  drcontext = dr_get_current_drcontext();
  dr_mcontext_t mc = { sizeof(mc),DR_MC_ALL };
  dr_get_mcontext(drcontext, &mc);

  // just for debugging 
  if (instr_addr == trace_para->start) {
    loop_start_end_counter += 1;
    DWORD pid = (DWORD) dr_get_process_id();
    module_data_t *modname = dr_lookup_module((byte*)instr_addr);
    dr_printf("[SIMPLECLIENT] [DEBUG] [process_instr_trace_instr] Start address reached (%llu): instr_addr 0x%zx Process PID %u (%s) Threat ID = %u \n",
            loop_start_end_counter, instr_addr, pid, dr_get_application_name(), dr_get_thread_id(drcontext), modname);

    dr_free_module_data(modname);
  }

  instr_t instr;
  instr_init(drcontext, &instr);
  instr_reset(drcontext, &instr);

  decode(drcontext, (byte *) instr_addr, &instr);

  size_t disasm_buf_size = 254;
  char*  disasm_buf      = (char*)dr_global_alloc(sizeof(char) * disasm_buf_size);

  instr_disassemble_to_buffer(dr_get_current_drcontext(), &instr, disasm_buf, disasm_buf_size);

  dr_printf("[SIMPLECLIENT] [DEBUG] [process_instr_trace_instr] Disasm: "PFX"  %s\n",instr_addr, disasm_buf);

  dr_global_free(disasm_buf, sizeof(char) * disasm_buf_size);
  instr_free(drcontext, &instr);
}


// Executed on every basic block once (inserts instrumentation code into BB)
dr_emit_flags_t event_bb_instr_global(void* drcontext, void* tag, instrlist_t* bb, instr_t* instr, bool for_trace, bool translating, void* user_data) {

  // just to avoid compiler warnings
  UNUSED(user_data);  
  UNUSED(translating);
  UNUSED(for_trace);
  UNUSED(bb);
  UNUSED(tag);
  UNUSED(drcontext);  

  size_t instr_addr;
  instr_addr = (size_t) instr_get_app_pc(instr);

  // only trace target application instructions
  if (instr_is_app(instr)) {
      // In most cases it is a very good idea to limit the number of instruction which are instrument.
      // E.g only instrument the range you are interested in. 
      if (instr_addr == trace_para->start) {
        start_reached = TRUE;
        end_reached = FALSE;
      }
      // Insert analysing function into basic block. Called for each basic block instruction if it is in start/end range.
      // This algo is a "Debugger step into" approach, branches into jmp, calls, etc until end addr is reached.
      // Dangerous in cases when code does not return for any reason and/or never reach the end 
      if ((start_reached == TRUE) && (end_reached == FALSE))

      // Alternatively, a more secure approach: if you are only interested in a certain code range (and want to skip e.g. calls):
      // if ((instr_addr >= trace_para->start) && (instr_addr <= trace_para->end))  
      {
        dr_printf("[SIMPLECLIENT] [DEBUG] [event_bb_instr_global] instrumenting: 0x%zx\n", instr_addr);
        dr_insert_clean_call(drcontext, bb, instr, (void *) process_instr_trace_instr, 
                                                       FALSE, 1, OPND_CREATE_INTPTR(instr_addr));
        instr_instructions_counter += 1;
        
        // Exit if something went wrong e.g. we instrumented a wrong range
        if (instr_instructions_counter >= MAX_INSTR) {
          dr_printf("\n[SIMPLECLIENT] [DEBUG] [event_bb_instr_global] [WARNING] Max. number of instructions reached.\n"); 
          dr_printf(  "[SIMPLECLIENT] [DEBUG] [event_bb_instr_global] [WARNING] Leaving target application        \n\n");
          dr_exit_process(1);
        }
      }

      if (instr_addr == trace_para->end) {
        end_reached = TRUE;
        start_reached = FALSE;
      }
  }
  return DR_EMIT_DEFAULT;
}

// --- Main Function ---

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[])
{
  // DynamoRio clients Main function

  // Save the client id in a global variable for later use in functions
  my_id = id; 

  // Initalize console printing (dr_printf)
  dr_enable_console_printing();

  // Set client name
  dr_set_client_name("Simpleclient", "hunterbr@cisco.com"); // Pls replace this with your email or a dummy :)

  // Init DynamoRIO’s extension manager 
  drmgr_init();

  //drwrap init;
  drwrap_init();

  // Get clients command line parameter. You can either use argc/argv here or dr_get_option_array() like we do in parse_cmd_opt
  for (int i = 0; i < argc; i++) {
        dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] argv[%d] = %s\n", i, argv[i]);
    }

    // Another way to parse command line parameters
    parse_cmd_opt();

  // Example for allocating a buffer, needs to be free'ed later via dr_global_free(my_buffer, buffer_size) - e.g. in event_exit function
  my_buffer = dr_global_alloc(buffer_size);

  dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] DynamoRio initialized.\n");
  dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Client DLL used  = %s\n", dr_get_client_path(id));
  dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] PID              = %u (0x%x)\n", dr_get_process_id(), dr_get_process_id());
  dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Processname      = %s \n", dr_get_application_name());

  disassemble_set_syntax(DR_DISASM_INTEL);
  dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Disassembler syntax set to INTEL\n");

  drmgr_register_module_load_event(event_module_load_trace_instr);                  // executed on module load e.g. imported DLLs
  drmgr_register_bb_instrumentation_event(NULL, event_bb_instr_global, NULL);       // executed on every basic block
  dr_register_exit_event(event_exit);                                               // executed on process exit

  dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Initalization done.\n");

}