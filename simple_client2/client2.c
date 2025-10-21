/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group

client2 - Very simple DynamoRio client to get started, it just prints out 
          loaded modules(DLLs) at runtime

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

// Used to avoid compiler warnings about unused local variables from functions
#define UNUSED(x) (void)(x)	

// Globals
client_id_t my_id;
int tls_idx;
void* my_buffer;
size_t buffer_size = 30 * 1024;

// Helper functions

void event_module_load_trace_instr(void* drcontext, const module_data_t* info, bool loaded)
// executed for every module (e.g. DLL) loaded 
{
	UNUSED(loaded);
	UNUSED(drcontext);

	char* pref_name = __wrap_strdup(dr_module_preferred_name(info));

	if (pref_name) {
		dr_printf("[SIMPLECLIENT] [DEBUG] [event_module_load_trace_instr] Process PID %u (%s) module loaded: %s:\n", dr_get_process_id(), dr_get_application_name(), pref_name);
		__wrap_free(pref_name);
	}
}

void event_exit(void)
// executed when process exits
{
	//dr_global_free(my_buffer, buffer_size); // free allocated buffer, try not to free this buffer and run a debug build
	                                          // to see the memory leak feature of drrun (-debug)
	drmgr_unregister_tls_field(tls_idx);
	drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[])
{
	UNUSED(argc);
	UNUSED(argv);
	dr_enable_console_printing();

#ifdef WINDOWS
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] dr_client_main started on Windows.\n");
#else
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] dr_client_main started.\n");
#endif

#ifdef X86_64
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] dr_client_main started on x86_64.\n");
#else
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] dr_client_main started on x86.\n");
#endif

	dr_set_client_name("client2", "hunterbr@cisco.com");

	drmgr_init();
	my_id = id;

	// Example for allocating a buffer, needs to be free'ed later via dr_global_free(my_buffer, buffer_size) - e.g. in event_exit function
	my_buffer = dr_global_alloc(buffer_size);

	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] DynamoRio Manager initialized.\n");
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Client DLL used  = %s\n", dr_get_client_path(id));
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] PID              = %u (0x%x)\n", dr_get_process_id(), dr_get_process_id());
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Processname      = %s\n", dr_get_application_name());

	drmgr_register_module_load_event(event_module_load_trace_instr);				    // executed on module load e.g. DLL
	dr_register_exit_event(event_exit);												    // executed on process exit

	tls_idx = drmgr_register_tls_field();
	DR_ASSERT(tls_idx > -1);

	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Initalization done.\n");

}