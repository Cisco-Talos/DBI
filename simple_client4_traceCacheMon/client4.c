#pragma once
#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "dr_tools.h"
#include "hashtable.h"
#include <stdio.h>

// Used to avoid compiler warnings about unused local variables from functions
#define UNUSED(x) (void)(x)		

// --- Structs ---
typedef struct s_argv_para {
	size_t start;
	size_t end;
} S_ARGV_PARA;

// --- Globals ---
client_id_t my_id;
S_ARGV_PARA* trace_para = NULL;
unsigned long long instr_instructions_counter = 0;

static void *mutex;
static hashtable_t bb_exec_counts;

void event_exit(void)
// executed when process exits
{
	hashtable_delete(&bb_exec_counts);
  dr_mutex_destroy(mutex);
	dr_printf("[SIMPLECLIENT] [DEBUG] [event_exit] Number of instrumented instructions: %d\n", instr_instructions_counter); 
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
	dr_printf("<SAMPLE.EXE>                     PE file to analyse\n\n");
	dr_printf("Example:\n");
	dr_printf("\"C:\\dynamorio_install\\bin64\\drrun.exe\" -c \"C:\\somedir\\simpleclient.dll\" -s 140001000 -e 140001000 -m \"sample1_64.exe\" -- \"C:\\samples\\sample1_64.exe\"\n\n");
}

void parse_cmd_opt() {
	// Parse the commandline arguments of the client library
	int argc;
	int i = 0;
	char** argv; 

	bool start_set 	= FALSE;
	bool end_set 	= FALSE;

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

	if (start_set == FALSE || end_set == FALSE ) {
		usage();
		dr_exit_process(1);
	}
}


// Executed on every basic block once
dr_emit_flags_t event_bb_instr_global(void* drcontext, void* tag, instrlist_t* bb, instr_t* instr, bool for_trace, bool translating, void* user_data) {

	UNUSED(user_data);	
	UNUSED(translating);
	UNUSED(for_trace);
	UNUSED(bb);
	UNUSED(tag);
	UNUSED(drcontext);	

	dr_mutex_lock(mutex);
  uintptr_t count = (uintptr_t)hashtable_lookup(&bb_exec_counts, tag);
  hashtable_add_replace(&bb_exec_counts, tag, (void *)(count + 1));
  dr_mutex_unlock(mutex);

	size_t instr_addr;

	instr_addr = (size_t) instr_get_app_pc(instr);

	// only trace sample applications instructions
	if (instr_is_app(instr)) {
			// insert analysing function into basic block. Called for each basic block instruction if it is in start/end range.
			if ((instr_addr >= trace_para->start) && (instr_addr <= trace_para->end))
			{
				dr_printf("[SIMPLECLIENT] [DEBUG] [event_bb_instr_global] instrumenting: 0x%zx\n", instr_addr);
				//dr_insert_clean_call(drcontext, bb, instr, (void *) process_instr_trace_instr, FALSE, 1, OPND_CREATE_INTPTR(instr_addr));
				instr_instructions_counter += 1;
		  }
	}
	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t event_trace(void *drcontext, void *tag, instrlist_t *trace, bool translating)
{	
		UNUSED(translating);
		UNUSED(trace);
		UNUSED(drcontext);
    dr_mutex_lock(mutex);
    uintptr_t count = (uintptr_t)hashtable_lookup(&bb_exec_counts, tag);
    dr_printf("[SIMPLECLIENT] [DEBUG] [event_trace] TRACE built at tag %p after %llu BB executions\n", tag, count);
    dr_mutex_unlock(mutex);
    return DR_EMIT_DEFAULT;
}


// --- Main Function ---

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[])
{
	mutex = dr_mutex_create();

	hashtable_init_ex(&bb_exec_counts,
                  8, HASH_INTPTR, false, true,
                  NULL, NULL, NULL);

	// Save the client id in a global variable for later use in functions
	my_id = id; 

	// Initalize console printing (dr_printf)
	dr_enable_console_printing();

	// Set client name
	dr_set_client_name("Simpleclient", "hunterbr@cisco.com"); 

	// Init DynamoRIO’s extension manager 
	drmgr_init();

	// Get clients command line parameter. You can either use argc/argv here or dr_get_option_array() like we do in parse_cmd_opt
	for (int i = 0; i < argc; i++) {
        dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] argv[%d] = %s\n", i, argv[i]);
    }

    // Another way to parse command line parameters
    parse_cmd_opt();

	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] DynamoRio initialized.\n");
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Client DLL used  = %s\n", dr_get_client_path(id));
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] PID              = %u (0x%x)\n", dr_get_process_id(), dr_get_process_id());
	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Processname      = %s \n", dr_get_application_name());

	drmgr_register_bb_instrumentation_event(NULL, event_bb_instr_global, NULL);		    
	dr_register_exit_event(event_exit);												    										

  // in most cases it is enough to instrument the target app
  // via drmgr_register_bb_instrumentation_event, but just in case
  // you want to see when DynamoRio traces are build
	dr_register_trace_event(event_trace);

	dr_printf("[SIMPLECLIENT] [DEBUG] [dr_client_main] Initalization done. Tracing activated.\n");

}