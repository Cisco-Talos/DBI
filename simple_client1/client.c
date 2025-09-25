/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group

client.c - Most simple "hello world" client for DynamoRio

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

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char* argv[]) {
    
    // Enable console output
    dr_enable_console_printing();

    // Say hello
    dr_printf("Hello from DynamoRIO client!\n");
}

