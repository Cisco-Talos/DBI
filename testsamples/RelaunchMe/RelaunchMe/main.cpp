/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group


relaunchme - this simulates malware behaviour of restarting itself from a tmp-dir


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


#include <Windows.h>
#include <stdio.h>
#include <string.h>

int main()
{
    char currentPath[MAX_PATH];
    char tempPath[MAX_PATH];
    char newExePath[MAX_PATH];
    char *basename;

    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    basename = strrchr(currentPath, '\\')+1;

    GetTempPathA(MAX_PATH, tempPath);

    snprintf(newExePath, MAX_PATH, "%s%s", tempPath, basename);
    printf("[RelaunchMe] Org. module path: %s\n", currentPath);

    if (strcmp(currentPath, newExePath) == 0) {
        printf("[RelaunchMe][SUCCESS] I am launched from tmp folder\n");
        exit(0);
    }
    else {
        printf("[RelaunchMe] New module path : %s\n", newExePath);


        if (!CopyFileA(currentPath, newExePath, FALSE)) {
            printf("[RelaunchMe] [ERROR] Copying failed with error: %lu\n", GetLastError());
            return 1;
        }

        // Start new copy of myself
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);

        if (!CreateProcessA(
            newExePath,
            NULL,
            NULL, NULL, FALSE, 0, NULL, NULL,
            &si, &pi))
        {
            printf("[RelaunchMe] [ERROR] Failed to create new process with error: %lu\n", GetLastError());
            return 1;
        }

        printf("[RelaunchMe] New process started from: %s\n", newExePath);
        return 0;
    }
}