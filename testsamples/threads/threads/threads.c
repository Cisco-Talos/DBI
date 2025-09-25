#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define NUM_THREADS 4
#define INCREMENTS_PER_THREAD 500000

volatile LONG g_counter = 0;
CRITICAL_SECTION g_cs;

DWORD WINAPI worker_thread(LPVOID lpParam)
{
    int id = (int)(intptr_t)lpParam;

    for (int i = 0; i < INCREMENTS_PER_THREAD; ++i) {
        InterlockedIncrement(&g_counter);
    }

    EnterCriticalSection(&g_cs);
    printf("[INFO] Thread %d finished (partial counter = %ld)\n", id, (long)g_counter);
    LeaveCriticalSection(&g_cs);

    return 0;
}

int main(void)
{
    HANDLE threads[NUM_THREADS];

    /* init critical section for console output */
    InitializeCriticalSection(&g_cs);

    for (int i = 0; i < NUM_THREADS; ++i) {
        threads[i] = CreateThread(
            NULL,
            0,
            worker_thread,
            (LPVOID)(intptr_t)i,
            0,
            NULL);

        if (threads[i] == NULL) {
            fprintf(stderr, "[ERROR] CreateThread failed (%lu)\n", GetLastError());
            /* clean up previously created threads */
            for (int j = 0; j < i; ++j) CloseHandle(threads[j]);
            DeleteCriticalSection(&g_cs);
            return 1;
        }
    }

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    printf("Final counter = %ld (expected %ld)\n",
        (long)g_counter,
        (long)(NUM_THREADS * (long)INCREMENTS_PER_THREAD));

    for (int i = 0; i < NUM_THREADS; ++i)
        CloseHandle(threads[i]);

    DeleteCriticalSection(&g_cs);
    return 0;
}