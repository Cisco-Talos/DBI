/*
PDX-License-Identifier: Apache-2.0

Copyright (C) 2025 Cisco Talos Security Intelligence and Research Group

anti-x - this simulates some typical x64 malware obfuscation techiques

Hint: Only 64 bit supported in the moment.

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
#include <stdint.h>
#include <intrin.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#define CRC32VALUE_OF_MYFUNC 0x6115FA29 // CRC32 value of the original function code
#define KEY 0xAA						// XOR key for shellcode encoding

extern "C" size_t __fastcall get_rip();
extern "C" bool selfmodify();

// Function prototypes (if neccessary)
__declspec(noinline) void MyFunction();

//Globals
void* func_start = (void*)MyFunction;

const char* DescribeException(DWORD code) {
	switch (code) {
	case EXCEPTION_ACCESS_VIOLATION: return "Access Violation";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "Array Bounds Exceeded";
	case EXCEPTION_DATATYPE_MISALIGNMENT: return "Datatype Misalignment";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "Float Divide by Zero";
	case EXCEPTION_INT_DIVIDE_BY_ZERO: return "Integer Divide by Zero";
	// ...
	default: 
		return "Unknown Exception";
	}
}

int get_status_code(HINTERNET hRequest, DWORD* status_code) {
	DWORD size = sizeof(DWORD);
	return WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX,
		status_code, &size, WINHTTP_NO_HEADER_INDEX);
}

int get_external_ip(char* ip_buffer, size_t buffer_size) {
	if (!ip_buffer || buffer_size == 0) return 0;

	DWORD dwSize = 0, dwDownloaded = 0;
	BOOL bResults = FALSE;
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
	char* tempBuffer = NULL;
	size_t totalCopied = 0;
	DWORD error;

	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (!hSession) { 
		error = GetLastError();
		printf("[ANTI-X] [ERROR] WinHttpOpen failed with error: %lu\n", error);
		goto cleanup; 
	}

	hConnect = WinHttpConnect(hSession, L"ifconfig.me",
		INTERNET_DEFAULT_HTTPS_PORT, 0);							// INTERNET_DEFAULT_HTTP_PORT  or INTERNET_DEFAULT_HTTPS_PORT
	if (!hConnect) {
		error = GetLastError();
		printf("[ANTI-X] [ERROR] WinHttpConnect failed with error: %lu\n", error);
		goto cleanup;
	}

	hRequest = WinHttpOpenRequest(
		hConnect,
		L"GET",
		NULL,
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_SECURE                // // HTTPS: Expands to 0x00800000 - For HTTP only use 0
	);

	if (!hRequest) {
		error = GetLastError();
		printf("[ANTI-X] [ERROR] WinHttpOpenRequest failed with error: %lu\n", error);
		goto cleanup;
	}
	
	bResults = WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);
	if (!bResults) {
		error = GetLastError();
		printf("[ANTI-X] [ERROR] WinHttpSendRequest failed with error: %lu\n", error);
		goto cleanup;
	}

	bResults = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResults) {
		error = GetLastError();
		printf("[ANTI-X] [ERROR] WinHttpReceiveResponse failed with error: %lu\n", error);
		goto cleanup;
	}
	else {
		DWORD statusCode = 0;
		get_status_code(hRequest, &statusCode);
		if (statusCode != 200) 
			printf("[ANTI-X] [ERROR] HTTP Statuscode: %d\n", statusCode);   
	}

	do {
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0)
			break;

		tempBuffer = (char*)malloc(dwSize + 1);
		if (!tempBuffer) goto cleanup;

		ZeroMemory(tempBuffer, dwSize + 1);
		if (!WinHttpReadData(hRequest, tempBuffer, dwSize, &dwDownloaded)) {
			free(tempBuffer);
			goto cleanup;
		}

		size_t spaceLeft = buffer_size - totalCopied - 1;
		size_t toCopy = (dwDownloaded < spaceLeft) ? dwDownloaded : spaceLeft;

		if (toCopy > 0) {
			memcpy(ip_buffer + totalCopied, tempBuffer, toCopy);
			totalCopied += toCopy;
			ip_buffer[totalCopied] = '\0';
		}

		free(tempBuffer);
		tempBuffer = NULL;

	} while (dwSize > 0 && totalCopied < buffer_size - 1);

	bResults = totalCopied > 0;

cleanup:
	if (tempBuffer) free(tempBuffer);
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return bResults ? 1 : 0;
}

// Shellcode for selfmod func
unsigned char encoded_code[] = {
	0x50 ^ KEY,																			// 1. push rax
	0x50 ^ KEY,																			// 2. push rax
	0x50 ^ KEY,																			// 3. push rax
	0x50 ^ KEY,																			// 4. push rax
	0x50 ^ KEY,																			// 5. push rax
	0x50 ^ KEY,																			// 6. push rax
	0x58 ^ KEY,																			// 1. pop rax
	0x58 ^ KEY,																			// 2. pop rax
	0x58 ^ KEY,																			// 3. pop rax
	0x58 ^ KEY,																			// 4. pop rax
	0x58 ^ KEY,																			// 5. pop rax
	0x58 ^ KEY,																			// 6. pop rax
	0xC3 ^ KEY                                                                          // ret
};

void xor_decrypt(unsigned char* data, size_t len) {
	for (size_t i = 0; i < len; ++i)
		data[i] ^= KEY;
}

int small_function() {
	int a = 0;
	int b = 0xdeadbeee;
	a += 1;
	b += a;

	return b;
}
	
bool decode_and_run_shellcode() {
	SIZE_T code_size = sizeof(encoded_code);
	void* dec_shellcode = VirtualAlloc(NULL, code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!dec_shellcode) {
		printf("[ANTI-X] VirtualAlloc failed.\n");
		return 1;
	}

	memcpy(dec_shellcode, encoded_code, code_size);
	xor_decrypt((unsigned char*)dec_shellcode, code_size);

	printf("[ANTI-X] running decoded shellcode ...\n");
	((void(*)())dec_shellcode)();

	return 0;
}

// Function to calculate CRC32 checksum
uint32_t crc32(const void* data, size_t length) {
	uint32_t crc = 0xFFFFFFFF;
	const uint8_t* buf = (const uint8_t*)data;

	for (size_t i = 0; i < length; i++) {
		//printf("[ANTI-X] buf[i] = %p\n", &(buf[i]));
		crc ^= buf[i];
		for (int j = 0; j < 8; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
	}

	return ~crc;
}

#pragma optimize( "", off )
bool always_return_true() {

	printf("[ANTI-X] This function always returns TRUE\n");
	return true;
}

void test_function() {
	for (volatile int i = 0; i < 100; ++i);
}

__declspec(noinline) void MyFunction() {
	// --- Protection part start ---

	size_t func_end = 0;
	size_t bp = 0;

	unsigned int a = 10;
	unsigned int b = 20;
	unsigned int c = 0;

	c = a + b;

	printf("[ANTI-X] This value is always true: %s\n", always_return_true() ? "true" : "false");

	bp = get_rip();
	printf("[ANTI-X] The sum of %u and %u is %u\n", a, b, c);

	// --- Protection part end ---

	// Get function end address for crc32 check in main()
	func_end = get_rip();
	printf("[ANTI-X] Function start : 0x%zX\n", (size_t)func_start);
	printf("[ANTI-X] Function end   : 0x%zX\n", (size_t)func_end);
	printf("[ANTI-X] Function length: %zu Byte\n", func_end - (size_t)func_start - 5); // 5 bytes offset for call get_rip
	printf("[ANTI-X] Try bp at      : 0x%zX\n", bp); // BP writes CC into the function code and will be detected by the CRC32 check

}
#pragma optimize( "", on )


int main()
{
	DWORD pid = GetCurrentProcessId();
	printf("[ANTI-X] Process ID is: %lu\n", pid);

	//Check if any function code was changed 
	size_t funcSize = 110;
	uint32_t crc = crc32(func_start, funcSize);
	printf("[ANTI-X] Function address: 0x%zX\n", (size_t)func_start);
	printf("[ANTI-X] Function size: %zu\n", funcSize);
	printf("[ANTI-X] CRC32: %08X\n", crc); // CRC32 value of the function code, put this into CRC32VALUE_OF_MYFUNC

	// Check pre-defined CRC32 value of org. function code - change this at compile time
	if (crc == CRC32VALUE_OF_MYFUNC) {
		printf("[ANTI-X] [SUCCESS] CRC32 matches! Function code is ok.\n");
	}
	else {
		printf("[ANTI-X] [INTEGRITY CHECK FAIL] CRC32 does not match! Function code is modified. Function might be debugged.\n");
	}

	printf("[ANTI-X] Running a small loop \n");
	UINT64 i = 0;
	UINT64 c = 0;
	for (i = 0; i < 100; i++) {
		if (i > 6) {
			c += i;
		}
	}
	printf("[ANTI-X] Running a larger loop\n");
	c = 0;
	for (i = 0; i < 1000000000; i++) {
		if (i > 6) {
			c += i;
		}
	}

	// Check for debugger presence (PEB->BeingDebugged)
	if (IsDebuggerPresent()) {
		printf("[ANTI-X] [INTEGRITY CHECK FAIL] Process is debugged! PEB->BeingDebugged\n");
	}
	else {
		printf("[ANTI-X] [SUCCESS] No debugger detected.\n");
	}

	// Check for hardware breakpoints
	HANDLE hThread = GetCurrentThread();
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(hThread, &ctx)) {
		printf("[ANTI-X] DR0: 0x%p\n", (PVOID)ctx.Dr0);
		printf("[ANTI-X] DR1: 0x%p\n", (PVOID)ctx.Dr1);
		printf("[ANTI-X] DR2: 0x%p\n", (PVOID)ctx.Dr2);
		printf("[ANTI-X] DR3: 0x%p\n", (PVOID)ctx.Dr3);
		printf("[ANTI-X] DR6 (status): 0x%08llx\n", ctx.Dr6);
		printf("[ANTI-X] DR7 (control): 0x%08llx\n", ctx.Dr7);

		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
			printf("[ANTI-X] [INTEGRITY CHECK FAIL] GetThreadContext: Hardware breakpoints detected!\n");
		}
		else {
			printf("[ANTI-X] [SUCCESS] GetThreadContext: No hardware breakpoints detected.\n");
		}
	}
	else {
		printf("[ANTI-X] [ERROR] GetThreadContext failed: %lu\n", GetLastError());
	}

	
	// Check for hardware breakpoint again with a different trick  (this breaks DynamoRio)  
	//CONTEXT* ctx2;
	//SIZE_T debugger_attached = 0;
	//__try {
	//	__writeeflags(__readeflags() | 0x100);  // Set TF flag aka set CPU to single step
	//	__nop();								// trigger exception in single step mode
	//}
	//__except (ctx2 = (GetExceptionInformation())->ContextRecord,
	//	debugger_attached = (ctx2->ContextFlags & CONTEXT_DEBUG_REGISTERS) ?
	//	ctx2->Dr0 | ctx2->Dr1 | ctx2->Dr2 | ctx2->Dr3 : 0,
	//	EXCEPTION_EXECUTE_HANDLER)
	//{
	//	if (debugger_attached) {
	//		printf("[ANTI-X] [INTEGRITY CHECK FAIL] Exception test: Hardware breakpoints detected!\n");
	//	}
	//	else {
	//		printf("[ANTI-X] [SUCCESS] Exception test: No hardware breakpoints detected.\n");
	//	}
	//}

	// Test runtime
	uint64_t start_runtime, end_runtime, runtime;
	int cpu_info[4];

	__cpuid(cpu_info, 0);
	start_runtime = __rdtsc();

	test_function();

	__cpuid(cpu_info, 0);
	end_runtime = __rdtsc();

	runtime = end_runtime - start_runtime;
	printf("[ANTI-X] CPU-cycles: %I64u\n", runtime);

	// Modify the hartcoded runtime value for your system
	if (runtime < 1000000) {
		printf("[ANTI-X] [SUCCESS] Runtime is ok!\n");
	}
	else {
		printf("[ANTI-X] [INTEGRITY CHECK FAIL] Runtime is too long! Function might be debugged.\n");
	}

	MyFunction();

	printf("[ANTI-X] Calling small_function three times...\n");
	printf("[ANTI-X] small_function ret: %x\n", small_function());
	printf("[ANTI-X] small_function ret: %x\n", small_function());
	printf("[ANTI-X] small_function ret: %x\n", small_function());

	// ---- Shelcode test ----
	decode_and_run_shellcode();

	printf("[ANTI-X] Shellcode Done.\n");

	// ---- Self-modifying code test ----
	unsigned char* func_ptr = (unsigned char*)&selfmodify;

	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(func_ptr, &mbi, sizeof(mbi))) {
		printf("[ANTI-X] [ERROR] VirtualQuery failed: %lu\n", GetLastError());
		exit(1);
	}

	// Change the memory protection of the selfmodify function section to RWX
	DWORD oldProtect;
	if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		printf("[ANTI-X] [ERROR] VirtualProtect failed: %lu\n", GetLastError());
		exit(1);
	}

	printf("[ANTI-X] Selfmod return value: 0x%x (should be 0x3)\n", selfmodify());
	printf("[ANTI-X] Selfmod return value: 0x%x (should be 0x0)\n", selfmodify());

	// Some Exception handling which sometimes gives instrumentation tools a hard time
	// Also nice to test mindumps for debuggers e.g. procdump -e 1 -x . anti_x.exe
	printf("[ANTI-X] triggering an exception...\n");  
	__try {
		char* p = NULL;
		*p = 0; // This will cause an access violation exception
		printf("[ANTI-X] This should never be reached due to the exception\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DWORD code = GetExceptionCode();
		printf("[ANTI-X] Exception caught: %s (0x%08X)\n", DescribeException(code), code);
	}
	printf("[ANTI-X] Exception triggert.\n");

	char myip[10000];
	if (get_external_ip(myip, 10000)) {
		printf("[ANTI-X] Successfully received data from server.\n");
	}
	else {
		printf("[ANTI-X] HTTPS request failed\n");
	}
	printf("[ANTI-X] Done.\n");
	return 0;

}



