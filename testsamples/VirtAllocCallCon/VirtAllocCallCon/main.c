#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

int main()
{
	SIZE_T code_size = sizeof(encoded_code);
	void* dec_shellcode = VirtualAlloc(NULL, code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	exit(0);
}