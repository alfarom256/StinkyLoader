#pragma once
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>

#define PE_VAL 0xe4a2
#define PE_XOR 0xbeef
#define IS_PE_MAGIC( x ) ((x ^ PE_XOR) == PE_VAL)

__forceinline HMODULE getK32() {
	HMODULE r;
#ifdef _WIN64
	PPEB _ppeb = (PPEB)__readgsqword(0x60);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x20);
#else
	PPEB _ppeb = (PPEB)__readfsdword(0x30);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x10);
#endif
	return r;
}
__forceinline HMODULE getNtdll() {
	HMODULE r;
#ifdef _WIN64
	PPEB _ppeb = (PPEB)__readgsqword(0x60);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink + 0x20);
#else
	PPEB _ppeb = (PPEB)__readfsdword(0x30);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink + 0x10);
#endif
	return r;
}

typedef DWORD APIHASH;
typedef ULONG MODULEHASH;

#define MODULEHASH_NTDLL ((MODULEHASH)0xf46857d4)
#define MOD_ADLER 65521

constexpr DWORD cexpr_adler32(const char* src) {
	DWORD result_a = 1;
	DWORD result_b = 0;
	for (int i = 0; src[i] != 0; i++) {
		// calculate result_a
		result_a = (result_a + (DWORD)src[i]) % MOD_ADLER;
		result_b = (result_b + result_a) % MOD_ADLER;
	}
	return (result_b << 16) | result_a;
}

static __forceinline DWORD static_adler32(char* src) {
	DWORD result_a = 1;
	DWORD result_b = 0;
	for (int i = 0; src[i] != 0; i++) {
		// calculate result_a
		result_a = (result_a + (DWORD)src[i]) % MOD_ADLER;
		result_b = (result_b + result_a) % MOD_ADLER;
	}
	return (result_b << 16) | result_a;
}

typedef struct LdrData {
	HMODULE base;
	void* p_eat_strtbl;
	PDWORD p_eat_ptrtbl;
	PWORD p_eat_ordtbl;
	size_t num_exp;
} LDR_DATA, *PLDR_DATA;

__forceinline BOOL init_ldr_data(PLDR_DATA pLdrDataIn, HMODULE hMod) {
	if (pLdrDataIn == NULL)
	{
		return FALSE;
	}

	uintptr_t base = (uintptr_t)hMod;

	// get the required items from the export table
	IMAGE_DOS_HEADER* _dos = (IMAGE_DOS_HEADER*)base;
	if (!IS_PE_MAGIC(_dos->e_magic))
		return FALSE;
	IMAGE_NT_HEADERS* _nt = (IMAGE_NT_HEADERS*)((size_t)base + _dos->e_lfanew);
	if (_nt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	IMAGE_EXPORT_DIRECTORY* _export = (IMAGE_EXPORT_DIRECTORY*)(_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (size_t)base);
	PDWORD funcTbl = (PDWORD)(_export->AddressOfFunctions + (size_t)base);
	void* nameTbl = (void*)(_export->AddressOfNames + (size_t)base);
	PWORD ordTbl = (PWORD)(_export->AddressOfNameOrdinals + (size_t)base);
	pLdrDataIn->p_eat_ptrtbl = funcTbl;
	pLdrDataIn->p_eat_strtbl = nameTbl;
	pLdrDataIn->p_eat_ordtbl = ordTbl;
	pLdrDataIn->num_exp = _export->NumberOfFunctions;
	return TRUE;
}

__forceinline void* get_from_ldr_data(PLDR_DATA pLdrDataIn, APIHASH dwHash) {
	void* string_tbl_iter = pLdrDataIn->p_eat_strtbl;
	for (unsigned int i = 0; i < pLdrDataIn->num_exp; i++) {
		DWORD name_offset = *(DWORD*)string_tbl_iter;
		char* namePtr = ((char*)pLdrDataIn->base + name_offset);
		APIHASH x = static_adler32(namePtr);
		if (x == dwHash) {
			DWORD fn_va = pLdrDataIn->p_eat_ptrtbl[pLdrDataIn->p_eat_ordtbl[i]];
			void* fn = (void*)((size_t)pLdrDataIn->base + (DWORD)fn_va);
			return fn;
		}
		string_tbl_iter = (void*)((unsigned char*)string_tbl_iter + sizeof(DWORD));
	}
	return NULL;
}