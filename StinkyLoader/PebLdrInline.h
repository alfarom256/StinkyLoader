#pragma once
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
	pLdrDataIn->base = hMod;
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

static BYTE prelude1[7]{
	0x4D, 0x8d, 0x4b, 0xf0, // lea r9, [r11-10h]
	0x45, 0x33, 0xc0 // xor r8d, r8d
};

static BYTE prelude2[9] = {
	0x44, 0x8B, 0xC5,
	0x48, 0x8B, 0xD6,
	0x48, 0x8B, 0xCF
};

static BYTE prelude3[9] = {
	0x48, 0x83, 0xEC, 0x20, //sub rsp, 20h
	0x44, 0x8B,	0x7C, 0x24, 0x70 //mov r15d, [rsp+48h+arg_20]
};

#pragma pack(push)
#pragma pack(1)
typedef struct _call_rel32 {
	BYTE opcode;
	LONG offset;
}call_rel32, * pcall_rel32;

typedef struct _lea_rel32 {
	BYTE lea[3];
	LONG offset;
}lea_rel32, * plea_rel32;
#pragma pack(pop)

__forceinline MODULEHASH static_x65599(const char* src) {
	MODULEHASH mhModuleHash = 0;
	for (int i = 0; src[i]; i++) {

		if (src[i] >= 'a' && src[i] <= 'z') {
			mhModuleHash = 65599 * mhModuleHash + (src[i] - 0x20);
		}
		else {
			mhModuleHash = 65599 * mhModuleHash + src[i];
		}

	}
	return mhModuleHash;
}


#pragma intrinsic(memcmp)
__forceinline PVOID findPattern(PVOID buf, PBYTE pattern, ULONG ulLength) {
	PBYTE pBuf = (PBYTE)buf;

	while (TRUE) {
		// check for return "ret; int3"
		DWORD wCheckRet = *(PDWORD)pBuf;
		if (wCheckRet == 0xCCCCCCC3) {
			return NULL;
		}

		BOOL res = !memcmp(pBuf, pattern, ulLength);

		if (res) {
			return pBuf;
		}

		pBuf += 1;
	}
}

__forceinline BOOL _wcstombs(const char* src, PVOID dest, PULONG pBufferSize) {
	for (size_t i = 0; src[i]; i++)
	{

	}
}