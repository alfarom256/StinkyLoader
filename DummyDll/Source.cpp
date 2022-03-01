#include <Windows.h>

BOOL DllMain(HINSTANCE, DWORD dwReason, LPVOID) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "d00t", ":)", MB_OK);
		break;
	default:
		break;
	}
	return TRUE;
}