#pragma once
#include <ntifs.h>

namespace Utility
{
	NTSTATUS EnumKernelModuleInfo();
	NTSTATUS ImportWinPrimitives();
	NTSTATUS EnumSysThreadInfo();
	bool IsValidPEHeader(_In_ const uintptr_t head);
	PVOID GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer);

	PVOID GetNtoskrnlBaseAddress();

	int	strcmpi_w(_In_ const wchar_t* s1,_In_ const wchar_t* s2);
	__forceinline wchar_t locase_w(wchar_t c);
}
