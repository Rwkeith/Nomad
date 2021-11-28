#pragma once
#include <ntifs.h>
#include "Driver.h"

#define WINAPI_IMPORT_COUNT 1

class Utility
{
public:
	Utility(PDRIVER_OBJECT DriverObject);
	~Utility();
	NTSTATUS InitUtils(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS EnumKernelModuleInfo();
	NTSTATUS ImportWinPrimitives();
	__int64 ScanSystemThreads();
	bool IsValidPEHeader(_In_ const uintptr_t head);
	PVOID GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer);
	PVOID GetNtoskrnlBaseAddress();
	int	strcmpi_w(_In_ const wchar_t* s1, _In_ const wchar_t* s2);
	__forceinline wchar_t locase_w(wchar_t c);
private:
	GenericFuncPtr pWinPrims[WINAPI_IMPORT_COUNT];
	MmSystemRoutinePtr pMmSysRoutine = NULL;
	ZwQuerySysInfoPtr pZwQuerySysInfo = NULL;
	PsGetCurrentProcessIdPtr pPsGetCurrentProcessId = NULL;

	PRTL_PROCESS_MODULES outProcMods = NULL;

	PVOID kernBase = NULL;
};





	
