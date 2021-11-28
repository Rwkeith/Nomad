#pragma once
#include <ntifs.h>
#include "Driver.h"

#define SystemBigPoolInformation 0x42
#define SystemModuleInformation 0x0B

#define WINAPI_IMPORT_COUNT 4
#define _ZwQuerySystemInformationIDX 0
#define _PsGetCurrentProcessIdIDX 1
#define _PsIsSystemThreadIDX 2
#define _PsGetCurrentProcessIDX 3

typedef void (*GenericFuncPtr)();
typedef NTSTATUS(*ZwQuerySysInfoPtr)(ULONG, PVOID, ULONG, PULONG);
typedef PVOID(*MmSystemRoutinePtr)(PUNICODE_STRING);
typedef HANDLE(*PsGetCurrentProcessIdPtr)();
typedef BOOLEAN(*PsIsSystemThreadPtr)(PETHREAD);
typedef PEPROCESS(*PsGetCurrentProcessPtr)();
typedef NTSTATUS(*PsLookupThreadByThreadIdPtr)(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);

typedef struct _SYSTEM_BIGPOOL_ENTRY {
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;


class Utility
{
public:
	Utility(PDRIVER_OBJECT DriverObject);
	~Utility();
	NTSTATUS InitUtils(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS EnumKernelModuleInfo(_In_opt_ PRTL_PROCESS_MODULES* procMods);
	NTSTATUS ImportNtPrimitives();
	bool IsValidPEHeader(_In_ const uintptr_t head);
	PVOID GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer);
	PVOID GetNtoskrnlBaseAddress();
	NTSTATUS QuerySystemInformation(_In_ INT64 infoClass, _Inout_ PVOID* dataBuf);
	int	strcmpi_w(_In_ const wchar_t* s1, _In_ const wchar_t* s2);
	__forceinline wchar_t locase_w(wchar_t c);

	NTSTATUS ScanSystemThreads();
	size_t CopyThreadKernelStack(__int64 threadObject, __int64 maxSize, void* outStackBuffer, signed int a4);
	char StackwalkThread(__int64 threadObject, CONTEXT* context, STACKWALK_BUFFER* stackwalkBuffer);

private:
	GenericFuncPtr pNtPrimitives[WINAPI_IMPORT_COUNT];
	MmSystemRoutinePtr pMmSysRoutine = NULL;
	ZwQuerySysInfoPtr pZwQuerySysInfo = NULL;
	PsGetCurrentProcessIdPtr pPsGetCurrentProcessId = NULL;
	PsIsSystemThreadPtr pPsIsSystemThread = NULL;
	PsGetCurrentProcessPtr pPsGetCurrentProcess = NULL;
	PsLookupThreadByThreadIdPtr pPsLookupThreadByThreadId = NULL;

	PRTL_PROCESS_MODULES outProcMods = NULL;

	PVOID kernBase = NULL;
};





	
