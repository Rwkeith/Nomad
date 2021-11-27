#pragma once
#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include "PEHdr.h"

#define MAX_NAME_LEN 25
#define WINAPI_IMPORT_COUNT 1
#define PAGE_SIZE 0x1000
#define PML4_OFFSET_MASK 0b00000000 11111111 00000000 00000000 00000000 00000000 00000000 00000000

#define ZW_QUERY_INFO 0
#define SYSTEM_MODULE_INFORMATION 0x0B

typedef unsigned long long uint64_t;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

extern "C" {
	NTKERNELAPI PVOID NTAPI RtlFindExportsRoutineByName(
		_In_ PVOID ImageBase,
		_In_ PCCH RoutineName
	);

	NTKERNELAPI PPEB PsGetProcessPeb(
		_In_ PEPROCESS Process
	);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	typedef void (*GenericFuncPtr)();
	typedef NTSTATUS(*ZwQuerySysInfoPtr)(ULONG, PVOID, ULONG, PULONG);
}

namespace NomadDrv {
	extern GenericFuncPtr pWinPrims[WINAPI_IMPORT_COUNT];
	extern PRTL_PROCESS_MODULES outProcMods;
	extern ZwQuerySysInfoPtr pZwQuerySysInfo;


	NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

	NTSTATUS Create(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
	NTSTATUS Close(_In_ PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT, _Inout_ PIRP Irp);
	void Unload(_In_ PDRIVER_OBJECT DriverObject);
	//NTSTATUS DumpKernelModule(_In_ char* moduleName);
}
