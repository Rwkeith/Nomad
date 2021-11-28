#pragma once
#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include "PEHdr.h"

#define MAX_NAME_LEN 25

#define PAGE_SIZE 0x1000
#define PML4_OFFSET_MASK 0b00000000 11111111 00000000 00000000 00000000 00000000 00000000 00000000

#define SYS_MOD_INF 0x0B

#define DEBUG

// @jk2
#ifdef DEBUG
#define Log(format, ...) DbgPrint("[NOMAD] " format "\n", __VA_ARGS__)
#define LogInfo(format, ...) DbgPrint("[NOMAD] [INFO] " format "\n", __VA_ARGS__)
#define LogError(format, ...) DbgPrint("[NOMAD] [ERROR] " format "\n", __VA_ARGS__)

#else
#define Log(format, ...) 
#define LogInfo(format, ...) 
#define LogError(format, ...)

#endif

typedef unsigned long long uint64_t, _QWORD;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONG  Unused;
	ULONG  Always0;
	PVOID  ModuleBaseAddress;
	ULONG  ModuleSize;
	ULONG  Unknown;
	ULONG  ModuleEntryIndex;
	USHORT ModuleNameLength;
	USHORT ModuleNameOffset;
	CHAR   ModuleName[256];

} 	SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG               	ModulesCount;
	SYSTEM_MODULE_ENTRY		Modules[0];

} 	SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

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
}

namespace NomadDrv {
	NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

	NTSTATUS Create(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
	NTSTATUS Close(_In_ PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT, _Inout_ PIRP Irp);
	void Unload(_In_ PDRIVER_OBJECT DriverObject);
}
