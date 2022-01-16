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

//typedef struct _SYSTEM_MODULE_ENTRY
//{
//	ULONG  Unused;
//	ULONG  Always0;
//	PVOID  ModuleBaseAddress;
//	ULONG  ModuleSize;
//	ULONG  Unknown;
//	ULONG  ModuleEntryIndex;
//	USHORT ModuleNameLength;
//	USHORT ModuleNameOffset;
//	CHAR   ModuleName[256];
//
//} 	SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG               	ModulesCount;
	SYSTEM_MODULE_ENTRY		Modules[1];		// changed from 0...using React OS's def https://doxygen.reactos.org/da/dda/filesystems_2udfs_2Include_2ntddk__ex_8h_source.html#l00087

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

	NTKERNELAPI
		POBJECT_TYPE
		NTAPI
		ObGetObjectType(
			_In_ PVOID Object
		);
	// https://github.com/processhacker/processhacker/blob/1aa402b6a29e8b60d5c93c8385c68f719896cb24/KProcessHacker/include/ntfill.h#L261
	NTKERNELAPI
		NTSTATUS
		NTAPI
		ObOpenObjectByName(
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_ POBJECT_TYPE ObjectType,
			_In_ KPROCESSOR_MODE PreviousMode,
			_In_opt_ PACCESS_STATE AccessState,
			_In_opt_ ACCESS_MASK DesiredAccess,
			_In_opt_ PVOID ParseContext,
			_Out_ PHANDLE Handle
		);

	// https://github.com/processhacker/processhacker/blob/27c3377a9c1d3500396ed886af3d070890a68164/phnt/include/ntzwapi.h#L2765
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		ZwQueryDirectoryObject(
			_In_ HANDLE DirectoryHandle,
			_Out_writes_bytes_opt_(Length) PVOID Buffer,
			_In_ ULONG Length,
			_In_ BOOLEAN ReturnSingleEntry,
			_In_ BOOLEAN RestartScan,
			_Inout_ PULONG Context,
			_Out_opt_ PULONG ReturnLength
		);

	// https://doxygen.reactos.org/db/d18/obref_8c.html#a727c1f0726c97a4d0f526d541cee1f6a
	NTSTATUS
		NTAPI
		ObReferenceObjectByName(IN PUNICODE_STRING ObjectPath,
			IN ULONG Attributes,
			IN PACCESS_STATE PassedAccessState,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_TYPE ObjectType,
			IN KPROCESSOR_MODE AccessMode,
			IN OUT PVOID ParseContext,
			OUT PVOID* ObjectPtr);
}

namespace NomadDrv {
	extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
	NTSTATUS Create(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
	NTSTATUS Close(_In_ PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT, _Inout_ PIRP Irp);
	void Unload(_In_ PDRIVER_OBJECT DriverObject);
}
