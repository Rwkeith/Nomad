#pragma once
#include <ntifs.h>
#include "Driver.h"


#define LAST_IND(x,part_type)    (sizeof(x)/sizeof(part_type) - 1)
#define HIGH_IND(x,part_type)  LAST_IND(x,part_type)
#define LOW_IND(x,part_type)   0
#define BYTEn(x, n)   (*((BYTE*)&(x)+n))
#define LOBYTE(x)  BYTEn(x,LOW_IND(x,BYTE))

#define CURRENT_KTHREAD_PTR 0x188
#define SystemBigPoolInformation 0x42
#define SystemModuleInformation 0x0B
#define STACK_BUF_SIZE 0x1000

#define WINAPI_IMPORT_COUNT 12
#define _ZwQuerySystemInformationIDX 0
#define _PsGetCurrentProcessIdIDX 1
#define _PsIsSystemThreadIDX 2
#define _PsGetCurrentProcessIDX 3
#define _IoThreadToProcessIDX 4
#define _PsGetProcessIdIDX 5
#define _RtlVirtualUnwindIDX 6
#define _RtlLookupFunctionEntryIDX 7
#define _KeAlertThreadIDX 8
#define _PsGetCurrentThreadStackBaseIDX 9
#define _PsGetCurrentThreadStackLimitIDX 10
#define _KeAcquireQueuedSpinLockRaiseToSynchIDX 11

typedef void (*GenericFuncPtr)();
typedef NTSTATUS(*ZwQuerySysInfoPtr)(ULONG, PVOID, ULONG, PULONG);
typedef PVOID(*MmSystemRoutinePtr)(PUNICODE_STRING);
typedef HANDLE(*PsGetCurrentProcessIdPtr)();
typedef BOOLEAN(*PsIsSystemThreadPtr)(PETHREAD);
typedef PEPROCESS(*PsGetCurrentProcessPtr)();
typedef NTSTATUS(*PsLookupThreadByThreadIdPtr)(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);
typedef PEPROCESS(*IoThreadToProcessPtr)(_In_ PETHREAD Thread);
typedef HANDLE(*PsGetProcessIdPtr)(_In_ PEPROCESS Process);
typedef NTSYSAPI PEXCEPTION_ROUTINE(*RtlVirtualUnwindPtr)(_In_ DWORD HandlerType, _In_ DWORD64 ImageBase, _In_ DWORD64 ControlPc, _In_ PRUNTIME_FUNCTION FunctionEntry, _Inout_ PCONTEXT ContextRecord, _Out_ PVOID* HandlerData, _Out_ PDWORD64 EstablisherFrame,_Inout_opt_ /*PKNONVOLATILE_CONTEXT_POINTERS*/PVOID ContextPointers);
typedef NTSYSAPI PRUNTIME_FUNCTION(*RtlLookupFunctionEntryPtr)(_In_ DWORD64 ControlPc, _Out_ PDWORD64 ImageBase, _Out_ /*PUNWIND_HISTORY_TABLE*/PVOID HistoryTable);
typedef BOOLEAN(*KeAlertThreadPtr)(IN PKTHREAD Thread, IN KPROCESSOR_MODE AlertMode);
typedef PVOID(*PsGetCurrentThreadStackBasePtr)();
typedef PVOID(*PsGetCurrentThreadStackLimitPtr)();
typedef void(*KeReleaseQueuedSpinLockPtr)(KSPIN_LOCK_QUEUE_NUMBER Number, KIRQL OldIrql);
typedef KIRQL(*KeAcquireQueuedSpinLockRaiseToSynchPtr)(_In_ KSPIN_LOCK_QUEUE_NUMBER Number);

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

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
	DWORD BeginAddress;
	DWORD EndAddress;
	union {
		DWORD UnwindInfoAddress;
		DWORD UnwindData;
	} DUMMYUNIONNAME;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, * _PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef struct _STACKWALK_ENTRY {
	DWORD rip;
} STACKWALK_ENTRY, *PSTACKWALK_ENTRY;

typedef struct _STACKWALK_BUFFER {
	UINT32 EntryCount;
	STACKWALK_ENTRY Entry[(STACK_BUF_SIZE - sizeof(EntryCount)) / sizeof(STACKWALK_ENTRY)];	// (STACK_BUF_SIZE - sizeof(EntryCount)) / sizeof(DWORD)
} STACKWALK_BUFFER, * PSTACKWALK_BUFFER;

class Utility
{
public:
	Utility(PDRIVER_OBJECT DriverObject);
	~Utility();
	NTSTATUS InitUtils(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS EnumKernelModuleInfo(_In_opt_ PRTL_PROCESS_MODULES* procMods);
	NTSTATUS ImportNtPrimitives();
	bool IsValidPEHeader(_In_ const uintptr_t head);
	bool CheckModulesForAddress(UINT64 address, PSYSTEM_MODULE_INFORMATION procMods);
	PVOID GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer);
	PVOID GetNtoskrnlBaseAddress();
	bool GetNtoskrnlSection(char* sectionName, DWORD* sectionVa, DWORD* sectionSize);
	NTSTATUS QuerySystemInformation(_In_ INT64 infoClass, _Inout_ PVOID* dataBuf);
	int	strcmpi_w(_In_ const wchar_t* s1, _In_ const wchar_t* s2);
	__forceinline wchar_t locase_w(wchar_t c);
	UINT32 GetThreadStateOffset();
	__int64 GetThreadStackLimit();
	__int64 GetThreadLockOffset();
	__int64 SpinLock(volatile signed __int64* Lock);
	__int64 GetKernelStackOffset();
	__int64 GetInitialStackOffset();
	__int64 GetStackBaseOffset();
	__int64 LockThread(__int64 Thread, unsigned __int8* Irql);
	__int64 patternMatcher(unsigned __int8* address, __int64 outBuffer);
	//PKTHREAD KeGetCurrentThread();

	NTSTATUS ScanSystemThreads();
	size_t CopyThreadKernelStack(_In_ PETHREAD threadObject, __int64 maxSize, void* outStackBuffer, signed int a4);
	bool StackwalkThread(_In_ PETHREAD threadObject, CONTEXT* context, _Out_ STACKWALK_BUFFER* stackwalkBuffer);

private:
	GenericFuncPtr pNtPrimitives[WINAPI_IMPORT_COUNT];
	MmSystemRoutinePtr pMmSysRoutine = NULL;
	ZwQuerySysInfoPtr pZwQuerySysInfo = NULL;
	PsGetCurrentProcessIdPtr pPsGetCurrentProcessId = NULL;
	PsIsSystemThreadPtr pPsIsSystemThread = NULL;
	PsGetCurrentProcessPtr pPsGetCurrentProcess = NULL;
	PsLookupThreadByThreadIdPtr pPsLookupThreadByThreadId = NULL;
	IoThreadToProcessPtr pIoThreadToProcess = NULL;
	PsGetProcessIdPtr pPsGetProcessId = NULL;
	RtlVirtualUnwindPtr pRtlVirtualUnwind = NULL;
	RtlLookupFunctionEntryPtr pRtlLookupFunctionEntry = NULL;
	KeAlertThreadPtr pKeAlertThread = NULL;
	PsGetCurrentThreadStackBasePtr pPsGetCurrentThreadStackBase = NULL;
	PsGetCurrentThreadStackLimitPtr pPsGetCurrentThreadStackLimit = NULL;
	KeReleaseQueuedSpinLockPtr pKeReleaseQueuedSpinLock = NULL;
	KeAcquireQueuedSpinLockRaiseToSynchPtr pKeAcquireQueuedSpinLockRaiseToSynch = NULL;

	PRTL_PROCESS_MODULES outProcMods = NULL;

	UINT32 gkThreadStateOffset = 0;
	UINT32 gThreadLockOffset = 0;
	UINT32 gKernelStackOffset = 0;
	UINT32 gInitialStackOffset = 0;
	UINT32 gStackBaseOffset = 0;
	UINT32 gThreadStackLimit = 0;

	volatile signed long long gSpinLock1 = 0;
	volatile signed long long gSpinLock2 = 0;
	volatile signed long long gSpinLock3 = 0;
	volatile signed long long gSpinLock4 = 0;
	volatile signed long long gSpinLock5 = 0;
	volatile signed long long gSpinLock6 = 0;

	PVOID kernBase = NULL;
};





	
