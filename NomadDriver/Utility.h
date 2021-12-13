#pragma once
#include <ntifs.h>
#include "Driver.h"

#define POOL_TAG 0x040703A2

#define LAST_IND(x,part_type)    (sizeof(x)/sizeof(part_type) - 1)
#define HIGH_IND(x,part_type)  LAST_IND(x,part_type)
#define LOW_IND(x,part_type)   0

#pragma warning( disable : 4005 )
#define BYTEn(x, n)   (*((BYTE*)&(x)+n))

#define LOBYTE(x)  BYTEn(x,LOW_IND(x,BYTE))

#define CURRENT_KTHREAD_PTR 0x188
#define SystemBigPoolInformation 0x42
#define SystemModuleInformation 0x0B
#define STACK_BUF_SIZE 0x2000

#define WINAPI_IMPORT_COUNT 14
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
#define _KeReleaseQueuedSpinLockIDX 12
#define _PsLookupThreadByThreadIdIDX 13

#define SUCCESS 1
#define FAIL 0

typedef enum _KTHREAD_STATE
{
	Initialized,
	Ready,
	Running,
	Standby,
	Terminated,
	Waiting,
	Transition,
	DeferredReady
} KTHREAD_STATE, * PKTHREAD_STATE;

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
	_QWORD RipValue;
	_QWORD RspValue;
} STACKWALK_ENTRY, *PSTACKWALK_ENTRY;

typedef struct _STACKWALK_BUFFER {
	bool Succeeded = 0;
	UINT32 EntryCount = 0;
	STACKWALK_ENTRY Entry[(STACK_BUF_SIZE - sizeof(UINT32)) / sizeof(STACKWALK_ENTRY)];	// (STACK_BUF_SIZE - sizeof(EntryCount)) / sizeof(DWORD)
} STACKWALK_BUFFER, * PSTACKWALK_BUFFER;

typedef void (*GenericFuncPtr)();
typedef NTSTATUS(*ZwQuerySysInfoPtr)(ULONG, PVOID, ULONG, PULONG);
typedef PVOID(*MmSystemRoutinePtr)(PUNICODE_STRING);
typedef HANDLE(*PsGetCurrentProcessIdPtr)();
typedef BOOLEAN(*PsIsSystemThreadPtr)(PETHREAD);
typedef PEPROCESS(*PsGetCurrentProcessPtr)();
typedef NTSTATUS(*PsLookupThreadByThreadIdPtr)(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);
typedef PEPROCESS(*IoThreadToProcessPtr)(_In_ PETHREAD Thread);
typedef HANDLE(*PsGetProcessIdPtr)(_In_ PEPROCESS Process);
typedef PEXCEPTION_ROUTINE(*RtlVirtualUnwindPtr)(_In_ DWORD HandlerType, _In_ DWORD64 ImageBase, _In_ DWORD64 ControlPc, _In_ PRUNTIME_FUNCTION FunctionEntry, _Inout_ PCONTEXT ContextRecord, _Out_ PVOID* HandlerData, _Out_ PDWORD64 EstablisherFrame, _Inout_opt_ PVOID ContextPointers);
typedef PRUNTIME_FUNCTION(*RtlLookupFunctionEntryPtr)(_In_ DWORD64 ControlPc, _Out_ PDWORD64 ImageBase, _Out_ PVOID HistoryTable);
typedef BOOLEAN(*KeAlertThreadPtr)(IN PKTHREAD Thread, IN KPROCESSOR_MODE AlertMode);
typedef PVOID(*PsGetCurrentThreadStackBasePtr)();
typedef PVOID(*PsGetCurrentThreadStackLimitPtr)();
typedef void(*KeReleaseQueuedSpinLockPtr)(KSPIN_LOCK_QUEUE_NUMBER Number, KIRQL OldIrql);
typedef KIRQL(*KeAcquireQueuedSpinLockRaiseToSynchPtr)(_In_ KSPIN_LOCK_QUEUE_NUMBER Number);

class Utility
{
public:
	Utility(PDRIVER_OBJECT DriverObject);
	~Utility();
	NTSTATUS InitUtils(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS EnumKernelModuleInfo(_In_opt_ PRTL_PROCESS_MODULES* procMods);
	NTSTATUS ImportNtPrimitives();
	bool IsValidPEHeader(_In_ const uintptr_t head);
	BOOLEAN IsWindows7();
	bool CheckModulesForAddress(UINT64 address, PRTL_PROCESS_MODULES procMods);
	PVOID GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer);
	PVOID GetNtoskrnlBaseAddress();
	bool GetNtoskrnlSection(char* sectionName, DWORD* sectionVa, DWORD* sectionSize);
	NTSTATUS QuerySystemInformation(_In_ ULONG infoClass, _Inout_ PVOID* dataBuf);
	int	strcmpi_w(_In_ const wchar_t* s1, _In_ const wchar_t* s2);
	__forceinline wchar_t locase_w(wchar_t c);
	UINT32 GetThreadStateOffset();
	UINT64 GetThreadStackLimit();
	UINT32 GetThreadLockOffset();
	UINT32 SpinLock(volatile signed __int64* Lock);
	__int64 GetKernelStackOffset();
	__int64 GetInitialStackOffset();
	UINT32 GetStackBaseOffset();
	_Success_(return) BOOL LockThread(_In_ PKTHREAD Thread, _Out_ KIRQL* Irql);
	BOOLEAN threadStatePatternMatch(_In_ BYTE* address, _Inout_ unsigned int **outOffset, _In_ UINT32 range);
	BOOLEAN threadLockPatternMatch(_In_ BYTE* address, _Inout_ unsigned __int8** outOffset, _In_ UINT32 range);
	NTSTATUS ScanSystemThreads();
	UINT64 CopyThreadKernelStack(_In_ PETHREAD threadObject, _Out_ void* outStackBuffer);
	bool StackwalkThread(_In_ PETHREAD threadObject, CONTEXT* context, _Out_ STACKWALK_BUFFER* stackwalkBuffer);

private:
	bool mImportFail = false;

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

	UINT64 gkThreadStateOffset = 0;
	UINT64 gThreadLockOffset = 0;
	UINT64 gKernelStackOffset = 0;
	UINT64 gInitialStackOffset = 0;
	UINT64 gStackBaseOffset = 0;
	UINT64 gThreadStackLimit = 0;

	volatile signed long long gSpinLock1 = 0;
	volatile signed long long gSpinLock2 = 0;
	volatile signed long long gSpinLock3 = 0;
	volatile signed long long gSpinLock4 = 0;
	volatile signed long long gSpinLock5 = 0;
	volatile signed long long gSpinLock6 = 0;

	PVOID kernBase = NULL;

	BYTE threadStatePattern[8] = { 0x8a, 0x83, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x05 };		// offset is 0x184 on 1903
	BYTE threadLockPattern[8] = {0xF0, 0x48, 0x0F, 0xBA, 0x6B, 0x00, 0x00, 0x0F};
};





	
