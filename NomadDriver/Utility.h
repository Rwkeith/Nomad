#pragma once
#include <ntifs.h>
#include "Driver.h"

#define POOL_TAG 0x040703A2

#define LAST_IND(x,part_type)    (sizeof(x)/sizeof(part_type) - 1)
#define HIGH_IND(x,part_type)  LAST_IND(x,part_type)
#define LOW_IND(x,part_type)   0

#pragma warning( disable : 4005 )
#define BYTEn(x, n)   (*((BYTE*)&(x)+n))

#pragma igno
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

#pragma pack(push, 1)
typedef struct _PatternContainer
{
	BYTE unk_1400567A0[74] = { 0xA5, 0xAA, 0xA5, 0xB8, 0xA5, 0xAA, 0xA5, 0xAA, 0xA5, 0xB8, 0xA5, 0xB8, 0xA5, 0xB8, 0xA5, 0xB8, 0xC0, 0xC0, 0xC0,
								0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xAC, 0xC0, 0xCC, 0xC0, 0xA1, 0xA1, 0xA1, 0xA1, 0xB1, 0xA5, 0xA5, 0xA6, 0xC0, 0xC0,
								0xD7, 0xDA, 0xE0, 0xC0, 0xE4, 0xC0, 0xEA, 0xEA, 0xE0, 0xE0, 0x98, 0xC8, 0xEE, 0xF1, 0xA5, 0xD3, 0xA5, 0xA5, 0xA1,
								0xEA, 0x9E, 0xC0, 0xC0, 0xC2, 0xC0, 0xE6, 0x03, 0x7F, 0x11, 0x7F, 0x01, 0x7F, 0x01, 0x3F, 0x01, 0x01 };

	BYTE unk_1400567EA[356] = { 0xAB, 0x8B, 0x90, 0x64, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x92, 0x5B, 0x5B, 0x76, 0x90, 0x92, 0x92, 0x5B, 0x5B, 0x5B,
								0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x6A, 0x73, 0x90, 0x5B, 0x52, 0x52, 0x52, 0x52, 0x5B, 0x5B,
								0x5B, 0x5B, 0x77, 0x7C, 0x77, 0x85, 0x5B, 0x5B, 0x70, 0x5B, 0x7A, 0xAF, 0x76, 0x76, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B,
								0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x86, 0x01, 0x03, 0x01, 0x04, 0x03, 0xD5, 0x03, 0xD5, 0x03, 0xCC, 0x01, 0xBC,
								0x03, 0xF0, 0x03, 0x03, 0x04, 0x00, 0x50, 0x50, 0x50, 0x50, 0xFF, 0x20, 0x20, 0x20, 0x20, 0x01, 0x01, 0x01, 0x01,
								0xC4, 0x02, 0x10, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x03, 0x11, 0xFF, 0x03, 0xC4, 0xC6, 0xC8, 0x02, 0x10, 0x00, 0xFF,
								0xCC, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x01, 0xFF, 0xFF, 0xC0, 0xC2, 0x10, 0x11, 0x02,
								0x03, 0x01, 0x01, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0x10,
								0x10, 0x10, 0x02, 0x10, 0x00, 0x00, 0xC6, 0xC8, 0x02, 0x02, 0x02, 0x02, 0x06, 0x00, 0x04, 0x00, 0x02, 0xFF, 0x00,
								0xC0, 0xC2, 0x01, 0x01, 0x03, 0x03, 0x03, 0xCA, 0x40, 0x00, 0x0A, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00,
								0x33, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xBF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
								0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
								0x00, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0xFF, 0x40, 0x40, 0x40, 0x40, 0x41,
								0x49, 0x40, 0x40, 0x40, 0x40, 0x4C, 0x42, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x4F, 0x44, 0x53, 0x40,
								0x40, 0x40, 0x44, 0x57, 0x43, 0x5C, 0x40, 0x60, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
								0x40, 0x40, 0x40, 0x64, 0x66, 0x6E, 0x6B, 0x40, 0x40, 0x6A, 0x46, 0x40, 0x40, 0x44, 0x46, 0x40, 0x40, 0x5B, 0x44,
								0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x06, 0x06, 0x01, 0x06, 0x06, 0x02, 0x06, 0x06, 0x00, 0x06, 0x00,
								0x0A, 0x0A, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x06, 0x02, 0x0D, 0x06, 0x06, 0x06, 0x0E, 0x05, 0x05, 0x02, 0x02,
								0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x05, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x0E };

	BYTE unk_14005694E[24] = { 0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x80, 0x01, 0x82, 0x01, 0x86, 0x00, 0xF6, 0xCF, 0xFE, 0x3F };

	BYTE unk_140056966[18] = { 0xAB,0x00,0xB0,0x00,0xB1,0x00,0xB3,0x00,0xBA,0xF8,0xBB,0x00,0xC0,0x00,0xC1,0x00,0xC7,0xBF };

	BYTE unk_140056978[15] = { 0x62, 0xFF, 0x00, 0x8D, 0xFF, 0x00, 0xC4, 0xFF, 0x00, 0xC5, 0xFF, 0x00, 0xFF, 0xFF, 0xEB };

	BYTE unk_140056987[42] = { 0x01, 0xFF, 0x0E, 0x12, 0x08, 0x00, 0x13, 0x09, 0x00, 0x16, 0x08, 0x00, 0x17, 0x09, 0x00, 0x2B,
								0x09, 0x00, 0xAE, 0xFF, 0x07, 0xB2, 0xFF, 0x00, 0xB4, 0xFF, 0x00, 0xB5, 0xFF, 0x00, 0xC3, 0x01,
								0x00, 0xC7, 0xFF, 0xBF, 0xE7, 0x08, 0x00, 0xF0, 0x02, 0x00 };

	BYTE unk_1400569B1[7] = { 0x0,0x0,0x0,0x0,0x0,0x0,0x0 };
} PatternContainer;
#pragma pack(pop)

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
	NTSTATUS QuerySystemInformation(_In_ ULONG infoClass, _Inout_ PVOID* dataBuf);
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
	__int64 patternMatcher(unsigned __int8* address, UINT64 outBuffer);
	//PKTHREAD KeGetCurrentThread();

	NTSTATUS ScanSystemThreads();
	size_t CopyThreadKernelStack(_In_ PETHREAD threadObject,_In_ __int64 maxSize,_Out_ void* outStackBuffer);
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

	PatternContainer patContainer;
};





	
