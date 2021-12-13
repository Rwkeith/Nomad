#pragma once
#include "Utility.h"
#include "Driver.h"

// https://www.unknowncheats.me/forum/anti-cheat-bypass/325212-eac-system-thread-detection.html
NTSTATUS Utility::ScanSystemThreads()
{
    if (mImportFail)
    {
        LogInfo("An import failed.  Aborting ScanSystemThreads()\n");
        return STATUS_UNSUCCESSFUL;
    }

    __int64 result;
    BOOLEAN isSystemThread = 0;
    HANDLE currentProcessId;
    PVOID systemBigPoolInformation = NULL;
    PRTL_PROCESS_MODULES systemModuleInformation = NULL;
    CONTEXT* context;
    UINT64 currentThreadId = 4;
    HANDLE processID;
    PEPROCESS processObject;

    NTSTATUS status;
    STACKWALK_BUFFER stackwalkBuffer;
    PETHREAD threadObject;

    UINT64 suspiciousThreads = 0;

    LogInfo("ScanSystemThreads(), Starting routine\n");
    currentProcessId = pPsGetCurrentProcessId();
    LogInfo("\tpPsGetCurrentProcessId() returned %p\n", (VOID*)currentProcessId);
    if (pPsIsSystemThread)
    {
        isSystemThread = pPsIsSystemThread((PETHREAD)__readgsqword(0x188u));
        LogInfo("\tpPsIsSystemThread() returned %u\n", isSystemThread);
    }
    else
    {
        isSystemThread = 0;
    }
    if (isSystemThread)
    {
        result = (long long)pPsGetCurrentProcess();
        LogInfo("\tpPsGetCurrentProcess() returned %p\n", (VOID*)result);
        if ((PEPROCESS)result == PsInitialSystemProcess)  // PsInitialSystemProcess is global from ntkrnl
        {
            // Get system big pool info
            //if (!NT_SUCCESS(result = QuerySystemInformation(SystemBigPoolInformation, &systemBigPoolInformation)))
            //{
            //    LogError("\tQuerySystemInformation(SystemBigPoolInformation) was unsuccessful 0x%08x\n", result);
            //    return result;
            //}

            // System != Process module info
            if (!NT_SUCCESS(status = QuerySystemInformation(SystemModuleInformation, (PVOID*)&systemModuleInformation)))
            {
                LogError("\tQuerySystemInformation(SystemModuleInformation) was unsuccessful 0x%08x\n", (long)status);
                return status;
            }

            //systemModuleInformation = (PSYSTEM_MODULE_INFORMATION)result;

            if (systemModuleInformation)
            {
                // allocate memory to store a thread's context
                context = (CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(CONTEXT), POOL_TAG);
                if (context)
                {
                    currentThreadId = 4;
                    do
                    {

                        status = pPsLookupThreadByThreadId((HANDLE)currentThreadId, &threadObject);

                        if (status == STATUS_SUCCESS)
                        {
                            LogInfo("\tFound valid thread id: 0x%llx (%llu)", currentThreadId, currentThreadId);
                            processObject = pIoThreadToProcess(threadObject);

                            if (!processObject)
                            {
                                LogError("\t\tpFailed to get process object, pIoThreadToProcess(threadObject) == NULL, skipping thread ID: %llu\n", currentThreadId);
                                continue;
                            }

                            processID = pPsGetProcessId(processObject);

                            if (!processID)
                            {
                                LogError("\t\tAborting thread check:  Failed to get process id, pPsGetProcessId(processObject) == NULL\n");
                                continue;
                            }

                            if (processID == currentProcessId)                                      // if...the thread's pid is the same as system pid, and threadobject 
                            {
                                if (threadObject != (PVOID)__readgsqword(0x188))                    // __readgsqword(0x188) == return (struct _KTHREAD *)__readgsqword(0x188) , and thread obj is not our current thread
                                {
                                    if (StackwalkThread(threadObject, context, &stackwalkBuffer))   // and succesfully walks the stack of thread
                                    {
                                        if (stackwalkBuffer.EntryCount > 0)                         // and has more than 1 entry in the stack
                                        {
                                            LogInfo("\t\t\tExamining thread stack.....");
                                            LogInfo("\t\t\tstackwalkBuffer.EntryCount: %lu", stackwalkBuffer.EntryCount);
                                            for (size_t i = 0; i < stackwalkBuffer.EntryCount; i++)
                                            {
                                                LogInfo("\t\t\tstackwalkBuffer.Entry[%llu].RipValue: 0x%llx", i, stackwalkBuffer.Entry[i].RipValue);
                                                if (!CheckModulesForAddress(stackwalkBuffer.Entry[i].RipValue, systemModuleInformation))
                                                {
                                                    LogInfo("\t\t\tSUSPICIOUS THREAD DETECTED\n");
                                                    suspiciousThreads += 1;
                                                    break;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            LogInfo("\t\tAborting thread check:  No entries in thread stack");
                                        }
                                    }
                                    else
                                    {
                                        LogInfo("\t\tAborting thread check:  Unsuccessful StackwalkThread() call");
                                    }
                                }
                                else
                                {
                                    LogInfo("\t\tAborting thread check:  Our thread");
                                }
                            }
                            else
                            {
                                LogInfo("\t\tAborting thread check:  Not a System thread");
                            }
                            ObfDereferenceObject(threadObject); // reference count was incremented by pPsLookupThreadByThreadId
                        }
                        currentThreadId += 4;               // thread id's are multiple of 4
                    } while (currentThreadId < 0x3000);     // lol, brute force method by EAC.  Maybe there's a better way
                    if (suspiciousThreads)
                    {
                        LogInfo("Found %llu suspicious threads!", suspiciousThreads);
                    }
                    else
                    {
                        LogInfo("No suspicious threads found.");
                    }
                    ExFreePool(context);
                }
                else
                {
                    LogError("\t\tUtility.cpp:%d, ExAllocatePool failed\n", __LINE__);
                    return STATUS_UNSUCCESSFUL;
                }
                ExFreePool(systemModuleInformation);
            }
            else
            {
                LogError("\t\tUtility.cpp:%d, systemModuleInformation == NULL\n", __LINE__);
                return STATUS_UNSUCCESSFUL;
            }
            if (systemBigPoolInformation)
                ExFreePoolWithTag(systemBigPoolInformation, POOL_TAG);
        }
    }
    return STATUS_SUCCESS;
}

bool Utility::StackwalkThread(_In_ PETHREAD threadObject, CONTEXT* context, _Out_ STACKWALK_BUFFER* stackwalkBuffer)
{
    _QWORD* stackBuffer;
    size_t copiedSize;
    DWORD64 startRip;
    unsigned int index;
    unsigned __int64 rip0;
    DWORD64 rsp0;
    PRUNTIME_FUNCTION functionTableEntry;
    __int64 moduleBase;
    __int64 v17;
    __int64 v18;
    DWORD sectionVa;
    DWORD sectionSize;
    unsigned __int64 textBase;

    if (!threadObject)
        return 0;
    if (!stackwalkBuffer)
        return 0;
    memset(context, 0, sizeof(CONTEXT));
    memset(stackwalkBuffer, 0, 0x208);

    stackBuffer = (_QWORD*)ExAllocatePoolWithTag(NonPagedPool, STACK_BUF_SIZE, POOL_TAG);
    if (stackBuffer)
    {
        copiedSize = CopyThreadKernelStack(threadObject, stackBuffer);
        LogInfo("\t\t\tCopyThreadKernelStack() copiedSize is: %llu", copiedSize);
        if (copiedSize)
        {
            if (copiedSize != 4096 && copiedSize >= 0x48)
            {
                if (GetNtoskrnlSection(".text", &sectionVa, &sectionSize))
                {
                    textBase = (unsigned __int64)((BYTE*)kernBase + sectionVa);
                    startRip = stackBuffer[7];
                    LogInfo("\t\t\tntos textBase is: 0x%llx", textBase);
                    LogInfo("\t\t\tntos textBase end is: 0x%llx", (UINT64)textBase + sectionVa);
                    LogInfo("\t\t\tthread's startRip is: 0x%llx", startRip);
                    if (startRip >= textBase && startRip < (UINT64)textBase + sectionVa)
                    {
                        context->Rip = startRip;
                        context->Rsp = (DWORD64)(stackBuffer + 8);
                        index = 0;
                        do
                        {
                            rip0 = context->Rip;
                            rsp0 = context->Rsp;
                            stackwalkBuffer->Entry[stackwalkBuffer->EntryCount].RipValue = rip0;
                            stackwalkBuffer->Entry[stackwalkBuffer->EntryCount++].RspValue = rsp0;
                            if (rip0 < (unsigned long long)MmSystemRangeStart)
                                break;
                            if (rsp0 < (unsigned long long)MmSystemRangeStart)
                                break;
                            functionTableEntry = pRtlLookupFunctionEntry(rip0, (PDWORD64)&moduleBase, 0);
                            if (!functionTableEntry)
                                break;
                            pRtlVirtualUnwind(0, moduleBase, context->Rip, functionTableEntry, context, (PVOID*)&v18, (PDWORD64)&v17, 0);
                            if (!context->Rip)
                            {
                                stackwalkBuffer->Succeeded = 1;
                                break;
                            }
                            ++index;
                        } while (index < 0x20);
                    }
                }
                else
                {
                    LogError("\t\t\tUnable to find .text section of ntoskrnl");
                    return 0;
                }
            }
            else
            {
                LogInfo("\t\t\tCopyThreadKernelStack() copiedSize is 0");
                return 0;
            }
        }
        else
        {
            LogInfo("\t\t\tCopyThreadKernelStack() returned copiedSize: %llu", copiedSize);
            return 0;
        }
        ExFreePoolWithTag(stackBuffer, POOL_TAG);
    }
    return 1;
}

UINT64 Utility::CopyThreadKernelStack(_In_ PETHREAD threadObject, _Out_ void* outStackBuffer)
{
    size_t copiedSize = 0;
    size_t threadStateOffset;
    size_t kernelStackOffset;
    size_t threadStackBaseOffset;
    size_t threadStackBase;
    size_t threadStackLimitOffset;
    size_t threadStackLimit;
    bool isSystemThread;
    void** pKernelStack;
    __int64 _oldIrql;
    __int64 threadLockOffset;
    KSPIN_LOCK* threadLock;
    KIRQL oldIrql;

    threadStateOffset = GetThreadStateOffset();
    LogInfo("\t\t\tthreadStateOffset: 0x%llx", threadStateOffset);
    kernelStackOffset = GetKernelStackOffset();
    LogInfo("\t\t\tkernelStackOffset: 0x%llx", kernelStackOffset);
    threadStackBaseOffset = GetStackBaseOffset();
    LogInfo("\t\t\tthreadStackBaseOffset: 0x%llx", threadStackBaseOffset);

    if (threadObject && threadStackBaseOffset)
        threadStackBase = *(_QWORD*)(threadStackBaseOffset + (BYTE*)threadObject);
    else
        threadStackBase = 0;

    threadStackLimitOffset = GetThreadStackLimit();
    LogInfo("\t\t\tthreadStackLimitOffset: 0x%llx", threadStackLimitOffset);
    if (!threadObject)
    {
        LogError("\t\t\tCopyThreadKernelStack(): threadObject == NULL");
        return 0;
    }

    threadStackLimit = threadStackLimitOffset ? *(_QWORD*)(threadStackLimitOffset + (BYTE*)threadObject) : 0;
    isSystemThread = pPsIsSystemThread ? pPsIsSystemThread(threadObject) : 0;

    if (!isSystemThread
        || !outStackBuffer
        || !(DWORD)threadStateOffset
        || !(DWORD)kernelStackOffset
        || !threadStackBase
        || !threadStackLimit
        || KeGetCurrentIrql() > 1
        || (PKTHREAD)threadObject == KeGetCurrentThread())        //KeGetCurrentThread() is inlined, gs register access.
    {
        LogInfo("\t\t\tCopyThreadKernelStack() aborted.  Examine checks.");
        return 0;
    }

    pKernelStack = (void**)((BYTE*)threadObject + kernelStackOffset);
    memset(outStackBuffer, 0, 0x2000);
    LogInfo("Thread State before locking");
    if (LockThread((PKTHREAD)threadObject, &oldIrql))
    {
        PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(*pKernelStack);
        if (!PsIsThreadTerminating(threadObject))
        {

            if (*(BYTE*)(threadStateOffset + (BYTE*)threadObject) == KTHREAD_STATE::Waiting)
            {
                if ((UINT64)*pKernelStack > threadStackLimit)
                {
                    if ((UINT64)*pKernelStack < threadStackBase)
                    {
                        if (physAddr.QuadPart)
                        {
                            copiedSize = threadStackBase - (_QWORD)*pKernelStack;
                            if (copiedSize > 0x2000)
                                copiedSize = 0x2000;
                            memmove(outStackBuffer, *pKernelStack, copiedSize);
                        }
                        else
                        {
                            LogInfo("\t\t\tCopyThreadKernelStack() aborted.  !physAddr.QuadPart");

                        }
                    }
                    else
                    {
                        LogInfo("\t\t\tCopyThreadKernelStack() aborted.  *pKernelStack >= threadStackBase");
                    }
                }
                else
                {
                    LogInfo("\t\t\tCopyThreadKernelStack() aborted.  *pKernelStack >= threadStackBase");
                }

            }
            else
            {
                LogInfo("\t\t\tCopyThreadKernelStack() aborted.  *(BYTE*)(threadStateOffset + (BYTE*)threadObject) != 5(Waiting state)");
                LogInfo("\t\t\tThread State is: %hhu", *(BYTE*)(threadStateOffset + (BYTE*)threadObject));
            }
        }
        else
        {
            LogInfo("\t\t\tCopyThreadKernelStack() aborted.  PsIsThreadTerminating(threadObject) == true");
        }

        if (SharedUserData->NtMajorVersion >= 6 && SharedUserData->NtMajorVersion != 6 || !SharedUserData->NtMinorVersion)  //  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
        {
            threadLockOffset = GetThreadLockOffset();
            LogInfo("\t\t\tthreadLockOffset: 0x%llx", threadLockOffset);
            BYTE* newthreadLock = (BYTE*)threadObject + threadLockOffset;
            signed __int64 rightExpression = -(signed __int64)(threadLockOffset != 0);
            threadLock = (KSPIN_LOCK*)((unsigned __int64)newthreadLock & rightExpression);
            if (threadLock != 0)
            {
                KeReleaseSpinLockFromDpcLevel(threadLock);
                __writecr8(oldIrql);
            }
        }
        else
        {
            LOBYTE(_oldIrql) = oldIrql;
            KeReleaseQueuedSpinLock(0, oldIrql);
        }
    }
    else
    {
        LogError("\t\t\tCopyThreadKernelStack(), LockThread() failed.  Examine.");
    }
    return copiedSize;
}

_Success_(return)
BOOL Utility::LockThread(_In_ PKTHREAD Thread, _Out_ KIRQL * Irql)
{
    KIRQL currentIrql;
    UINT64 ThreadLockOffset;
    KSPIN_LOCK* threadLock;

    if (Thread && Irql)
    {
        if (SharedUserData->NtMajorVersion >= 6 && (SharedUserData->NtMajorVersion != 6 || SharedUserData->NtMinorVersion))
        {
            ThreadLockOffset = GetThreadLockOffset();
            threadLock = (PKSPIN_LOCK)((BYTE*)Thread + ThreadLockOffset);
            if (threadLock && ThreadLockOffset)
            {
                currentIrql = KeGetCurrentIrql();
                LogInfo("\t\t\tCurrent IRQL: %d", currentIrql);
                // set interrupt mask 3:0 to b1100
                __writecr8(0xC);
                *Irql = currentIrql;
                LogInfo("\t\t\tThread State before KeAcquireSpinLockAtDpcLevel: %hhu", *((BYTE*)Thread + gkThreadStateOffset));
                KeAcquireSpinLockAtDpcLevel(threadLock);
                LogInfo("\t\t\tThread State after KeAcquireSpinLockAtDpcLevel: %hhu", *((BYTE*)Thread + gkThreadStateOffset));
                currentIrql = KeGetCurrentIrql();
                LogInfo("\t\t\tCurrent IRQL after KeAcquireSpinLockAtDpcLevel: %hhu", currentIrql);
                return SUCCESS;
            }
            else
            {
                return FAIL;
            }
        }
        else
        {
            LogInfo("\t\t\tUsing pKeAcquireQueuedSpinLockRaiseToSynch");
            *Irql = pKeAcquireQueuedSpinLockRaiseToSynch(0);
            return SUCCESS;
        }
    }
    else
    {
        return FAIL;
    }
}

UINT64 Utility::GetThreadStackLimit()
{
    PETHREAD thisKThread;
    unsigned __int64 v2;
    _QWORD* v3;

    thisKThread = (PETHREAD)__readgsqword(0x188);
    if (SpinLock(&gSpinLock6) == 259)
    {
        v2 = (__int64)pPsGetCurrentThreadStackLimit();
        v3 = (_QWORD*)thisKThread;
        if ((BYTE*)thisKThread < ((BYTE*)thisKThread + 0x2F8))
        {
            while (*v3 != v2)
            {
                if ((unsigned __int64)++v3 >= ((UINT64)thisKThread + 0x2F8))
                    goto LABEL_9;
            }
            gThreadStackLimit = (UINT64)v3 - (UINT64)thisKThread;
        }
    LABEL_9:
        _InterlockedExchange64(&gSpinLock6, 2);
    }
    return gThreadStackLimit;
}

__int64 Utility::GetKernelStackOffset()
{
    unsigned __int64 thisThread; // rbx
    UINT64 InitialStackOffset; // ebp
    UINT64 stackBaseOffset; // eax
    unsigned __int64 v3; // rdi
    unsigned __int64 v4; // rsi
    UINT64 v5; // eax
    unsigned __int64* v7; // rax
    bool i; // cf
    _LARGE_INTEGER Interval; // [rsp+40h] [rbp+8h] BYREF
    _LARGE_INTEGER v10; // [rsp+48h] [rbp+10h] BYREF

    Interval.QuadPart = 0;
    thisThread = __readgsqword(0x188);
    InitialStackOffset = GetInitialStackOffset();
    stackBaseOffset = GetStackBaseOffset();
    if (thisThread)
    {
        if (stackBaseOffset)
            v4 = *(_QWORD*)(stackBaseOffset + thisThread);
        else
            v4 = 0;
        v5 = GetThreadStackLimit();
        if (v5)
            v3 = *(_QWORD*)(v5 + thisThread);
        else
            v3 = 0;
    }
    else
    {
        GetThreadStackLimit();
        v3 = 0;
        v4 = 0;
    }
    if (KeGetCurrentIrql() > 1u)
        return 0;
    if ((unsigned int)SpinLock(&gSpinLock4) == 259)
    {
        if (InitialStackOffset && v3 && v4)
        {
            if (KeDelayExecutionThread(0, 0, &Interval))
            {
                v10.QuadPart = -10000;
                KeDelayExecutionThread(0, 0, &v10);
            }
            v7 = (unsigned __int64*)thisThread;
            for (i = thisThread < thisThread + 760; i; i = (unsigned __int64)v7 < thisThread + 760)
            {
                if ((DWORD)v7 - (DWORD)thisThread != InitialStackOffset && *v7 < v4 && *v7 > v3)
                {
                    gKernelStackOffset = (DWORD)v7 - thisThread;
                    break;
                }
                ++v7;
            }
        }
        _InterlockedExchange64(&gSpinLock4, 2);
    }
    return (unsigned int)gKernelStackOffset;
}

__int64 Utility::GetInitialStackOffset()
{
    unsigned __int64 thisKThread;
    _int64 v2;
    _QWORD* v3;

    thisKThread = __readgsqword(0x188);
    if ((unsigned int)SpinLock(&gSpinLock2) == 259)
    {
        v2 = (__int64)IoGetInitialStack();
        v3 = (_QWORD*)thisKThread;
        if (thisKThread < thisKThread + 760)
        {
            while (*v3 != v2)
            {
                if ((unsigned __int64)++v3 >= thisKThread + 760)
                    goto LABEL_9;
            }
            gInitialStackOffset = (DWORD)v3 - thisKThread;
        }
    LABEL_9:
        _InterlockedExchange64(&gSpinLock2, 2);
    }
    return (unsigned int)gInitialStackOffset;
}

/// <summary>
/// Get offset of Tcb.StackBase from ETHREAD
/// </summary>
/// <returns>offset on success</returns>
UINT32 Utility::GetStackBaseOffset()
{
    PETHREAD kThread;
    PVOID stackBase;
    UINT64* kThreadStackBaseAddr;

    kThread = (PETHREAD)__readgsqword(0x188);
    if (SpinLock(&gSpinLock5) == 259)
    {
        stackBase = pPsGetCurrentThreadStackBase();
        kThreadStackBaseAddr = (UINT64*)kThread;
        if ((UINT64)kThread < ((UINT64)kThread + 0x2F8))
        {
            while (*kThreadStackBaseAddr != (UINT64)stackBase)
            {
                if ((UINT64)++kThreadStackBaseAddr >= (UINT64)kThread + 0x2F8)
                {
                    LogInfo("\t\t\tUnable to find Stack Base Offset.");
                    _InterlockedExchange64(&gSpinLock5, 2);
                    return FAIL;
                }
            }
            gStackBaseOffset = (UINT64)kThreadStackBaseAddr - (UINT64)kThread;
            _InterlockedExchange64(&gSpinLock5, 2);
        }
    }
    return gStackBaseOffset;
}

/// <summary>
/// Get the thread lock offset
/// </summary>
/// <returns>byte offset of thread lock from base of ETHREAD</returns>
UINT32 Utility::GetThreadLockOffset()
{
    BYTE* maxOffset;
    BYTE* threadLockOffset;

    if (SpinLock(&gSpinLock1) == 259)
    {
        if ((UINT64)KeSetPriorityThread)
        {
            if (threadLockPatternMatch((BYTE*)KeSetPriorityThread, &threadLockOffset, 0xF1))
            {
                LogInfo("\t\t\tthreadLockPatternMatch() found a match at %p with offset value %lu", threadLockOffset, *threadLockOffset);
                gThreadLockOffset = (unsigned __int8)*threadLockOffset;
            }
            else
            {
                LogInfo("\t\t\tthreadLockPatternMatch() failed to find a match");
                gThreadLockOffset = 0;
            }
        }
        _InterlockedExchange64(&gSpinLock1, 2);
    }
    return gThreadLockOffset;
}

/// <summary>
/// Get the thread state offset
/// </summary>
/// <returns>byte offset of thread state from base of ETHREAD</returns>
UINT32 Utility::GetThreadStateOffset()
{
    UINT32* threadStateOffset;

    if (SpinLock(&gSpinLock3) == 259)
    {
        if (IsWindows7())
        {
            gkThreadStateOffset = 0x164;
        }
        else
        {
            if (pKeAlertThread)
            {
                if (threadStatePatternMatch((BYTE*)pKeAlertThread, &threadStateOffset, 0x132))
                {
                    LogInfo("\t\t\tthreadStatePatternMatch() found a match at %p with offset value %lu", threadStateOffset, *threadStateOffset);
                    gkThreadStateOffset = *threadStateOffset;
                }
                else
                {
                    LogError("\t\t\tthreadStatePatternMatch() failed to find a match");
                    return gkThreadStateOffset;
                }
            }
        }
        if (gkThreadStateOffset)
        {
            auto kThreadState = *(BYTE*)((BYTE*)__readgsqword(0x188) + gkThreadStateOffset);

            if (kThreadState != KTHREAD_STATE::Running)
            {
                LogError("\t\t\tGetThreadState(), thread state offset check failure.");
                gkThreadStateOffset = 0;
            }
        }
        _InterlockedExchange64(&gSpinLock3, 2);
    }
    return gkThreadStateOffset;
}

/// <summary>
/// Only tested on 2104 (21H1)
/// </summary>
/// <param name="address">start address</param>
/// <param name="outOffset">if successful, initialized with offset</param>
/// <param name="range">length to scan</param>
/// <returns>1 on success</returns>
BOOLEAN Utility::threadLockPatternMatch(_In_ BYTE* address, _Inout_ unsigned __int8** outOffset, _In_ UINT32 range)
{
    for (BYTE* currByte = address; currByte < (address + range); currByte++)
    {
        if (currByte[0] == threadLockPattern[0]
            && currByte[1] == threadLockPattern[1]
            && currByte[2] == threadLockPattern[2]
            && currByte[3] == threadLockPattern[3]
            && currByte[4] == threadLockPattern[4]
            && currByte[6] == threadLockPattern[6]
            && currByte[7] == threadLockPattern[7])
        {
            *outOffset = (unsigned __int8*)((BYTE*)currByte + 5);
            return SUCCESS;
        }
    }
    return FAIL;
}

/// <summary>
/// Only tested on 2104 (21H1)
/// </summary>
/// <param name="address">start address</param>
/// <param name="outOffset">if successful, initialized with offset</param>
/// <param name="range">length to scan</param>
/// <returns>1 on success</returns>
BOOLEAN Utility::threadStatePatternMatch(_In_ BYTE* address, _Inout_ unsigned int** outOffset, _In_ UINT32 range)
{
    for (BYTE* currByte = address; currByte < (address + range); currByte++)
    {
        if (currByte[0] == threadStatePattern[0]
            && currByte[1] == threadStatePattern[1]
            && currByte[6] == threadStatePattern[6]
            && currByte[7] == threadStatePattern[7])
        {
            *outOffset = (unsigned int*)((BYTE*)currByte + 2);
            return SUCCESS;
        }
    }
    return FAIL;
}