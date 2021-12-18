#pragma once
#include "Utility.h"
#include "Driver.h"

// https://www.unknowncheats.me/forum/anti-cheat-bypass/325212-eac-system-thread-detection.html

/// <summary>
/// Scans for system threads and checks if within a valid module
/// </summary>
/// <returns>success on no error</returns>
NTSTATUS Utility::ScanSystemThreads()
{
    if (mImportFail)
    {
        LogInfo("An import failed.  Aborting ScanSystemThreads()\n");
        return STATUS_UNSUCCESSFUL;
    }

    PEPROCESS thisEPROC;
    BOOLEAN isSystemThread = 0;
    HANDLE currentProcessId;
    PVOID systemBigPoolInformation = NULL;
    PRTL_PROCESS_MODULES systemModuleInformation = NULL;
    CONTEXT* context;
    HANDLE processID;
    PEPROCESS processObject;

    NTSTATUS status;
    STACKWALK_BUFFER stackwalkBuffer;
    PETHREAD threadObject;
    UINT32 suspiciousThreads = 0;

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
        thisEPROC = pPsGetCurrentProcess();
        LogInfo("\tpPsGetCurrentProcess() returned %p\n", (VOID*)thisEPROC);
        if (thisEPROC == PsInitialSystemProcess)  // PsInitialSystemProcess is global from ntkrnl
        {
            // Get system big pool info
            if (!NT_SUCCESS(status = QuerySystemInformation(SystemBigPoolInformation, &systemBigPoolInformation)))
            {
                LogError("\tQuerySystemInformation(SystemBigPoolInformation) was unsuccessful 0x%08x\n", status);
                return status;
            }

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
                    // thread id's are multiple of 4
                    for (size_t currentThreadId = 4; currentThreadId < 0x3000; currentThreadId += 4)
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
                                if (threadObject != (PVOID)__readgsqword(0x188))                    // and thread obj is not our current thread
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
                    }

                    if (suspiciousThreads)
                    {
                        LogInfo("Found %lu suspicious threads!", suspiciousThreads);
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

/// <summary>
/// Unwinds and walks the thread's stack
/// </summary>
/// <param name="threadObject">thread being examined</param>
/// <param name="context"></param>
/// <param name="stackwalkBuffer">rip/rsp entries from the stack being walked</param>
/// <returns>1 on successful thread stack walk</returns>
BOOLEAN Utility::StackwalkThread(_In_ PETHREAD threadObject, _Out_ CONTEXT* context, _Out_ STACKWALK_BUFFER* stackwalkBuffer)
{
    UINT64* stackBuffer;
    size_t copiedSize;
    UINT64 startRip;
    UINT64 rip;
    UINT64 rsp;
    PRUNTIME_FUNCTION functionTableEntry;
    UINT64 moduleBase;
    UINT64 establisherFrame;
    UINT64 handlerData;
    DWORD sectionVa;
    DWORD sectionSize;
    UINT64 textBase;

    if (!threadObject)
        return FAIL;
    if (!stackwalkBuffer)
        return FAIL;
    memset(context, 0, sizeof(CONTEXT));
    memset(stackwalkBuffer, 0, 0x208);

    stackBuffer = (UINT64*)ExAllocatePoolWithTag(NonPagedPool, STACK_BUF_SIZE, POOL_TAG);
    if (stackBuffer)
    {
        copiedSize = CopyThreadKernelStack(threadObject, stackBuffer);
        LogInfo("\t\t\tCopyThreadKernelStack() stackSize is: %llu", copiedSize);
        if (copiedSize)
        {
            if (copiedSize != 0x1000 && copiedSize >= 0x48)
            {
                if (GetNtoskrnlSection(".text", &sectionVa, &sectionSize))
                {
                    textBase = (UINT64)((BYTE*)kernBase + sectionVa);
                    startRip = stackBuffer[7];
                    LogInfo("\t\t\tntos textBase is: 0x%llx", textBase);
                    LogInfo("\t\t\tntos textBase end is: 0x%llx", (UINT64)textBase + sectionVa);
                    LogInfo("\t\t\tthread's startRip is: 0x%llx", startRip);
                    if (startRip >= textBase && startRip < (UINT64)textBase + sectionVa)
                    {
                        context->Rip = startRip;
                        context->Rsp = (DWORD64)(stackBuffer + 8);
                        for (size_t i = 0; i < 0x20; i++)
                        {
                            rip = context->Rip;
                            rsp = context->Rsp;
                            stackwalkBuffer->Entry[stackwalkBuffer->EntryCount].RipValue = rip;
                            stackwalkBuffer->Entry[stackwalkBuffer->EntryCount++].RspValue = rsp;
                            if (rip < (UINT64)MmSystemRangeStart || rsp < (UINT64)MmSystemRangeStart)
                                break;

                            functionTableEntry = pRtlLookupFunctionEntry(rip, (PDWORD64)&moduleBase, 0);
                            
                            if (!functionTableEntry)
                                break;
                            pRtlVirtualUnwind(0, moduleBase, context->Rip, functionTableEntry, context, (PVOID*)&handlerData, (PDWORD64)&establisherFrame, 0);
                            
                            if (!context->Rip)
                            {
                                stackwalkBuffer->Succeeded = 1;
                                break;
                            }
                        }
                    }
                }
                else
                {
                    LogError("\t\t\tUnable to find .text section of ntoskrnl");
                    return FAIL;
                }
            }
            else
            {
                LogInfo("\t\t\tCopyThreadKernelStack() stackSize is 0");
                return FAIL;
            }
        }
        else
        {
            LogInfo("\t\t\tCopyThreadKernelStack() returned stackSize: %llu", copiedSize);
            return FAIL;
        }
        ExFreePoolWithTag(stackBuffer, POOL_TAG);
    }
    return SUCCESS;
}

/// <summary>
/// Copies the passed thread's kernel stack into a passed buffer
/// </summary>
/// <param name="threadObject">thread to copy kernel stack of</param>
/// <param name="outStackBuffer">buffer that receives stack contents</param>
/// <returns>size that was copied</returns>
UINT32 Utility::CopyThreadKernelStack(_In_ PETHREAD threadObject, _Out_ void* outStackBuffer)
{
    UINT32 stackSize = 0;
    UINT32 threadStateOffset;
    UINT32 kernelStackOffset;
    UINT32 threadStackBaseOffset;
    UINT32 threadStackLimitOffset;
    UINT32 threadLockOffset;
    UINT64 stackBase;
    UINT64 threadStackLimit;
    bool isSystemThread;
    void** pKernelStack;
    KSPIN_LOCK* threadLock;
    KIRQL oldIrql;

    threadStateOffset = GetThreadStateOffset();
    LogInfo("\t\t\tthreadStateOffset: 0x%lx", threadStateOffset);
    kernelStackOffset = GetKernelStackOffset();
    LogInfo("\t\t\tkernelStackOffset: 0x%lx", kernelStackOffset);
    threadStackBaseOffset = GetStackBaseOffset();
    LogInfo("\t\t\tthreadStackBaseOffset: 0x%lx", threadStackBaseOffset);

    if (threadObject && threadStackBaseOffset)
        stackBase = *(UINT64*)(threadStackBaseOffset + (UINT64)threadObject);
    else
        stackBase = 0;

    threadStackLimitOffset = GetThreadStackLimit();
    LogInfo("\t\t\tthreadStackLimitOffset: 0x%lx", threadStackLimitOffset);
    if (!threadObject)
    {
        LogError("\t\t\tCopyThreadKernelStack(): threadObject == NULL");
        return 0;
    }

    threadStackLimit = threadStackLimitOffset ? *(UINT64*)(threadStackLimitOffset + (UINT64)threadObject) : 0;
    isSystemThread = pPsIsSystemThread ? pPsIsSystemThread(threadObject) : 0;

    if (!isSystemThread
        || !outStackBuffer
        || !threadStateOffset
        || !kernelStackOffset
        || !stackBase
        || !threadStackLimit
        || KeGetCurrentIrql() > 1
        || (PKTHREAD)threadObject == KeGetCurrentThread())
    {
        LogInfo("\t\t\tCopyThreadKernelStack() aborted.  Examine checks.");
        return 0;
    }

    pKernelStack = (void**)((BYTE*)threadObject + kernelStackOffset);
    memset(outStackBuffer, 0, STACK_BUF_SIZE);
    if (LockThread((PKTHREAD)threadObject, &oldIrql))
    {
        PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(*pKernelStack);
        if (!PsIsThreadTerminating(threadObject))
        {

            if (*(BYTE*)(threadStateOffset + (BYTE*)threadObject) == KTHREAD_STATE::Waiting)
            {
                if ((UINT64)*pKernelStack > threadStackLimit)
                {
                    if ((UINT64)*pKernelStack < stackBase)
                    {
                        if (physAddr.QuadPart)
                        {
                            stackSize = stackBase - (_QWORD)*pKernelStack;
                            if (stackSize > STACK_BUF_SIZE)
                                stackSize = STACK_BUF_SIZE;
                            memmove(outStackBuffer, *pKernelStack, stackSize);
                        }
                        else
                        {
                            LogInfo("\t\t\tCopyThreadKernelStack() aborted.  !physAddr.QuadPart");

                        }
                    }
                    else
                    {
                        LogInfo("\t\t\tCopyThreadKernelStack() aborted.  *pKernelStack >= stackBase");
                    }
                }
                else
                {
                    LogInfo("\t\t\tCopyThreadKernelStack() aborted.  *pKernelStack >= stackBase");
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
            LogInfo("\t\t\tthreadLockOffset: 0x%lx", threadLockOffset);
            threadLock = (KSPIN_LOCK*)((BYTE*)threadObject + threadLockOffset);

            if (threadLockOffset)
            {
                if (threadLock != 0)
                {
                    KeReleaseSpinLockFromDpcLevel(threadLock);
                    __writecr8(oldIrql);
                }
            }
        }
        else
        {
            KeReleaseQueuedSpinLock(0, oldIrql);
        }
    }
    else
    {
        LogError("\t\t\tCopyThreadKernelStack(), LockThread() failed.  Examine.");
    }
    return stackSize;
}

/// <summary>
/// Acquires a spinlock from a thread.
/// </summary>
/// <param name="Thread">the thread we are acquiring a spinlock from</param>
/// <param name="Irql">old irql</param>
/// <returns>returns true when acquiring thread spinlock</returns>
_Success_(return) BOOL Utility::LockThread(_In_ PKTHREAD Thread, _Out_ KIRQL * Irql)
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
                // set cr8[3:0] (interrupt mask)
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

/// <summary>
/// Get offset of Tcb.StackLimit from ETHREAD
/// </summary>
/// <returns>offset on success</returns>
UINT32 Utility::GetThreadStackLimit()
{
    PETHREAD thisThread;
    UINT64 currThreadStackLimit;
    UINT64* currThreadAddr;
    USHORT maxOffset = 0x2F8;

    if (SpinLock(&gSpinLock6) == 259)
    {
        thisThread = (PETHREAD)__readgsqword(0x188);
        currThreadStackLimit = (UINT64)pPsGetCurrentThreadStackLimit();
        currThreadAddr = (UINT64*)thisThread;
        if ((UINT64)thisThread < ((UINT64)thisThread + maxOffset))
        {
            while (*currThreadAddr != currThreadStackLimit)
            {
                if ((UINT64)++currThreadAddr >= ((UINT64)thisThread + maxOffset))
                {
                    _InterlockedExchange64(&gSpinLock6, 2);
                    return gThreadStackLimit;
                }
            }
            gThreadStackLimit = (UINT64)currThreadAddr - (UINT64)thisThread;
        }
    }
    _InterlockedExchange64(&gSpinLock6, 2);
    return gThreadStackLimit;
}

/// <summary>
/// Get offset of Tcb.KernelStack from ETHREAD
/// </summary>
/// <returns>offset on success</returns>
UINT32 Utility::GetKernelStackOffset()
{
    PETHREAD thisThread;
    UINT32 initialStackOffset;
    UINT32 stackBaseOffset;
    UINT64 stackLimit;
    UINT64 stackLimitOffset;
    UINT64* currThreadAddr;
    _LARGE_INTEGER interval;
    UINT64 stackBase;
    USHORT maxOffset = 0x2F8;

    thisThread = (PETHREAD)__readgsqword(0x188);
    initialStackOffset = GetInitialStackOffset();

    stackBaseOffset = GetStackBaseOffset();
    
    if (thisThread)
    {
        if (stackBaseOffset)
            stackBase = *((UINT64*)(stackBaseOffset + (UINT64)thisThread));
        else
            stackBase = 0;

        stackLimitOffset = GetThreadStackLimit();
        
        if (stackLimitOffset)
            stackLimit = *(UINT64*)(stackLimitOffset + (PBYTE)thisThread);
        else
            stackLimit = 0;
    }
    else
    {
        GetThreadStackLimit();
        stackLimit = 0;
        stackBase = 0;
    }
    
    if (KeGetCurrentIrql() > APC_LEVEL)
        return 0;

    if (SpinLock(&gSpinLock4) == 259)
    {
        if (initialStackOffset && stackLimit && stackBase)
        {
            interval.QuadPart = 0;
            if (KeDelayExecutionThread(KernelMode, FALSE, &interval))
            {
                // 1 second delay
                interval.QuadPart = -10000;
                KeDelayExecutionThread(KernelMode, FALSE, &interval);
            }
            currThreadAddr = (UINT64*)thisThread;
            while ((UINT64)currThreadAddr < ((UINT64)thisThread + maxOffset))
            {
                if (((UINT64)currThreadAddr - (UINT64)thisThread) != initialStackOffset)
                {
                    if (*currThreadAddr < stackBase && *currThreadAddr > stackLimit)
                    {
                        gKernelStackOffset = (UINT64)currThreadAddr - (UINT64)thisThread;
                        break;
                    }
                }
                ++currThreadAddr;
            }
        }
        _InterlockedExchange64(&gSpinLock4, 2);
    }
    return gKernelStackOffset;
}

/// <summary>
/// Get offset of Tcb.InitialStack from ETHREAD
/// </summary>
/// <returns>offset on success</returns>
UINT32 Utility::GetInitialStackOffset()
{
    PETHREAD thisThread;
    UINT64 initialStack;
    UINT64* currThreadAddr;
    USHORT maxOffset = 0x2F8;

    if (SpinLock(&gSpinLock2) == 259)
    {
        thisThread = (PETHREAD)__readgsqword(0x188);
        initialStack = (UINT64)IoGetInitialStack();
        currThreadAddr = (UINT64*)thisThread;
        
        while (*currThreadAddr != initialStack)
        {
            if ((UINT64)++currThreadAddr >= (UINT64)thisThread + maxOffset)
            {
                _InterlockedExchange64(&gSpinLock2, 2);
                return FAIL;
            }
        }
        gInitialStackOffset = (UINT64)currThreadAddr - (UINT64)thisThread;
    }
    _InterlockedExchange64(&gSpinLock2, 2);
    return gInitialStackOffset;
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

    if (SpinLock(&gSpinLock5) == 259)
    {
        kThread = (PETHREAD)__readgsqword(0x188);
        stackBase = pPsGetCurrentThreadStackBase();
        kThreadStackBaseAddr = (UINT64*)kThread;
        
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
    }
    _InterlockedExchange64(&gSpinLock5, 2);
    return gStackBaseOffset;
}

/// <summary>
/// Get the thread lock offset
/// </summary>
/// <returns>byte offset of thread lock from base of ETHREAD</returns>
UINT32 Utility::GetThreadLockOffset()
{
    BYTE* threadLockOffset = NULL;

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
    UINT32* threadStateOffset = NULL;

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
            auto kThreadState = *((BYTE*)__readgsqword(0x188) + gkThreadStateOffset);

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
BOOLEAN Utility::threadLockPatternMatch(_In_ BYTE* address, _Inout_ UINT8** outOffset, _In_ UINT32 range)
{
    for (UINT8* currByte = address; currByte < (address + range); currByte++)
    {
        if (currByte[0] == threadLockPattern[0]
            && currByte[1] == threadLockPattern[1]
            && currByte[2] == threadLockPattern[2]
            && currByte[3] == threadLockPattern[3]
            && currByte[4] == threadLockPattern[4]
            && currByte[6] == threadLockPattern[6]
            && currByte[7] == threadLockPattern[7])
        {
            *outOffset = currByte + 5;
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
BOOLEAN Utility::threadStatePatternMatch(_In_ BYTE* address, _Inout_ UINT32** outOffset, _In_ UINT32 range)
{
    for (BYTE* currByte = address; currByte < (address + range); currByte++)
    {
        if (currByte[0] == threadStatePattern[0]
            && currByte[1] == threadStatePattern[1]
            && currByte[6] == threadStatePattern[6]
            && currByte[7] == threadStatePattern[7])
        {
            *outOffset = (UINT32*)((BYTE*)currByte + 2);
            return SUCCESS;
        }
    }
    return FAIL;
}

NTSTATUS Utility::GetThreadStartAddr(_In_ PETHREAD threadObject, _Out_ uintptr_t* pStartAddr)
{
    *pStartAddr = NULL;
    HANDLE hThread;
    if (!NT_SUCCESS(ObOpenObjectByPointer(threadObject, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsThreadType, KernelMode, &hThread))) {
        LogError("ObOpenObjectByPointer failed.\n");
        return;
    }
    
    uintptr_t start_addr;
    ULONG returned_bytes;
    
    if (!NT_SUCCESS(pNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &start_addr, sizeof(start_addr), &returned_bytes))) {
        LogError("NtQueryInformationThread failed.\n");
        NtClose(hThread);
        return;
    }

    if (MmIsAddressValid((void*)start_addr)) {
        *pStartAddr = start_addr;
    }
    else
        DbgPrint("(not a detection) Invalid start addr %p.\r\n", start_addr);

    NtClose(hThread);
}

//BOOLEAN IsAddressWithinBigPool(_In_ )