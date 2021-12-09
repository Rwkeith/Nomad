#pragma once
#include "Utility.h"
#include "Driver.h"

Utility::Utility(PDRIVER_OBJECT DriverObject)
{
    if (!NT_SUCCESS(InitUtils(DriverObject)))
    {
        LogError("Failed to init Utilities\n");
    }
    else
    {
        LogInfo("Utilities initialized\n");
    }
}

Utility::~Utility()
{
    LogInfo("Deconstructing utilities...\n");

    if (outProcMods)
    {
        ExFreePool(outProcMods);
    }
}

NTSTATUS Utility::InitUtils(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    kernBase = Utility::GetKernelBaseAddr(DriverObject);
    if (!kernBase)
    {
        LogError("Unable to get kernel base. Aborting init\n");
        return STATUS_UNSUCCESSFUL;
    }

    LogInfo("Frostiest method:  Found ntoskrnl.exe base @ 0x%p\n", kernBase);

    kernBase = GetNtoskrnlBaseAddress();

    LogInfo("Barakat method: Found ntoskrnl.exe base @ 0x%p\n", kernBase);

    status = FindExport((uintptr_t)kernBase, "MmGetSystemRoutineAddress", (uintptr_t*)&pMmSysRoutine);

    if (!NT_SUCCESS(status))
    {
        LogError("Unable to import core Nt function MmGetSystemRoutineAddress. Aborting init\n");
        return STATUS_UNSUCCESSFUL;
    }

    LogInfo("Parsed export MmGetSystemRoutineAddress: %p\n", pMmSysRoutine);

    status = ImportNtPrimitives();
    if (!NT_SUCCESS(status))
    {
        LogError("Unable to Nt* primitives via MmGetSystemRoutineAddress. Aborting init\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
/// <summary>
/// Uses a pointer to ZwQuerySystemInformation to enumerate all loaded modules
/// </summary>
/// <returns></returns>
NTSTATUS Utility::EnumKernelModuleInfo(_In_opt_ PRTL_PROCESS_MODULES* procMods)
{
    ULONG size = NULL;

    NTSTATUS status = pZwQuerySysInfo(SYS_MOD_INF, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH == status) {
        LogInfo("ZwQuerySystemInformation data struct size retrieved");
    }
    else
    {
        LogError("ZwQuerySystemInformation, status: %08x", status);
        return status;
    }

    if (outProcMods)
    {
        ExFreePool(outProcMods);
        outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
    }
    else
    {
        outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
    }
        
    if (!outProcMods) {
        LogError("Insufficient memory in the free pool to satisfy the request");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status = pZwQuerySysInfo(SYS_MOD_INF, outProcMods, size, 0))) {
        LogError("ZwQuerySystemInformation failed");
        ExFreePoolWithTag(outProcMods, POOL_TAG);
        outProcMods = NULL;
        return status;
    }

    if (procMods != NULL)
    {
        *procMods = outProcMods;
    }

#ifdef VERBOSE_LOG
    LogInfo("\tModules->NumberOfModules = %lu\n", outProcMods->NumberOfModules);
    for (ULONG i = 0; i < outProcMods->NumberOfModules; i++)
    {
        LogInfo("\tModule[%d].FullPathName: %s\n", (int)i, (char*)outProcMods->Modules[i].FullPathName);
        LogInfo("\tModule[%d].ImageBase: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageBase);
        LogInfo("\tModule[%d].MappedBase: %p\n", (int)i, (char*)outProcMods->Modules[i].MappedBase);
        LogInfo("\tModule[%d].LoadCount: %p\n", (int)i, (char*)outProcMods->Modules[i].LoadCount);
        LogInfo("\tModule[%d].ImageSize: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageSize);
    }
    LogInfo("EnumKernelModuleInfo() complete\n");
#endif
    return STATUS_SUCCESS;
}

/// <summary>
/// Dynamic importing via a documented method
/// </summary>
/// <param name="pNtPrimitives"></param>
/// <param name="names"></param>
/// <returns></returns>
NTSTATUS Utility::ImportNtPrimitives()
{
    LogInfo("Importing windows primitives\n");
    wchar_t* names[WINAPI_IMPORT_COUNT] = { L"ZwQuerySystemInformation" , L"PsGetCurrentProcessId", L"PsIsSystemThread", L"PsGetCurrentProcess", 
                                            L"IoThreadToProcess", L"PsGetProcessId", L"RtlVirtualUnwind", L"RtlLookupFunctionEntry", 
                                            L"KeAlertThread", L"PsGetCurrentThreadStackBase", L"PsGetCurrentThreadStackLimit", L"KeAcquireQueuedSpinLockRaiseToSynch", 
                                            L"KeReleaseQueuedSpinLock", L"PsLookupThreadByThreadId"};
    UNICODE_STRING uniNames[WINAPI_IMPORT_COUNT];

    for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
    {
        RtlInitUnicodeString(&uniNames[i], names[i]);
    }

    CHAR ansiImportName[MAX_NAME_LEN];

    for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
    {
        pNtPrimitives[i] = (GenericFuncPtr)pMmSysRoutine(&uniNames[i]);
        if (pNtPrimitives[i] == NULL)
        {
            LogError("Failed to import %s\n", (unsigned char*)ansiImportName);
            mImportFail = true;
            return STATUS_UNSUCCESSFUL;
        }
        else
        {
            LogInfo("Succesfully imported %ls at %p\n", uniNames[i].Buffer, pNtPrimitives[i]);
        }
    }

    pZwQuerySysInfo = (ZwQuerySysInfoPtr)pNtPrimitives[_ZwQuerySystemInformationIDX];
    pPsGetCurrentProcessId = (PsGetCurrentProcessIdPtr)pNtPrimitives[_PsGetCurrentProcessIdIDX];
    pPsIsSystemThread = (PsIsSystemThreadPtr)pNtPrimitives[_PsIsSystemThreadIDX];
    pPsGetCurrentProcess = (PsGetCurrentProcessPtr)pNtPrimitives[_PsGetCurrentProcessIDX];
    pIoThreadToProcess = (IoThreadToProcessPtr)pNtPrimitives[_IoThreadToProcessIDX];
    pPsGetProcessId = (PsGetProcessIdPtr)pNtPrimitives[_PsGetProcessIdIDX];
    pRtlVirtualUnwind = (RtlVirtualUnwindPtr)pNtPrimitives[_RtlVirtualUnwindIDX];
    pRtlLookupFunctionEntry = (RtlLookupFunctionEntryPtr)pNtPrimitives[_RtlLookupFunctionEntryIDX];
    pKeAlertThread = (KeAlertThreadPtr)pNtPrimitives[_KeAlertThreadIDX];
    pPsGetCurrentThreadStackBase = (PsGetCurrentThreadStackBasePtr)pNtPrimitives[_PsGetCurrentThreadStackBaseIDX];
    pPsGetCurrentThreadStackLimit = (PsGetCurrentThreadStackLimitPtr)pNtPrimitives[_PsGetCurrentThreadStackLimitIDX];
    pKeAcquireQueuedSpinLockRaiseToSynch = (KeAcquireQueuedSpinLockRaiseToSynchPtr)pNtPrimitives[_KeAcquireQueuedSpinLockRaiseToSynchIDX];
    pKeReleaseQueuedSpinLock = (KeReleaseQueuedSpinLockPtr)pNtPrimitives[_KeReleaseQueuedSpinLockIDX];
    pPsLookupThreadByThreadId = (PsLookupThreadByThreadIdPtr)pNtPrimitives[_PsLookupThreadByThreadIdIDX];

    return STATUS_SUCCESS;
}

bool Utility::IsValidPEHeader(_In_ const uintptr_t pHead)
{
    // ideally should parse the PT so this can't be IAT spoofed
    if (!MmIsAddressValid((PVOID)pHead))
    {
        LogError("Was unable to read page @ 0x%p", (PVOID)pHead);
        return false;
    }

    if (!pHead)
    {
        LogInfo("pHead is null @ 0x%p", (PVOID)pHead);
        return false;
    }

    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_magic != E_MAGIC)
    {
        LogInfo("pHead is != 0x%02x @ %p", E_MAGIC, (PVOID)pHead);
        return false;
    }

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(pHead + reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_lfanew);

    // avoid reading a page not paged in
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_lfanew > 0x1000)
    {
        LogInfo("pHead->e_lfanew > 0x1000 , doesn't seem valid @ 0x%p", (PVOID)pHead);
        return false;
    }

    if (ntHeader->Signature != NT_HDR_SIG)
    {
        LogInfo("ntHeader->Signature != 0x%02x @ 0x%p", NT_HDR_SIG, (PVOID)pHead);
        return false;
    }

    LogInfo("Found valid PE header @ 0x%p", (PVOID)pHead);
    return true;
}

// @ weak1337
// https://github.com/weak1337/EvCommunication/blob/cab42dda45a5feb9d2c62f8685d00b0d39fb783e/Driver/Driver/nt.cpp
NTSTATUS Utility::FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer)
{
    if (!imageBase)
        return STATUS_INVALID_PARAMETER_1;

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
    const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    if (!exportDirectory)
        return STATUS_INVALID_IMAGE_FORMAT;

    const auto exportedFunctions = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfFunctions);
    const auto exportedNames = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfNames);
    const auto exportedNameOrdinals = reinterpret_cast<UINT16*>(imageBase + exportDirectory->AddressOfNameOrdinals);

    for (size_t i{}; i < exportDirectory->NumberOfNames; ++i) {
        const auto functionName = reinterpret_cast<const char*>(imageBase + exportedNames[i]);
        if (!strcmp(exportName, functionName)) {
            *functionPointer = imageBase + exportedFunctions[exportedNameOrdinals[i]];
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

__forceinline wchar_t Utility::locase_w(wchar_t c)
{
    if ((c >= 'A') && (c <= 'Z'))
        return c + 0x20;
    else
        return c;
}

int Utility::strcmpi_w(_In_ const wchar_t* s1, _In_ const wchar_t* s2)
{
    wchar_t c1, c2;

    if (s1 == s2)
        return 0;

    if (s1 == 0)
        return -1;

    if (s2 == 0)
        return 1;

    do {
        c1 = locase_w(*s1);
        c2 = locase_w(*s2);
        s1++;
        s2++;
    } while ((c1 != 0) && (c1 == c2));

    return (int)(c1 - c2);
}

// @Frostiest , Driver object method
// https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html
PVOID Utility::GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    PLDR_DATA_TABLE_ENTRY first = entry;
    while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
        if (strcmpi_w(entry->BaseDllName.Buffer, L"ntoskrnl.exe") == 0) return entry->DllBase;
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
    return NULL;
}

// @ Barakat , GS Register, reverse page walk until MZ header of ntos
// https://gist.github.com/Barakat/34e9924217ed81fd78c9c92d746ec9c6
// Lands above nt module, but can page fault! Tweak to check PTE's instead of using MmIsAddressValid.  Refer to:  https://www.unknowncheats.me/forum/anti-cheat-bypass/437451-whats-proper-write-read-physical-memory.html
PVOID Utility::GetNtoskrnlBaseAddress()
{
#pragma pack(push, 1)
    typedef struct
    {
        UCHAR Padding[4];
        PVOID InterruptServiceRoutine;
    } IDT_ENTRY;
#pragma pack(pop)

    // Find the address of IdtBase using gs register.
    const auto idt_base = reinterpret_cast<IDT_ENTRY*>(__readgsqword(0x38));

    // Find the address of the first (or any) interrupt service routine.
    const auto first_isr_address = idt_base[0].InterruptServiceRoutine;

    // Align the address on page boundary.
    auto pageInNtoskrnl = reinterpret_cast<uintptr_t>(first_isr_address) & ~static_cast<uintptr_t>(0xfff);

    // Traverse pages backward until we find the PE signature (MZ) of ntoskrnl.exe in the beginning of some page.
    while (!IsValidPEHeader(pageInNtoskrnl))
    {
        pageInNtoskrnl -= 0x1000;
    }

    // Now we have the base address of ntoskrnl.exe
    return reinterpret_cast<void*>(pageInNtoskrnl);
}

//wrapper for ZwQuerySysInfo
// for now we want PSYSTEM_BIGPOOL_INFORMATION
NTSTATUS Utility::QuerySystemInformation(_In_ ULONG infoClass, _Inout_ PVOID* dataBuf) /*, 0x100000, 0x2000000) <- ?? */
{
    if (!dataBuf)
    {
        LogError("QuerySystemInformation(), dataBuf == NULL");
        return STATUS_UNSUCCESSFUL;
    }

    if (infoClass == SystemBigPoolInformation)
    {
        // https://github.com/ApexLegendsUC/anti-cheat-emulator/blob/9e53bb4a329e0286ff4f237c5ded149d53b0dd56/Source.cpp#L428
        ULONG len = 4 * 1024 * 1024;
        ULONG attemptedSize = 0;
        *dataBuf = ExAllocatePoolWithTag(NonPagedPool, len, POOL_TAG);

        if (!*dataBuf) {
            LogError("\tInsufficient memory in the free pool to satisfy the request");
            return STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(pZwQuerySysInfo(infoClass, *dataBuf, len, &attemptedSize)))
        {
            LogError("\tZwQuerySystemInformation failed for SystemBigPoolInformation. *dataBuf: %p , len: %d , attemptedSize: %d", *dataBuf, len, attemptedSize);
            ExFreePoolWithTag(*dataBuf, POOL_TAG);
            return STATUS_UNSUCCESSFUL;
        }
        LogInfo("\tQuerySystemInformation() succeeded for SystemBigPoolInformation.\n");
    }
    else
    {
        ULONG size = NULL;
        NTSTATUS status = pZwQuerySysInfo(infoClass, 0, 0, &size);
        if (STATUS_INFO_LENGTH_MISMATCH == status) {
            LogInfo("\tZwQuerySystemInformation data struct size: %d", size);
        }
        else
        {
            LogError("\tZwQuerySystemInformation, status: %08x", status);
            return status;
        }

        *dataBuf = ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);

        if (!*dataBuf) {
            LogError("\tInsufficient memory in the free pool to satisfy the request");
            return STATUS_UNSUCCESSFUL;
        }

        ULONG attemptedSize = 0;
        if (!NT_SUCCESS(status = pZwQuerySysInfo(infoClass, *dataBuf, size, &attemptedSize))) {
            LogError("\tZwQuerySystemInformation failed. *dataBuf: %p , size: %d , attemptedSize: %d", *dataBuf, size, attemptedSize);
            ExFreePoolWithTag(*dataBuf, POOL_TAG);
            outProcMods = NULL;
            return status;
        }
        LogInfo("\tQuerySystemInformation() succeeded for infoClass: %lu\n", infoClass);
    }

    
    return STATUS_SUCCESS;
}

bool Utility::CheckModulesForAddress(UINT64 address, PSYSTEM_MODULE_INFORMATION procMods)
{
    for (size_t i = 0; i < procMods->ModulesCount; i++)
    {
        SYSTEM_MODULE_ENTRY sysMod = procMods->Modules[i];
        if ((UINT64)sysMod.ModuleBaseAddress < address && address < ((UINT64)sysMod.ModuleBaseAddress + sysMod.ModuleSize))
        {
            return true;
        }
    }
    return false;
}

bool Utility::GetNtoskrnlSection(char* sectionName, DWORD* sectionVa, DWORD* sectionSize)
{
    if (!kernBase)
    {
        kernBase = GetNtoskrnlBaseAddress();
    }
    
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_magic != E_MAGIC)
    {
        LogInfo("GetNtoskrnlSection() expected MZ header != 0x%02x @ %p", E_MAGIC, kernBase);
        return FALSE;
    }

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>((BYTE*)kernBase + reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_lfanew);

    // avoid reading a page not paged in
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_lfanew > 0x1000)
    {
        LogInfo("GetNtoskrnlSection() pHead->e_lfanew > 0x1000 , doesn't seem valid @ 0x%p", kernBase);
        return FALSE;
    }

    if (ntHeader->Signature != NT_HDR_SIG)
    {
        LogInfo("GetNtoskrnlSection() ntHeader->Signature != 0x%02x @ 0x%p", NT_HDR_SIG, kernBase);
        return FALSE;
    }

    auto ntSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((BYTE*)ntHeader + sizeof(PIMAGE_NT_HEADERS64));
    
    for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        char* ret = strstr((char*)ntSection[i].Name, sectionName);

        if (ret)
        {
            *sectionVa = ntSection[i].VirtualAddress;
            *sectionSize = ntSection[i].Misc.VirtualSize;
            LogInfo("Found %s in ntoskrnl.exe at %p , size %lu \n", sectionName, (VOID*)*sectionVa, (ULONG)*sectionSize);
            return true;
        }
    }
    
    return false;
}
/// EAC's System thread scanning method
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
    PSYSTEM_MODULE_INFORMATION systemModuleInformation = NULL;
    CONTEXT* context;
    UINT64 currentThreadId = 4;
    HANDLE processID;
    PEPROCESS processObject;
    STACKWALK_ENTRY* entry;

    NTSTATUS status;
    STACKWALK_BUFFER stackwalkBuffer;
    PETHREAD threadObject;


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
                        LogInfo("Scanning thread. currentThreadId: %llu", currentThreadId);
                        status = pPsLookupThreadByThreadId((HANDLE)currentThreadId, &threadObject);

                        if (status >= 0)
                        {
                            processObject = pIoThreadToProcess(threadObject);

                            if (!processObject)
                            {
                                LogError("\tpFailed to get process object, pIoThreadToProcess(threadObject) == NULL, skipping thread ID: %d\n", currentThreadId);
                                continue;
                            }

                            processID = pPsGetProcessId(processObject);

                            if (!processID)
                            {
                                LogError("\tpFailed to get process id, pPsGetProcessId(processObject) == NULL, skipping thread ID: %d\n", currentThreadId);
                                continue;
                            }

                            if (processID == currentProcessId   // if...the thread's pid is the same as system pid, and threadobject 
                                && threadObject != (PVOID)__readgsqword(0x188)     // __readgsqword(0x188) == return (struct _KTHREAD *)__readgsqword(0x188) , and thread obj is not our current thread
                                && StackwalkThread(threadObject, context, &stackwalkBuffer)    // and succesfully walks the stack of thread
                                && stackwalkBuffer.EntryCount > 0)     // and has more than 1 entry in the stack
                            {
                                for (size_t i = 0; i < stackwalkBuffer.EntryCount; i++)
                                {
                                    if (!CheckModulesForAddress(stackwalkBuffer.Entry[i].RipValue, systemModuleInformation))
                                    {
                                        LogInfo("\tSUSPICIOUS THREAD DETECTED\n");
                                        break;
                                    }
                                }
                            }
                            ObfDereferenceObject(threadObject); // reference count was incremented on pPsLookupThreadByThreadId
                        }               
                        currentThreadId += 4;    // thread id's are multiple of 4
                    } while (currentThreadId < 0x3000);     // lol, brute force method by EAC.  Maybe there's a better way
                    ExFreePool(context);
                }
                else
                {
                    LogError("\tUtility.cpp:%d, ExAllocatePool failed\n", __LINE__);
                    return STATUS_UNSUCCESSFUL;
                }
                ExFreePool(systemModuleInformation);
            }
            else
            {
                LogError("\tUtility.cpp:%d, systemModuleInformation == NULL\n", __LINE__);
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
    char status; // di
    _QWORD* stackBuffer; // rax MAPDST
    size_t copiedSize; // rax
    DWORD64 startRip; // rdx
    unsigned int index; // ebp
    unsigned __int64 rip0; // rcx
    DWORD64 rsp0; // rdx
    PRUNTIME_FUNCTION functionTableEntry; // rax
    __int64 moduleBase; // [rsp+40h] [rbp-48h]
    __int64 v17; // [rsp+48h] [rbp-40h]
    __int64 v18; // [rsp+50h] [rbp-38h]
    DWORD sectionVa; // [rsp+90h] [rbp+8h]
    DWORD sectionSize; // [rsp+A8h] [rbp+20h]

    status = 0;
    if (!threadObject)
        return 0;
    if (!stackwalkBuffer)
        return 0;
    memset(context, 0, sizeof(CONTEXT));
    memset(stackwalkBuffer, 0, 0x208);
    
    stackBuffer = (_QWORD*)ExAllocatePool(NonPagedPool, STACK_BUF_SIZE);   // sizeof(stackBuffer) == 4096 || 0x1000
    if (stackBuffer)
    {
        copiedSize = CopyThreadKernelStack(threadObject, STACK_BUF_SIZE, stackBuffer);
        if (copiedSize)
        {
            if (copiedSize != 4096 && copiedSize >= 0x48)
            {
                if (GetNtoskrnlSection(".text", &sectionVa, &sectionSize))
                {
                    startRip = stackBuffer[7];
                    if (startRip >= sectionVa && startRip < sectionSize + sectionVa)
                    {
                        status = 1;
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
                LogError("Unable to find .text section of ntoskrnl");
                return 0;
            }
        }
        ExFreePool(stackBuffer);
    }
    return status;
}

size_t Utility::CopyThreadKernelStack(PETHREAD threadObject, __int64 maxSize, void* outStackBuffer)
{
    size_t copiedSize;
    size_t threadStateOffset;
    size_t kernelStackOffset;
    size_t threadStackBaseOffset;
    size_t threadStackBase;
    size_t threadStackLimitOffset;
    size_t threadStackLimit;
    bool isSystemThread;
    void** pKernelStack; // r12
    __int64 _oldIrql; // rdx
    size_t threadLockOffset; // eax
    KSPIN_LOCK* threadLock; // rcx
    unsigned int ThreadPriorityOffset; // rax
    unsigned __int8 oldIrql; // [rsp+50h] [rbp+8h]

    copiedSize = 0;
    threadStateOffset = GetThreadStateOffset();
    kernelStackOffset = GetKernelStackOffset();
    threadStackBaseOffset = GetStackBaseOffset();
    
    if (threadObject && threadStackBaseOffset)
        threadStackBase = *(_QWORD*)(threadStackBaseOffset + (BYTE*)threadObject);
    else
        threadStackBase = 0;

    threadStackLimitOffset = GetThreadStackLimit();
    
    if (!threadObject)
        return 0;

    threadStackLimit = threadStackLimitOffset ? *(_QWORD*)(threadStackLimitOffset + (BYTE*)threadObject) : 0;
    isSystemThread = pPsIsSystemThread ? (unsigned __int8)pPsIsSystemThread(threadObject) : 0;
    
    if (!isSystemThread
        || !outStackBuffer
        || !(DWORD)threadStateOffset
        || !(DWORD)kernelStackOffset
        || !threadStackBase
        || !threadStackLimit
        || KeGetCurrentIrql() > 1       // read cr8
        || (PKTHREAD)threadObject == KeGetCurrentThread())        //KeGetCurrentThread() is inlined, gs register access.
    {
        return 0;
    }

    pKernelStack = (void**)((BYTE*)threadObject + kernelStackOffset);
    memset(outStackBuffer, 0, 0x2000);
    if (LockThread((__int64)threadObject, (unsigned __int8*)&oldIrql))
    {
        if (!PsIsThreadTerminating(threadObject)
            && *(BYTE*)(threadStateOffset + (BYTE*)threadObject) == 5
            && (unsigned __int64)*pKernelStack > threadStackLimit
            && (unsigned __int64)*pKernelStack < threadStackBase
            && *(_QWORD*)&MmGetPhysicalAddress(*pKernelStack))
        {
            copiedSize = threadStackBase - (_QWORD)*pKernelStack;
            if (copiedSize > 0x2000)
                copiedSize = 0x2000;
            memmove(outStackBuffer, *pKernelStack, copiedSize);
        }

        if (SharedUserData->NtMajorVersion >= 6 && SharedUserData->NtMajorVersion != 6 || !SharedUserData->NtMinorVersion)  //  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
        {
            threadLockOffset = GetThreadLockOffset();
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
            KeReleaseQueuedSpinLock(0, _oldIrql);
        }
    }
    return copiedSize;
}

__int64 Utility::LockThread(__int64 Thread, unsigned __int8* Irql)
{
    char v2; // bl
    unsigned int ThreadLockOffset; // eax
    unsigned __int8 CurrentIrql; // al
    __int64(__fastcall * Export)(_QWORD); // rax

    if (Thread && Irql)
    {
        if (SharedUserData->NtMajorVersion >= 6 && (SharedUserData->NtMajorVersion != 6 || SharedUserData->NtMinorVersion))
        {
            ThreadLockOffset = GetThreadLockOffset();
            if (((Thread + ThreadLockOffset) & -(__int64)(ThreadLockOffset != 0)) != 0)
            {
                CurrentIrql = KeGetCurrentIrql();
                __writecr8(0xC);
                *Irql = CurrentIrql;
                ((void (*)(void))KeAcquireSpinLockAtDpcLevel)();
                return 1;
            }
            return 0;
        }
        if (pKeReleaseQueuedSpinLock && pKeAcquireQueuedSpinLockRaiseToSynch)
        {
            *Irql = pKeAcquireQueuedSpinLockRaiseToSynch(0);
            return 1;
        }
        return 0;
    }
    return 0;
}

__int64 Utility::GetThreadStackLimit()
{
    unsigned __int64 thisKThread; // rbx
    __int64 (*Export)(void); // rax
    __int64 v2; // rax
    _QWORD* v3; // rcx

    thisKThread = __readgsqword(0x188u);
    if ((unsigned int)SpinLock(&gSpinLock6) == 259)
    {
            v2 = (__int64)pPsGetCurrentThreadStackLimit();
            v3 = (_QWORD*)thisKThread;
            if (thisKThread < thisKThread + 0x2F8)
            {
                while (*v3 != v2)
                {
                    if ((unsigned __int64)++v3 >= thisKThread + 0x2F8)
                        goto LABEL_9;
                }
                gThreadStackLimit = (DWORD)v3 - thisKThread;
            }
    LABEL_9:
        _InterlockedExchange64(&gSpinLock6, 2i64);
    }
    return (unsigned int)gThreadStackLimit;
}

__int64 Utility::GetKernelStackOffset()
{
    unsigned __int64 thisThread; // rbx
    int InitialStackOffset; // ebp
    unsigned int stackBaseOffset; // eax
    unsigned __int64 v3; // rdi
    unsigned __int64 v4; // rsi
    unsigned int v5; // eax
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
    unsigned __int64 thisKThread; // rbx
    __int64 (*Export)(void); // rax
    _int64 v2; // rax
    _QWORD* v3; // rcx

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

__int64 Utility::GetStackBaseOffset()
{
    unsigned __int64 thiskThread; // rbx
    __int64 (*Export)(void); // rax
    __int64 stackBase; // rax
    _QWORD* v3; // rcx

    thiskThread = __readgsqword(0x188);
    if ((unsigned int)SpinLock(&gSpinLock5) == 259)
    {
        stackBase = (__int64)pPsGetCurrentThreadStackBase();
        v3 = (_QWORD*)thiskThread;
        if (thiskThread < thiskThread + 0x2F8)
        {
            while (*v3 != stackBase)
            {
                if ((unsigned __int64)++v3 >= thiskThread + 0x2F8)
                    goto LABEL_9;
            }
            gStackBaseOffset = (DWORD)v3 - thiskThread;
        }
    LABEL_9:
        _InterlockedExchange64(&gSpinLock5, 2);
    }
    return (unsigned int)gStackBaseOffset;
}

__int64 Utility::GetThreadLockOffset()
{
    unsigned __int8* Export; // rax
    unsigned __int8* maxOffset; // rdi
    unsigned __int8* addrOffset; // rbx
    char outBuf[37]; // [rsp+20h] [rbp-38h] BYREF

    if ((unsigned int)SpinLock(&gSpinLock1) == 259)
    {
        Export = (unsigned __int8*)KeSetPriorityThread;
        if (Export)
        {
            maxOffset = Export + 0xF1;
            for (addrOffset = &Export[(unsigned int)patternMatcher(Export, (__int64)outBuf)];// (unsigned int)patternMatcher(Export, (__int64)outBuf) returns address offset
                addrOffset < maxOffset && (*(WORD*)&outBuf[33] & 0x1000) == 0;
                addrOffset += (unsigned int)patternMatcher(addrOffset, (__int64)outBuf))
            {
                if ((*(DWORD*)&outBuf[33] & 0x40000000) != 0
                    && (*(DWORD*)&outBuf[33] & 0x10000000) != 0
                    && (outBuf[33] & 1) != 0
                    && (outBuf[33] & 0x40) != 0
                    && (outBuf[33] & 4) != 0
                    && !outBuf[21]
                    && outBuf[7]
                    && outBuf[11] == 15
                    && outBuf[12] == -70)
                {
                    gThreadLockOffset = (unsigned __int8)outBuf[29];
                    break;
                }
            }
        }
        _InterlockedExchange64(&gSpinLock1, 2);
    }
    return (unsigned int)gThreadLockOffset;
}

UINT32 Utility::GetThreadStateOffset()
{
    unsigned int kThreadStateOffset; // eax
    unsigned __int8* Export; // rax
    unsigned __int8* maxOffset; // rdi
    unsigned __int8* i; // rbx
    int v6; // edx
    char outBuf[37];

    if ((unsigned int)SpinLock(&gSpinLock3) == 259)
    {
        if (SharedUserData->NtMajorVersion == 6 && SharedUserData->NtMinorVersion == 1)// Windows 7 check
        {
            kThreadStateOffset = 0x164;
            gkThreadStateOffset = 0x164;
        }
        else
        {
            Export = (unsigned __int8*)pKeAlertThread;
            if (Export)
            {
                maxOffset = Export + 0x132;             // v4 is some offset to v3.  v3 must be a ptr to some struct
                for (i = &Export[(unsigned int)patternMatcher(Export, (__int64)outBuf)];
                    i < maxOffset && (*(WORD*)&outBuf[33] & 0x1000) == 0 && ((outBuf[11] + 62) & 0xF6) != 0;
                    i += (unsigned int)patternMatcher(i, (__int64)outBuf))
                {
                    if ((outBuf[33] & 1) != 0
                        && (*(WORD*)&outBuf[33] & 0x100) != 0
                        && outBuf[11] == -118
                        && !outBuf[15]
                        && *(DWORD*)&outBuf[29] < 0x300u)
                    {
                        gkThreadStateOffset = *(DWORD*)&outBuf[29];
                        i += (unsigned int)patternMatcher(i, (__int64)outBuf);
                        if ((*(WORD*)&outBuf[33] & 0x1000) == 0 && (outBuf[33] & 4) != 0 && outBuf[11] == 60 && outBuf[21] == 5)
                            break;
                        gkThreadStateOffset = 0;
                    }
                }
            }
            kThreadStateOffset = gkThreadStateOffset;
        }
        if (kThreadStateOffset)
        {
            v6 = gkThreadStateOffset;
            if (*(BYTE*)(__readgsqword(0x188u) + kThreadStateOffset) != 2)
                v6 = 0;
            gkThreadStateOffset = v6;
        }
        _InterlockedExchange64(&gSpinLock3, 2);
    }
    return (unsigned int)gkThreadStateOffset;
}

__int64 Utility::SpinLock(volatile signed __int64* Lock)
{
    if (*Lock != 2)
    {
        if (!_InterlockedCompareExchange64(Lock, 1, 0))
            return 259;
        while (*Lock != 2)
            _mm_pause();
    }
    return 0;
}

__int64 Utility::patternMatcher(unsigned __int8* address, __int64 outBuffer)
{
    BYTE* v3; // rbx
    char v4; // r14
    unsigned __int8 v5; // dl
    unsigned __int8 v6; // r13
    unsigned __int8* _localAddress; // r9
    char v8; // r11
    unsigned int currentByte; // er10
    unsigned __int64 v10; // rcx
    unsigned __int64 v11; // rax
    char v12; // al
    char v13; // cl
    int v14; // er11
    unsigned __int8 v15; // bp
    unsigned __int16 v16; // si
    unsigned __int8 v17; // r12
    __int16 v18; // di
    char v19; // r15
    int v20; // ebx
    int v21; // ebx
    int v22; // er10
    unsigned __int8 v23; // r14
    char v24; // cl
    unsigned __int8 v25; // al
    unsigned __int8 v26; // r14
    unsigned __int8 v27; // r11
    int v28; // eax
    unsigned __int8 v29; // di
    __int64 v30; // rdx
    unsigned __int8 v31; // cl
    char v32; // r11
    bool v33; // sf
    char v34; // bl
    char v35; // dl
    BYTE* v36; // r10
    BYTE* v37; // rcx
    BYTE* v38; // rcx
    BYTE* v39; // rdx
    bool v40; // zf
    unsigned __int8 v41; // dl
    unsigned __int8* v42; // r9
    char v43; // al
    char v44; // dl
    unsigned __int8* v45; // r9
    __int16 v46; // ax
    __int64 v47; // rax
    __int16 v48; // ax
    char v49; // al
    unsigned __int8 v50; // al
    unsigned __int8 offsetFromAddress; // r9
    int v53; // eax
    int v54; // eax
    char v55; // [rsp+0h] [rbp-58h]
    char localAddr; // [rsp+60h] [rbp+8h]
    unsigned __int8 v57; // [rsp+68h] [rbp+10h]
    unsigned __int8 v58; // [rsp+70h] [rbp+18h]
    char v59; // [rsp+78h] [rbp+20h]

    BYTE unk_1400567A0[] = { 0xA5, 0xAA, 0xA5, 0xB8, 0xA5, 0xAA, 0xA5, 0xAA, 0xA5, 0xB8, 0xA5, 0xB8, 0xA5, 0xB8, 0xA5, 0xB8, 0xC0, 0xC0, 0xC0, 
                                0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xAC, 0xC0, 0xCC, 0xC0, 0xA1, 0xA1, 0xA1, 0xA1, 0xB1, 0xA5, 0xA5, 0xA6, 0xC0, 0xC0, 
                                0xD7, 0xDA, 0xE0, 0xC0, 0xE4, 0xC0, 0xEA, 0xEA, 0xE0, 0xE0, 0x98, 0xC8, 0xEE, 0xF1, 0xA5, 0xD3, 0xA5, 0xA5, 0xA1, 
                                0xEA, 0x9E, 0xC0, 0xC0, 0xC2, 0xC0, 0xE6, 0x03, 0x7F, 0x11, 0x7F, 0x01, 0x7F, 0x01, 0x3F, 0x01, 0x01 };

    BYTE unk_1400567EA[] = { 0xAB, 0x8B, 0x90, 0x64, 0x5B, 0x5B, 0x5B, 0x5B, 0x5B, 0x92, 0x5B, 0x5B, 0x76, 0x90, 0x92, 0x92, 0x5B, 0x5B, 0x5B,
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

    BYTE unk_140056978[] = { 0x62, 0xFF, 0x00, 0x8D, 0xFF, 0x00, 0xC4, 0xFF, 0x00, 0xC5, 0xFF, 0x00, 0xFF, 0xFF, 0xEB };

    BYTE unk_140056966[] = { 0xAB,0x00,0xB0,0x00,0xB1,0x00,0xB3,0x00,0xBA,0xF8,0xBB,0x00,0xC0,0x00,0xC1,0x00,0xC7,0xBF };

    BYTE unk_14005694E[] = { 0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x80, 0x01, 0x82, 0x01, 0x86, 0x00, 0xF6, 0xCF, 0xFE, 0x3F };

    BYTE unk_140056987[] = { 0x01, 0xFF, 0x0E, 0x12, 0x08, 0x00, 0x13, 0x09, 0x00, 0x16, 0x08, 0x00, 0x17, 0x09, 0x00, 0x2B, 0x09, 0x00, 0xAE, 0xFF, 0x07, 0xB2, 0xFF, 0x00, 0xB4, 0xFF, 0x00, 0xB5, 0xFF, 0x00, 0xC3, 0x01, 0x00, 0xC7, 0xFF, 0xBF, 0xE7, 0x08, 0x00, 0xF0, 0x02, 0x00 };

    BYTE unk_1400569B1[] = { 0x0,0x0,0x0,0x0,0x0,0x0,0x0 };


    localAddr = (char)address;
    v3 = unk_1400567A0;
    v4 = 0;
    v5 = 0;
    v55 = 0;
    v6 = 0;
    _localAddress = address;
    v8 = 16;
    memset((void *)outBuffer, 0, 37);
    do
    {
        currentByte = *_localAddress++;
        if (currentByte > 0x65)
        {
            switch (currentByte)
            {
            case 0x66:
                *(BYTE*)(outBuffer + 4) = 0x66;
                v12 = 8;
                break;
            case 0x67:
                *(BYTE*)(outBuffer + 5) = 0x67;
                v12 = 16;
                break;
            case 0xF0:
                *(BYTE*)(outBuffer + 2) = 0xF0;
                v12 = 32;
                break;
            case 0xF2:
                *(BYTE*)(outBuffer + 1) = 0xF2;
                v12 = 2;
                break;
            case 0xF3:
                *(BYTE*)(outBuffer + 1) = 0xF3;
                v12 = 4;
                break;
            default:
                goto LABEL_17;
            }
            goto LABEL_16;
        }
        v10 = currentByte - 0x26;
        if ((unsigned int)v10 > 0x3F)
            break;
        v11 = 0xC000000001010101;
        if (!_bittest64((const __int64*)&v11, v10))
            break;
        *(BYTE*)(outBuffer + 3) = currentByte;
        v12 = 64;
    LABEL_16:
        v5 |= v12;
        --v8;
    } while (v8);
LABEL_17:
    v13 = 1;
    v14 = v5 << 23;
    *(DWORD*)(outBuffer + 33) = v14;
    if (v5)
        v13 = v5;
    if ((currentByte & 0xF0) == 64)
    {
        v14 |= 0x40000000u;
        *(DWORD*)(outBuffer + 33) = v14;
        *(BYTE*)(outBuffer + 7) = (currentByte & 8) != 0;
        if ((currentByte & 8) != 0)
        {
            v4 = (*_localAddress & 0xF8) == 0xB8;
            v55 = v4;
        }
        *(BYTE*)(outBuffer + 8) = (currentByte & 4) != 0;
        *(BYTE*)(outBuffer + 10) = currentByte & 1;
        *(BYTE*)(outBuffer + 9) = (currentByte & 2) != 0;
        LOBYTE(currentByte) = *_localAddress++;
        if ((currentByte & 0xF0) == 64)
        {
            v57 = currentByte;
            v15 = v13;
            goto LABEL_32;
        }
    }
    *(BYTE*)(outBuffer + 11) = currentByte;
    v15 = v13;
    if ((BYTE)currentByte == 15)
    {
        LOBYTE(currentByte) = *_localAddress;
        v3 = unk_1400567EA;
        *(BYTE*)(outBuffer + 12) = *_localAddress++;
    }
    else if ((unsigned __int8)currentByte >= 0xA0u && (unsigned __int8)currentByte <= 0xA3u)
    {
        v55 = ++v4;
        if ((v13 & 0x10) != 0)
            v15 = v13 | 8;
        else
            v15 = v13 & 0xF7;
    }
    v57 = currentByte;
    LOBYTE(v16) = v3[(unsigned __int8)v3[(unsigned __int64)(unsigned __int8)currentByte >> 2] + (currentByte & 3)];
    if ((BYTE)v16 == 0xFF)
    {
    LABEL_32:
        v14 |= 0x3000u;
        *(DWORD*)(outBuffer + 33) = v14;
        LOBYTE(v16) = 0;
        if ((currentByte & 0xFD) == 36)
        {
            LOBYTE(v16) = 1;
            v17 = currentByte;
            LOBYTE(v18) = 0;
            goto LABEL_36;
        }
    }
    LOBYTE(v18) = 0;
    v17 = currentByte;
    if ((v16 & 0x80u) != 0)
    {
        v16 = *(WORD*)&v3[v16 & 0x7F];
        v18 = HIBYTE(v16);
    }
LABEL_36:
    v19 = *(BYTE*)(outBuffer + 12);
    v20 = v14;
    bool leftHalf_RightExp = (v15 & *(BYTE*)unk_1400567A0 + (currentByte & 3) + (unsigned __int64)*((unsigned __int8*)unk_1400567A0 + ((unsigned __int64)(unsigned __int8)currentByte >> 2) + 316) + 316);
    bool rightExp = leftHalf_RightExp != 0;
    if (v19 && rightExp)
    {
        v20 = v14 | 0x3000;
        *(DWORD*)(outBuffer + 33) = v14 | 0x3000;
    }
    if ((v16 & 1) != 0)
    {
        v21 = v20 | 1;
        *(DWORD*)(outBuffer + 33) = v21;
        v22 = v21;
        v23 = *_localAddress;
        *(BYTE*)(outBuffer + 13) = *_localAddress;
        v24 = v23 >> 6;
        v25 = v23 & 7;
        v26 = (v23 >> 3) & 7;
        v59 = v24;
        *(BYTE*)(outBuffer + 14) = v24;
        v58 = v25;
        *(BYTE*)(outBuffer + 16) = v25;
        *(BYTE*)(outBuffer + 15) = v26;
        if ((BYTE)v18 && (((unsigned __int8)v18 << v26) & 0x80u) != 0)
        {
            v22 = v21 | 0x3000;
            *(DWORD*)(outBuffer + 33) = v21 | 0x3000;
        }
        v27 = v57;
        v28 = v22;
        if (v19 || v57 < 0xD9u || v57 > 0xDFu)
        {
            v29 = v58;
        }
        else
        {
            v29 = v58;
            v30 = (unsigned __int8)(v57 + 39);
            if (v24 == 3)
            {
                v31 = v58;
                v32 = *((BYTE*)unk_1400567A0 + 8 * v30 + v26 + 260);
            }
            else
            {
                v31 = v26;
                v32 = *((BYTE*)unk_1400567A0 + v30 + 253);
            }
            v28 = v22;
            v33 = ((v32 << v31) & 0x80u) != 0;
            v27 = v57;
            if (v33)
            {
                v28 = v22 | 0x3000;
                *(DWORD*)(outBuffer + 33) = v22 | 0x3000;
            }
        }
        v34 = v59;
        if ((v15 & 0x20) != 0)
        {
            if (v59 == 3)
            {
                *(DWORD*)(outBuffer + 33) = v28 | 0x9000;
            }
            else
            {
                v35 = v27;
                if (!v19)
                    v35 = v27 & 0xFE;
                v36 = unk_140056978;
                if (!v19)
                    v36 = unk_140056966;
                v37 = unk_140056966;
                if (!v19)
                    v37 = unk_14005694E;
                while (v37 != v36)
                {
                    if (*v37 == v35)
                    {
                        if ((((unsigned __int8)v37[1] << v26) & 0x80u) == 0)
                            goto LABEL_68;
                        break;
                    }
                    v37 += 2;
                }
                *(DWORD*)(outBuffer + 33) |= 0x9000u;
            }
        }
    LABEL_68:
        if (!v19)
        {
            if (v17 != 140)
            {
                if (v17 != 142)
                    goto LABEL_80;
                if (v26 == 1)
                    goto LABEL_103;
            }
            if (v26 > 5u)
                goto LABEL_103;
            goto LABEL_104;
        }
        switch (v17)
        {
        case ' ':
            goto LABEL_75;
        case '!':
            goto LABEL_73;
        case '"':
        LABEL_75:
            v34 = 3;
            if (v26 <= 4u && v26 != 1)
                goto LABEL_104;
            goto LABEL_103;
        case '#':
        LABEL_73:
            v34 = 3;
            if ((unsigned __int8)(v26 - 4) <= 1u)
                goto LABEL_103;
            goto LABEL_104;
        }
    LABEL_80:
        if (v59 == 3)
        {
            if (!v19)
            {
                v39 = unk_140056987;
                v38 = unk_140056978;
                goto LABEL_85;
            }
            v38 = unk_140056987;
            v39 = unk_1400569B1;
            if (unk_140056987 == unk_1400569B1)
                goto LABEL_104;
        LABEL_85:
            // PAGE FAULT HERE
            while (*v38 != v27)
            {
                v38 += 3;
                if (v38 == v39)
                    goto LABEL_104;
            }
            if ((v15 & v38[1]) == 0 || (((unsigned __int8)v38[2] << v26) & 0x80u) != 0)
            {
            LABEL_104:
                v41 = _localAddress[1];
                v42 = _localAddress + 2;
                if (v26 <= 1u)
                {
                    if (v27 == 0xF6)
                    {
                        LOBYTE(v16) = v16 | 2;
                    }
                    else if (v27 == 0xF7)
                    {
                        LOBYTE(v16) = v16 | 0x10;
                    }
                }
                if (v34)
                {
                    if (v34 == 1)
                    {
                        v6 = 1;
                    }
                    else if (v34 == 2)
                    {
                        v6 = 2;
                        if ((v15 & 0x10) == 0)
                            v6 = 4;
                    }
                }
                else if ((v15 & 0x10) != 0)
                {
                    v6 = v29 != 6 ? 0 : 2;
                }
                else
                {
                    v6 = 0;
                    if (v29 == 5)
                        v6 = 4;
                }
                if (v34 != 3 && v29 == 4)
                {
                    *(DWORD*)(outBuffer + 33) |= 2u;
                    ++v42;
                    *(BYTE*)(outBuffer + 18) = v41 >> 6;
                    v43 = (v41 >> 3) & 7;
                    *(BYTE*)(outBuffer + 17) = v41;
                    v44 = v41 & 7;
                    *(BYTE*)(outBuffer + 19) = v43;
                    *(BYTE*)(outBuffer + 20) = v44;
                    if (v44 == 5 && (v34 & 1) == 0)
                        v6 = 4;
                }
                v45 = v42 - 1;
                switch (v6)
                {
                case 1u:
                    *(DWORD*)(outBuffer + 33) |= 0x40u;
                    *(BYTE*)(outBuffer + 29) = *v45;
                    break;
                case 2u:
                    *(DWORD*)(outBuffer + 33) |= 0x80u;
                    *(WORD*)(outBuffer + 29) = *(WORD*)v45;
                    break;
                case 4u:
                    *(DWORD*)(outBuffer + 33) |= 0x100u;
                    *(DWORD*)(outBuffer + 29) = *(DWORD*)v45;
                    break;
                }
                v4 = v55;
                _localAddress = &v45[v6];
                goto LABEL_133;
            }
        LABEL_103:
            *(DWORD*)(outBuffer + 33) |= 0x11000u;
            goto LABEL_104;
        }
        if (!v19)
            goto LABEL_104;
        switch (v17)
        {
        case 0x50u:
        LABEL_97:
            v40 = (v15 & 9) == 0;
            break;
        case 0xC5u:
            goto LABEL_103;
        case 0xD6u:
            v40 = (v15 & 6) == 0;
            break;
        case 0xD7u:
        case 0xF7u:
            goto LABEL_97;
        default:
            goto LABEL_104;
        }
        if (!v40)
            goto LABEL_103;
        goto LABEL_104;
    }
    if ((v15 & 0x20) != 0)
        *(DWORD*)(outBuffer + 33) = v20 | 0x9000;
LABEL_133:
    if ((v16 & 0x10) != 0)
    {
        if ((v16 & 0x40) != 0)
        {
            if ((v15 & 8) != 0)
            {
                *(DWORD*)(outBuffer + 33) |= 0x208u;
                v46 = *(WORD*)_localAddress;
                LOBYTE(_localAddress) = (BYTE)_localAddress + 2;
                *(WORD*)(outBuffer + 21) = v46;
                goto LABEL_146;
            }
        LABEL_151:
            *(DWORD*)(outBuffer + 33) |= 0x210u;
            v54 = *(DWORD*)_localAddress;
            LOBYTE(_localAddress) = (BYTE)_localAddress + 4;
            *(DWORD*)(outBuffer + 21) = v54;
            goto LABEL_146;
        }
        if (v4)
        {
            *(DWORD*)(outBuffer + 33) |= 0x20u;
            v47 = *(_QWORD*)_localAddress;
            _localAddress += 8;
            *(_QWORD*)(outBuffer + 21) = v47;
            goto LABEL_139;
        }
        if ((v15 & 8) == 0)
        {
            *(DWORD*)(outBuffer + 33) |= 0x10u;
            v53 = *(DWORD*)_localAddress;
            _localAddress += 4;
            *(DWORD*)(outBuffer + 21) = v53;
            goto LABEL_139;
        }
    LABEL_140:
        *(DWORD*)(outBuffer + 33) |= 8u;
        v48 = *(WORD*)_localAddress;
        _localAddress += 2;
        *(WORD*)(outBuffer + 21) = v48;
    }
    else
    {
    LABEL_139:
        if ((v16 & 4) != 0)
            goto LABEL_140;
    }
    if ((v16 & 2) != 0)
    {
        *(DWORD*)(outBuffer + 33) |= 4u;
        v49 = *_localAddress++;
        *(BYTE*)(outBuffer + 21) = v49;
    }
    if ((v16 & 0x40) != 0)
        goto LABEL_151;
    if ((v16 & 0x20) != 0)
    {
        *(DWORD*)(outBuffer + 33) |= 0x204u;
        v50 = *_localAddress;
        LOBYTE(_localAddress) = (BYTE)_localAddress + 1;
        *(BYTE*)(outBuffer + 21) = v50;
    }
LABEL_146:
    offsetFromAddress = (BYTE)_localAddress - localAddr;
    *(BYTE*)outBuffer = offsetFromAddress;
    if (offsetFromAddress > 0xFu)
    {
        *(DWORD*)(outBuffer + 33) |= 0x5000u;
        offsetFromAddress = 0xF;
        *(BYTE*)outBuffer = 15;
    }
    return offsetFromAddress;
}

    /**
     * Checks if an address range lies within a kernel module.
     *
     * \param Address The beginning of the address range.
     * \param Length The number of bytes in the address range.
     */
     //NTSTATUS KphValidateAddressForSystemModules(_In_ PVOID Address, _In_ SIZE_T Length)
     // {
     //     NTSTATUS status;
     //     PRTL_PROCESS_MODULES modules;
     //     ULONG i;
     //     BOOLEAN valid;
     // 
     //     PAGED_CODE();
     // 
     //     //status = EnumKernelModuleInfo(&modules);
     // 
     //     if (!NT_SUCCESS(status))
     //         return status;
     // 
     //     valid = FALSE;
     // 
     //     for (i = 0; i < modules->NumberOfModules; i++)
     //     {
     //         if (
     //             (ULONG_PTR)Address + Length >= (ULONG_PTR)Address &&
     //             (ULONG_PTR)Address >= (ULONG_PTR)modules->Modules[i].ImageBase &&
     //             (ULONG_PTR)Address + Length <= (ULONG_PTR)modules->Modules[i].ImageBase + modules->Modules[i].ImageSize
     //             )
     //         {
     //             dprintf("Validated address 0x%Ix in %s\n", Address, modules->Modules[i].FullPathName);
     //             valid = TRUE;
     //             break;
     //         }
     //     }
     // 
     //     ExFreePoolWithTag(modules, 'ThpK');
     // 
     //     if (valid)
     //         status = STATUS_SUCCESS;
     //     else
     //         status = STATUS_ACCESS_VIOLATION;
     // 
     //     return status;
     // }
    
    /*
    * WIP to manually parse PTE entries
    *
    void ShowPTEData(PVOID VirtAddress)
    {
        UINT64 cr3 = __readcr3();
        KdPrint(("CR3: 0x%08x", cr3));

        // 47 : 39
        UINT64 PML4_ENTRY = cr3 + ((*(UINT64*)VirtAddress)&&);

    }

    bool IsValidPTE(PVOID VirtAddress)
    {
        UINT64 cr3 = __readcr3();
        // Page-Map Level-4 Table (PML4) (Bits 47-39)
        UINT64 PML4_ENTRY = cr3 + ((*(UINT64*)VirtAddress) && )

    }
    */