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
#endif // VERBOSE_LOG

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
        //LogInfo("pHead is != 0x%02x @ %p", E_MAGIC, (PVOID)pHead);
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

bool Utility::CheckModulesForAddress(UINT64 address, PRTL_PROCESS_MODULES procMods)
{
    RTL_PROCESS_MODULE_INFORMATION sysMod;
    for (size_t i = 0; i < outProcMods->NumberOfModules; i++)
    {
        sysMod = outProcMods->Modules[i];

        if ((UINT64)sysMod.ImageBase < address && address < ((UINT64)sysMod.ImageBase + sysMod.ImageSize))
        {
            LogInfo("\t\t\tAddress is within system module:  sysMod.ImageBase: 0x%p , sysMod.MaxAddr: 0x%llx", sysMod.ImageBase, ((UINT64)sysMod.ImageBase + sysMod.ImageSize));
            return true;
        }
    }
    LogInfo("\t\t\tDetected! Address NOT within system module:  address: 0x%llx", address);
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
        LogInfo("\t\t\tGetNtoskrnlSection() expected MZ header != 0x%02x @ %p", E_MAGIC, kernBase);
        return FALSE;
    }

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>((BYTE*)kernBase + reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_lfanew);

    // avoid reading a page not paged in
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_lfanew > 0x1000)
    {
        LogInfo("\t\t\tGetNtoskrnlSection() pHead->e_lfanew > 0x1000 , doesn't seem valid @ 0x%p", kernBase);
        return FALSE;
    }

    if (ntHeader->Signature != NT_HDR_SIG)
    {
        LogInfo("\t\t\tGetNtoskrnlSection() ntHeader->Signature != 0x%02x @ 0x%p", NT_HDR_SIG, kernBase);
        return FALSE;
    }

    auto ntSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((BYTE*)ntHeader + sizeof(IMAGE_NT_HEADERS64));
    //LogInfo("\t\t\tntHeader->FileHeader.Machine: 0x%hx", ntHeader->FileHeader.Machine);
    //LogInfo("\t\t\tntHeader->FileHeader.NumberOfSections: 0x%hx", ntHeader->FileHeader.NumberOfSections);

    for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        char* ret = strstr((char*)ntSection[i].Name, sectionName);
        
        if (ret)
        {
            *sectionVa = ntSection[i].VirtualAddress;
            *sectionSize = ntSection[i].Misc.VirtualSize;
            LogInfo("\t\t\tfound %s in ntoskrnl.exe at %p , size %lu", sectionName, (VOID*)*sectionVa, (ULONG)*sectionSize);
            return true;
        }
        //else
        //{
        //    LogInfo("\t\t\No match, ntSection[%llu] = %p ; ntSection[%llu].Name: %s != %s .  VirtualAddress: 0x%lx ", i, &ntSection[i], i, ntSection[i].Name, sectionName, ntSection[i].VirtualAddress);
        //}
    }
    LogInfo("\t\t\tfailed to find %s in ntoskrnl.exe", sectionName);
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
BOOL Utility::LockThread(_In_ PKTHREAD Thread, _Out_ KIRQL* Irql)
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
    unsigned __int64 thisKThread; // rbx
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
    PETHREAD thiskThread; // rbx
    __int64 stackBase; // rax
    _QWORD* v3; // rcx

    thiskThread = (PETHREAD)__readgsqword(0x188);
    if ((unsigned int)SpinLock(&gSpinLock5) == 259)
    {
        stackBase = (__int64)pPsGetCurrentThreadStackBase();
        v3 = (_QWORD*)thiskThread;
        if ((UINT64)thiskThread < ((UINT64)thiskThread + 0x2F8))
        {
            while (*v3 != stackBase)
            {
                if ((unsigned __int64)++v3 >= (UINT64)thiskThread + 0x2F8)
                    goto LABEL_9;
            }
            gStackBaseOffset = (UINT64)v3 - (UINT64)thiskThread;
        }
    LABEL_9:
        _InterlockedExchange64(&gSpinLock5, 2);
    }
    return (unsigned int)gStackBaseOffset;
}

__int64 Utility::GetThreadLockOffset()
{
    unsigned __int8* Export;
    unsigned __int8* maxOffset;
    unsigned __int8* addrOffset;
    unsigned __int8* threadLockOffset;

    if ((unsigned int)SpinLock(&gSpinLock1) == 259)
    {
        Export = (unsigned __int8*)KeSetPriorityThread;
        if (Export)
        {
            maxOffset = Export + 0xF1;
            if (threadLockPatternMatch(Export, &threadLockOffset, 0xF1))
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
        // Acquire the lock so we only search for the offset once
        _InterlockedExchange64(&gSpinLock1, 2);
    }
    return gThreadLockOffset;
}

__int64 Utility::GetThreadStateOffset()
{
    UINT64 kThreadStateOffset;
    unsigned __int8* Export;
    unsigned __int8* maxOffset;
    unsigned __int8* i;
    UINT64 v6;
    unsigned int* threadStateOffset;

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
                if (threadStatePatternMatch(Export, &threadStateOffset, 0x132))
                {
                    LogInfo("\t\t\tthreadStatePatternMatch() found a match at %p with offset value %lu", threadStateOffset, *threadStateOffset);
                    gkThreadStateOffset = *threadStateOffset;
                }
                else
                {
                    LogError("\t\t\tthreadStatePatternMatch() failed to find a match");
                }
            }
            kThreadStateOffset = gkThreadStateOffset;
        }
        if (kThreadStateOffset)
        {
            v6 = gkThreadStateOffset;
            // we would expect this thread to be in RUNNING STATE, https://doxygen.reactos.org/dd/d83/ndk_2ketypes_8h.html#a89cf35e06b66523904596d9dbdd93af4a7ac9ab6c2e98f6df96b82b175d42747a
            if (*(BYTE*)((BYTE*)__readgsqword(0x188u) + kThreadStateOffset) != 2)
            {
                LogError("\t\t\tGetThreadState(), our thread state was not running based on thread state offset.");
                v6 = 0;
            }
            gkThreadStateOffset = v6;
        }
        _InterlockedExchange64(&gSpinLock3, 2);
    }
    return (unsigned int)gkThreadStateOffset;
}

UINT32 Utility::SpinLock(volatile signed __int64* Lock)
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

// Failing to match for GetThreadStateOffset, GetThreadLockOffset
__int64 Utility::patternMatcher(unsigned __int8* address, UINT64 outBuffer)
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



    localAddr = (char)address;
    v3 = patContainer.unk_1400567A0;
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
        v3 = patContainer.unk_1400567EA;
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
    bool leftHalf_RightExp = ((unsigned __int64)(v15 & *(BYTE*)patContainer.unk_1400567A0 + (currentByte & 3)) + (unsigned __int64)*((unsigned __int8*)patContainer.unk_1400567A0 + ((unsigned __int64)(unsigned __int8)currentByte >> 2) + 316) + 316);
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
                v32 = *((BYTE*)patContainer.unk_1400567A0 + 8 * v30 + v26 + 260);
            }
            else
            {
                v31 = v26;
                v32 = *((BYTE*)patContainer.unk_1400567A0 + v30 + 253);
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
                v36 = patContainer.unk_140056978;
                if (!v19)
                    v36 = patContainer.unk_140056966;
                v37 = patContainer.unk_140056966;
                if (!v19)
                    v37 = patContainer.unk_14005694E;
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
                v39 = patContainer.unk_140056987;
                v38 = patContainer.unk_140056978;
                goto LABEL_85;
            }
            v38 = patContainer.unk_140056987;
            v39 = patContainer.unk_1400569B1;
            if (patContainer.unk_140056987 == patContainer.unk_1400569B1)
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

__int64 Utility::threadLockPatternMatch(unsigned __int8* address, unsigned __int8** outOffset, int range)
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
            return true;
        }
    }
    return false;
}

__int64 Utility::threadStatePatternMatch(unsigned __int8* address, unsigned int **outOffset, int range)
{
    for (BYTE* currByte = address; currByte < (address + range); currByte++)
    {
        if (currByte[0] == threadStatePattern[0]
            && currByte[1] == threadStatePattern[1]
            && currByte[6] == threadStatePattern[6]
            && currByte[7] == threadStatePattern[7])
        {
            *outOffset = (unsigned int*)((BYTE*)currByte + 2);
            return true;
        }
    }
    return false;
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