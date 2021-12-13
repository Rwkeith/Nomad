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

BOOLEAN Utility::IsWindows7()
{
    return SharedUserData->NtMajorVersion == 6 && SharedUserData->NtMinorVersion == 1;
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