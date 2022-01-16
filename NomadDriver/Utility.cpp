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

    auto whatIsthisAddr = *(long long*)((int*)outProcMods + 6);
    //LogInfo("whatIsthisAddr: %016X", outProcMods->Modules->);
    LogInfo("whatIsthisAddr: %x", whatIsthisAddr);

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
    wchar_t* names[WINAPI_IMPORT_COUNT] = { L"ZwQuerySystemInformation",    L"PsGetCurrentProcessId",       L"PsIsSystemThread",             L"PsGetCurrentProcess", 
                                            L"IoThreadToProcess",           L"PsGetProcessId",              L"RtlVirtualUnwind",             L"RtlLookupFunctionEntry", 
                                            L"KeAlertThread",               L"PsGetCurrentThreadStackBase", L"PsGetCurrentThreadStackLimit", L"KeAcquireQueuedSpinLockRaiseToSynch", 
                                            L"KeReleaseQueuedSpinLock",     L"PsLookupThreadByThreadId",    L"NtQueryInformationThread",     L"PsGetContextThread"};
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
    pNtQueryInformationThread = (NtQueryInformationThreadPtr)pNtPrimitives[_NtQueryInformationThreadIDX];
    pPsGetContextThread = (PsGetContextThreadPtr)pNtPrimitives[_PsGetContextThreadIDX];
    return STATUS_SUCCESS;
}

bool Utility::IsValidPEHeader(_In_ const uintptr_t pHead)
{
    // ideally should parse the PT so this can't be IAT spoofed
    __try
    {

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LogInfo("Exception executed for 0x%p , ExceptionCode == 0x%p", (PVOID)pHead, GetExceptionCode());
        return false;
    }
    if (!MmIsAddressValid((PVOID)pHead))
    {
#ifdef VERBOSE_LOG
        LogError("Was unable to read page @ 0x%p", (PVOID)pHead);
#endif
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
NTSTATUS Utility::FindExport(_In_ const uintptr_t imageBase, _In_ const char* exportName, _Out_ uintptr_t* functionPointer)
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

__forceinline wchar_t Utility::locase_w(_In_ wchar_t c)
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

// @Frostiest
// https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html

/// <summary>
/// Finds the kernel's base through our driver object (credits @Frostiest)
/// </summary>
/// <param name="DriverObject">our driver obj</param>
/// <returns>ntoskrnl's base addr on success</returns>
PVOID Utility::GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    PLDR_DATA_TABLE_ENTRY first = entry;

    while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
        if (strcmpi_w(entry->BaseDllName.Buffer, L"ntoskrnl.exe") == 0)
            return entry->DllBase;
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
    Log("Current IRQL: %d", (int)KeGetCurrentIrql());
    while (!IsValidPEHeader(pageInNtoskrnl))
    {
        pageInNtoskrnl -= 0x1000;
    }

    // Now we have the base address of ntoskrnl.exe
    return reinterpret_cast<void*>(pageInNtoskrnl);
}

/// <summary>
/// Wrapper for ZwQuerySystemInformation
/// </summary>
/// <param name="infoClass">type of query</param>
/// <param name="dataBuf">query data buffer</param>
/// <returns>NTSTATUS success on success</returns>
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

/// <summary>
/// Checks if given address is within any module reported from ZwQueryInfo
/// </summary>
/// <param name="address">address to check</param>
/// <param name="procMods">unused, using global for now</param>
/// <returns></returns>
BOOLEAN Utility::CheckModulesForAddress(_In_ UINT64 address, _In_ PRTL_PROCESS_MODULES procMods)
{
    if (address < (UINT64)MmSystemRangeStart)
    {
        LogInfo("Address is not in system range: %p", (PVOID)address);
        return SUCCESS;
    }

    UNREFERENCED_PARAMETER(procMods);
    RTL_PROCESS_MODULE_INFORMATION sysMod;
    for (size_t i = 0; i < outProcMods->NumberOfModules; i++)
    {
        sysMod = outProcMods->Modules[i];

        if ((UINT64)sysMod.ImageBase <= address && address <= ((UINT64)sysMod.ImageBase + sysMod.ImageSize))
        {
#ifdef VERBOSE_LOG
            LogInfo("\t\t\tAddress %p is within system module:  sysMod.ImageBase: 0x%p , sysMod.MaxAddr: 0x%llx", (VOID*)address, sysMod.ImageBase, ((UINT64)sysMod.ImageBase + sysMod.ImageSize));
#endif // VERBOSE_LOG
            return SUCCESS;
        }
    }
    LogInfo("\t\t\t[SUSPICIOUS] Address NOT within system module: 0x%p", (VOID*)address);
    return FAIL;
}

/// <summary>
/// Locates a given section in ntoskrnl
/// </summary>
/// <param name="sectionName">section to locate</param>
/// <param name="sectionVa">RVA from section base</param>
/// <param name="sectionSize">Virtual size</param>
/// <returns>1 on success</returns>
_Success_(return) BOOLEAN Utility::GetNtoskrnlSection(_In_ char* sectionName, _Out_ DWORD* sectionVa, _Out_ DWORD* sectionSize)
{
    if (!kernBase)
    {
        kernBase = GetNtoskrnlBaseAddress();
    }
    
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_magic != E_MAGIC)
    {
        LogInfo("\t\t\tGetNtoskrnlSection() expected MZ header != 0x%02x @ %p", E_MAGIC, kernBase);
        return FAIL;
    }

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>((BYTE*)kernBase + reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_lfanew);

    // avoid reading a page not paged in
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(kernBase)->e_lfanew > 0x1000)
    {
        LogInfo("\t\t\tGetNtoskrnlSection() pHead->e_lfanew > 0x1000 , doesn't seem valid @ 0x%p", kernBase);
        return FAIL;
    }

    if (ntHeader->Signature != NT_HDR_SIG)
    {
        LogInfo("\t\t\tGetNtoskrnlSection() ntHeader->Signature != 0x%02x @ 0x%p", NT_HDR_SIG, kernBase);
        return FAIL;
    }

    auto ntSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((BYTE*)ntHeader + sizeof(IMAGE_NT_HEADERS64));

    for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        char* ret = strstr((char*)ntSection[i].Name, sectionName);
        
        if (ret)
        {
            *sectionVa = ntSection[i].VirtualAddress;
            *sectionSize = ntSection[i].Misc.VirtualSize;
#ifdef VERBOSE_LOG
            LogInfo("\t\t\tfound %s in ntoskrnl.exe at VA offset 0x%08x , size %lu", sectionName, (VOID*)*sectionVa, (ULONG)*sectionSize);
#endif
            return SUCCESS;
        }
    }
    LogInfo("\t\t\tfailed to find %s in ntoskrnl.exe", sectionName);
    return FAIL;
}

UINT32 Utility::SpinLock(_In_ volatile signed __int64* Lock)
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

NTSTATUS Utility::Sleep(_In_ LONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(10ll * milliseconds);

    return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/// <summary>
/// Search for pattern https://github.com/DarthTon/Blackbone/blob/a672509b5458efeb68f65436259b96fa8cd4dcfc/src/BlackBoneDrv/Utils.c#L199
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS Utility::SearchPattern(_In_ PCUCHAR pattern, _In_ UCHAR wildcard, _In_ ULONG_PTR len, _In_ const VOID* base, _In_ ULONG_PTR size, _Out_ PVOID* ppFound)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}
