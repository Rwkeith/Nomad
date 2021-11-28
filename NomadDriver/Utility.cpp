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

NTSTATUS Utility::InitUtils(PDRIVER_OBJECT DriverObject)
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

    status = ImportWinPrimitives();
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
NTSTATUS Utility::EnumKernelModuleInfo() {
    ULONG size = NULL;

    // test our pointer
    if (!pZwQuerySysInfo)
    {
        LogError("ZwQuerySystemInformation == NULL");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = pZwQuerySysInfo(SYS_MOD_INF, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH == status) {
        LogInfo("ZwQuerySystemInformation test successed, status: %08x", status);
    }
    else
    {
        LogError("Unexpected value from ZwQuerySystemInformation, status: %08x", status);
        return status;
    }

    if (outProcMods)
    {
        ExFreePool(outProcMods);
        outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
    }
    else
    {
        outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
    }
        
    if (!outProcMods) {
        LogError("Insufficient memory in the free pool to satisfy the request");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status = pZwQuerySysInfo(SYS_MOD_INF, outProcMods, size, 0))) {
        LogError("ZwQuerySystemInformation failed");
        ExFreePool(outProcMods);
        outProcMods = NULL;
        return status;
    }

    LogInfo("Using ZwQuerySystemInformation with SYS_MOD_INF.  Modules->NumberOfModules = %lu\n", outProcMods->NumberOfModules);

    for (ULONG i = 0; i < outProcMods->NumberOfModules; i++)
    {
        LogInfo("Module[%d].FullPathName: %s\n", (int)i, (char*)outProcMods->Modules[i].FullPathName);
        LogInfo("Module[%d].ImageBase: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageBase);
        LogInfo("Module[%d].MappedBase: %p\n", (int)i, (char*)outProcMods->Modules[i].MappedBase);
        LogInfo("Module[%d].LoadCount: %p\n", (int)i, (char*)outProcMods->Modules[i].LoadCount);
        LogInfo("Module[%d].ImageSize: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageSize);
    }

    LogInfo("Using ZwQuerySystemInformation complete\n");
    return STATUS_SUCCESS;
}

/// <summary>
/// Dynamic importing via a documented method
/// </summary>
/// <param name="pWinPrims"></param>
/// <param name="names"></param>
/// <returns></returns>
NTSTATUS Utility::ImportWinPrimitives()
{
    LogInfo("Importing windows primitives\n");

    wchar_t* names[WINAPI_IMPORT_COUNT] = { L"ZwQuerySystemInformation" };
    UNICODE_STRING uniNames[WINAPI_IMPORT_COUNT];

    for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
    {
        RtlInitUnicodeString(&uniNames[i], names[i]);
    }

    CHAR ansiImportName[MAX_NAME_LEN];

    for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
    {
        pWinPrims[i] = (GenericFuncPtr)pMmSysRoutine(&uniNames[i]);
        if (pWinPrims[i] == NULL)
        {
            LogError("Failed to import %s\n", (unsigned char*)ansiImportName);
            return STATUS_UNSUCCESSFUL;
        }
        else
        {
            LogInfo("Succesfully imported %ls at %p\n", uniNames[i].Buffer, pWinPrims[i]);
        }
    }

    pZwQuerySysInfo = (ZwQuerySysInfoPtr)pWinPrims[ZW_QUERY_INFO];

    return STATUS_SUCCESS;
}

bool Utility::IsValidPEHeader(_In_ const uintptr_t pHead)
{
    // ideally should parse the PT so this can't be IAT spoofed
    if (!MmIsAddressValid((PVOID)pHead))
    {
        LogError("Was unable to read page @ 0x%p", (PVOID)pHead);
        return FALSE;
    }

    if (!pHead)
    {
        LogInfo("pHead is null @ 0x%p", (PVOID)pHead);
        return FALSE;
    }

    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_magic != E_MAGIC)
    {
        LogInfo("pHead is != 0x%02x @ %p", E_MAGIC, (PVOID)pHead);
        return FALSE;
    }

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(pHead + reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_lfanew);

    // avoid reading a page not paged in
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_lfanew > 0x1000)
    {
        LogInfo("pHead->e_lfanew > 0x1000 , doesn't seem valid @ 0x%p", (PVOID)pHead);
        return FALSE;
    }

    if (ntHeader->Signature != NT_HDR_SIG)
    {
        LogInfo("ntHeader->Signature != 0x%02x @ 0x%p", NT_HDR_SIG, (PVOID)pHead);
        return FALSE;
    }

    LogInfo("SUCCESSFULLY FOUND PAGE @ 0x%p", (PVOID)pHead);
    return TRUE;
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
// Lands above nt module, but memory could be paged out.  Tweak to check PTE's instead of using MmIsAddressValid.  Refer to:  https://www.unknowncheats.me/forum/anti-cheat-bypass/437451-whats-proper-write-read-physical-memory.html
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

    //__int64 ScanSystemThreads()
    //{
    //    __int64 result;
    //    __int64 currentProcessId;
    //    int isSystemThread;
    //    __int64 systemBigPoolInformation;
    //    PRTL_PROCESS_MODULE_INFORMATION systemModuleInformation;
    //    CONTEXT* context;
    //    unsigned __int64 currentThreadId;
    //    signed int status0;
    //    STACKWALK_ENTRY* entry;
    //    __int64 v10;
    //    int entryIndex;
    //    __int64 v12;
    //    unsigned __int64 v13;
    //    int status1;
    //    __int64 threadProcessId;
    //    STACKWALK_BUFFER stackwalkBuffer;
    //    PVOID threadObject;
    //    __int64 win32StartAddress;

    //    result = (long long)NomadDrv::pPsGetCurrentProcessId();
    //    currentProcessId = result;
    //    if (import_PsIsSystemThread)
    //    {
    //        result = import_PsIsSystemThread(__readgsqword(0x188u));
    //        isSystemThread = (unsigned __int8)result;
    //    }
    //    else
    //    {
    //        isSystemThread = 0;
    //    }
    //    if (isSystemThread)
    //    {
    //        result = import_PsGetCurrentProcess();
    //        if (result == PsInitialSystemProcess)
    //        {
    //            systemBigPoolInformation = QuerySystemInformation(0x42i64, 0x100000i64, 0x2000000i64);
    //            result = QuerySystemModuleInformation();
    //            systemModuleInformation = (PRTL_PROCESS_MODULE_INFORMATION)result;
    //            EnumKernelModuleInfo();
    //            if (result)
    //            {
    //                context = (CONTEXT*)AllocatePool(0x4D0i64);
    //                if (context)
    //                {
    //                    currentThreadId = 4i64;
    //                    do
    //                    {
    //                        if (import_PsLookupThreadByThreadId)
    //                            status0 = import_PsLookupThreadByThreadId(currentThreadId, &threadObject);
    //                        else
    //                            status0 = 0xC0000002;
    //                        if (status0 >= 0)
    //                        {
    //                            if (GetProcessId((__int64)threadObject) == currentProcessId
    //                                && threadObject != (PVOID)__readgsqword(0x188u)
    //                                && StackwalkThread((__int64)threadObject, context, &stackwalkBuffer)
    //                                && stackwalkBuffer.EntryCount > 0u)
    //                            {
    //                                entry = stackwalkBuffer.Entries;
    //                                while (1)
    //                                {
    //                                    if (!GetModuleEntryForAddress(entry->RipValue, &systemModuleInformation->Count))
    //                                    {
    //                                        if (!v10)
    //                                            break;
    //                                        if (!v12)
    //                                            break;
    //                                        v13 = *(_QWORD*)(v12 + 24);
    //                                        if (!v13
    //                                            || *(_DWORD*)(v12 + 32) <= 0u
    //                                            || entry->RipValue < v13
    //                                            || entry->RipValue >= v13 + *(unsigned int*)(v12 + 32))
    //                                        {
    //                                            break;
    //                                        }
    //                                    }
    //                                    ++entry;
    //                                    if ((unsigned int)(entryIndex + 1) >= stackwalkBuffer.EntryCount)
    //                                        goto LABEL_30;
    //                                }
    //                                status1 = QueryWin32StartAddress((__int64)threadObject, &win32StartAddress);
    //                                if (status1 < 0)
    //                                    win32StartAddress = 0i64;
    //                                threadProcessId = GetProcessId((__int64)threadObject);
    //                                PerformAdditionalScans(         // This is virtualized.
    //                                                                // Probably checks if address is within any big pool and sends report to server.
    //                                    threadProcessId,
    //                                    (unsigned int)currentThreadId,
    //                                    win32StartAddress,
    //                                    systemModuleInformation,
    //                                    systemBigPoolInformation,
    //                                    &stackwalkBuffer);
    //                            }
    //                        LABEL_30:
    //                            ObfDereferenceObject(threadObject);
    //                        }
    //                        currentThreadId += 4i64;
    //                    } while (currentThreadId < 0x3000);
    //                    FreePool((__int64)context);
    //                }
    //                result = FreePool((__int64)systemModuleInformation);
    //            }
    //            if (systemBigPoolInformation)
    //                result = FreePool(systemBigPoolInformation);
    //        }
    //    }
    //    return result;
    //}

    //char __fastcall StackwalkThread(__int64 threadObject, CONTEXT* context, STACKWALK_BUFFER* stackwalkBuffer)
    //{
    //    char status; // di
    //    _QWORD* stackBuffer; // rax MAPDST
    //    size_t copiedSize; // rax
    //    DWORD64 startRip; // rdx
    //    unsigned int index; // ebp
    //    unsigned __int64 rip0; // rcx
    //    DWORD64 rsp0; // rdx
    //    __int64 functionTableEntry; // rax
    //    __int64 moduleBase; // [rsp+40h] [rbp-48h]
    //    __int64 v17; // [rsp+48h] [rbp-40h]
    //    __int64 v18; // [rsp+50h] [rbp-38h]
    //    unsigned __int64 sectionVa; // [rsp+90h] [rbp+8h]
    //    __int64 sectionSize; // [rsp+A8h] [rbp+20h]

    //    status = 0;
    //    if (!threadObject)
    //        return 0;
    //    if (!stackwalkBuffer)
    //        return 0;
    //    memset(context, 0, 0x4D0ui64);
    //    memset(stackwalkBuffer, 0, 0x208ui64);
    //    if (!import_RtlVirtualUnwind)
    //    {
    //        import_RtlVirtualUnwind = (__int64(__fastcall*)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD))FindExport((__int64)&unk_47420);
    //        if (!import_RtlVirtualUnwind)
    //            return 0;
    //    }
    //    if (!import_RtlLookupFunctionEntry)
    //    {
    //        import_RtlLookupFunctionEntry = (__int64(__fastcall*)(_QWORD, _QWORD, _QWORD))FindExport((__int64)&unk_473F0);
    //        if (!import_RtlLookupFunctionEntry)
    //            return 0;
    //    }
    //    stackBuffer = (_QWORD*)AllocatePool(4096i64);
    //    if (stackBuffer)
    //    {
    //        copiedSize = CopyThreadKernelStack(threadObject, 4096i64, stackBuffer, 4096);
    //        if (copiedSize)
    //        {
    //            if (copiedSize != 4096 && copiedSize >= 0x48)
    //            {
    //                if (GetNtoskrnlSection('txet.', &sectionVa, &sectionSize))
    //                {
    //                    startRip = stackBuffer[7];
    //                    if (startRip >= sectionVa && startRip < sectionSize + sectionVa)
    //                    {
    //                        status = 1;
    //                        context->Rip = startRip;
    //                        context->Rsp = (DWORD64)(stackBuffer + 8);
    //                        index = 0;
    //                        do
    //                        {
    //                            rip0 = context->Rip;
    //                            rsp0 = context->Rsp;
    //                            stackwalkBuffer->Entries[stackwalkBuffer->EntryCount].RipValue = rip0;
    //                            stackwalkBuffer->Entries[stackwalkBuffer->EntryCount++].RspValue = rsp0;
    //                            if (rip0 < MmSystemRangeStart)
    //                                break;
    //                            if (rsp0 < MmSystemRangeStart)
    //                                break;
    //                            functionTableEntry = import_RtlLookupFunctionEntry(rip0, &moduleBase, 0i64);
    //                            if (!functionTableEntry)
    //                                break;
    //                            import_RtlVirtualUnwind(0i64, moduleBase, context->Rip, functionTableEntry, context, &v18, &v17, 0i64);
    //                            if (!context->Rip)
    //                            {
    //                                stackwalkBuffer->Succeded = 1;
    //                                break;
    //                            }
    //                            ++index;
    //                        } while (index < 0x20);
    //                    }
    //                }
    //            }
    //        }
    //        FinalizeFreePool((__int64)stackBuffer);
    //    }
    //    return status;
    //}

    //size_t __usercall CopyThreadKernelStack@<rax>(__int64 threadObject@<rcx>, __int64 maxSize@<rdx>, void* outStackBuffer@<r8>, signed int a4@<r14d>)
    //{
    //    size_t copiedSize; // rsi
    //    __int64 threadStateOffset; // r12 MAPDST
    //    __int64 kernelStackOffset; // r14
    //    unsigned int threadStackBaseOffset; // eax
    //    unsigned __int64 threadStackBase; // rdi
    //    unsigned int threadStackLimitOffset; // eax
    //    unsigned __int64 threadStackLimit; // rbp
    //    int isSystemThread; // er11
    //    const void** pKernelStack; // r12
    //    __int64 v16; // rdx
    //    unsigned int threadLockOffset; // eax
    //    KSPIN_LOCK* threadLock; // rcx
    //    void(__fastcall * v19)(_QWORD, __int64); // rax
    //    unsigned __int8 oldIrql; // [rsp+50h] [rbp+8h]

    //    copiedSize = 0i64;
    //    threadStateOffset = (unsigned int)GetThreadStateOffset(a4);
    //    kernelStackOffset = (unsigned int)GetKernelStackOffset();
    //    threadStackBaseOffset = GetThreadStackBaseOffset();
    //    if (threadObject && threadStackBaseOffset)
    //        threadStackBase = *(_QWORD*)(threadStackBaseOffset + threadObject);
    //    else
    //        threadStackBase = 0i64;
    //    threadStackLimitOffset = GetThreadStackLimitOffset();
    //    if (!threadObject)
    //        return 0i64;
    //    threadStackLimit = threadStackLimitOffset ? *(_QWORD*)(threadStackLimitOffset + threadObject) : 0i64;
    //    isSystemThread = import_PsIsSystemThread ? (unsigned __int8)import_PsIsSystemThread(threadObject) : 0;
    //    if (!isSystemThread
    //        || !outStackBuffer
    //        || !(_DWORD)threadStateOffset
    //        || !(_DWORD)kernelStackOffset
    //        || !threadStackBase
    //        || !threadStackLimit
    //        || KeGetCurrentIrql() > 1u
    //        || threadObject == __readgsqword(0x188u))
    //    {
    //        return 0i64;
    //    }
    //    pKernelStack = (const void**)(threadObject + kernelStackOffset);
    //    memset(outStackBuffer, 0, 0x1000ui64);
    //    if (LockThread(&oldIrql, threadObject, 0x1000))
    //    {
    //        if (!(unsigned __int8)PsIsThreadTerminating(threadObject)
    //            && *(_BYTE*)(threadStateOffset + threadObject) == 5
    //            && (unsigned __int64)*pKernelStack > threadStackLimit
    //            && (unsigned __int64)*pKernelStack < threadStackBase
    //            && MmGetPhysicalAddress(*pKernelStack))
    //        {
    //            copiedSize = threadStackBase - (_QWORD)*pKernelStack;
    //            if (copiedSize > 0x1000)
    //                copiedSize = 0x1000i64;
    //            memmove(outStackBuffer, *pKernelStack, copiedSize);
    //        }
    //        if (MEMORY[0xFFFFF7800000026C] >= 6u && (MEMORY[0xFFFFF7800000026C] != 6 || MEMORY[0xFFFFF78000000270]))
    //        {
    //            threadLockOffset = GetThreadLockOffset(0x1000);
    //            threadLock = (KSPIN_LOCK*)((threadObject + threadLockOffset) & -(signed __int64)(threadLockOffset != 0));
    //            if (threadLock)
    //            {
    //                KeReleaseSpinLockFromDpcLevel(threadLock);
    //                __writecr8(oldIrql);
    //            }
    //        }
    //        else
    //        {
    //            v19 = (void(__fastcall*)(_QWORD, __int64))qword_4DF00;
    //            if (qword_4DF00
    //                || (v19 = (void(__fastcall*)(_QWORD, __int64))FindExport((__int64)&unk_46D00),
    //                    (qword_4DF00 = (__int64)v19) != 0))
    //            {
    //                LOBYTE(v16) = oldIrql;
    //                v19(0i64, v16);
    //            }
    //        }
    //    }
    //    return copiedSize;
    //}

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