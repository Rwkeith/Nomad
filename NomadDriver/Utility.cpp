#pragma once
#include "Utility.h"
#include "Driver.h"

namespace Utility
{

    /// <summary>
    /// Uses a pointer to ZwQuerySystemInformation to enumerate all loaded modules
    /// </summary>
    /// <returns></returns>
    NTSTATUS EnumKernelModuleInfo() {
        ULONG size = NULL;
        NomadDrv::outProcMods = NULL;

        // test our pointer
        if (!NomadDrv::pZwQuerySysInfo)
        {
            KdPrint(("[NOMAD] [ERROR]pZwQuerySysInf == NULL"));
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = NomadDrv::pZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, 0, 0, &size);
        if (STATUS_INFO_LENGTH_MISMATCH == status) {
            KdPrint(("[NOMAD] [INFO] ZwQuerySystemInformation test successed, status: %08x", status));
        }
        else
        {
            KdPrint(("[NOMAD] [ERROR] Unexpected value from ZwQuerySystemInformation, status: %08x", status));
            return status;
        }

        NomadDrv::outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
        if (!NomadDrv::outProcMods) {
            KdPrint(("[NOMAD] [ERROR] Insufficient memory in the free pool to satisfy the request"));
            return STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(status = NomadDrv::pZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, NomadDrv::outProcMods, size, 0))) {
            KdPrint(("[NOMAD] [ERROR] ZwQuerySystemInformation failed"));
            ExFreePool(NomadDrv::outProcMods);
            return status;
        }

        KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation with SYSTEM_MODULE_INFORMATION.  Modules->NumberOfModules = %lu\n", NomadDrv::outProcMods->NumberOfModules));

        for (ULONG i = 0; i < NomadDrv::outProcMods->NumberOfModules; i++)
        {
            KdPrint(("[NOMAD] [INFO] Module[%d].FullPathName: %s\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].FullPathName));
            KdPrint(("[NOMAD] [INFO] Module[%d].ImageBase: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].ImageBase));
            KdPrint(("[NOMAD] [INFO] Module[%d].MappedBase: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].MappedBase));
            KdPrint(("[NOMAD] [INFO] Module[%d].LoadCount: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].LoadCount));
            KdPrint(("[NOMAD] [INFO] Module[%d].ImageSize: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].ImageSize));
        }

        KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation complete\n"));
        return STATUS_SUCCESS;
    }

    /// <summary>
    /// Dynamic importing via a documented method
    /// </summary>
    /// <param name="pWinPrims"></param>
    /// <param name="names"></param>
    /// <returns></returns>
    NTSTATUS ImportWinPrimitives()
    {
        KdPrint(("[NOMAD] [INFO] Importing windows primitives\n"));

        wchar_t* names[WINAPI_IMPORT_COUNT] = { L"ZwQuerySystemInformation" };
        UNICODE_STRING uniNames[WINAPI_IMPORT_COUNT];

        for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
        {
            RtlInitUnicodeString(&uniNames[i], names[i]);
        }

        CHAR ansiImportName[MAX_NAME_LEN];

        for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
        {
            //pWinPrims[i] = MmGetSystemRoutineAddress(&uniNames[i]);
            NomadDrv::pWinPrims[i] = (GenericFuncPtr)MmGetSystemRoutineAddress(&uniNames[i]);
            if (NomadDrv::pWinPrims[i] == NULL)
            {
                KdPrint(("[NOMAD] [ERROR] Failed to import %s\n", (unsigned char*)ansiImportName));
                return STATUS_UNSUCCESSFUL;
            }
            else
            {
                KdPrint(("[NOMAD] [INFO] Succesfully imported %ls at %p\n", uniNames[i].Buffer, NomadDrv::pWinPrims[i]));
            }
        }

        NomadDrv::pZwQuerySysInfo = (ZwQuerySysInfoPtr)NomadDrv::pWinPrims[ZW_QUERY_INFO];

        return STATUS_SUCCESS;
    }

    bool IsValidPEHeader(_In_ const uintptr_t pHead)
    {
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
    NTSTATUS FindExport(_In_ const uintptr_t imageBase, const char* exportName, uintptr_t functionPointer)
    {
        if (!imageBase)
            return STATUS_INVALID_PARAMETER_1;

        const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
        const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

        if (!exportDirectory)
            STATUS_INVALID_IMAGE_FORMAT;

        const auto exportedFunctions = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfFunctions);
        const auto exportedNames = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfNames);
        const auto exportedNameOrdinals = reinterpret_cast<UINT16*>(imageBase + exportDirectory->AddressOfNameOrdinals);

        for (size_t i{}; i < exportDirectory->NumberOfNames; ++i) {
            const auto functionName = reinterpret_cast<const char*>(imageBase + exportedNames[i]);
            if (!strcmp(exportName, functionName)) {
                functionPointer = imageBase + exportedFunctions[exportedNameOrdinals[i]];
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    __forceinline wchar_t locase_w(wchar_t c)
    {
        if ((c >= 'A') && (c <= 'Z'))
            return c + 0x20;
        else
            return c;
    }

    int strcmpi_w(const wchar_t* s1, const wchar_t* s2)
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
    PVOID GetKernelBaseAddr(_In_ PDRIVER_OBJECT DriverObject)
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
    PVOID GetNtoskrnlBaseAddress()
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

    // TODO
    NTSTATUS EnumSysThreadInfo() {
        ULONG size = NULL;
        NomadDrv::outProcMods = NULL;

        // test our pointer
        if (!NomadDrv::pZwQuerySysInfo)
        {
            KdPrint(("[NOMAD] [ERROR] ZwQuerySystemInformation == NULL"));
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = NomadDrv::pZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, 0, 0, &size);
        if (STATUS_INFO_LENGTH_MISMATCH == status) {
            KdPrint(("[NOMAD] [INFO] ZwQuerySystemInformation test successed, status: %08x", status));
        }
        else
        {
            KdPrint(("[NOMAD] [ERROR] Unexpected value from ZwQuerySystemInformation, status: %08x", status));
            return status;
        }

        NomadDrv::outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
        if (!NomadDrv::outProcMods) {
            KdPrint(("[NOMAD] [ERROR] Insufficient memory in the free pool to satisfy the request"));
            return STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(status = NomadDrv::pZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, NomadDrv::outProcMods, size, 0))) {
            KdPrint(("[NOMAD] [ERROR] ZwQuerySystemInformation failed"));
            ExFreePool(NomadDrv::outProcMods);
            return status;
        }

        KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation with SYSTEM_MODULE_INFORMATION.  Modules->NumberOfModules = %lu\n", NomadDrv::outProcMods->NumberOfModules));

        for (ULONG i = 0; i < NomadDrv::outProcMods->NumberOfModules; i++)
        {
            KdPrint(("[NOMAD] [INFO] Module[%d].FullPathName: %s\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].FullPathName));
            KdPrint(("[NOMAD] [INFO] Module[%d].ImageBase: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].ImageBase));
            KdPrint(("[NOMAD] [INFO] Module[%d].MappedBase: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].MappedBase));
            KdPrint(("[NOMAD] [INFO] Module[%d].LoadCount: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].LoadCount));
            KdPrint(("[NOMAD] [INFO] Module[%d].ImageSize: %p\n", (int)i, (char*)NomadDrv::outProcMods->Modules[i].ImageSize));
        }

        KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation complete\n"));
        return STATUS_SUCCESS;
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
}