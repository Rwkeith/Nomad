#pragma once
#include "Utility.h"
#include "Driver.h"

// TODO
NTSTATUS Utility::EnumSysThreadInfo() {
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

NTSTATUS Utility::EnumKernelModuleInfo() {
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
NTSTATUS Utility::ImportWinPrimitives()
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


// TODO
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

