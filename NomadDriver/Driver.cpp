#pragma once
#include "Driver.h"
#include "Common.h"

// for register macros
#include <intrin.h>
#include "asmstubs.h"

//PLOAD_IMAGE_NOTIFY_ROUTINE ImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcID, PIMAGE_INFO ImageInfo)
//{
//
//    UNREFERENCED_PARAMETER(ImageInfo);
//    UNREFERENCED_PARAMETER(ProcID);
//
//
//    if (wcsstr(FullImageName->Buffer, L"\\WinKernelProgDrv.sys"))
//    {
//        KdPrint(("[NOMAD] [INFO] Found WinKernelProgDrv.sys!  Dumping!\n"));
//        UINT64 base = (UINT64)ImageInfo->ImageBase;
//        DumpKernelModule("WinKernelProgDrv.sys");
//    }
//
//    return STATUS_SUCCESS;
//}

PRTL_PROCESS_MODULES outProcMods = NULL;

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
    KdPrint(("[NOMAD] [INFO] Starting Initialization\n"));

    //PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotifyRoutine);
    
    // map major function handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = NomadCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NomadClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NomadDeviceControl;
    DriverObject->DriverUnload = NomadUnload;
    
    // Create a device object for the usermode application to use
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Nomad");

    PDEVICE_OBJECT DeviceObject;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

    // error check for successful driver object creation
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[NOMAD] [ERROR] Failed to create device object (0x%08X)\n", status));
        return status;
    }

    // provide symbolic link to device object to make accessible to usermode
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Nomad");
    status = IoCreateSymbolicLink(&symLink, &devName);

    // error check for sym link creation
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[NOMAD] [ERROR] Failed to create symbolic link (0x%08X)\n", status));
        IoDeleteDevice(DeviceObject);
        return status;
    }

    KdPrint(("[NOMAD] [INFO] Nomad driver initialized successfully\n"));

    wchar_t* apiNames[WINAPI_IMPORT_COUNT] = { L"ZwQuerySystemInformation" };
    //PVOID pWinPrims[WINAPI_IMPORT_COUNT];
    GenericFuncPtr(pWinPrims[WINAPI_IMPORT_COUNT]);
    status = ImportWinPrimitives(pWinPrims, apiNames);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[NOMAD] [ERROR] Importing windows primitives failed.  Aborting task\n"));
        return STATUS_SUCCESS;
    }

    EnumKernelModuleInfo((ZwQuerySysInfoPtr)pWinPrims[ZW_QUERY_INFO]);
    

    // All checks complete
    KdPrint(("[NOMAD] [INFO] All checks passed.  Nothing suspicious.\n"));
    return STATUS_SUCCESS;
}

/// <summary>
/// Dynamic importing via a documented method
/// </summary>
/// <param name="pWinPrims"></param>
/// <param name="names"></param>
/// <returns></returns>
NTSTATUS ImportWinPrimitives(_Out_ GenericFuncPtr(pWinPrims[]), _In_ wchar_t* names[])
{
    KdPrint(("[NOMAD] [INFO] Importing windows primitives\n"));
    
    UNICODE_STRING uniNames[WINAPI_IMPORT_COUNT];

    for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
    {
        RtlInitUnicodeString(&uniNames[i], names[i]);
    }

    CHAR ansiImportName[MAX_NAME_LEN];

    for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
    {
        //pWinPrims[i] = MmGetSystemRoutineAddress(&uniNames[i]);
        pWinPrims[i] = (GenericFuncPtr)MmGetSystemRoutineAddress(&uniNames[i]);
        if (pWinPrims[i] == NULL)
        {
            KdPrint(("[NOMAD] [ERROR] Failed to import %s\n", (unsigned char*)ansiImportName));
            return STATUS_UNSUCCESSFUL;
        }
        else
        {
            KdPrint(("[NOMAD] [INFO] Succesfully imported %ls at %p\n", uniNames[i].Buffer, pWinPrims[i]));
        }
    }
    
    return STATUS_SUCCESS;
}

void NomadUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Nomad");
    // delete sym link
    IoDeleteSymbolicLink(&symLink);

    // delete device object
    IoDeleteDevice(DriverObject->DeviceObject);
    KdPrint(("[NOMAD] [INFO] Nomad unloaded\n"));

    if (outProcMods)
    {
        ExFreePool(outProcMods);
    }
}

_Use_decl_annotations_
NTSTATUS NomadCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    KdPrint(("[NOMAD] [INFO] Client connection received\n"));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS NomadClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    KdPrint(("[NOMAD] [INFO] Client closed handle.\n"));
    return STATUS_SUCCESS;
}


_Use_decl_annotations_
NTSTATUS NomadDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
    // get our IO_STACK_LOCATION
    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_DUMP_KERNEL_MODULE: {
        // do the work
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MD_MODULE_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (PMD_MODULE_DATA)stack->Parameters.DeviceIoControl.Type3InputBuffer;

        if (data == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        //status = DumpKernelModule(data->moduleName);
        //if (!NT_SUCCESS(status))
        //{
        //    KdPrint(("[NOMAD] [ERROR] Failed to dump kernel module\n"));
        //    break;
        //}

        KdPrint(("[NOMAD] [INFO] Successfully dumped kernel module\n"));
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

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

//NTSTATUS DumpKernelModule(_In_ char* moduleName) {
//
//    RTL_PROCESS_MODULE_INFORMATION ModuleInfo;
//    NTSTATUS status = EnumKernelModuleInfo(moduleName, &ModuleInfo);
//
//    if (!NT_SUCCESS(status)) {
//        return STATUS_UNSUCCESSFUL;
//    }
//    KdPrint(("[NOMAD] [INFO] RTL_PROCESS_MODULE_INFORMATION DEBUG INFO\n"));
//    KdPrint(("[NOMAD] [INFO] ModuleInfo.ImageSize: 0x%lx\n", ModuleInfo.ImageSize));
//    KdPrint(("[NOMAD] [INFO] ModuleInfo.ImageBase: 0x%p\n", ModuleInfo.ImageBase));
//    KdPrint(("[NOMAD] [INFO] ModuleInfo.FullPathName: 0x%s\n", ModuleInfo.FullPathName));
//    KdPrint(("[NOMAD] [INFO] ModuleInfo.MappedBase: 0x%p\n", ModuleInfo.MappedBase));
//    KdPrint(("[NOMAD] [INFO] ModuleInfo.Section: 0x%p\n", ModuleInfo.Section));
//
//
//    //PVOID byteBuffer = ExAllocatePool(NonPagedPool, ModuleInfo.ImageSize);
//    PVOID byteBuffer = ExAllocatePoolZero(NonPagedPool, ModuleInfo.ImageSize, 0x4A4A4A4A);
//    PVOID byteBufferBase = byteBuffer;
//    if (!byteBuffer) {
//        KdPrint(("[NOMAD] [ERROR] Failed to allocate pool\n"));
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    MM_COPY_ADDRESS mmCopyAddress;
//    MM_COPY_ADDRESS mmCurrCopyAddr;
//    mmCopyAddress.VirtualAddress = ModuleInfo.ImageBase;
//    mmCurrCopyAddr.VirtualAddress = ModuleInfo.ImageBase;
//    size_t numOfBytesCopied = 0;
//    
//    size_t remainingBytes = ModuleInfo.ImageSize;
//    size_t incrementVal = PAGE_SIZE;
//    size_t totalBytesCopied = 0;
//    PVOID finalAddress = ((BYTE*)mmCopyAddress.VirtualAddress + ModuleInfo.ImageSize);
//
//    if (ModuleInfo.ImageSize < PAGE_SIZE)
//    {
//        KdPrint(("[NOMAD] [ERROR] ImageSize shouldn't be less than a page in size.  Halting operation\n"));
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    KdPrint(("[NOMAD] [INFO] Starting MmCopyMemory Routine from %p to %p\n", mmCopyAddress.VirtualAddress, finalAddress));
//    while (mmCopyAddress.VirtualAddress < finalAddress)
//    {
//        bool isValid = MmIsAddressValid(mmCopyAddress.VirtualAddress);
//        if (isValid)
//        {
//            KdPrint(("[NOMAD] [INFO] MmIsAddressValid found valid page at %p\n", mmCopyAddress.VirtualAddress));
//            // read it
//            status = MmCopyMemory(byteBuffer, mmCopyAddress, PAGE_SIZE, MM_COPY_MEMORY_VIRTUAL, (PSIZE_T)&numOfBytesCopied);
//            if (!NT_SUCCESS(status))
//            {
//                KdPrint(("[NOMAD] [WARN] Failed to copy bytes at address: %p\n", mmCopyAddress.VirtualAddress));
//                KdPrint(("[NOMAD] [WARN] MmCopyMemory() NTSTATUS: STATUS_ACCESS_VIOLATION.  Handling by filling invalid pages with 00's\n"));
//                goto makeBlank;
//            }
//
//            byteBuffer = ((BYTE*)byteBuffer + incrementVal);
//            totalBytesCopied += incrementVal;
//            mmCopyAddress.VirtualAddress = ((BYTE*)mmCopyAddress.VirtualAddress + incrementVal);
//            remainingBytes -= incrementVal;
//            continue;
//        }
//        else {
//            // make a blank page
//            KdPrint(("[NOMAD] [WARN] MmIsAddressValid invalid page: %p\n", mmCopyAddress.VirtualAddress));
//        makeBlank:
//            RtlSecureZeroMemory(byteBuffer, PAGE_SIZE);
//            byteBuffer = ((BYTE*)byteBuffer + incrementVal);
//            totalBytesCopied += incrementVal;
//            mmCopyAddress.VirtualAddress = ((BYTE*)mmCopyAddress.VirtualAddress + incrementVal);
//            remainingBytes -= incrementVal;
//        }
//    }
//    KdPrint(("[NOMAD] [INFO] Copied memory range from %p to %p into buffer at %p\n", ModuleInfo.ImageBase, mmCopyAddress.VirtualAddress, byteBufferBase));
//    KdPrint(("[NOMAD] [INFO] Number of bytes copied: %zu\n", totalBytesCopied));
//    HANDLE fileHandle = NULL;
//    UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\DumpedDriver.sys");
//    OBJECT_ATTRIBUTES objAttr;
//    IO_STATUS_BLOCK ioStatusBlock;
//
//    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
//    if (!NT_SUCCESS(ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) {
//        KdPrint(("[NOMAD] [ERROR] Failed to create file\n"));
//        //ExFreePool(byteBufferBase);
//        ExFreePoolWithTag(byteBufferBase, 0x4A4A4A4A);
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    if (!NT_SUCCESS(ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, byteBufferBase, ModuleInfo.ImageSize, NULL, NULL))) {
//        KdPrint(("[NOMAD] [ERROR] Failed to write to file!\n"));
//        //ExFreePool(byteBufferBase);
//        ExFreePoolWithTag(byteBufferBase, 0x4A4A4A4A);
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    KdPrint(("[NOMAD] [INFO] %s was saved \n", moduleName));
//    ZwClose(fileHandle);
//    //ExFreePool(byteBufferBase);
//    ExFreePoolWithTag(byteBufferBase, 0x4A4A4A4A);
//    return STATUS_SUCCESS;
//}

/// <summary>
/// Uses ZwQuerySysInfo to get legit module ranges
/// </summary>
/// <param name="ZwQuerySysInfo">pointer to ZwQuerySystemInformation</param>
/// <param name="outProcMods">pointer to struct with data out</param>
/// <returns>status</returns>
NTSTATUS EnumKernelModuleInfo(_In_ ZwQuerySysInfoPtr ZwQuerySysInfo) {
    ULONG size = NULL;
    outProcMods = NULL;

    // test our pointer
    NTSTATUS status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH == status) {
        KdPrint(("[NOMAD] [INFO] ZwQuerySystemInformation test successed, status: %08x", status));
    }
    else
    {
        KdPrint(("[NOMAD] [ERROR] Unexpected value from ZwQuerySystemInformation, status: %08x", status));
        return status;
    }

    outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
    if (!outProcMods) {
        KdPrint(("[NOMAD] [ERROR] Insufficient memory in the free pool to satisfy the request"));
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, outProcMods, size, 0))) {
        KdPrint(("[NOMAD] [ERROR] ZwQuerySystemInformation failed"));
        ExFreePool(outProcMods);
        return status;
    }

    KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation with SYSTEM_MODULE_INFORMATION.  Modules->NumberOfModules = %lu\n", outProcMods->NumberOfModules));

    for (ULONG i = 0; i < outProcMods->NumberOfModules; i++)
    {
        //KdPrint(("[NOMAD] [TEST] PRINT TEST\n"));
        KdPrint(("[NOMAD] [INFO] Module[%d].FullPathName: %s\n", (int)i, (char*)outProcMods->Modules[i].FullPathName));
        KdPrint(("[NOMAD] [INFO] Module[%d].ImageBase: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageBase));
        KdPrint(("[NOMAD] [INFO] Module[%d].MappedBase: %p\n", (int)i, (char*)outProcMods->Modules[i].MappedBase));
        KdPrint(("[NOMAD] [INFO] Module[%d].LoadCount: %p\n", (int)i, (char*)outProcMods->Modules[i].LoadCount));
        KdPrint(("[NOMAD] [INFO] Module[%d].ImageSize: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageSize));

        //char* fileName = (char*)(outProcMods->Modules[i].FullPathName + outProcMods->Modules[i].OffsetToFileName);
        //KdPrint(("[NOMAD] [INFO] fileName == %s\n", fileName));
        //char* ret = strstr((char*)Modules->Modules[i].FullPathName + outProcMods->Modules[i].OffsetToFileName, ModuleName);

        //if (!ret)
        //    continue;
        //else {
        //    KdPrint(("[NOMAD] [INFO] Found Requested Module %s\n", fileName));
        //    *ModuleInfo = Modules->Modules[i];
        //    break;
    }

    KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation complete\n"));
    //ExFreePool(Modules);
    return STATUS_SUCCESS;
}