#pragma once
#include "Utility.h"
#include "Hook.h"

void Utility::check_driver_dispatch()
{
	HANDLE hDir;
	UNICODE_STRING str;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&str, L"\\Driver");
	InitializeObjectAttributes(&oa, &str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	if (!NT_SUCCESS(ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa))) {
		LogError("Failed to open \\Driver directory object.");
		return;
	}

	PVOID Obj;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(hDir, DIRECTORY_QUERY, nullptr, KernelMode, &Obj, nullptr))) {
		LogError("ObReferenceObjectByHandle failed.");
		return;
	}
	NtClose(hDir);

	auto obj_type = ObGetObjectType(Obj);
	ObDereferenceObject(Obj);
	
	HANDLE h;

	if (!NT_SUCCESS(ObOpenObjectByName(&oa, obj_type, KernelMode, NULL, DIRECTORY_QUERY, nullptr, &h))) {
		LogError("ObOpenObjectByName failed.");
		return;
	}

	auto dir_info = (PDIRECTORY_BASIC_INFORMATION)ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, PAGE_SIZE, POOL_TAG);

	if (!dir_info)
	{
		LogError("checkDispatch() Failed to allocate pool.");
		return;
	}

	ULONG ulContext = 0;

	ULONG returned_bytes;
	bool isClean = true;
	int suspiciousDrivers = 0;
	while (NT_SUCCESS(ZwQueryDirectoryObject(h, dir_info, PAGE_SIZE, TRUE, FALSE, &ulContext, &returned_bytes))) {
		isClean = true;
		PDRIVER_OBJECT pObj;
		wchar_t wsDriverName[100] = L"\\Driver\\";
		wcscat(wsDriverName, dir_info->ObjectName.Buffer);
		UNICODE_STRING ObjName;
		ObjName.Length = ObjName.MaximumLength = wcslen(wsDriverName) * 2;
		ObjName.Buffer = wsDriverName;
		if (NT_SUCCESS(ObReferenceObjectByName(&ObjName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pObj))) {
			LogInfo("Checking driver object: %ls", wsDriverName);
			LogInfo("\t\tChecking ->MajorFunction[IRP_MJ_DEVICE_CONTROL]");
			if (!CheckModulesForAddress(reinterpret_cast<uintptr_t>(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]), outProcMods)) {
				LogInfo("\t\t\t[SUSPICIOUS] %wZ driver has suspicious driver dispatch", pObj->DriverName);
				isClean = false;
			}

			LogInfo("\t\tChecking ->DriverStart");
			if (!CheckModulesForAddress((uintptr_t)pObj->DriverStart, outProcMods)) {
				LogInfo("\t\t\t[SUSPICIOUS] %wZ driver has suspicious DriverStart", pObj->DriverName);
				isClean = false;
			}

			//auto dd = reinterpret_cast<uintptr_t>(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
			//if (dd < (uintptr_t)pObj->DriverStart || dd > (uintptr_t)pObj->DriverStart + pObj->DriverSize) {
			//	LogInfo("[DETECTION] %wZ driver has spoofed driver dispatch (2)", pObj->DriverName);
			//	isClean = false;
			//}
			LogInfo("\t\tChecking ->FastIoDispatch");
			if (reinterpret_cast<uintptr_t>(pObj->FastIoDispatch))
			{
				if (!CheckModulesForAddress(reinterpret_cast<uintptr_t>(pObj->FastIoDispatch->FastIoDeviceControl), outProcMods)) {
					LogInfo("\t\t\t[SUSPICIOUS] %wZ driver has suspicious FastIoDispatch->FastIoDeviceControl", pObj->DriverName);
					isClean = false;
				}
			}
			else
			{
				LogInfo("\t\t\tFastIoDispatch == NULL");
			}

			if (isClean)
			{
				LogInfo("Driver object clean.");
			}
			else
			{
				suspiciousDrivers++;
			}

			ObDereferenceObject(pObj);
		}
	}
	LogInfo("[REPORT] Found %d driver object(s) with suspicious pointer(s)", suspiciousDrivers);

	ZwClose(h);
}