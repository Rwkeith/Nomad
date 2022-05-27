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

	auto dirInfo = (PDIRECTORY_BASIC_INFORMATION)ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, PAGE_SIZE, POOL_TAG);

	if (!dirInfo)
	{
		LogError("checkDispatch() Failed to allocate pool.");
		return;
	}

	ULONG ulContext = 0;

	ULONG returnedBytes;
	bool isClean = true;
	int suspiciousDrivers = 0;
	while (NT_SUCCESS(ZwQueryDirectoryObject(h, dirInfo, PAGE_SIZE, TRUE, FALSE, &ulContext, &returnedBytes)))
	{
		isClean = true;
		PDRIVER_OBJECT pObj;
		wchar_t wsDriverName[100] = L"\\Driver\\";
		wcscat(wsDriverName, dirInfo->ObjectName.Buffer);
		UNICODE_STRING objName;
		objName.Length = objName.MaximumLength = wcslen(wsDriverName) * 2;
		objName.Buffer = wsDriverName;
		if (NT_SUCCESS(ObReferenceObjectByName(&objName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pObj)))
		{
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