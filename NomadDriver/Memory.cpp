#pragma once
#include "Utility.h"
#include "Driver.h"


INT Utility::ScanBigPoolsForAddr(_In_ uintptr_t addr)
{
	ULONG len = 4 * 1024 * 1024;
	auto mem = ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, len, POOL_TAG);

	if (!mem)
	{
		LogError("\t\t\tFailed to allocate memory pool in ScanBigPoolsForAddr().");
		return 0;
	}

	if (NT_SUCCESS(pZwQuerySysInfo(SystemBigPoolInformation, mem, len, &len))) {
		auto pBuf = reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(mem);
		for (ULONG i = 0; i < pBuf->Count; i++) {
			if (addr >= pBuf->AllocatedInfo[i].VirtualAddress && addr < pBuf->AllocatedInfo[i].VirtualAddress + pBuf->AllocatedInfo[i].SizeInBytes)
			{
				LogInfo("[DETECTION] Detected a mapped image in an allocated memory pool!  Pool tag:0x%04x\n", pBuf->AllocatedInfo[i].TagUlong);
				ExFreePoolWithTag(mem, POOL_TAG);
				return 1;
			}

			if (pBuf->AllocatedInfo[i].TagUlong == 'enoN' && addr >= pBuf->AllocatedInfo[i].VirtualAddress && addr < pBuf->AllocatedInfo[i].VirtualAddress + pBuf->AllocatedInfo[i].SizeInBytes) {
				if (pBuf->AllocatedInfo[i].SizeInBytes > 0x1000) {
					__try {
						UCHAR zeroedoutpehdr[0x1000]{};
						if (auto pe_hdr = MmMapIoSpace(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, MEMORY_CACHING_TYPE::MmNonCached)) {
							if (memcmp(pe_hdr, zeroedoutpehdr, 0x1000))
							{
								LogInfo("[DETECTION] kdmapper/drvmap manual mapped driver detected (99%% confidence).\n");
								MmUnmapIoSpace(pe_hdr, PAGE_SIZE);
								ExFreePoolWithTag(mem, POOL_TAG);
								return 1;
							}
							else
							{
								LogInfo("[DETECTION] Detected a mapped image!\n");
								MmUnmapIoSpace(pe_hdr, PAGE_SIZE);
								ExFreePoolWithTag(mem, POOL_TAG);
								return 1;
							}
							MmUnmapIoSpace(pe_hdr, PAGE_SIZE);
						}
						else
						{
							LogInfo("[DETECTION] Unable to map physical memory to dump/verify but manual map driver detected anyways with 95%% confidence.\n");
							ExFreePoolWithTag(mem, POOL_TAG);
							return 1;
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						LogError("Access Violation was raised.\n");
						ExFreePoolWithTag(mem, POOL_TAG);
						return 0;
					}
				}
			}
		}
	}
	else
		LogError("Failed to get bigpool.\n");

	ExFreePoolWithTag(mem, POOL_TAG);
	return 0;
}