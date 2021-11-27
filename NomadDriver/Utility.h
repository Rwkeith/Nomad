#pragma once
#include <ntifs.h>

namespace Utility
{
	NTSTATUS EnumKernelModuleInfo();
	NTSTATUS ImportWinPrimitives();
	NTSTATUS EnumSysThreadInfo();
}
