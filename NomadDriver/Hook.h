#pragma once
// https://doxygen.reactos.org/d8/d5b/struct__DIRECTORY__BASIC__INFORMATION.html

// https://community.osr.com/discussion/166794/obreferenceobjectbyname-0xc00000024-windows-7
extern "C" POBJECT_TYPE * IoDriverObjectType;

typedef struct  _DIRECTORY_BASIC_INFORMATION {
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, * PDIRECTORY_BASIC_INFORMATION;