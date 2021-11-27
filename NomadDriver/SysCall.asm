_DATA SEGMENT
call_number DQ 0
_DATA ENDS

.code

SyscallNtClose proc
		mov r10, rcx
		mov eax, dword ptr[call_number]
		syscall
		ret
SyscallNtClose endp


SyscallTerminateProc proc
		mov r10, rcx
		mov eax, dword ptr[call_number]
		syscall
		ret
SyscallTerminateProc endp


SetCallNumber proc
        mov [call_number], rcx
        ret
SetCallNumber endp

SyscallNtQuerySystemInformation proc
		mov     r10,rcx
		mov     eax,36h
		syscall
		ret
SyscallNtQuerySystemInformation endp

end 