;EXTERNDEF C mysize:DWORD
;EXTERNDEF C size:DWORD

_DATA SEGMENT
call_number DQ 0
my_size DD 0
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
		mov     eax, 036h
		syscall
		ret
SyscallNtQuerySystemInformation endp

NtQueryWrapper proc
       PUSH       RBP
       SUB        RSP , 060h
       LEA        RBP ,[RSP + 020h]
       LEA        R9 ,[ my_size ]
       XOR        R8D ,R8D
       XOR        EDX ,EDX
       MOV        ECX ,0bh
       CALL       SyscallNtQuerySystemInformation
       LEA        RSP ,[RBP + 040h]
       POP        RBP
       RET
NtQueryWrapper endp

NtShutdownSystem proc
        ;mov     r10,rcx
		mov     rdi, 1
        mov     eax, 01B4h
		syscall
		ret
NtShutdownSystem endp

NtShutdownWrapper proc
       PUSH       RBP
       SUB        RSP , 060h
       LEA        RBP ,[RSP + 020h]
       LEA        R9 ,[ my_size ]
       XOR        R8D ,R8D
       XOR        EDX ,EDX
       MOV        ECX ,0bh
       CALL       SyscallNtQuerySystemInformation
       LEA        RSP ,[RBP + 040h]
       POP        RBP
       RET
NtShutdownWrapper endp

end 