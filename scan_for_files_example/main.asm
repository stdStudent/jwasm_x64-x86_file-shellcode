ifdef _WIN64
CurrentStdcallNotation equ <fastcall>
CurrentCdeclNotation equ <fastcall>
else
CurrentStdcallNotation equ <stdcall>
CurrentCdeclNotation equ <c>
.486
endif


option casemap:none
.model flat, CurrentStdcallNotation

LIST_ENTRY32 struct
    Flink dd ?
    Blink dd ?
LIST_ENTRY32 ends

;LIST_ENTRY64 struct
    ;Flink dd ?
    ;Blink dd ?
;LIST_ENTRY64 ends

ifdef _WIN64
CLIST_ENTRY typedef LIST_ENTRY64
; машинное слово текущей архитектуры
cword typedef qword
cax equ <rax>
cbx equ <rbx>
ccx equ <rcx>
cdx equ <rdx>
csi equ <rsi>
cdi equ <rdi>
csp equ <rsp>
cbp equ <rbp>
OFFSET_PEB equ <60h>
OFFSET_LDR equ <18h>
OFFSET_INIT_LIST equ <30h>
cur_seg_reg equ <gs>
else
CLIST_ENTRY typedef LIST_ENTRY32
; машинное слово текущей архитектуры
cword typedef cword
cax equ <eax>
cbx equ <ebx>
ccx equ <ecx>
cdx equ <edx>
csi equ <esi>
cdi equ <edi>
csp equ <esp>
cbp equ <ebp>
OFFSET_PEB equ <30h>
OFFSET_LDR equ <0Ch>
OFFSET_INIT_LIST equ <1Ch>
cur_seg_reg equ <fs>
endif

include c:\masm32\include\windows.inc
include c:\masm32\include\msvcrt.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\Strings.mac

;function1 proto :DWORD, :DWORD

_ffd struct
    dwFileAttributes dd ?
    ftCreationTime FILETIME <>
    ftLastAccessTime FILETIME <>
    ftLastWriteTime FILETIME <>
    nFileSizeHigh dd ?
    nFileSizeLow dd ?
    dwReserved0 dd ?
    dwReserved1 dd ?
    cFileName db MAX_PATH dup(?)
    cAlternateFileName db 14 dup(?)
    dwFileType dd ?
    dwCreatorType dd ?
    wFinderFlags dw ?
_ffd ends

FileFunc typedef proc ptr

.data
	outputFormat db "%s", 13, 10, 0
	dirPath db 'C:\Users\Labour\Downloads', 0
    exeExt db '\*.exe', 0
    ffd _ffd <>
    hFind dd ?

.data?
 
 
.const


.code
printFileName proc c szFileName:ptr dword
    invoke crt_printf, addr outputFormat, szFileName
    ret
printFileName endp

SearchForFiles proc c uses esi edi ecx eax szDir:ptr dword, fileExtension:ptr dword, func:ptr FileFunc
	local szExt[10]:byte
	
	invoke crt_memset, addr szExt, 0, 10

	; Initialize szExt
    invoke crt_sprintf, addr szExt, fileExtension
    
    ; Append szExt to szDir
    invoke crt_strcat, szDir, addr szExt
    
    ; Call FindFirstFile
    invoke FindFirstFileA, szDir, addr ffd
    mov hFind, eax

    ; Loop through the files
    cmp hFind, INVALID_HANDLE_VALUE
    je out_end

    do_loop:
		;movzx ecx, ffd
        test ffd._ffd.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
        jz not_dir

    not_dir:
		;; func(ffd.cFileName);
		mov edi, func ; Load the function pointer into edi
		lea esi, ffd._ffd.cFileName
		push esi ; Push the argument and call the function
		call edi ; Call func
		add esp, 4 ; Restore the stack
		
        invoke FindNextFileA, hFind, addr ffd
        cmp eax, 0
        jne do_loop

    out_end:
        invoke FindClose, hFind
        ret
SearchForFiles endp

main proc c argc:DWORD, argv:DWORD, envp:DWORD
	local szDir[260]:byte
	local szExt[10]:byte
	
	invoke crt_memset, addr szDir, 0, 260
	invoke crt_memset, addr szExt, 0, 10
	
	 ; Copy the directory path to szDir
    invoke crt_strcpy, addr szDir, addr dirPath
    
     ; Copy the directory path to szDir
    invoke crt_strcpy, addr szExt, addr exeExt


	; Get addres of function
	mov edi, offset printFileName

	; Call SearchForFiles
    invoke SearchForFiles, addr szDir, addr szExt, edi

    ; Exit the program
    invoke ExitProcess, 0
    
    ret
main endp

end
