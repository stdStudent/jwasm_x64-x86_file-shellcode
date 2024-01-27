ifdef _WIN64
CurrentStdcallNotation equ <fastcall>
CurrentCdeclNotation equ <fastcall>
else
CurrentStdcallNotation equ <stdcall>
CurrentCdeclNotation equ <c>
.486
endif

include c:\masm32\include\kernel32.inc
include c:\masm32\include\windows.inc
include c:\masm32\include\msvcrt.inc

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
cword typedef dword
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


PeHeaders struct

    filename 	cword      ?   ;имя файла

    fd          HANDLE  ?   ;хендл открытого файла
    mapd        HANDLE  ?   ;хендл файловой проекции
    mem	        cword   ?   ;указатель на память спроецированного файла
    filesize    cword   ?   ;размер спроецированной части файла

    doshead     cword   ?   ;указатель на DOS заголовок
    nthead      cword   ?   ;указатель на NT заголовок

    impdir      cword   ?   ;указатель на массив дескрипторов таблицы импорта
    sizeImpdir  DWORD   ?   ;размер таблицы импорта
    countImpdes DWORD   ?   ;количество элементов в таблице импорта

    expdir      cword   ?   ;указатель на таблицу экспорта
    sizeExpdir  DWORD   ?   ;размер таблицы экспорта

    sections    cword   ?   ;указатель на таблицу секций (на первый элемент)
    countSec    DWORD   ?   ;количество секций

PeHeaders ends