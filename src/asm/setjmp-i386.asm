;
; The MIT License (MIT)
;
; Copyright © 2016 Franklin "Snaipe" Mathieu <http://snai.pe/>
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
; THE SOFTWARE.
;
.386
.MODEL FLAT, C
.CODE

; The windows CRT defines the jmp_buf on x86 as:
;   uint32_t Ebp;
;   uint32_t Ebx;
;   uint32_t Edi;
;   uint32_t Esi;
;   uint32_t Esp;
;   uint32_t Eip;
;   uint32_t Registration;
;   uint32_t TryLevel;
;   uint32_t Cookie;
;   uint32_t UnwindFunc;
;   uint32_t UnwindData[6];

; We're only setting the first 6 fields.

bxfi_setjmp label far
    mov eax, [esp+4]

    mov [eax], ebp
    mov [eax + 4], ebx
    mov [eax + 8], edi
    mov [eax + 12], esi
    mov [eax + 16], esp
    mov esi, [esp]
    mov [eax + 20], esi

    xor eax, eax
    ret

bxfi_longjmp label far
    mov esi, [esp+4]

    mov eax, [esi + 20] ; EIP
    mov ebx, [esi + 16] ; ESP
    mov [ebx], eax

    mov eax, [esp + 8] ; return value

    mov ebp, [esi]
    mov ebx, [esi + 4]
    mov edi, [esi + 8]
    mov esp, [esi + 16]
    mov esi, [esi + 12]

    ret

public bxfi_setjmp
public bxfi_longjmp

end
