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
.CODE

; The windows CRT defines the jmp_buf on x86_64 as:
;    uint64_t Frame;
;    uint64_t Rbx;
;    uint64_t Rsp;
;    uint64_t Rbp;
;    uint64_t Rsi;
;    uint64_t Rdi;
;    uint64_t R12;
;    uint64_t R13;
;    uint64_t R14;
;    uint64_t R15;
;    uint64_t Rip;
;    uint64_t Spare;
;    uint128_t Xmm6;
;    uint128_t Xmm7;
;    uint128_t Xmm8;
;    uint128_t Xmm9;
;    uint128_t Xmm10;
;    uint128_t Xmm11;
;    uint128_t Xmm12;
;    uint128_t Xmm13;
;    uint128_t Xmm14;
;    uint128_t Xmm15;

bxfi_setjmp label far

    mov [rcx + 8], rbx
    mov [rcx + 16], rsp
    mov [rcx + 24], rbp
    mov [rcx + 32], rsi
    mov [rcx + 40], rdi
    mov [rcx + 48], r12
    mov [rcx + 56], r13
    mov [rcx + 64], r14
    mov [rcx + 72], r15
    pop [rcx + 80]  ; rip
    push [rcx + 80]

    xor rax, rax
    ret

bxfi_longjmp label far

    mov rbx, [rcx + 8]
    mov rsp, [rcx + 16]
    mov rbp, [rcx + 24]
    mov rsi, [rcx + 32]
    mov rdi, [rcx + 40]
    mov r12, [rcx + 48]
    mov r13, [rcx + 56]
    mov r14, [rcx + 64]
    mov r15, [rcx + 72]
    pop rax
    push [rcx + 80]

    mov rax, rdx ; return value
    ret

public bxfi_setjmp
public bxfi_longjmp

end

