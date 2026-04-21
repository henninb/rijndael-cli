; rijndael-decrypt.asm  —  AES-256/CBC/PKCS7 decrypt + HMAC-SHA512 verify
; x86_64 Linux, NASM, SysV AMD64 ABI
; Links with: rijndael-alg-fst.o, rijndael-api-fst.o, -lssl -lcrypto -lc

bits 64
default rel

; ── constants ────────────────────────────────────────────────────────────────
%define KEY_SIZE_BITS     256
%define IV_SIZE_BITS      128
%define MAC_SIZE          64
%define DIR_DECRYPT       1
%define MODE_CBC          2
%define KEY_TEXT_LEN      (KEY_SIZE_BITS / 8 * 2)
%define KEY_TEXT_SIZE     (KEY_TEXT_LEN + 1)
%define IV_TEXT_LEN       (IV_SIZE_BITS  / 8 * 2)
%define IV_TEXT_SIZE      (IV_TEXT_LEN  + 1)
%define KEYINSTANCE_SIZE  560
%define CIPINSTANCE_SIZE  20
%define STAT_ST_SIZE_OFF  48

; ── main stack frame ─────────────────────────────────────────────────────────
%define FRAME   88
%define v_ifname      -8
%define v_ofname      -16
%define v_keyfname    -24
%define v_ivfname     -32
%define v_key_text    -40
%define v_iv_text     -48
%define v_cipherText  -56
%define v_plainText   -64
%define v_fsize       -68   ; dword  (original ciphertext size)

; ── read-only data ────────────────────────────────────────────────────────────
section .data
fmt_algo    db "[ nasm | decrypt ] algorithm  : AES-%d/CBC/PKCS7", 10, 0
fmt_input   db "[ nasm | decrypt ] input      : %d bytes", 10, 0
fmt_mac_ok  db "[ nasm | decrypt ] MAC        : verified OK", 10, 0
fmt_output  db "[ nasm | decrypt ] output     : %s", 10, 0
fmt_usage   db "Usage: %s <ifname> <ofname> <key> <iv>", 10, 0
msg_malloc  db "ABORT: malloc failed.", 10, 0
msg_fopen   db "ABORT: fopen() failed for '%s'.", 10, 0
msg_fwrite  db "ABORT: fwrite() failed for '%s'.", 10, 0
msg_stat    db "ABORT: stat() failed.", 10, 0
msg_cipher  db "ABORT: cipherInit() failed: %d", 10, 0
msg_key     db "ABORT: makeKey() failed: %d", 10, 0
msg_dec     db "ABORT: blockDecrypt() failed: %d", 10, 0
msg_mac     db "ABORT: MAC verification failed", 10, 0
msg_pkcs7   db "ABORT: invalid PKCS7 padding", 10, 0
str_rb      db "rb", 0
str_wb      db "wb", 0
str_sig_ext db "%s.sig", 0

; ── zero-initialised storage ──────────────────────────────────────────────────
section .bss
key_inst        resb KEYINSTANCE_SIZE
cip_inst        resb CIPINSTANCE_SIZE
key_bytes       resb 32
stored_mac      resb MAC_SIZE
computed_mac    resb MAC_SIZE
mac_len         resd 1
sig_fname       resb 512
stat_buf        resb 144

; ── code ──────────────────────────────────────────────────────────────────────
section .text
global main

extern malloc, free, memset
extern printf, fprintf, snprintf
extern fopen, fread, fwrite, fclose
extern stat, exit
extern cipherInit, makeKey, blockDecrypt
extern HMAC, EVP_sha512, CRYPTO_memcmp
extern stderr

; ─────────────────────────────────────────────────────────────────────────────
main:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, FRAME

    mov  r14d, edi
    mov  r15, rsi

    cmp  r14d, 5
    je   .args_ok
    mov  rdi, [rel stderr]
    lea  rsi, [rel fmt_usage]
    mov  rdx, [r15]
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

.args_ok:
    mov  rax, [r15 +  8]
    mov  [rbp + v_ifname],   rax
    mov  rax, [r15 + 16]
    mov  [rbp + v_ofname],   rax
    mov  rax, [r15 + 24]
    mov  [rbp + v_keyfname], rax
    mov  rax, [r15 + 32]
    mov  [rbp + v_ivfname],  rax

    lea  rdi, [rel fmt_algo]
    mov  esi, KEY_SIZE_BITS
    xor  eax, eax
    call printf

    ; ── malloc + read key_text ───────────────────────────────────────────────
    mov  edi, KEY_TEXT_SIZE
    call malloc
    test rax, rax
    jz   .abort_malloc
    mov  [rbp + v_key_text], rax
    mov  rdi, rax
    xor  esi, esi
    mov  edx, KEY_TEXT_SIZE
    call memset
    mov  rdi, [rbp + v_keyfname]
    mov  rsi, [rbp + v_key_text]
    mov  edx, KEY_TEXT_LEN
    call file_read

    ; ── malloc + read iv_text ────────────────────────────────────────────────
    mov  edi, IV_TEXT_SIZE
    call malloc
    test rax, rax
    jz   .abort_malloc
    mov  [rbp + v_iv_text], rax
    mov  rdi, rax
    xor  esi, esi
    mov  edx, IV_TEXT_SIZE
    call memset
    mov  rdi, [rbp + v_ivfname]
    mov  rsi, [rbp + v_iv_text]
    mov  edx, IV_TEXT_LEN
    call file_read

    ; ── cipherInit (must happen before blockDecrypt) ─────────────────────────
    lea  rdi, [rel cip_inst]
    mov  esi, MODE_CBC
    mov  rdx, [rbp + v_iv_text]
    call cipherInit
    test eax, eax
    js   .abort_cipher

    ; ── read ciphertext ──────────────────────────────────────────────────────
    mov  rdi, [rbp + v_ifname]
    call file_length
    mov  [rbp + v_fsize], eax

    lea  rdi, [rel fmt_input]
    mov  esi, [rbp + v_fsize]
    xor  eax, eax
    call printf

    mov  edi, [rbp + v_fsize]
    add  edi, 1
    call malloc
    test rax, rax
    jz   .abort_malloc
    mov  [rbp + v_cipherText], rax

    mov  edi, [rbp + v_fsize]
    add  edi, 1
    call malloc
    test rax, rax
    jz   .abort_malloc
    mov  [rbp + v_plainText], rax

    mov  rdi, [rbp + v_cipherText]
    xor  esi, esi
    mov  edx, [rbp + v_fsize]
    inc  edx
    call memset

    mov  rdi, [rbp + v_plainText]
    xor  esi, esi
    mov  edx, [rbp + v_fsize]
    inc  edx
    call memset

    mov  rdi, [rbp + v_ifname]
    mov  rsi, [rbp + v_cipherText]
    mov  edx, [rbp + v_fsize]
    call file_read

    ; ── HMAC-SHA512 verify ───────────────────────────────────────────────────
    mov  rdi, [rbp + v_key_text]
    lea  rsi, [rel key_bytes]
    mov  edx, 32
    call hex_to_bytes

    ; format sig filename
    lea  rdi, [rel sig_fname]
    mov  esi, 512
    lea  rdx, [rel str_sig_ext]
    mov  rcx, [rbp + v_ifname]
    xor  eax, eax
    call snprintf

    ; read stored MAC
    lea  rdi, [rel sig_fname]
    lea  rsi, [rel stored_mac]
    mov  edx, MAC_SIZE
    call file_read

    ; compute MAC
    mov  dword [rel mac_len], MAC_SIZE

    call EVP_sha512
    mov  r12, rax           ; EVP_MD*

    sub  rsp, 16
    lea  rax, [rel mac_len]
    mov  [rsp], rax         ; arg7
    mov  rdi, r12
    lea  rsi, [rel key_bytes]
    mov  edx, 32
    mov  rcx, [rbp + v_cipherText]
    mov  r8d, [rbp + v_fsize]
    lea  r9,  [rel computed_mac]
    xor  eax, eax
    call HMAC
    add  rsp, 16

    ; compare MACs
    lea  rdi, [rel stored_mac]
    lea  rsi, [rel computed_mac]
    mov  edx, MAC_SIZE
    call CRYPTO_memcmp
    test eax, eax
    jnz  .abort_mac

    ; zeroize key material after MAC check
    lea  rdi, [rel key_bytes]
    xor  esi, esi
    mov  edx, 32
    call memset

    lea  rdi, [rel fmt_mac_ok]
    xor  eax, eax
    call printf

    ; ── makeKey (decrypt) ────────────────────────────────────────────────────
    lea  rdi, [rel key_inst]
    mov  esi, DIR_DECRYPT
    mov  edx, KEY_SIZE_BITS
    mov  rcx, [rbp + v_key_text]
    call makeKey
    test eax, eax
    js   .abort_key

    ; ── blockDecrypt ─────────────────────────────────────────────────────────
    lea  rdi, [rel cip_inst]
    lea  rsi, [rel key_inst]
    mov  rdx, [rbp + v_cipherText]
    mov  eax, [rbp + v_fsize]
    imul eax, 8
    mov  ecx, eax
    mov  r8,  [rbp + v_plainText]
    call blockDecrypt
    cmp  eax, 0
    jle  .abort_dec

    ; ── PKCS7 un-pad ─────────────────────────────────────────────────────────
    ; pad_byte = plainText[fsize - 1]
    mov  r12, [rbp + v_plainText]
    mov  ecx, [rbp + v_fsize]
    movzx ebx, byte [r12 + rcx - 1]   ; pad_byte → ebx

    ; idx_i = fsize; count back while plainText[idx_i-1] == pad_byte
    mov  ecx, [rbp + v_fsize]          ; idx_i = fsize
.unpad_loop:
    test ecx, ecx
    jz   .unpad_done
    movzx eax, byte [r12 + rcx - 1]
    cmp  eax, ebx
    jne  .unpad_done
    dec  ecx
    jmp  .unpad_loop
.unpad_done:
    ; verify: (fsize - idx_i) == pad_byte
    mov  eax, [rbp + v_fsize]
    sub  eax, ecx
    cmp  eax, ebx
    jne  .abort_pkcs7

    ; write plaintext[0..idx_i-1]
    mov  rdi, [rbp + v_ofname]
    mov  rsi, r12
    mov  edx, ecx
    call file_write

    lea  rdi, [rel fmt_output]
    mov  rsi, [rbp + v_ofname]
    xor  eax, eax
    call printf

    ; ── zeroize ──────────────────────────────────────────────────────────────
    mov  rdi, [rbp + v_key_text]
    xor  esi, esi
    mov  edx, KEY_TEXT_SIZE
    call memset
    mov  rdi, [rbp + v_iv_text]
    xor  esi, esi
    mov  edx, IV_TEXT_SIZE
    call memset
    lea  rdi, [rel key_inst]
    xor  esi, esi
    mov  edx, KEYINSTANCE_SIZE
    call memset
    lea  rdi, [rel cip_inst]
    xor  esi, esi
    mov  edx, CIPINSTANCE_SIZE
    call memset

    ; ── free ─────────────────────────────────────────────────────────────────
    mov  rdi, [rbp + v_key_text]
    call free
    mov  rdi, [rbp + v_iv_text]
    call free
    mov  rdi, [rbp + v_cipherText]
    call free
    mov  rdi, [rbp + v_plainText]
    call free

    xor  eax, eax
    add  rsp, FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

.abort_malloc:
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_malloc]
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

.abort_cipher:
    mov  r15d, eax
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_cipher]
    mov  edx, r15d
    xor  eax, eax
    call fprintf
    mov  edi, r15d
    neg  edi
    call exit
    ud2

.abort_key:
    mov  r15d, eax
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_key]
    mov  edx, r15d
    xor  eax, eax
    call fprintf
    mov  edi, r15d
    neg  edi
    call exit
    ud2

.abort_dec:
    mov  r15d, eax
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_dec]
    mov  edx, r15d
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

.abort_mac:
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_mac]
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

.abort_pkcs7:
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_pkcs7]
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

; ─────────────────────────────────────────────────────────────────────────────
; file_read(path:rdi, buf:rsi, nbytes:edx)
; ─────────────────────────────────────────────────────────────────────────────
file_read:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8

    mov  r15, rdi
    mov  rbx, rsi
    mov  r12d, edx

    lea  rsi, [rel str_rb]
    call fopen
    test rax, rax
    jz   .fr_fail
    mov  r14, rax

    xor  r13d, r13d
.fr_loop:
    cmp  r13d, r12d
    jge  .fr_done
    lea  rdi, [rbx + r13]
    mov  esi, 1
    mov  edx, r12d
    sub  edx, r13d
    mov  rcx, r14
    call fread
    test rax, rax
    jle  .fr_done
    add  r13d, eax
    jmp  .fr_loop
.fr_done:
    mov  rdi, r14
    call fclose
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.fr_fail:
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_fopen]
    mov  rdx, r15
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

; ─────────────────────────────────────────────────────────────────────────────
; file_write(path:rdi, buf:rsi, nbytes:edx)
; ─────────────────────────────────────────────────────────────────────────────
file_write:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8

    mov  r15, rdi
    mov  rbx, rsi
    mov  r12d, edx

    lea  rsi, [rel str_wb]
    call fopen
    test rax, rax
    jz   .fw_fail_open
    mov  r14, rax

    mov  rdi, rbx
    mov  esi, 1
    mov  edx, r12d
    mov  rcx, r14
    call fwrite
    cmp  rax, r12
    jne  .fw_fail_write

    mov  rdi, r14
    call fclose
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.fw_fail_open:
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_fopen]
    mov  rdx, r15
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2
.fw_fail_write:
    mov  rdi, r14
    call fclose
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_fwrite]
    mov  rdx, r15
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

; ─────────────────────────────────────────────────────────────────────────────
; file_length(path:rdi) -> eax = file size (bytes)
; ─────────────────────────────────────────────────────────────────────────────
file_length:
    push rbp
    mov  rbp, rsp
    push rbx
    sub  rsp, 8

    mov  rbx, rdi
    lea  rsi, [rel stat_buf]
    call stat
    test eax, eax
    jnz  .fl_fail

    mov  eax, dword [rel stat_buf + STAT_ST_SIZE_OFF]
    add  rsp, 8
    pop  rbx
    pop  rbp
    ret
.fl_fail:
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_stat]
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

; ─────────────────────────────────────────────────────────────────────────────
; hex_to_bytes(hex:rdi, out:rsi, nbytes:edx)
; ─────────────────────────────────────────────────────────────────────────────
hex_to_bytes:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8

    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    xor  r15d, r15d

.hb_loop:
    cmp  r15d, r14d
    jge  .hb_done
    movzx eax, byte [r12 + r15*2]
    call  nibble_val
    shl   eax, 4
    mov   ebx, eax
    movzx eax, byte [r12 + r15*2 + 1]
    call  nibble_val
    or    ebx, eax
    mov   [r13 + r15], bl
    inc   r15d
    jmp   .hb_loop
.hb_done:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ─────────────────────────────────────────────────────────────────────────────
; nibble_val: ASCII hex char in al → 0-15 in eax  (leaf)
; ─────────────────────────────────────────────────────────────────────────────
nibble_val:
    movzx eax, al
    cmp   al, '0'
    jl    .nv_bad
    cmp   al, '9'
    jle   .nv_digit
    cmp   al, 'A'
    jl    .nv_lower_check
    cmp   al, 'F'
    jle   .nv_upper
.nv_lower_check:
    cmp   al, 'a'
    jl    .nv_bad
    cmp   al, 'f'
    jg    .nv_bad
    sub   eax, 'a' - 10
    ret
.nv_upper:
    sub   eax, 'A' - 10
    ret
.nv_digit:
    sub   eax, '0'
    ret
.nv_bad:
    xor   eax, eax
    ret
