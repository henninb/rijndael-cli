; rijndael-encrypt.asm  —  AES-256/CBC/PKCS7 encrypt + HMAC-SHA512 sign
; x86_64 Linux, NASM, SysV AMD64 ABI
; Links with: rijndael-alg-fst.o, rijndael-api-fst.o, -lssl -lcrypto -lc

bits 64
default rel

; ── constants ────────────────────────────────────────────────────────────────
%define KEY_SIZE_BITS     256
%define IV_SIZE_BITS      128
%define MAC_SIZE          64
%define DIR_ENCRYPT       0
%define MODE_CBC          2
%define KEY_TEXT_LEN      (KEY_SIZE_BITS / 8 * 2)   ; 64 hex chars
%define KEY_TEXT_SIZE     (KEY_TEXT_LEN + 1)         ; 65 with NUL
%define IV_TEXT_LEN       (IV_SIZE_BITS  / 8 * 2)   ; 32 hex chars
%define IV_TEXT_SIZE      (IV_TEXT_LEN  + 1)         ; 33 with NUL
%define KEYINSTANCE_SIZE  560
%define CIPINSTANCE_SIZE  20   ; sizeof = 17, round up
%define STAT_ST_SIZE_OFF  48   ; offsetof st_size in struct stat (x86-64 Linux)

; ── main stack frame  (rbp-relative locals) ──────────────────────────────────
; After prologue: push rbp + push rbx/r12/r13/r14/r15 (5×8=40) + sub 88
;   entry rsp≡8 → +rbp→0 → +5 regs→8 → sub 88 (≡8 mod 16) → rsp≡0  ✓
%define FRAME   88
%define v_ifname      -8
%define v_ofname      -16
%define v_keyfname    -24
%define v_ivfname     -32
%define v_key_text    -40
%define v_iv_text     -48
%define v_cipherText  -56
%define v_plainText   -64
%define v_ofsize      -68   ; dword
%define v_nfsize      -72   ; dword

; ── read-only data ────────────────────────────────────────────────────────────
section .data
fmt_algo    db "[ nasm | encrypt ] algorithm  : AES-%d/CBC/PKCS7", 10, 0
fmt_sizes   db "[ nasm | encrypt ] input      : %d bytes  ->  padded : %d bytes", 10, 0
fmt_output  db "[ nasm | encrypt ] output     : %s", 10, 0
fmt_sig_ok  db "[ nasm | encrypt ] signature  : written", 10, 0
fmt_usage   db "Usage: %s <ifname> <ofname> <key> <iv>", 10, 0
msg_malloc  db "ABORT: malloc failed.", 10, 0
msg_fopen   db "ABORT: fopen() failed for '%s'.", 10, 0
msg_fwrite  db "ABORT: fwrite() failed for '%s'.", 10, 0
msg_stat    db "ABORT: stat() failed.", 10, 0
msg_cipher  db "ABORT: cipherInit() failed: %d", 10, 0
msg_key     db "ABORT: makeKey() failed: %d", 10, 0
msg_enc     db "ABORT: blockEncrypt() failed: %d", 10, 0
str_rb      db "rb", 0
str_wb      db "wb", 0
str_sig_ext db "%s.sig", 0

; ── zero-initialised storage ──────────────────────────────────────────────────
section .bss
key_inst    resb KEYINSTANCE_SIZE
cip_inst    resb CIPINSTANCE_SIZE
key_bytes   resb 32
mac_buf     resb MAC_SIZE
mac_len     resd 1
sig_fname   resb 512
stat_buf    resb 144   ; struct stat (x86-64 Linux = 144 bytes)

; ── code ──────────────────────────────────────────────────────────────────────
section .text
global main

extern malloc, free, memset
extern printf, fprintf, snprintf
extern fopen, fread, fwrite, fclose
extern stat, exit
extern cipherInit, makeKey, blockEncrypt
extern HMAC, EVP_sha512
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

    mov  r14d, edi          ; argc
    mov  r15, rsi           ; argv

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
    mov  rax, [r15 +  8]  ;  argv[1]
    mov  [rbp + v_ifname],    rax
    mov  rax, [r15 + 16]  ;  argv[2]
    mov  [rbp + v_ofname],    rax
    mov  rax, [r15 + 24]  ;  argv[3]
    mov  [rbp + v_keyfname],  rax
    mov  rax, [r15 + 32]  ;  argv[4]
    mov  [rbp + v_ivfname],   rax

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

    ; ── file sizes ───────────────────────────────────────────────────────────
    mov  rdi, [rbp + v_ifname]
    call file_length            ; eax = ofsize
    mov  [rbp + v_ofsize], eax

    ; nfsize = ofsize + (16 - ofsize % 16)
    mov  eax, [rbp + v_ofsize]
    mov  ecx, 16
    cdq
    idiv ecx                    ; edx = ofsize % 16
    mov  ecx, 16
    sub  ecx, edx               ; 16 - rem  (always 1..16)
    add  eax, ecx               ; nfsize  (note: idiv clobbered eax → but we re-read below)
    ; idiv put quotient in eax; we only need ofsize+pad, so:
    mov  ebx, [rbp + v_ofsize]
    add  ebx, ecx               ; ebx = nfsize
    mov  [rbp + v_nfsize], ebx

    lea  rdi, [rel fmt_sizes]
    mov  esi, [rbp + v_ofsize]
    mov  edx, [rbp + v_nfsize]
    xor  eax, eax
    call printf

    ; ── malloc buffers ───────────────────────────────────────────────────────
    mov  edi, [rbp + v_nfsize]
    call malloc
    test rax, rax
    jz   .abort_malloc
    mov  [rbp + v_cipherText], rax

    mov  edi, [rbp + v_nfsize]
    call malloc
    test rax, rax
    jz   .abort_malloc
    mov  [rbp + v_plainText], rax

    mov  rdi, [rbp + v_plainText]
    xor  esi, esi
    mov  edx, [rbp + v_nfsize]
    call memset

    mov  rdi, [rbp + v_cipherText]
    xor  esi, esi
    mov  edx, [rbp + v_nfsize]
    call memset

    ; ── read plaintext ───────────────────────────────────────────────────────
    mov  rdi, [rbp + v_ifname]
    mov  rsi, [rbp + v_plainText]
    mov  edx, [rbp + v_ofsize]
    call file_read

    ; ── PKCS7 padding ────────────────────────────────────────────────────────
    mov  eax, [rbp + v_nfsize]
    sub  eax, [rbp + v_ofsize]  ; pad_byte = nfsize - ofsize
    movzx r13d, al
    mov  r12, [rbp + v_plainText]
    mov  ecx, [rbp + v_ofsize]
.pad_loop:
    cmp  ecx, [rbp + v_nfsize]
    jge  .pad_done
    mov  [r12 + rcx], r13b
    inc  ecx
    jmp  .pad_loop
.pad_done:

    ; ── cipherInit ───────────────────────────────────────────────────────────
    lea  rdi, [rel cip_inst]
    mov  esi, MODE_CBC
    mov  rdx, [rbp + v_iv_text]
    call cipherInit
    test eax, eax
    js   .abort_cipher

    ; ── makeKey (encrypt) ────────────────────────────────────────────────────
    lea  rdi, [rel key_inst]
    mov  esi, DIR_ENCRYPT
    mov  edx, KEY_SIZE_BITS
    mov  rcx, [rbp + v_key_text]
    call makeKey
    test eax, eax
    js   .abort_key

    ; ── blockEncrypt ─────────────────────────────────────────────────────────
    lea  rdi, [rel cip_inst]
    lea  rsi, [rel key_inst]
    mov  rdx, [rbp + v_plainText]
    mov  eax, [rbp + v_nfsize]
    imul eax, 8
    mov  ecx, eax               ; inputLen in bits
    mov  r8,  [rbp + v_cipherText]
    call blockEncrypt
    cmp  eax, 0
    jle  .abort_enc

    ; ── write ciphertext ─────────────────────────────────────────────────────
    mov  rdi, [rbp + v_ofname]
    mov  rsi, [rbp + v_cipherText]
    mov  edx, [rbp + v_nfsize]
    call file_write

    lea  rdi, [rel fmt_output]
    mov  rsi, [rbp + v_ofname]
    xor  eax, eax
    call printf

    ; ── HMAC-SHA512 ──────────────────────────────────────────────────────────
    mov  rdi, [rbp + v_key_text]
    lea  rsi, [rel key_bytes]
    mov  edx, 32
    call hex_to_bytes

    mov  dword [rel mac_len], MAC_SIZE

    call EVP_sha512
    mov  r12, rax               ; EVP_MD*

    ; HMAC has 7 args; arg7 (&mac_len) goes on stack
    sub  rsp, 16                ; keep 16-byte alignment; use lower 8 bytes
    lea  rax, [rel mac_len]
    mov  [rsp], rax
    mov  rdi, r12
    lea  rsi, [rel key_bytes]
    mov  edx, 32
    mov  rcx, [rbp + v_cipherText]
    mov  r8d, [rbp + v_nfsize]
    lea  r9,  [rel mac_buf]
    xor  eax, eax
    call HMAC
    add  rsp, 16

    ; ── write .sig ───────────────────────────────────────────────────────────
    lea  rdi, [rel sig_fname]
    mov  esi, 512
    lea  rdx, [rel str_sig_ext]
    mov  rcx, [rbp + v_ofname]
    xor  eax, eax
    call snprintf

    lea  rdi, [rel sig_fname]
    lea  rsi, [rel mac_buf]
    mov  edx, MAC_SIZE
    call file_write

    lea  rdi, [rel fmt_sig_ok]
    xor  eax, eax
    call printf

    ; ── zeroize ──────────────────────────────────────────────────────────────
    lea  rdi, [rel key_bytes]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel mac_buf]
    xor  esi, esi
    mov  edx, MAC_SIZE
    call memset
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
    mov  rdi, [rbp + v_key_text];   call free
    call free
    mov  rdi, [rbp + v_iv_text]
    call free
    mov  rdi, [rbp + v_plainText]
    call free
    mov  rdi, [rbp + v_cipherText]
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

.abort_enc:
    mov  r15d, eax
    mov  rdi, [rel stderr]
    lea  rsi, [rel msg_enc]
    mov  edx, r15d
    xor  eax, eax
    call fprintf
    mov  edi, 1
    call exit
    ud2

; ─────────────────────────────────────────────────────────────────────────────
; file_read(path:rdi, buf:rsi, nbytes:edx)
; Reads exactly nbytes bytes from file at path into buf.
; entry rsp≡8 → +rbp→0 → +5 regs (40 bytes)→8 → sub 8 → 0  ✓
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

    mov  r15, rdi       ; path
    mov  rbx, rsi       ; buf
    mov  r12d, edx      ; nbytes

    lea  rsi, [rel str_rb]
    call fopen
    test rax, rax
    jz   .fr_fail
    mov  r14, rax       ; fp

    xor  r13d, r13d     ; fsize = 0
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

    mov  r15, rdi       ; path
    mov  rbx, rsi       ; buf
    mov  r12d, edx      ; nbytes

    lea  rsi, [rel str_wb]
    call fopen
    test rax, rax
    jz   .fw_fail_open
    mov  r14, rax       ; fp

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
; file_length(path:rdi) -> eax = file size (bytes, truncated to 32 bits)
; entry rsp≡8 → +rbp→0 → +rbx→8 → sub 8 → 0  ✓
; ─────────────────────────────────────────────────────────────────────────────
file_length:
    push rbp
    mov  rbp, rsp
    push rbx
    sub  rsp, 8

    mov  rbx, rdi       ; save path (rdi used by stat)
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
; Converts nbytes hex-pairs from hex into binary bytes in out.
; entry rsp≡8 → +rbp→0 → +5 regs (40)→8 → sub 8 → 0  ✓
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

    mov  r12, rdi       ; hex
    mov  r13, rsi       ; out
    mov  r14d, edx      ; nbytes
    xor  r15d, r15d     ; i = 0

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
; nibble_val: ASCII hex char in al → nibble value 0-15 in eax  (leaf)
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
