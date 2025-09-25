.code
ALIGN 16

get_rip PROC
	pop rax
	push rax
	ret
get_rip ENDP

somefunc1 PROC
    mov     rax, 666h
    ret
somefunc1 ENDP

selfmodify PROC
    push    rbx               ; Save RBX                                          
postpatch:
    mov     rax, 1234h        ; <-- gets post-patched with 'mov rax, 1'
    mov     rbx, 1234h        ; Load second value into RBX 
    cmp     rax, rbx          ; Compare RAX and RBX
    je      equal_label       ; Jump if equal (ZF = 1)                            
    mov     rax, 0h           ;                                                   
    jmp     end_label         ;                                                   

equal_label:
    mov     rax, 1h           ; rax = 1h                                          
    inc     rax               ; rax = 2h 
    call    somefunc1         ; rax = 666h
    nop
    lea     rsi, prepatch               ; Pre-Exec Patch 
    mov     byte ptr [rsi],   048h      ; 48 C7 C0 03 00 00 00 = 'mov rax, 3'
    mov     byte ptr [rsi+1], 0C7h     
    mov     byte ptr [rsi+2], 0C0h     
    mov     byte ptr [rsi+3], 003h     
    mov     byte ptr [rsi+4], 000h
    mov     byte ptr [rsi+5], 000h
    mov     byte ptr [rsi+6], 000h
    nop
    nop
    inc     rax                       ; rax = 4h
    dec     rax                       ; rax = 3h
    inc     rax                       ; rax = 4h
    dec     rax                       ; rax = 3h
prepatch:
    jmp     end_label                 ; <-- gets pre-patched with: 'mov rax, 3' 
    nop                               ; 2nd run: rax = 0h                       
    nop
    nop
    nop
    nop
    test    rax, rax                  ; always set ZF = 0
    jz      int_leav                  ; Anti-Disassembler trick make a 'jmp,nop,nop' out of a 'mov'
    jnz     int_leav+3                ; Anti-Disassembler trick make a 'jmp,nop,nop' out of a 'mov'      
int_leav:
    db      048h, 0C7h, 0C0h, 0ebh, 00Ch, 090h, 090h        ; eb 09 = jmp by 7bytes ('inc rax' two instr below)
    mov     rbx, 0deadbeefh
    inc	    rax                                             ; jmp addr   rax = 1h
    dec     rax                                             ;            rax = 0h      

end_label:
    push    rsi                         ; Save RSI
    lea     rsi, postpatch              ; Post-Exec Patch   
    mov     byte ptr [rsi],   048h      ; 48 C7 C0 00 00 00 00  mov     rax, 1
    mov     byte ptr [rsi+1], 0C7h     
    mov     byte ptr [rsi+2], 0C0h     
    mov     byte ptr [rsi+3], 001h     
    mov     byte ptr [rsi+4], 000h
    mov     byte ptr [rsi+5], 000h
    mov     byte ptr [rsi+6], 000h

    pop	    rsi              ; Restore RSI
    pop     rbx              ; Restore RBX
    ret
selfmodify ENDP

END

