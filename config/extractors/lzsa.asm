;
; Compile: 
; nasm -f win64/elf64 -o lzsa.o lzsa.asm
; gcc -shared -o lzsa.so lzsa.o
;

global lzsa2_decompress

bits 64
section .text

lzsa2_decompress:
_lzsa2_decompress:
    ; mov    rdi, [esp+32+4]      
    ; mov    rsi, [esp+32+8]      
    
    xor    rcx, rcx
    xor    rbx, rbx             
    inc    bh
    xor    rbp, rbp

.decode_token:
    mul    rcx
    lodsb                       
    mov    dl, al               
   
    and    al, 018H             
    shr    al, 3                

    cmp    al, 03H              
    jne    .got_literals        

    call   .get_nibble          
    add    al, cl               
    cmp    al, 012H             
    jne    .got_literals        

    lodsb                       
    add    al,012H              
    jnc    .got_literals        

    lodsw                       

.got_literals:
    xchg   rcx, rax
    rep    movsb                

    test   dl, 0C0h             
    js     .rep_match_or_large_offset

    xchg   rcx, rax             
    jne    .offset_9_bit

                                
    cmp    dl, 020H             
    call   .get_nibble_x
    jmp    .dec_offset_top

.offset_9_bit:                  
    lodsb                       
    dec    ah                   
    test   dl, 020H             
    je     .get_match_length
.dec_offset_top:
    dec    ah                   
                                
    jmp    .get_match_length

.rep_match_or_large_offset:
    jpe    .rep_match_or_16_bit

                                

    cmp    dl, 0A0H             
    xchg   ah, al
    call   .get_nibble_x
    sub    al, 2                
    jmp    .get_match_length_1

.rep_match_or_16_bit:
    test   dl, 020H             
    jne    .repeat_match        

                                
    lodsb                       

.get_match_length_1:
    xchg   ah, al
    lodsb                       

.get_match_length:
    xchg   rbp, rax             
.repeat_match:
    xchg   rax, rdx             
    and    al, 07H              
    add    al, 2                

    cmp    al, 09H              
    jne    .got_matchlen        

    call   .get_nibble          
    add    al, cl               
    cmp    al, 018H             
    jne    .got_matchlen        

    lodsb                       
    add    al,018H              
    jnc    .got_matchlen        
    je     .done_decompressing  

    lodsw                       

.got_matchlen:
    xchg   rcx, rax             
    xchg   rsi, rax          
    movsx  rbp, bp              
    lea    rsi,[rbp+rdi]        
    rep    movsb                
    xchg   rsi, rax             
    jmp    .decode_token        

.done_decompressing:
    sub    rdi, [esp+32+4]
    mov    [esp+28], rdi
    ret                         

.get_nibble_x:
    cmc                         
    rcr    al, 1
    call   .get_nibble          
    or     al, cl               
    rol    al, 1
    xor    al, 0E1H             
    ret

.get_nibble:
    neg    bh                   
    jns    .has_nibble
   
    xchg   rbx, rax
    lodsb                       
    xchg   rbx, rax

.has_nibble:
    mov    cl, 4                
    ror    bl, cl
    mov    cl, 0FH
    and    cl, bl
    ret