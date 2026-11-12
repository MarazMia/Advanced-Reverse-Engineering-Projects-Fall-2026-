        global main
        extern puts

        section .text

main:
        push    rbp
        mov     rbp, rsp

        lea     rdi, [rel message]
        call    puts

        xor     eax, eax
        pop     rbp
        ret

        section .rodata

message:
        db      "P3 stripped test", 0