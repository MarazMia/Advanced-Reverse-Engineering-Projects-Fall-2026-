        global _start
        extern puts

        section startup exec nowrite align=16

_start:
        lea     rdi, [rel message]
        call    puts
        mov     eax, 60
        xor     edi, edi
        syscall

        section .rodata

message:
        db      "Entry section test", 0