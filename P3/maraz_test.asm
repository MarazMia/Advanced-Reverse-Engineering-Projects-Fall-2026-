        global main

        section .text

main:
        push    rbp
        mov     rbp, rsp

        xor     eax, eax
        cmp     eax, 1
        je      .equal
        jne     .not_equal

        ; Unreachable fall-through.
        ud2

.not_equal:
        mov     ecx, 3

.loop:
        dec     ecx
        loop    .loop

        call    helper

        test    eax, eax
        js      .negative

        mov     eax, 0
        jmp     .done

.equal:
        mov     eax, 1
        jmp     .done

.negative:
        mov     eax, 2

.done:
        pop     rbp
        ret

helper:
        mov     eax, 0
        ret

        ; Separate executable section.
        section extra exec nowrite align=16

extra_code:
        nop
        ret

        section .data

        dq      extra_code