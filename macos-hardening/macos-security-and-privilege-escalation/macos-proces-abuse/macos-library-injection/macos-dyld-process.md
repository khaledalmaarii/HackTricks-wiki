# Processo Dyld do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

O verdadeiro **ponto de entrada** de um binário Mach-o é o link dinâmico, definido em `LC_LOAD_DYLINKER`, geralmente é `/usr/lib/dyld`.

Este linker precisará localizar todas as bibliotecas executáveis, mapeá-las na memória e vincular todas as bibliotecas não preguiçosas. Somente após esse processo, o ponto de entrada do binário será executado.

Claro, o **`dyld`** não tem dependências (ele usa chamadas de sistema e trechos de libSystem).

{% hint style="danger" %}
Se este linker contiver alguma vulnerabilidade, como ele está sendo executado antes de executar qualquer binário (mesmo os altamente privilegiados), seria possível **escalar privilégios**.
{% endhint %}

### Fluxo

O Dyld será carregado por **`dyldboostrap::start`**, que também carregará coisas como o **canário de pilha**. Isso ocorre porque esta função receberá em seu argumento **`apple`** este e outros **valores** **sensíveis**.

**`dyls::_main()`** é o ponto de entrada do dyld e sua primeira tarefa é executar `configureProcessRestrictions()`, que geralmente restringe as variáveis de ambiente **`DYLD_*`** explicadas em:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Em seguida, ele mapeia o cache compartilhado do dyld que pré-vincula todas as bibliotecas do sistema importantes e em seguida mapeia as bibliotecas nas quais o binário depende e continua de forma recursiva até que todas as bibliotecas necessárias sejam carregadas. Portanto:

1. começa a carregar bibliotecas inseridas com `DYLD_INSERT_LIBRARIES` (se permitido)
2. Em seguida, as compartilhadas em cache
3. Em seguida, as importadas
4. Em seguida, continua importando bibliotecas de forma recursiva

Uma vez que todas são carregadas, os **inicializadores** dessas bibliotecas são executados. Estes são codificados usando **`__attribute__((constructor))`** definidos no `LC_ROUTINES[_64]` (agora obsoletos) ou por ponteiro em uma seção marcada com `S_MOD_INIT_FUNC_POINTERS` (geralmente: **`__DATA.__MOD_INIT_FUNC`**).

Os terminadores são codificados com **`__attribute__((destructor))`** e estão localizados em uma seção marcada com `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Todos os binários no macOS são vinculados dinamicamente. Portanto, eles contêm algumas seções de stubs que ajudam o binário a pular para o código correto em máquinas e contextos diferentes. É o dyld quando o binário é executado o cérebro que precisa resolver esses endereços (pelo menos os não preguiçosos).

Algumas seções de stubs no binário:

* **`__TEXT.__[auth_]stubs`**: Ponteiros das seções `__DATA`
* **`__TEXT.__stub_helper`**: Pequeno código invocando a vinculação dinâmica com informações sobre a função a ser chamada
* **`__DATA.__[auth_]got`**: Tabela de Deslocamento Global (endereços de funções importadas, quando resolvidos, (vinculados durante o tempo de carregamento, pois é marcado com a flag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Ponteiros de símbolos não preguiçosos (vinculados durante o tempo de carregamento, pois é marcado com a flag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Ponteiros de símbolos preguiçosos (vinculados no primeiro acesso)

{% hint style="warning" %}
Observe que os ponteiros com o prefixo "auth\_" estão usando uma chave de criptografia em processo para protegê-lo (PAC). Além disso, é possível usar a instrução arm64 `BLRA[A/B]` para verificar o ponteiro antes de segui-lo. E o RETA\[A/B\] pode ser usado em vez de um endereço RET.\
Na verdade, o código em **`__TEXT.__auth_stubs`** usará **`braa`** em vez de **`bl`** para chamar a função solicitada para autenticar o ponteiro.

Também observe que as versões atuais do dyld carregam **tudo como não preguiçoso**.
{% endhint %}

### Encontrando símbolos preguiçosos
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Parte de desmontagem interessante:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
É possível ver que o salto para chamar printf está indo para **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Na desmontagem da seção **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Pode-se ver que estamos **saltando para o endereço do GOT**, que neste caso é resolvido de forma não preguiçosa e conterá o endereço da função printf.

Em outras situações, em vez de saltar diretamente para o GOT, poderia-se saltar para **`__DATA.__la_symbol_ptr`**, que carregará um valor que representa a função que está tentando carregar, e então saltar para **`__TEXT.__stub_helper`**, que salta para **`__DATA.__nl_symbol_ptr`**, que contém o endereço de **`dyld_stub_binder`**, que recebe como parâmetros o número da função e um endereço.\
Esta última função, após encontrar o endereço da função procurada, escreve-o na localização correspondente em **`__TEXT.__stub_helper`** para evitar pesquisas no futuro.

{% hint style="success" %}
No entanto, observe que as versões atuais do dyld carregam tudo como não preguiçoso.
{% endhint %}

#### Dyld opcodes

Finalmente, **`dyld_stub_binder`** precisa encontrar a função indicada e escrevê-la no endereço apropriado para não procurá-la novamente. Para fazer isso, ele usa opcodes (uma máquina de estados finitos) dentro do dyld.

## apple\[] argument vector

No macOS, a função principal na verdade recebe 4 argumentos em vez de 3. O quarto é chamado de apple e cada entrada está no formato `chave=valor`. Por exemplo:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
## macOS Dynamic Linker (dyld) Process

### macOS Library Injection

Library injection is a technique used to force a process to load a dynamic library. This can be achieved by manipulating the `DYLD_INSERT_LIBRARIES` environment variable or using tools like `insert_dylib` to inject a library into a process. Once the library is injected, it can intercept function calls, manipulate process behavior, and potentially escalate privileges. This technique is commonly used in malware and rootkit development. 

### macOS Process Abuse

Process abuse involves manipulating processes to achieve malicious goals. This can include injecting code into a process, hijacking process execution flow, or abusing legitimate processes to gain unauthorized access or escalate privileges. Process abuse techniques are often used in privilege escalation attacks and malware development. 

### macOS Library Injection Countermeasures

To defend against library injection attacks, macOS users and administrators can implement the following countermeasures:

- **Monitor Process Activity**: Regularly monitor process activity for suspicious behavior, such as unexpected libraries being loaded.
- **Restrict Library Loading**: Use tools like `csrutil` to restrict the loading of unsigned or unauthorized libraries.
- **Implement Code Signing**: Enforce code signing requirements to ensure that only trusted libraries are loaded into processes.
- **Update Security Patches**: Keep macOS systems up to date with the latest security patches to mitigate known vulnerabilities that could be exploited for library injection.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Quando esses valores chegam à função principal, as informações sensíveis já foram removidas deles ou teria ocorrido um vazamento de dados.
{% endhint %}

é possível ver todos esses valores interessantes depurando antes de entrar na função principal com:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Executable atual definido como '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Esta é uma estrutura exportada pelo dyld com informações sobre o estado do dyld que podem ser encontradas no [**código-fonte**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) com informações como a versão, ponteiro para o array dyld\_image\_info, para dyld\_image\_notifier, se o proc está desanexado do cache compartilhado, se o inicializador do libSystem foi chamado, ponteiro para o próprio cabeçalho Mach do dyld, ponteiro para a string de versão do dyld...

## Variáveis de ambiente dyld

### debug dyld

Variáveis de ambiente interessantes que ajudam a entender o que o dyld está fazendo:

* **DYLD\_PRINT\_LIBRARIES**

Verifica cada biblioteca que é carregada:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Verifique como cada biblioteca é carregada:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Imprime quando cada inicializador de biblioteca está sendo executado:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Outros

* `DYLD_BIND_AT_LAUNCH`: As ligações preguiçosas são resolvidas com as não preguiçosas
* `DYLD_DISABLE_PREFETCH`: Desativar pré-busca de conteúdo \_\_DATA e \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Ligações de um único nível
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Caminhos de resolução
* `DYLD_INSERT_LIBRARIES`: Carregar uma biblioteca específica
* `DYLD_PRINT_TO_FILE`: Escrever debug do dyld em um arquivo
* `DYLD_PRINT_APIS`: Imprimir chamadas de API do libdyld
* `DYLD_PRINT_APIS_APP`: Imprimir chamadas de API do libdyld feitas pelo main
* `DYLD_PRINT_BINDINGS`: Imprimir símbolos quando vinculados
* `DYLD_WEAK_BINDINGS`: Apenas imprimir símbolos fracos quando vinculados
* `DYLD_PRINT_CODE_SIGNATURES`: Imprimir operações de registro de assinatura de código
* `DYLD_PRINT_DOFS`: Imprimir seções de formato de objeto D-Trace carregadas
* `DYLD_PRINT_ENV`: Imprimir env visto pelo dyld
* `DYLD_PRINT_INTERPOSTING`: Imprimir operações de interposição
* `DYLD_PRINT_LIBRARIES`: Imprimir bibliotecas carregadas
* `DYLD_PRINT_OPTS`: Imprimir opções de carregamento
* `DYLD_REBASING`: Imprimir operações de rebase de símbolos
* `DYLD_RPATHS`: Imprimir expansões de @rpath
* `DYLD_PRINT_SEGMENTS`: Imprimir mapeamentos de segmentos Mach-O
* `DYLD_PRINT_STATISTICS`: Imprimir estatísticas de tempo
* `DYLD_PRINT_STATISTICS_DETAILS`: Imprimir estatísticas de tempo detalhadas
* `DYLD_PRINT_WARNINGS`: Imprimir mensagens de aviso
* `DYLD_SHARED_CACHE_DIR`: Caminho a ser usado para o cache de biblioteca compartilhada
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Habilitar closures

É possível encontrar mais com algo como:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ou baixando o projeto dyld de [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) e executando dentro da pasta:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Referências

* [**\*OS Internals, Volume I: User Mode. Por Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
