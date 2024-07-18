# macOS Apps - Inspeção, depuração e Fuzzing

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares stealers**.

O principal objetivo do WhiteIntel é combater a apropriação de contas e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

***

## Análise Estática

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}
```bash
nm -m ./tccd # List of symbols
```
### jtool2 & Disarm

Você pode [**baixar disarm daqui**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Você pode [**baixar o jtool2 aqui**](http://www.newosxbook.com/tools/jtool.html) ou instalá-lo com `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
{% hint style="danger" %}
**jtool está obsoleto em favor do disarm**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`** pode ser encontrado no **macOS** enquanto **`ldid`** pode ser encontrado no **iOS**
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e ver o que está dentro antes de instalá-los.\
Esses instaladores possuem scripts bash `preinstall` e `postinstall` que os autores de malware geralmente abusam para **persistir** o **malware**.

### hdiutil

Esta ferramenta permite **montar** imagens de disco da Apple (**.dmg**) para inspecioná-las antes de executar qualquer coisa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Será montado em `/Volumes`

### Binários compactados

* Verificar alta entropia
* Verificar as strings (se houver quase nenhuma string compreensível, está compactado)
* O empacotador UPX para MacOS gera uma seção chamada "\_\_XHDR"

## Análise Estática de Objective-C

### Metadados

{% hint style="danger" %}
Observe que programas escritos em Objective-C **mantêm** suas declarações de classe **quando** **compilados** em [binários Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tais declarações de classe **incluem** o nome e tipo de:
{% endhint %}

* As interfaces definidas
* Os métodos da interface
* As variáveis de instância da interface
* Os protocolos definidos

Observe que esses nomes podem ser ofuscados para dificultar a reversão do binário.

### Chamada de Função

Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará **`objc_msgSend`**. Que chamará a função final:

![](<../../../.gitbook/assets/image (305).png>)

Os parâmetros que essa função espera são:

* O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que vai receber a mensagem**". Ou de forma mais simples, é o objeto sobre o qual o método está sendo invocado. Se o método for um método de classe, isso será uma instância do objeto da classe (como um todo), enquanto para um método de instância, self apontará para uma instância instanciada da classe como um objeto.
* O segundo parâmetro, (**op**), é "o seletor do método que manipula a mensagem". Novamente, de forma mais simples, este é apenas o **nome do método**.
* Os parâmetros restantes são quaisquer **valores necessários pelo método** (op).

Veja como **obter essas informações facilmente com `lldb` em ARM64** nesta página:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argumento**      | **Registrador**                                                | **(para) objc\_msgSend**                              |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1º argumento**  | **rdi**                                                         | **self: objeto sobre o qual o método está sendo invocado** |
| **2º argumento**  | **rsi**                                                         | **op: nome do método**                               |
| **3º argumento**  | **rdx**                                                         | **1º argumento para o método**                       |
| **4º argumento**  | **rcx**                                                         | **2º argumento para o método**                       |
| **5º argumento**  | **r8**                                                          | **3º argumento para o método**                       |
| **6º argumento**  | **r9**                                                          | **4º argumento para o método**                       |
| **7º+ argumento** | <p><strong>rsp+</strong><br><strong>(na pilha)</strong></p> | **5º+ argumento para o método**                      |

### Despejar metadados ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) é uma ferramenta para class-dump de binários Objective-C. O github especifica dylibs, mas isso também funciona com executáveis.
```bash
./dynadump dump /path/to/bin
```
No momento da escrita, este é **atualmente o que funciona melhor**.

#### Ferramentas regulares
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) é a ferramenta original que gera declarações para as classes, categorias e protocolos em código formatado em ObjetiveC.

É antiga e não é mantida, então provavelmente não funcionará corretamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) é um dump de classe Objective-C moderno e multiplataforma. Comparado às ferramentas existentes, o iCDump pode ser executado independentemente do ecossistema da Apple e expõe ligações em Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Análise estática do Swift

Com binários Swift, como há compatibilidade com Objective-C, às vezes é possível extrair declarações usando [class-dump](https://github.com/nygard/class-dump/), mas nem sempre.

Com os comandos **`jtool -l`** ou **`otool -l`**, é possível encontrar várias seções que começam com o prefixo **`__swift5`**:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Pode encontrar mais informações sobre a **informação armazenada nesta seção neste post do blog**.

Além disso, **os binários Swift podem ter símbolos** (por exemplo, bibliotecas precisam armazenar símbolos para que suas funções possam ser chamadas). Os **símbolos geralmente têm informações sobre o nome da função** e atributos de uma maneira feia, então eles são muito úteis e existem "**demanglers"** que podem obter o nome original:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Análise Dinâmica

{% hint style="warning" %}
Note que, para depurar binários, **o SIP precisa estar desativado** (`csrutil disable` ou `csrutil enable --without debug`) ou copiar os binários para uma pasta temporária e **remover a assinatura** com `codesign --remove-signature <caminho-do-binário>` ou permitir a depuração do binário (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Note que, para **instrumentar binários do sistema** (como `cloudconfigurationd`) no macOS, **o SIP deve estar desativado** (apenas remover a assinatura não funcionará).
{% endhint %}

### APIs

O macOS expõe algumas APIs interessantes que fornecem informações sobre os processos:

* `proc_info`: Esta é a principal API que fornece muitas informações sobre cada processo. Você precisa ser root para obter informações de outros processos, mas não precisa de privilégios especiais ou portas mach.
* `libsysmon.dylib`: Permite obter informações sobre processos por meio de funções expostas via XPC, no entanto, é necessário ter a permissão `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** é uma técnica usada para capturar o estado dos processos, incluindo as pilhas de chamadas de todos os threads em execução. Isso é particularmente útil para depuração, análise de desempenho e compreensão do comportamento do sistema em um ponto específico no tempo. No iOS e macOS, o stackshotting pode ser realizado usando várias ferramentas e métodos como as ferramentas **`sample`** e **`spindump`**.

### Sysdiagnose

Esta ferramenta (`/usr/bini/ysdiagnose`) basicamente coleta muitas informações do seu computador executando dezenas de comandos diferentes, como `ps`, `zprint`...

Deve ser executada como **root** e o daemon `/usr/libexec/sysdiagnosed` possui permissões muito interessantes, como `com.apple.system-task-ports` e `get-task-allow`.

Seu plist está localizado em `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, que declara 3 MachServices:

* `com.apple.sysdiagnose.CacheDelete`: Exclui arquivos antigos em /var/rmp
* `com.apple.sysdiagnose.kernel.ipc`: Porta especial 23 (kernel)
* `com.apple.sysdiagnose.service.xpc`: Interface de modo usuário por meio da classe `Libsysdiagnose` Obj-C. Três argumentos em um dicionário podem ser passados (`compress`, `display`, `run`)

### Logs Unificados

O macOS gera muitos logs que podem ser muito úteis ao executar um aplicativo tentando entender **o que ele está fazendo**.

Além disso, existem alguns logs que conterão a tag `<private>` para **ocultar** algumas informações **identificáveis do usuário** ou do **computador**. No entanto, é possível **instalar um certificado para divulgar essas informações**. Siga as explicações de [**aqui**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Painel esquerdo

No painel esquerdo do hopper, é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Essas não são todas as strings, mas as definidas em várias partes do arquivo Mac-O (como _cstring ou_ `objc_methname`).

#### Painel central

No painel central, você pode ver o **código desmontado**. E você pode vê-lo como um desmonte **bruto**, como **gráfico**, como **decompilado** e como **binário** clicando no ícone respectivo:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Ao clicar com o botão direito em um objeto de código, você pode ver as **referências para/de esse objeto** ou até mesmo alterar seu nome (isso não funciona no pseudocódigo decompilado):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Além disso, na **parte inferior do meio, você pode escrever comandos python**.

#### Painel direito

No painel direito, você pode ver informações interessantes, como o **histórico de navegação** (para saber como você chegou à situação atual), o **grafo de chamadas** onde você pode ver todas as **funções que chamam essa função** e todas as funções que **essa função chama**, e informações sobre **variáveis locais**.

### dtrace

Ele permite que os usuários acessem aplicativos em um nível extremamente **baixo** e fornece uma maneira para os usuários **rastrearem** **programas** e até mesmo alterarem seu fluxo de execução. O Dtrace usa **sondas** que são **colocadas em todo o kernel** e estão em locais como o início e o fim das chamadas de sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar uma sonda para cada chamada de sistema. Essas sondas podem ser disparadas no **ponto de entrada e saída de cada chamada de sistema**. A interação com o DTrace ocorre por meio de /dev/dtrace, que está disponível apenas para o usuário root.

{% hint style="success" %}
Para habilitar o Dtrace sem desativar completamente a proteção do SIP, você pode executar no modo de recuperação: `csrutil enable --without dtrace`

Você também pode **`dtrace`** ou **`dtruss`** binários que **você compilou**.
{% endhint %}

As sondas disponíveis do dtrace podem ser obtidas com:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
O nome da sonda consiste em quatro partes: o provedor, módulo, função e nome (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do nome, o Dtrace aplicará essa parte como um caractere curinga.

Para configurar o DTrace para ativar sondas e especificar quais ações executar quando elas dispararem, precisaremos usar a linguagem D.

Uma explicação mais detalhada e mais exemplos podem ser encontrados em [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemplos

Execute `man -k dtrace` para listar os **scripts DTrace disponíveis**. Exemplo: `sudo dtruss -n binary`

* Em linha
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* script
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

É uma facilidade de rastreamento do kernel. Os códigos documentados podem ser encontrados em **`/usr/share/misc/trace.codes`**.

Ferramentas como `latency`, `sc_usage`, `fs_usage` e `trace` o utilizam internamente.

Para interagir com `kdebug`, `sysctl` é usado sobre o namespace `kern.kdebug` e os MIBs a serem usados podem ser encontrados em `sys/sysctl.h`, tendo as funções implementadas em `bsd/kern/kdebug.c`.

Para interagir com kdebug com um cliente personalizado, geralmente são seguidos os seguintes passos:

- Remover as configurações existentes com KERN\_KDSETREMOVE
- Definir o rastreamento com KERN\_KDSETBUF e KERN\_KDSETUP
- Usar KERN\_KDGETBUF para obter o número de entradas de buffer
- Obter o próprio cliente fora do rastreamento com KERN\_KDPINDEX
- Habilitar o rastreamento com KERN\_KDENABLE
- Ler o buffer chamando KERN\_KDREADTR
- Para associar cada thread ao seu processo, chame KERN\_KDTHRMAP.

Para obter essas informações, é possível usar a ferramenta da Apple **`trace`** ou a ferramenta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Observe que o Kdebug está disponível apenas para 1 cliente por vez.** Portanto, apenas uma ferramenta com suporte a k-debug pode ser executada ao mesmo tempo.

### ktrace

As APIs `ktrace_*` vêm de `libktrace.dylib`, que envolvem as do `Kdebug`. Assim, um cliente pode simplesmente chamar `ktrace_session_create` e `ktrace_events_[single/class]` para definir callbacks em códigos específicos e então iniciá-lo com `ktrace_start`.

Você pode usar este mesmo com **SIP ativado**

Você pode usar como clientes a utilidade `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ou `tailspin`.

### kperf

Isso é usado para fazer um perfil de nível de kernel e é construído usando chamadas `Kdebug`.

Basicamente, a variável global `kernel_debug_active` é verificada e, se estiver definida, chama `kperf_kdebug_handler` com o código `Kdebug` e o endereço do quadro do kernel chamando. Se o código `Kdebug` corresponder a um selecionado, ele obtém as "ações" configuradas como um bitmap (verifique `osfmk/kperf/action.h` para as opções).

Kperf também possui uma tabela MIB sysctl: (como root) `sysctl kperf`. Esses códigos podem ser encontrados em `osfmk/kperf/kperfbsd.c`.

Além disso, um subconjunto da funcionalidade do Kperf reside em `kpc`, que fornece informações sobre contadores de desempenho da máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está realizando (por exemplo, monitorar quais novos processos um processo está criando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) é uma ferramenta que imprime as relações entre processos.\
Você precisa monitorar seu Mac com um comando como **`sudo eslogger fork exec rename create > cap.json`** (o terminal que inicia isso requer FDA). E então você pode carregar o json nesta ferramenta para visualizar todas as relações:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorar eventos de arquivos (como criação, modificações e exclusões) fornecendo informações detalhadas sobre tais eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) é uma ferramenta GUI com a aparência que os usuários do Windows podem conhecer do _Procmon_ da Microsoft Sysinternal. Esta ferramenta permite iniciar e parar a gravação de vários tipos de eventos, permite filtrar esses eventos por categorias como arquivo, processo, rede, etc., e fornece a funcionalidade de salvar os eventos gravados em um formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fazem parte das ferramentas de desenvolvedor do Xcode - usadas para monitorar o desempenho do aplicativo, identificar vazamentos de memória e rastrear a atividade do sistema de arquivos.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Permite seguir as ações realizadas pelos processos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que ele está usando e as **conexões de rede**.\
Também verifica os processos binários no **virustotal** e mostra informações sobre o binário.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Neste [**post do blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) você pode encontrar um exemplo de como **depurar um daemon em execução** que usou **`PT_DENY_ATTACH`** para evitar a depuração, mesmo que o SIP estivesse desativado.

### lldb

**lldb** é a ferramenta de **fato** para **depuração** de binários **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Você pode definir o sabor intel ao usar o lldb criando um arquivo chamado **`.lldbinit`** em sua pasta pessoal com a seguinte linha:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Dentro do lldb, faça dump de um processo com `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descrição</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Iniciar a execução, que continuará sem parar até atingir um ponto de interrupção ou o processo terminar.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continuar a execução do processo em depuração.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Executar a próxima instrução. Este comando irá pular chamadas de função.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Executar a próxima instrução. Ao contrário do comando nexti, este comando irá entrar nas chamadas de função.</td></tr><tr><td><strong>finish (f)</strong></td><td>Executar o restante das instruções na função atual ("frame") e parar.</td></tr><tr><td><strong>control + c</strong></td><td>Pausar a execução. Se o processo foi executado (r) ou continuado (c), isso fará com que o processo pare ... onde quer que esteja executando no momento.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Qualquer função chamada main</p><p>b &#x3C;nome_do_bin>`main #Função principal do binário</p><p>b set -n main --shlib &#x3C;nome_da_biblioteca> #Função principal do binário indicado</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista de pontos de interrupção</p><p>br e/dis &#x3C;número> #Ativar/Desativar ponto de interrupção</p><p>breakpoint delete &#x3C;número></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Obter ajuda do comando de ponto de interrupção</p><p>help memory write #Obter ajuda para escrever na memória</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">formato</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C>endereço_do_registrador/memória</strong></td><td>Exibir a memória como uma string terminada por nulo.</td></tr><tr><td><strong>x/i &#x3C>endereço_do_registrador/memória</strong></td><td>Exibir a memória como instrução de montagem.</td></tr><tr><td><strong>x/b &#x3C>endereço_do_registrador/memória</strong></td><td>Exibir a memória como byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Isto irá imprimir o objeto referenciado pelo parâmetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Observe que a maioria das APIs ou métodos Objective-C da Apple retornam objetos e, portanto, devem ser exibidos através do comando "print object" (po). Se po não produzir uma saída significativa, use <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escrever AAAA nesse endereço<br>memory write -f s $rip+0x11f+7 "AAAA" #Escrever AAAA no endereço</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Desmontar a função atual</p><p>dis -n &#x3C;nome_da_função> #Desmontar função</p><p>dis -n &#x3C;nome_da_função> -b &#x3C;nome_base> #Desmontar função<br>dis -c 6 #Desmontar 6 linhas<br>dis -c 0x100003764 -e 0x100003768 # De um endereço até o outro<br>dis -p -c 4 # Iniciar no endereço atual desmontando</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Verificar array de 3 componentes no registro x1</td></tr></tbody></table>

{% hint style="info" %}
Ao chamar a função **`objc_sendMsg`**, o registro **rsi** contém o **nome do método** como uma string terminada por nulo ("C"). Para imprimir o nome via lldb faça:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Análise Anti-Dinâmica

#### Detecção de VM

* O comando **`sysctl hw.model`** retorna "Mac" quando o **host é um MacOS**, mas algo diferente quando é uma VM.
* Manipulando os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se é uma VM.
* Alguns malwares também podem **detectar** se a máquina é baseada no **VMware** com base no endereço MAC (00:50:56).
* Também é possível descobrir se um processo está sendo depurado com um código simples como:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processo sendo depurado }`
* Também pode-se invocar a chamada de sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Isso **impede** um deb**u**gger de anexar e rastrear.
* Pode-se verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware poderia importá-la dinamicamente)
* Conforme observado neste artigo, “[Derrotando Técnicas Anti-Depuração: variantes de ptrace no macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_A mensagem Processo # saiu com **status = 45 (0x0000002d)** geralmente é um sinal revelador de que o alvo de depuração está usando **PT\_DENY\_ATTACH**_”
## Despejos de Núcleo

Os despejos de núcleo são criados se:

- `kern.coredump` sysctl estiver definido como 1 (por padrão)
- Se o processo não era suid/sgid ou `kern.sugid_coredump` for 1 (por padrão é 0)
- O limite `AS_CORE` permite a operação. É possível suprimir a criação de despejos de código chamando `ulimit -c 0` e reativá-los com `ulimit -c unlimited`.

Nesses casos, os despejos de núcleo são gerados de acordo com `kern.corefile` sysctl e geralmente armazenados em `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

O ReportCrash **analisa processos que estão travando e salva um relatório de travamento no disco**. Um relatório de travamento contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de um travamento.\
Para aplicativos e outros processos **em execução no contexto de lançamento por usuário**, o ReportCrash é executado como um LaunchAgent e salva relatórios de travamento em `~/Library/Logs/DiagnosticReports/` do usuário.\
Para daemons, outros processos **em execução no contexto de lançamento do sistema** e outros processos privilegiados, o ReportCrash é executado como um LaunchDaemon e salva relatórios de travamento em `/Library/Logs/DiagnosticReports` do sistema.

Se você está preocupado com os relatórios de travamento **sendo enviados para a Apple**, você pode desativá-los. Caso contrário, os relatórios de travamento podem ser úteis para **descobrir como um servidor travou**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sono

Durante o fuzzing em um MacOS, é importante não permitir que o Mac entre em modo de sono:

* systemsetup -setsleep Nunca
* pmset, Preferências do Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexão SSH

Se estiver fazendo fuzzing via uma conexão SSH, é importante garantir que a sessão não seja encerrada. Portanto, altere o arquivo sshd\_config com:

* TCPKeepAlive Sim
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Manipuladores Internos

**Confira a seguinte página** para descobrir como você pode encontrar qual aplicativo é responsável por **manipular o esquema ou protocolo especificado:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerando Processos de Rede
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Ou use `netstat` ou `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona para ferramentas de linha de comando

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Ele "**simplesmente funciona"** com ferramentas GUI do macOS. Note que alguns aplicativos do macOS têm requisitos específicos como nomes de arquivos únicos, a extensão correta, precisam ler os arquivos do sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Alguns exemplos:

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Mais Informações sobre Fuzzing no MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referências

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo de informações**.

O principal objetivo do WhiteIntel é combater tomadas de contas e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Aprenda e pratique Hacking em AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking em GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
