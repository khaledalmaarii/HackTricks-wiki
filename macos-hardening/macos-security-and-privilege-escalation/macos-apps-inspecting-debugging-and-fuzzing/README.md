# macOS Apps - Inspeção, Depuração e Fuzzing

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Análise Estática

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
### jtool2

A ferramenta pode ser usada como uma **substituição** para **codesign**, **otool** e **objdump**, e oferece algumas funcionalidades adicionais. [**Baixe-a aqui**](http://www.newosxbook.com/tools/jtool.html) ou instale-a com `brew`.
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
### Codesign / ldid

{% hint style="danger" %}
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e ver o que há dentro antes de instalá-los.\
Esses instaladores possuem scripts bash `preinstall` e `postinstall` que autores de malware geralmente abusam para **persistir** **o** **malware**.

### hdiutil

Esta ferramenta permite **montar** imagens de disco da Apple (**.dmg**) para inspecioná-las antes de executar qualquer coisa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Será montado em `/Volumes`

### Objective-C

#### Metadados

{% hint style="danger" %}
Observe que programas escritos em Objective-C **mantêm** suas declarações de classe **quando** **compilados** em [binários Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tais declarações de classe **incluem** o nome e tipo de:
{% endhint %}

* A classe
* Os métodos da classe
* As variáveis de instância da classe

Você pode obter essas informações usando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Chamada de função

Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará **`objc_msgSend`**. Que estará chamando a função final:

![](<../../../.gitbook/assets/image (560).png>)

Os parâmetros que esta função espera são:

* O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que vai receber a mensagem**". Ou, de forma mais simples, é o objeto sobre o qual o método está sendo invocado. Se o método for um método de classe, isso será uma instância do objeto da classe (como um todo), enquanto que para um método de instância, self apontará para uma instância instanciada da classe como um objeto.
* O segundo parâmetro, (**op**), é "o seletor do método que lida com a mensagem". Novamente, de forma mais simples, isso é apenas o **nome do método.**
* Os parâmetros restantes são quaisquer **valores que são necessários pelo método** (op).

| **Argumento**      | **Registrador**                                                 | **(para) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1º argumento**  | **rdi**                                                         | **self: objeto sobre o qual o método está sendo invocado** |
| **2º argumento**  | **rsi**                                                         | **op: nome do método**                                 |
| **3º argumento**  | **rdx**                                                         | **1º argumento para o método**                         |
| **4º argumento**  | **rcx**                                                         | **2º argumento para o método**                         |
| **5º argumento**  | **r8**                                                          | **3º argumento para o método**                         |
| **6º argumento**  | **r9**                                                          | **4º argumento para o método**                         |
| **7º+ argumento** | <p><strong>rsp+</strong><br><strong>(na pilha)</strong></p>     | **5º+ argumento para o método**                        |

### Swift

Com binários Swift, já que há compatibilidade com Objective-C, às vezes é possível extrair declarações usando [class-dump](https://github.com/nygard/class-dump/), mas nem sempre.

Com as linhas de comando **`jtool -l`** ou **`otool -l`**, é possível encontrar várias seções que começam com o prefixo **`__swift5`**:
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
Você pode encontrar mais informações sobre a [**informação armazenada nestas seções neste post do blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Além disso, **binários Swift podem ter símbolos** (por exemplo, bibliotecas precisam armazenar símbolos para que suas funções possam ser chamadas). Os **símbolos geralmente têm informações sobre o nome da função** e atributos de uma forma não atraente, então eles são muito úteis e existem "**demanglers**" que podem recuperar o nome original:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Binários compactados

* Verifique a alta entropia
* Verifique as strings (se houver quase nenhuma string compreensível, compactada)
* O compactador UPX para MacOS gera uma seção chamada "\_\_XHDR"

## Análise Dinâmica

{% hint style="warning" %}
Observe que, para depurar binários, **SIP precisa ser desativado** (`csrutil disable` ou `csrutil enable --without debug`) ou copiar os binários para uma pasta temporária e **remover a assinatura** com `codesign --remove-signature <caminho-do-binário>` ou permitir a depuração do binário (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Observe que, para **instrumentar binários do sistema**, (como `cloudconfigurationd`) no macOS, **SIP deve ser desativado** (apenas remover a assinatura não funcionará).
{% endhint %}

### Logs Unificados

O MacOS gera muitos logs que podem ser muito úteis ao executar um aplicativo tentando entender **o que ele está fazendo**.

Além disso, existem alguns logs que conterão a tag `<private>` para **ocultar** algumas informações **identificáveis** do **usuário** ou do **computador**. No entanto, é possível **instalar um certificado para divulgar essas informações**. Siga as explicações de [**aqui**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Painel esquerdo

No painel esquerdo do Hopper é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Essas não são todas as strings, mas as definidas em várias partes do arquivo Mac-O (como _cstring ou_ `objc_methname`).

#### Painel do meio

No painel do meio, você pode ver o **código desmontado**. E você pode vê-lo como desmontagem **bruta**, como **gráfico**, como **decompilado** e como **binário** clicando no ícone respectivo:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Clicando com o botão direito em um objeto de código, você pode ver **referências para/de esse objeto** ou até mudar seu nome (isso não funciona no pseudocódigo descompilado):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Além disso, **na parte inferior do meio, você pode escrever comandos em python**.

#### Painel direito

No painel direito, você pode ver informações interessantes, como o **histórico de navegação** (para saber como chegou à situação atual), o **gráfico de chamadas** onde você pode ver todas as **funções que chamam esta função** e todas as funções que **esta função chama**, e informações sobre **variáveis locais**.

### dtrace

Permite aos usuários acesso a aplicativos em um nível **extremamente baixo** e fornece uma maneira de **rastrear** **programas** e até alterar seu fluxo de execução. O dtrace usa **probes** que são **colocados em todo o kernel** e estão em locais como o início e o fim de chamadas de sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar um probe para cada chamada de sistema. Esses probes podem ser ativados no **ponto de entrada e saída de cada chamada de sistema**. A interação com o DTrace ocorre através de /dev/dtrace, que está disponível apenas para o usuário root.

{% hint style="success" %}
Para habilitar o Dtrace sem desativar completamente a proteção SIP, você pode executar no modo de recuperação: `csrutil enable --without dtrace`

Você também pode **`dtrace`** ou **`dtruss`** binários que **você compilou**.
{% endhint %}

Os probes disponíveis do dtrace podem ser obtidos com:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
O nome da sonda consiste em quatro partes: o provedor, o módulo, a função e o nome (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do nome, o Dtrace aplicará essa parte como um curinga.

Para configurar o DTrace para ativar sondas e especificar quais ações realizar quando elas são acionadas, precisaremos usar a linguagem D.

Uma explicação mais detalhada e mais exemplos podem ser encontrados em [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemplos

Execute `man -k dtrace` para listar os **scripts DTrace disponíveis**. Exemplo: `sudo dtruss -n binary`

* Na linha
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
### ktrace

Você pode usar este mesmo com o **SIP ativado**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está executando (por exemplo, monitorar quais novos processos um processo está criando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) é uma ferramenta que imprime as relações entre processos.\
Você precisa monitorar seu mac com um comando como **`sudo eslogger fork exec rename create > cap.json`** (o terminal que lança isso requer FDA). E então você pode carregar o json nesta ferramenta para visualizar todas as relações:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorar eventos de arquivos (como criação, modificações e exclusões), fornecendo informações detalhadas sobre tais eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) é uma ferramenta GUI com uma aparência que usuários do Windows podem reconhecer do _Procmon_ da Microsoft Sysinternal. Ela permite iniciar e parar a gravação de eventos de todos os tipos, filtrá-los por categorias (arquivo, processo, rede, etc) e salvar os eventos gravados como arquivo json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fazem parte das ferramentas de desenvolvedor do Xcode – usadas para monitorar o desempenho de aplicativos, identificar vazamentos de memória e rastrear atividade do sistema de arquivos.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Permite acompanhar ações realizadas por processos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**TaskExplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que está utilizando e as conexões de **rede**.\
Também verifica os processos binários contra o **virustotal** e mostra informações sobre o binário.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Neste [**post do blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), você pode encontrar um exemplo de como **depurar um daemon em execução** que usou **`PT_DENY_ATTACH`** para prevenir a depuração mesmo com o SIP desativado.

### lldb

**lldb** é a ferramenta **de fato** para **depuração** de binários no **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Você pode definir o sabor intel ao usar o lldb criando um arquivo chamado **`.lldbinit`** na sua pasta pessoal com a seguinte linha:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
No lldb, faça um dump de um processo com `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descrição</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Inicia a execução, que continuará ininterrupta até que um ponto de interrupção seja atingido ou o processo termine.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continua a execução do processo em depuração.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Executa a próxima instrução. Este comando irá ignorar chamadas de função.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Executa a próxima instrução. Ao contrário do comando nexti, este comando irá entrar nas chamadas de função.</td></tr><tr><td><strong>finish (f)</strong></td><td>Executa o restante das instruções na função atual ("frame") e retorna e para.</td></tr><tr><td><strong>control + c</strong></td><td>Interrompe a execução. Se o processo foi iniciado (r) ou continuado (c), isso fará com que o processo pare... onde quer que esteja executando atualmente.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Qualquer função chamada main</p><p>b &#x3C;binname>`main #Função principal do bin</p><p>b set -n main --shlib &#x3C;lib_name> #Função principal do bin indicado</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista de pontos de interrupção</p><p>br e/dis &#x3C;num> #Habilitar/Desabilitar ponto de interrupção</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Obter ajuda do comando breakpoint</p><p>help memory write #Obter ajuda para escrever na memória</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;endereço reg/memória></strong></td><td>Exibe a memória como uma string terminada em nulo.</td></tr><tr><td><strong>x/i &#x3C;endereço reg/memória></strong></td><td>Exibe a memória como instrução de montagem.</td></tr><tr><td><strong>x/b &#x3C;endereço reg/memória></strong></td><td>Exibe a memória como byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Isso imprimirá o objeto referenciado pelo parâmetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Note que a maioria das APIs ou métodos Objective-C da Apple retornam objetos, e assim devem ser exibidos através do comando "print object" (po). Se po não produzir uma saída significativa, use <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escrever AAAA nesse endereço<br>memory write -f s $rip+0x11f+7 "AAAA" #Escrever AAAA no endereço</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Desmontar função atual</p><p>dis -n &#x3C;funcname> #Desmontar função</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Desmontar função<br>dis -c 6 #Desmontar 6 linhas<br>dis -c 0x100003764 -e 0x100003768 # De um endereço até o outro<br>dis -p -c 4 #Começar no endereço atual desmontando</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Verificar array de 3 componentes no reg x1</td></tr></tbody></table>

{% hint style="info" %}
Ao chamar a função **`objc_sendMsg`**, o registro **rsi** contém o **nome do método** como uma string terminada em nulo ("C"). Para imprimir o nome via lldb, faça:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Análise Dinâmica

#### Detecção de VM

* O comando **`sysctl hw.model`** retorna "Mac" quando o **host é um MacOS** mas algo diferente quando é uma VM.
* Manipulando os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se é uma VM.
* Alguns malwares também podem **detectar** se a máquina é baseada em **VMware** com base no endereço MAC (00:50:56).
* Também é possível descobrir **se um processo está sendo depurado** com um código simples como:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processo sendo depurado }`
* Também pode invocar a chamada de sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Isso **impede** que um dep**u**rador se anexe e rastreie.
* Você pode verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware pode importá-la dinamicamente)
* Como observado neste artigo, “[Derrotando Técnicas Anti-Depuração: variantes do macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_A mensagem Processo # saiu com **status = 45 (0x0000002d)** é geralmente um sinal claro de que o alvo de depuração está usando **PT\_DENY\_ATTACH**_”

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analisa processos que estão falhando e salva um relatório de falhas no disco**. Um relatório de falhas contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de uma falha.\
Para aplicações e outros processos **executados no contexto de lançamento por usuário**, o ReportCrash funciona como um LaunchAgent e salva relatórios de falhas no `~/Library/Logs/DiagnosticReports/` do usuário\
Para daemons, outros processos **executados no contexto de lançamento do sistema** e outros processos privilegiados, o ReportCrash funciona como um LaunchDaemon e salva relatórios de falhas no `/Library/Logs/DiagnosticReports` do sistema

Se você está preocupado com relatórios de falhas **sendo enviados para a Apple**, você pode desativá-los. Se não, relatórios de falhas podem ser úteis para **descobrir como um servidor falhou**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Suspensão

Ao realizar fuzzing em um MacOS, é importante não permitir que o Mac entre em modo de suspensão:

* systemsetup -setsleep Never
* pmset, Preferências do Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexão SSH

Se você está realizando fuzzing via uma conexão SSH, é importante garantir que a sessão não seja interrompida. Portanto, altere o arquivo sshd_config com:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Manipuladores Internos

**Consulte a seguinte página** para descobrir como você pode encontrar qual aplicativo é responsável por **manipular o esquema ou protocolo especificado:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerando Processos de Rede

Isso é interessante para encontrar processos que estão gerenciando dados de rede:
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona para ferramentas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Ele "**simplesmente funciona**" com ferramentas GUI do macOS. Note que alguns aplicativos do macOS têm requisitos específicos como nomes de arquivos únicos, a extensão correta, precisam ler os arquivos do sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
```markdown
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

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
