# macOS Apps - Inspeção, depuração e Fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

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
{% endcode %}

### jtool2

A ferramenta pode ser usada como um **substituto** para **codesign**, **otool** e **objdump**, e oferece algumas funcionalidades adicionais. [**Baixe-a aqui**](http://www.newosxbook.com/tools/jtool.html).
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
```
### Codesign

O comando `codesign` é uma ferramenta de linha de comando no macOS que permite assinar digitalmente aplicativos e bibliotecas para garantir sua autenticidade e integridade. A assinatura digital é um mecanismo de segurança que verifica se o código não foi alterado ou adulterado desde que foi assinado.

A assinatura digital é especialmente importante para aplicativos distribuídos fora da Mac App Store, pois fornece uma maneira de verificar se o aplicativo não foi modificado por terceiros mal-intencionados. Além disso, a assinatura digital é necessária para recursos como a capacidade de acessar certos recursos protegidos do sistema operacional e para permitir que o aplicativo seja executado em sistemas macOS com Gatekeeper habilitado.

O comando `codesign` pode ser usado para inspecionar, adicionar ou remover assinaturas digitais de aplicativos e bibliotecas. Ele também pode ser usado para verificar a validade de uma assinatura digital existente.

A assinatura digital é baseada em certificados de identidade, que são emitidos por uma autoridade de certificação confiável. Ao assinar um aplicativo ou biblioteca, um certificado de identidade é usado para criar uma assinatura digital que é anexada ao código. Quando o aplicativo ou biblioteca é executado, o sistema operacional verifica a assinatura digital usando o certificado de identidade correspondente para garantir que o código não tenha sido alterado.

O comando `codesign` também pode ser usado para verificar se um aplicativo ou biblioteca foi assinado por um desenvolvedor confiável. Isso pode ser útil para verificar a autenticidade de um aplicativo antes de instalá-lo ou executá-lo em seu sistema.

Em resumo, o comando `codesign` é uma ferramenta essencial para garantir a segurança e a integridade de aplicativos e bibliotecas no macOS, permitindo a verificação da autenticidade e a detecção de qualquer modificação não autorizada.
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
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e ver o que está dentro antes de instalá-los.\
Esses instaladores possuem scripts bash `preinstall` e `postinstall` que os autores de malware geralmente abusam para **persistir** o **malware**.

### hdiutil

Essa ferramenta permite **montar** imagens de disco Apple (**.dmg**) para inspecioná-las antes de executar qualquer coisa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Será montado em `/Volumes`

### Objective-C

#### Metadados

{% hint style="danger" %}
Observe que programas escritos em Objective-C **mantêm** suas declarações de classe **quando** **compilados** em [binários Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tais declarações de classe **incluem** o nome e o tipo de:
{% endhint %}

* A classe
* Os métodos da classe
* As variáveis de instância da classe

Você pode obter essas informações usando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Chamada de função

Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará **`objc_msgSend`**. Que irá chamar a função final:

![](<../../../.gitbook/assets/image (560).png>)

Os parâmetros que essa função espera são:

* O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que receberá a mensagem**". Ou de forma mais simples, é o objeto no qual o método está sendo invocado. Se o método for um método de classe, isso será uma instância do objeto da classe (como um todo), enquanto que para um método de instância, self apontará para uma instância instanciada da classe como um objeto.
* O segundo parâmetro (**op**) é "o seletor do método que manipula a mensagem". Novamente, de forma mais simples, este é apenas o **nome do método**.
* Os parâmetros restantes são quaisquer **valores necessários pelo método** (op).

| **Argumento**      | **Registrador**                                                 | **(para) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1º argumento**  | **rdi**                                                         | **self: objeto no qual o método está sendo invocado**  |
| **2º argumento**  | **rsi**                                                         | **op: nome do método**                                 |
| **3º argumento**  | **rdx**                                                         | **1º argumento para o método**                         |
| **4º argumento**  | **rcx**                                                         | **2º argumento para o método**                         |
| **5º argumento**  | **r8**                                                          | **3º argumento para o método**                         |
| **6º argumento**  | **r9**                                                          | **4º argumento para o método**                         |
| **7º+ argumento** | <p><strong>rsp+</strong><br><strong>(na pilha)</strong></p> | **5º+ argumento para o método**                        |

### Swift

Com binários Swift, como há compatibilidade com Objective-C, às vezes é possível extrair declarações usando [class-dump](https://github.com/nygard/class-dump/), mas nem sempre.

Com os comandos de linha **`jtool -l`** ou **`otool -l`**, é possível encontrar várias seções que começam com o prefixo **`__swift5`**:
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
Você pode encontrar mais informações sobre as seções de informações armazenadas neste [**post do blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

### Binários compactados

* Verifique a entropia alta
* Verifique as strings (se houver quase nenhuma string compreensível, está compactado)
* O empacotador UPX para MacOS gera uma seção chamada "\_\_XHDR"

## Análise Dinâmica

{% hint style="warning" %}
Observe que, para depurar binários, o **SIP precisa estar desativado** (`csrutil disable` ou `csrutil enable --without debug`) ou copiar os binários para uma pasta temporária e **remover a assinatura** com `codesign --remove-signature <caminho-do-binário>` ou permitir a depuração do binário (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Observe que, para **instrumentar binários do sistema**, (como `cloudconfigurationd`) no macOS, o **SIP deve estar desativado** (apenas remover a assinatura não funcionará).
{% endhint %}

### Logs Unificados

O MacOS gera muitos logs que podem ser muito úteis ao executar um aplicativo para entender **o que ele está fazendo**.

Além disso, existem alguns logs que conterão a tag `<private>` para **ocultar** algumas informações **identificáveis do usuário** ou do **computador**. No entanto, é possível **instalar um certificado para divulgar essas informações**. Siga as explicações [**aqui**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Painel esquerdo

No painel esquerdo do Hopper, é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Essas não são todas as strings, mas as definidas em várias partes do arquivo Mac-O (como _cstring ou_ `objc_methname`).

#### Painel central

No painel central, você pode ver o **código desmontado**. E você pode vê-lo como um desmonte **bruto**, como **gráfico**, como **descompilado** e como **binário** clicando no ícone respectivo:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Ao clicar com o botão direito em um objeto de código, você pode ver **referências para/deste objeto** ou até mesmo alterar seu nome (isso não funciona no pseudocódigo descompilado):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Além disso, no **meio inferior, você pode escrever comandos python**.

#### Painel direito

No painel direito, você pode ver informações interessantes, como o **histórico de navegação** (para saber como você chegou à situação atual), o **gráfico de chamadas** onde você pode ver todas as **funções que chamam essa função** e todas as funções que **essa função chama**, e informações sobre **variáveis locais**.

### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Você pode usar este mesmo com o **SIP ativado**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### dtrace

Ele permite que os usuários acessem aplicativos em um nível extremamente **baixo** e fornece uma maneira para os usuários **rastrearem** **programas** e até mesmo alterarem seu fluxo de execução. O Dtrace usa **sondas** que são **colocadas em todo o kernel** e estão em locais como o início e o fim das chamadas do sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar uma sonda para cada chamada do sistema. Essas sondas podem ser disparadas no **ponto de entrada e saída de cada chamada do sistema**. A interação com o DTrace ocorre através do /dev/dtrace, que está disponível apenas para o usuário root.

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
O nome da sonda consiste em quatro partes: o provedor, módulo, função e nome (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do nome, o Dtrace a considerará como um caractere curinga.

Para configurar o DTrace para ativar sondas e especificar quais ações executar quando elas são acionadas, precisaremos usar a linguagem D.

Uma explicação mais detalhada e mais exemplos podem ser encontrados em [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemplos

Execute `man -k dtrace` para listar os **scripts do DTrace disponíveis**. Exemplo: `sudo dtruss -n binary`

* Na linha
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
# Inspeção, Depuração e Fuzzing de Aplicativos no macOS

Neste guia, exploraremos técnicas para inspecionar, depurar e realizar fuzzing em aplicativos no macOS. Essas técnicas são úteis para identificar vulnerabilidades e realizar escalonamento de privilégios.

## Inspeção de Aplicativos

A inspeção de aplicativos envolve examinar o código e a estrutura interna de um aplicativo para identificar possíveis vulnerabilidades. Existem várias ferramentas disponíveis para ajudar nesse processo, como:

- **Hopper**: uma ferramenta de desmontagem que permite visualizar o código de um aplicativo.
- **class-dump**: uma ferramenta que extrai informações sobre as classes e métodos de um aplicativo.
- **otool**: uma ferramenta que exibe informações sobre os binários de um aplicativo.

Essas ferramentas podem ser usadas para analisar um aplicativo em busca de vulnerabilidades conhecidas ou para entender melhor seu funcionamento interno.

## Depuração de Aplicativos

A depuração de aplicativos envolve a execução de um aplicativo em um ambiente controlado para identificar e corrigir erros. No macOS, podemos usar o **lldb** (Low-Level Debugger) para depurar aplicativos. O lldb permite definir pontos de interrupção, examinar o estado do aplicativo durante a execução e executar comandos para investigar problemas.

## Fuzzing de Aplicativos

O fuzzing é uma técnica usada para encontrar vulnerabilidades em aplicativos por meio da inserção de dados aleatórios ou inválidos. No macOS, podemos usar a ferramenta **AFL** (American Fuzzy Lop) para realizar fuzzing em aplicativos. O AFL gera entradas aleatórias e monitora o comportamento do aplicativo em busca de falhas, como travamentos ou vazamentos de memória.

## Conclusão

A inspeção, depuração e fuzzing de aplicativos no macOS são técnicas valiosas para identificar vulnerabilidades e realizar escalonamento de privilégios. Ao usar as ferramentas e técnicas mencionadas neste guia, você poderá analisar aplicativos de forma mais eficaz e descobrir possíveis falhas de segurança.
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
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está executando (por exemplo, monitorar quais novos processos um processo está criando).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorar eventos de arquivos (como criação, modificações e exclusões), fornecendo informações detalhadas sobre esses eventos.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fazem parte das ferramentas de desenvolvedor do Xcode - usadas para monitorar o desempenho do aplicativo, identificar vazamentos de memória e rastrear a atividade do sistema de arquivos.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Permite acompanhar as ações executadas pelos processos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que ele está usando e as **conexões de rede**.\
Ele também verifica os processos binários no **virustotal** e mostra informações sobre o binário.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Neste [**post do blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), você pode encontrar um exemplo de como **depurar um daemon em execução** que usa **`PT_DENY_ATTACH`** para evitar a depuração, mesmo que o SIP esteja desativado.

### lldb

**lldb** é a ferramenta de **fato** para **depuração** de binários no **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
{% hint style="warning" %}
Dentro do lldb, faça o dump de um processo com `process save-core`
{% endhint %}

| **Comando (lldb)**            | **Descrição**                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **run (r)**                   | Inicia a execução, que continuará até que um ponto de interrupção seja atingido ou o processo seja encerrado.                                                                                                                                                                                                                                                                                                            |
| **continue (c)**              | Continua a execução do processo em depuração.                                                                                                                                                                                                                                                                                                                                                                            |
| **nexti (n / ni)**            | Executa a próxima instrução. Este comando irá pular chamadas de função.                                                                                                                                                                                                                                                                                                                                                  |
| **stepi (s / si)**            | Executa a próxima instrução. Ao contrário do comando nexti, este comando irá entrar nas chamadas de função.                                                                                                                                                                                                                                                                                                              |
| **finish (f)**                | Executa o restante das instruções na função atual ("frame") e retorna.                                                                                                                                                                                                                                                                                                                                                   |
| **control + c**               | Pausa a execução. Se o processo foi iniciado (r) ou continuado (c), isso fará com que o processo pare ... onde quer que esteja executando no momento.                                                                                                                                                                                                                                                                     |
| **breakpoint (b)**            | <p>b main</p><p>b -[NSDictionary objectForKey:]</p><p>b 0x0000000100004bd9</p><p>br l #Lista de pontos de interrupção</p><p>br e/dis &#x3C;num> #Habilitar/Desabilitar ponto de interrupção</p><p>breakpoint delete &#x3C;num><br>b set -n main --shlib &#x3C;lib_name></p>                                                                                                                                                                               |
| **help**                      | <p>help breakpoint #Obter ajuda sobre o comando breakpoint</p><p>help memory write #Obter ajuda para escrever na memória</p>                                                                                                                                                                                                                                                                                            |
| **reg**                       | <p>reg read</p><p>reg read $rax</p><p>reg write $rip 0x100035cc0</p>                                                                                                                                                                                                                                                                                                                                                      |
| **x/s \<reg/endereço de memória>** | Exibe a memória como uma string terminada em nulo.                                                                                                                                                                                                                                                                                                                                                                        |
| **x/i \<reg/endereço de memória>** | Exibe a memória como instrução de montagem.                                                                                                                                                                                                                                                                                                                                                                              |
| **x/b \<reg/endereço de memória>** | Exibe a memória como byte.                                                                                                                                                                                                                                                                                                                                                                                               |
| **print object (po)**         | <p>Isso irá imprimir o objeto referenciado pelo parâmetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Observe que a maioria das APIs ou métodos Objective-C da Apple retornam objetos e, portanto, devem ser exibidos por meio do comando "print object" (po). Se po não produzir uma saída significativa, use <code>x/b</code></p> |
| **memory**                    | <p>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escreve AAAA nesse endereço<br>memory write -f s $rip+0x11f+7 "AAAA" #Escreve AAAA no endereço</p>                                                                                                                                                                                                                            |
| **disassembly**               | <p>dis #Desmonta a função atual<br>dis -c 6 #Desmonta 6 linhas<br>dis -c 0x100003764 -e 0x100003768 #De um endereço até o outro<br>dis -p -c 4 #Inicia no endereço atual desmontando</p>                                                                                                                                                                                                                                 |
| **parray**                    | parray 3 (char \*\*)$x1 #Verifica o array de 3 componentes no registro x1                                                                                                                                                                                                                                                                                                                                                |

{% hint style="info" %}
Ao chamar a função **`objc_sendMsg`**, o registro **rsi** contém o **nome do método** como uma string terminada em nulo ("C"). Para imprimir o nome via lldb, faça:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Análise Dinâmica

#### Detecção de VM

* O comando **`sysctl hw.model`** retorna "Mac" quando o **host é um MacOS**, mas algo diferente quando é uma VM.
* Brincando com os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se é uma VM.
* Alguns malwares também podem **detectar** se a máquina é baseada no VMware pelo endereço MAC (00:50:56).
* Também é possível descobrir se um processo está sendo depurado com um código simples como:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processo sendo depurado }`
* Também pode invocar a chamada de sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Isso **impede** um depurador de anexar e rastrear.
* Você pode verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware pode importá-la dinamicamente)
* Como observado neste artigo, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_A mensagem Processo # saiu com **status = 45 (0x0000002d)** é geralmente um sinal revelador de que o alvo de depuração está usando **PT\_DENY\_ATTACH**_”

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analisa processos que estão travando e salva um relatório de travamento no disco**. Um relatório de travamento contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de um travamento.\
Para aplicativos e outros processos **executados no contexto do launchd por usuário**, o ReportCrash é executado como um LaunchAgent e salva os relatórios de travamento em `~/Library/Logs/DiagnosticReports/` do usuário.\
Para daemons, outros processos **executados no contexto do launchd do sistema** e outros processos privilegiados, o ReportCrash é executado como um LaunchDaemon e salva os relatórios de travamento em `/Library/Logs/DiagnosticReports` do sistema.

Se você está preocupado com os relatórios de travamento **sendo enviados para a Apple**, você pode desativá-los. Caso contrário, os relatórios de travamento podem ser úteis para **descobrir como um servidor travou**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sleep

Durante a realização de fuzzing em um MacOS, é importante não permitir que o Mac entre em modo de repouso:

* systemsetup -setsleep Never
* pmset, Preferências do Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexão SSH

Se você estiver realizando fuzzing por meio de uma conexão SSH, é importante garantir que a sessão não seja encerrada. Portanto, altere o arquivo sshd\_config com:

* TCPKeepAlive Yes
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

Funciona para ferramentas de linha de comando.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Ele "**simplesmente funciona"** com ferramentas de GUI do macOS. Observe que alguns aplicativos do macOS têm requisitos específicos, como nomes de arquivos exclusivos, a extensão correta e a necessidade de ler os arquivos do sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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

### Mais informações sobre Fuzzing no MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referências

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
