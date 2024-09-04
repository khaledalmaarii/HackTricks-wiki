# AppArmor

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

## Basic Information

AppArmor는 **프로그램별 프로필을 통해 프로그램에 제공되는 리소스를 제한하도록 설계된 커널 향상 기능**으로, 사용자 대신 프로그램에 직접 액세스 제어 속성을 연결하여 강제 액세스 제어(MAC)를 효과적으로 구현합니다. 이 시스템은 **부팅 중에 프로필을 커널에 로드**하여 작동하며, 이러한 프로필은 프로그램이 접근할 수 있는 리소스(예: 네트워크 연결, 원시 소켓 접근 및 파일 권한)를 규정합니다.

AppArmor 프로필에는 두 가지 운영 모드가 있습니다:

* **강제 모드**: 이 모드는 프로필 내에서 정의된 정책을 적극적으로 시행하며, 이러한 정책을 위반하는 행동을 차단하고 syslog 또는 auditd와 같은 시스템을 통해 위반 시도를 기록합니다.
* **불만 모드**: 강제 모드와 달리 불만 모드는 프로필의 정책에 반하는 행동을 차단하지 않습니다. 대신, 이러한 시도를 정책 위반으로 기록하지만 제한을 시행하지 않습니다.

### Components of AppArmor

* **커널 모듈**: 정책 시행을 담당합니다.
* **정책**: 프로그램 동작 및 리소스 접근에 대한 규칙과 제한을 지정합니다.
* **파서**: 정책을 커널에 로드하여 시행 또는 보고합니다.
* **유틸리티**: AppArmor와 상호작용하고 관리하기 위한 인터페이스를 제공하는 사용자 모드 프로그램입니다.

### Profiles path

Apparmor 프로필은 일반적으로 _**/etc/apparmor.d/**_에 저장됩니다.\
`sudo aa-status`를 사용하면 일부 프로필에 의해 제한된 바이너리를 나열할 수 있습니다. 나열된 각 바이너리의 경로에서 문자 "/"를 점으로 변경하면 언급된 폴더 내의 apparmor 프로필 이름을 얻을 수 있습니다.

예를 들어, _/usr/bin/man_에 대한 **apparmor** 프로필은 _/etc/apparmor.d/usr.bin.man_에 위치합니다.

### Commands
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## 프로파일 생성

* 영향을 받는 실행 파일을 나타내기 위해 **절대 경로와 와일드카드**가 파일을 지정하는 데 허용됩니다.
* 바이너리가 **파일**에 대해 가질 접근을 나타내기 위해 다음 **접근 제어**를 사용할 수 있습니다:
* **r** (읽기)
* **w** (쓰기)
* **m** (실행 가능한 메모리 맵)
* **k** (파일 잠금)
* **l** (하드 링크 생성)
* **ix** (새 프로그램이 정책을 상속받아 다른 프로그램을 실행)
* **Px** (환경을 정리한 후 다른 프로파일 아래에서 실행)
* **Cx** (환경을 정리한 후 자식 프로파일 아래에서 실행)
* **Ux** (환경을 정리한 후 제한 없이 실행)
* **변수**는 프로파일에서 정의할 수 있으며 프로파일 외부에서 조작할 수 있습니다. 예: @{PROC} 및 @{HOME} (프로파일 파일에 #include \<tunables/global> 추가)
* **허용 규칙을 무시하기 위해 거부 규칙이 지원됩니다**.

### aa-genprof

프로파일 생성을 쉽게 시작하기 위해 apparmor가 도움을 줄 수 있습니다. **apparmor가 바이너리에 의해 수행된 작업을 검사하고 어떤 작업을 허용하거나 거부할지 결정할 수 있게 해줍니다**.\
단순히 다음을 실행하면 됩니다:
```bash
sudo aa-genprof /path/to/binary
```
그런 다음, 다른 콘솔에서 바이너리가 일반적으로 수행할 모든 작업을 수행합니다:
```bash
/path/to/binary -a dosomething
```
그런 다음 첫 번째 콘솔에서 "**s**"를 누르고 기록된 작업에서 무시할지, 허용할지 또는 다른 작업을 선택합니다. 완료되면 "**f**"를 눌러 새 프로필이 _/etc/apparmor.d/path.to.binary_에 생성됩니다.

{% hint style="info" %}
화살표 키를 사용하여 허용/거부/기타 작업을 선택할 수 있습니다.
{% endhint %}

### aa-easyprof

이진 파일의 apparmor 프로필 템플릿을 다음과 같이 생성할 수 있습니다:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
기본적으로 생성된 프로필에서는 아무것도 허용되지 않으므로 모든 것이 거부됩니다. 예를 들어, 이진 파일이 `/etc/passwd`를 읽을 수 있도록 `/etc/passwd r,`와 같은 줄을 추가해야 합니다.
{% endhint %}

그런 다음 **강제 적용**할 수 있습니다.
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### 로그에서 프로필 수정하기

다음 도구는 로그를 읽고 사용자가 감지된 금지된 행동 중 일부를 허용할 것인지 물어봅니다:
```bash
sudo aa-logprof
```
{% hint style="info" %}
화살표 키를 사용하여 허용/거부/기타 원하는 항목을 선택할 수 있습니다.
{% endhint %}

### 프로필 관리
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

예시 **AUDIT** 및 **DENIED** 로그는 실행 파일 **`service_bin`**의 _/var/log/audit/audit.log_에서 가져온 것입니다:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
이 정보를 다음을 사용하여 얻을 수도 있습니다:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

docker의 프로필 **docker-profile**이 기본적으로 로드되는 방식을 주목하세요:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
기본적으로 **Apparmor docker-default 프로필**은 [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)에서 생성됩니다.

**docker-default 프로필 요약**:

* 모든 **네트워킹**에 대한 **접근**
* **능력**이 정의되어 있지 않음 (그러나 일부 능력은 기본 기본 규칙을 포함하여 올 수 있음, 즉 #include \<abstractions/base>)
* **/proc** 파일에 대한 **쓰기**는 **허용되지 않음**
* 다른 **하위 디렉토리**/**파일**인 /**proc** 및 /**sys**에 대한 읽기/쓰기/잠금/링크/실행 접근이 **거부됨**
* **마운트**는 **허용되지 않음**
* **Ptrace**는 **같은 apparmor 프로필**로 제한된 프로세스에서만 실행할 수 있음

**docker 컨테이너를 실행하면** 다음 출력을 볼 수 있어야 합니다:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Note that **apparmor는 기본적으로 컨테이너에 부여된 capabilities privileges도 차단합니다**. 예를 들어, **SYS\_ADMIN capability가 부여되더라도 /proc 내부에 쓰기 권한을 차단할 수 있습니다**. 기본적으로 docker apparmor 프로필이 이 접근을 거부하기 때문입니다:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
You need to **disable apparmor** to bypass its restrictions:  
당신은 그 제한을 우회하기 위해 **apparmor를 비활성화**해야 합니다:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
기본적으로 **AppArmor**는 **SYS\_ADMIN** 권한이 있어도 컨테이너가 내부에서 폴더를 마운트하는 것을 **금지**합니다.

컨테이너에 **capabilities**를 **추가/제거**할 수 있지만(여전히 **AppArmor** 및 **Seccomp**와 같은 보호 방법에 의해 제한됩니다):

* `--cap-add=SYS_ADMIN` `SYS_ADMIN` 권한 부여
* `--cap-add=ALL` 모든 권한 부여
* `--cap-drop=ALL --cap-add=SYS_PTRACE` 모든 권한 제거 및 `SYS_PTRACE`만 부여

{% hint style="info" %}
보통, **docker** 컨테이너 **내부**에서 **특권 권한**이 **있음을 발견**했지만 **익스플로잇의 일부가 작동하지 않는** 경우, 이는 docker **apparmor가 이를 방지하고 있기 때문**입니다.
{% endhint %}

### 예시

(예시는 [**여기**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)에서 가져옴)

AppArmor 기능을 설명하기 위해, 다음 줄을 추가하여 새로운 Docker 프로필 “mydocker”를 생성했습니다:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
프로필을 활성화하려면 다음을 수행해야 합니다:
```
sudo apparmor_parser -r -W mydocker
```
프로필을 나열하려면 다음 명령을 실행할 수 있습니다. 아래 명령은 내 새로운 AppArmor 프로필을 나열하고 있습니다.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
아래와 같이, AppArmor 프로파일이 “/etc”에 대한 쓰기 접근을 방지하고 있기 때문에 “/etc/”를 변경하려고 할 때 오류가 발생합니다.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

어떤 **apparmor 프로파일이 컨테이너를 실행하고 있는지** 확인하려면:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
그런 다음, 다음 명령어를 실행하여 **사용 중인 정확한 프로필을 찾을 수 있습니다**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In the weird case you can **modify the apparmor docker profile and reload it.** 당신은 제한을 제거하고 "우회"할 수 있습니다.

### AppArmor Docker Bypass2

**AppArmor는 경로 기반**입니다. 이는 **`/proc`**와 같은 디렉토리 내의 파일을 **보호**하고 있을지라도, **컨테이너가 어떻게 실행될지를 구성할 수 있다면**, 호스트의 proc 디렉토리를 **`/host/proc`**에 **마운트**할 수 있으며, 그러면 **더 이상 AppArmor에 의해 보호되지 않습니다**.

### AppArmor Shebang Bypass

[**이 버그**](https://bugs.launchpad.net/apparmor/+bug/1911431)에서는 **특정 리소스와 함께 perl의 실행을 방지하고 있더라도**, 첫 번째 줄에 **`#!/usr/bin/perl`**을 지정한 셸 스크립트를 생성하고 **파일을 직접 실행하면**, 원하는 것을 실행할 수 있는 방법의 예를 볼 수 있습니다. 예:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
