# AppArmor

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, **무료** 기능을 제공하여 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인할 수 있습니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료로** 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

## 기본 정보

AppArmor는 **프로그램별 프로필을 통해 프로그램에 제공되는 리소스를 제한하는 것을 목적으로 하는 커널 개선**으로, 사용자가 아닌 프로그램에 직접 액세스 제어 속성을 묶어 강제 액세스 제어(MAC)를 효과적으로 구현합니다. 이 시스템은 **프로필을 커널에 로드**하여 작동하며, 이러한 프로필은 프로그램이 액세스할 수 있는 리소스를 지시합니다. 네트워크 연결, raw 소켓 액세스 및 파일 권한과 같은 것들이 포함됩니다.

AppArmor 프로필에는 두 가지 운영 모드가 있습니다:

- **강제 모드**: 이 모드는 프로필 내에서 정의된 정책을 적극적으로 시행하여 이러한 정책을 위반하는 조치를 차단하고 syslog 또는 auditd와 같은 시스템을 통해 이러한 위반 시도를 기록합니다.
- **불평 모드**: 강제 모드와 달리 불평 모드는 프로필의 정책을 위반하는 조치를 차단하지 않습니다. 대신, 이러한 시도를 정책 위반으로 기록하고 제한을 시행하지 않습니다.

### AppArmor 구성 요소

- **커널 모듈**: 정책 시행을 담당합니다.
- **정책**: 프로그램 동작 및 리소스 액세스에 대한 규칙과 제한을 지정합니다.
- **파서**: 정책을 커널에 로드하여 시행하거나 보고합니다.
- **유틸리티**: AppArmor와 상호 작용하고 관리하는 인터페이스를 제공하는 사용자 모드 프로그램입니다.

### 프로필 경로

AppArmor 프로필은 일반적으로 _**/etc/apparmor.d/**_에 저장됩니다.\
`sudo aa-status`를 사용하여 일부 프로필에 제한이 있는 이진 파일을 나열할 수 있습니다. 각 나열된 이진 파일의 경로에서 "/" 문자를 점으로 변경하면 언급된 폴더 내의 apparmor 프로필 이름을 얻을 수 있습니다.

예를 들어, _/usr/bin/man_에 대한 **apparmor** 프로필은 _/etc/apparmor.d/usr.bin.man_에 위치합니다.

### 명령어
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## 프로필 생성

* 영향을 받는 실행 파일을 나타내기 위해 **절대 경로 및 와일드카드**가 허용됩니다 (파일 글로빙을 위해).
* **파일**에 대한 이진 파일의 액세스를 나타내기 위해 다음 **액세스 제어**를 사용할 수 있습니다:
* **r** (읽기)
* **w** (쓰기)
* **m** (실행 가능한 메모리 맵)
* **k** (파일 잠금)
* **l** (하드 링크 생성)
* **ix** (새 프로그램이 정책을 상속하여 다른 프로그램을 실행)
* **Px** (환경을 정리한 후 다른 프로필 하에서 실행)
* **Cx** (환경을 정리한 후 자식 프로필 하에서 실행)
* **Ux** (환경을 정리한 후 비제한적으로 실행)
* **변수**는 프로필에서 정의될 수 있으며 외부에서 조작할 수 있습니다. 예: @{PROC} 및 @{HOME} (프로필 파일에 #include \<tunables/global> 추가)
* **허용 규칙을 무시하는 거부 규칙이 지원**됩니다.

### aa-genprof

프로필 생성을 쉽게 시작하려면 apparmor를 사용할 수 있습니다. **이진 파일이 수행하는 작업을 apparmor가 검사한 다음 허용하거나 거부할 작업을 결정할 수 있습니다**.\
다음을 실행하면 됩니다:
```bash
sudo aa-genprof /path/to/binary
```
그런 다음, 다른 콘솔에서 일반적으로 실행되는 이진 파일이 수행하는 모든 작업을 수행하십시오:
```bash
/path/to/binary -a dosomething
```
그럼, 첫 번째 콘솔에서 "**s**"를 누르고 기록된 작업에서 무시하거나 허용할지를 지정하십시오. 완료하면 "**f**"를 누르고 새 프로필이 _/etc/apparmor.d/path.to.binary_에 생성됩니다.

{% hint style="info" %}
화살표 키를 사용하여 허용/거부/기타를 선택할 수 있습니다.
{% endhint %}

### aa-easyprof

또한 이진 파일의 apparmor 프로필 템플릿을 만들 수 있습니다.
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
기본적으로 생성된 프로필에서는 아무 것도 허용되지 않으므로 모든 것이 거부됩니다. 예를 들어 `/etc/passwd r,`와 같은 줄을 추가하여 이진 파일이 `/etc/passwd`를 읽을 수 있도록 허용해야 합니다.
{% endhint %}

그런 다음 새 프로필을 **강제로 적용**할 수 있습니다.
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### 로그에서 프로필 수정

다음 도구는 로그를 읽고 사용자에게 감지된 금지된 작업 중 일부를 허용할지 묻습니다:
```bash
sudo aa-logprof
```
{% hint style="info" %}
화살표 키를 사용하여 허용할지 거부할지 기타 작업을 선택할 수 있습니다.
{% endhint %}

### 프로필 관리
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## 로그

실행 파일 **`service_bin`**의 _/var/log/audit/audit.log_에서 **AUDIT** 및 **DENIED** 로그의 예시:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
당신은 다음을 사용하여 이 정보를 얻을 수도 있습니다:
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
## Docker에서 Apparmor

도커의 프로필 **docker-profile**이 기본적으로 로드되는 방법에 주목하세요:
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
기본적으로 **Apparmor 도커 기본 프로필**은 [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)에서 생성됩니다.

**도커 기본 프로필 요약**:

- 모든 **네트워킹에 대한 액세스**
- **능력(capability)**이 정의되지 않음 (그러나 일부 능력은 기본 기본 규칙을 포함하여 제공됨 예: #include \<abstractions/base>)
- **/proc** 파일에 **쓰기가 허용되지 않음**
- 다른 /**proc** 및 /**sys**의 **하위 디렉토리/파일**은 읽기/쓰기/잠금/링크/실행 액세스가 **거부됨**
- **마운트가 허용되지 않음**
- **Ptrace**는 **동일한 apparmor 프로필로 제한된 프로세스에서만 실행**될 수 있음

도커 컨테이너를 **실행**하면 다음 출력이 표시됩니다:
```bash
1 processes are in enforce mode.
docker-default (825)
```
**apparmor는 심지어 컨테이너에 부여된 권한(capabilities privileges)도 차단할 것**입니다. 예를 들어, **SYS_ADMIN 권한이 부여되더라도 /proc 내부에 쓰기 권한을 차단**할 수 있습니다. 왜냐하면 기본적으로 도커(apparmor) 프로필이 이 액세스를 거부하기 때문입니다:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Apparmor 제한을 우회하려면 **apparmor를 비활성화**해야 합니다:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
기본적으로 **AppArmor**은 **컨테이너가 내부에서 폴더를 마운트하는 것을 금지**합니다. 

도커 컨테이너에 **권한을 추가/제거**할 수 있습니다 (이는 여전히 **AppArmor** 및 **Seccomp**과 같은 보호 방법에 의해 제한될 것입니다):

- `--cap-add=SYS_ADMIN`은 `SYS_ADMIN` 권한을 부여합니다.
- `--cap-add=ALL`은 모든 권한을 부여합니다.
- `--cap-drop=ALL --cap-add=SYS_PTRACE`은 모든 권한을 제거하고 `SYS_PTRACE`만 부여합니다.

{% hint style="info" %}
일반적으로 **도커 컨테이너 내에서 특권 권한**을 발견했지만 **일부 부분의 exploit이 작동하지 않는** 경우, 이는 도커 **AppArmor가 방지하고 있기 때문**일 수 있습니다.
{% endhint %}

### 예시

([**여기**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)의 예시에서 가져옴)

AppArmor 기능을 설명하기 위해 새로운 Docker 프로필 "mydocker"를 만들고 다음 라인을 추가했습니다:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
프로필을 활성화하려면 다음을 수행해야 합니다:
```
sudo apparmor_parser -r -W mydocker
```
프로필을 나열하려면 다음 명령을 사용할 수 있습니다. 아래 명령은 새로운 AppArmor 프로필을 나열하고 있습니다.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
다음과 같이 AppArmor 프로필이 "/etc/"에 쓰기 액세스를 방지하고 있기 때문에 "/etc/"를 변경하려고 시도할 때 오류가 발생합니다.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

컨테이너에서 실행 중인 **apparmor 프로필을 찾을 수 있습니다**.
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
그럼, 다음 줄을 실행하여 **사용 중인 정확한 프로필을 찾을 수 있습니다**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmor은 경로를 기반으로 합니다**, 이는 **`/proc`** 디렉토리 내의 파일을 **보호**하고 있더라도 **컨테이너가 실행될 방법을 구성**할 수 있다면 호스트의 proc 디렉토리를 **`/host/proc`**에 마운트할 수 있으며 이는 더 이상 AppArmor에 의해 **보호되지 않을 것**입니다.

### AppArmor Shebang Bypass

[**이 버그**](https://bugs.launchpad.net/apparmor/+bug/1911431)에서 **특정 리소스로 perl 실행을 방지하고 있더라도**, 첫 줄에 **`#!/usr/bin/perl`**을 지정한 쉘 스크립트를 만들고 해당 파일을 직접 **실행**하면 원하는 대로 실행할 수 있습니다. 예:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**에서 파워를 받아 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인하는 **무료** 기능을 제공하는 검색 엔진입니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**를 통해 제로부터 영웅이 되는 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **HackTricks에 귀사를 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
