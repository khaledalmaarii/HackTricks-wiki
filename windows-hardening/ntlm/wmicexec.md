# WmicExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Comment ça fonctionne Expliqué

Les processus peuvent être ouverts sur des hôtes où le nom d'utilisateur et soit le mot de passe, soit le hachage sont connus grâce à l'utilisation de WMI. Les commandes sont exécutées à l'aide de WMI par Wmiexec, offrant une expérience de shell semi-interactif.

**dcomexec.py :** En utilisant différents points de terminaison DCOM, ce script offre un shell semi-interactif similaire à wmiexec.py, en exploitant spécifiquement l'objet DCOM ShellBrowserWindow. Il prend actuellement en charge les objets MMC20. Application, Shell Windows et Shell Browser Window. (source : [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Fondamentaux de WMI

### Espace de noms

Structuré dans une hiérarchie de style répertoire, le conteneur de niveau supérieur de WMI est \root, sous lequel des répertoires supplémentaires, appelés espaces de noms, sont organisés.
Commandes pour lister les espaces de noms :
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Les classes au sein d'un espace de noms peuvent être répertoriées en utilisant :
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

Connaître le nom d'une classe WMI, comme win32\_process, et l'espace de noms dans lequel elle réside est crucial pour toute opération WMI.
Commandes pour lister les classes commençant par `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocation d'une classe :
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Méthodes

Les méthodes, qui sont une ou plusieurs fonctions exécutables des classes WMI, peuvent être exécutées.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Énumération WMI

### État du service WMI

Commandes pour vérifier si le service WMI est opérationnel :
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informations sur le système et les processus

Collecte d'informations sur le système et les processus via WMI :
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Pour les attaquants, WMI est un outil puissant pour énumérer des données sensibles sur les systèmes ou les domaines.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Interrogation à distance de WMI**

L'identification discrète des administrateurs locaux sur une machine distante et des utilisateurs connectés peut être réalisée grâce à des requêtes WMI spécifiques. `wmic` prend également en charge la lecture à partir d'un fichier texte pour exécuter des commandes sur plusieurs nœuds simultanément.

Pour exécuter un processus à distance via WMI, tel que le déploiement d'un agent Empire, la structure de commande suivante est utilisée, avec une exécution réussie indiquée par une valeur de retour "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ce processus illustre la capacité du WMI à l'exécution à distance et à l'énumération du système, mettant en évidence son utilité à la fois pour l'administration système et les tests de pénétration.


# Références
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Outils Automatiques

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
