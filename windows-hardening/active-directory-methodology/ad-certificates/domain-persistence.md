# Persistance dans le domaine AD CS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Falsification de certificats avec des certificats CA volés - DPERSIST1

Comment savoir qu'un certificat est un certificat CA ?

* Le certificat CA existe sur le **serveur CA lui-même**, avec sa **clé privée protégée par le DPAPI de la machine** (à moins que l'OS utilise un TPM/HSM/autre matériel pour la protection).
* L'**Émetteur** et le **Sujet** du certificat sont tous deux définis sur le **nom distinctif du CA**.
* Les certificats CA (et seulement les certificats CA) **ont une extension “Version CA”**.
* Il n'y a **pas d'EKUs**

La méthode prise en charge par l'interface graphique intégrée pour **extraire cette clé privée de certificat** est avec `certsrv.msc` sur le serveur CA.\
Cependant, ce certificat **n'est pas différent** des autres certificats stockés dans le système, donc par exemple, consultez la technique [**THEFT2**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) pour voir comment les **extraire**.

Vous pouvez également obtenir le certificat et la clé privée en utilisant [**certipy**](https://github.com/ly4k/Certipy) :
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Une fois que vous avez le **certificat CA** avec la clé privée au format `.pfx`, vous pouvez utiliser [**ForgeCert**](https://github.com/GhostPack/ForgeCert) pour créer des certificats valides :
```bash
# Create new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Create new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Use new certificate with Rubeus to authenticate
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# User new certi with certipy to authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
**Note** : L'**utilisateur** cible spécifié lors de la création du certificat doit être **actif/activé** dans AD et **capable de s'authentifier**, car un échange d'authentification aura toujours lieu en tant que cet utilisateur. Essayer de forger un certificat pour le compte krbtgt, par exemple, ne fonctionnera pas.
{% endhint %}

Ce certificat forgé sera **valide** jusqu'à la date de fin spécifiée et tant que le certificat de l'autorité de certification racine est valide (généralement de 5 à **10+ ans**). Il est également valide pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir la persistance sur n'importe quelle machine du domaine** aussi longtemps que le certificat de l'AC est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** car l'AC n'en est pas informée.

## Faire confiance aux certificats CA Rogue - DPERSIST2

L'objet `NTAuthCertificates` définit un ou plusieurs **certificats CA** dans son **attribut** `cacertificate` et AD l'utilise : Lors de l'authentification, le **contrôleur de domaine** vérifie si l'objet **`NTAuthCertificates`** **contient** une entrée pour l'**AC spécifiée** dans le champ Émetteur du **certificat** authentifiant. Si **c'est le cas, l'authentification se poursuit**.

Un attaquant pourrait générer un **certificat CA auto-signé** et l'**ajouter** à l'objet **`NTAuthCertificates`**. Les attaquants peuvent faire cela s'ils ont le **contrôle** de l'objet AD **`NTAuthCertificates`** (dans les configurations par défaut, seuls les membres du groupe **Enterprise Admin** et les membres des groupes **Domain Admins** ou **Administrators** dans le **domaine racine de la forêt** ont ces permissions). Avec l'accès élevé, on peut **modifier** l'objet **`NTAuthCertificates`** depuis n'importe quel système avec `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou en utilisant l'[**outil PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).&#x20;

Le certificat spécifié devrait **fonctionner avec la méthode de contrefaçon précédemment détaillée avec ForgeCert** pour générer des certificats à la demande.

## Mauvaise configuration malveillante - DPERSIST3

Il existe une myriade d'opportunités pour la **persistance** via des **modifications du descripteur de sécurité des composants AD CS**. Tout scénario décrit dans la section “[Domain Escalation](domain-escalation.md)” pourrait être malicieusement mis en œuvre par un attaquant avec un accès élevé, ainsi que l'ajout de "droits de contrôle" (c'est-à-dire, WriteOwner/WriteDACL/etc.) aux composants sensibles. Cela inclut :

* L'objet **ordinateur AD du serveur CA**
* Le **serveur RPC/DCOM du serveur CA**
* Tout **objet ou conteneur AD descendant** dans le conteneur **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur des modèles de certificats, le conteneur des autorités de certification, l'objet NTAuthCertificates, etc.)
* **Groupes AD délégués des droits pour contrôler AD CS par défaut ou par l'organisation actuelle** (par exemple, le groupe Cert Publishers intégré et tous ses membres)

Par exemple, un attaquant avec des **permissions élevées** dans le domaine pourrait ajouter la permission **`WriteOwner`** au modèle de certificat **`User`** par défaut, où l'attaquant est le principal pour le droit. Pour abuser de cela plus tard, l'attaquant modifierait d'abord la propriété du modèle **`User`** à lui-même, puis **définirait** **`mspki-certificate-name-flag`** à **1** sur le modèle pour activer **`ENROLLEE_SUPPLIES_SUBJECT`** (c'est-à-dire, permettant à un utilisateur de fournir un nom alternatif de sujet dans la demande). L'attaquant pourrait alors **s'inscrire** au **modèle**, en spécifiant un nom d'administrateur de domaine comme nom alternatif, et utiliser le certificat résultant pour l'authentification en tant que DA.

## Références

* Toutes les informations de cette page ont été prises de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
