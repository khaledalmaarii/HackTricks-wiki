# AD CS Persistence de domaine

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Falsification de certificats avec des certificats CA volés - DPERSIST1

Comment pouvez-vous dire qu'un certificat est un certificat CA ?

* Le certificat CA existe sur le **serveur CA lui-même**, avec sa **clé privée protégée par DPAPI de la machine** (sauf si le système d'exploitation utilise un TPM/HSM/autre matériel pour la protection).
* L'**émetteur** et le **sujet** du certificat sont tous deux définis sur le **nom distinctif du CA**.
* Les certificats CA (et uniquement les certificats CA) **ont une extension "Version CA"**.
* Il n'y a **pas d'EKU**.

La façon prise en charge par l'interface graphique intégrée pour **extraire cette clé privée de certificat** est avec `certsrv.msc` sur le serveur CA.\
Cependant, ce certificat n'est pas différent des autres certificats stockés dans le système, donc par exemple, vérifiez la technique [**THEFT2**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) pour voir comment les **extraire**.

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
**Note**: L'utilisateur cible spécifié lors de la falsification du certificat doit être **actif / activé** dans AD et **capable de s'authentifier** car un échange d'authentification aura toujours lieu en tant qu'utilisateur. Essayer de falsifier un certificat pour le compte krbtgt, par exemple, ne fonctionnera pas.
{% endhint %}

Ce certificat falsifié sera **valide** jusqu'à la date de fin spécifiée et aussi longtemps que le certificat de CA racine est valide (généralement de 5 à **10+ ans**). Il est également valide pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir une persistance sur n'importe quelle machine de domaine** aussi longtemps que le certificat de CA est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** car la CA n'en est pas consciente.

## Faire confiance aux certificats CA malveillants - DPERSIST2

L'objet `NTAuthCertificates` définit un ou plusieurs **certificats CA** dans son attribut `cacertificate` et AD l'utilise : lors de l'authentification, le **contrôleur de domaine** vérifie si l'objet **`NTAuthCertificates`** contient une entrée pour le **CA spécifié** dans le champ **Émetteur** du certificat d'authentification. Si c'est le cas, l'authentification se poursuit.

Un attaquant pourrait générer un **certificat CA auto-signé** et l'**ajouter** à l'objet **`NTAuthCertificates`**. Les attaquants peuvent le faire s'ils ont **le contrôle** sur l'objet AD **`NTAuthCertificates`** (dans les configurations par défaut, seuls les membres du groupe **Enterprise Admin** et les membres des groupes **Domain Admins** ou **Administrateurs** dans le domaine racine de la forêt ont ces autorisations). Avec l'accès élevé, on peut **modifier** l'objet **`NTAuthCertificates`** depuis n'importe quel système avec `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou en utilisant l'outil [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).&#x20;

Le certificat spécifié devrait **fonctionner avec la méthode de falsification détaillée précédemment avec ForgeCert** pour générer des certificats à la demande.

## Mauvaise configuration malveillante - DPERSIST3

Il existe une myriade d'opportunités pour la **persistance** via les **modifications de descripteur de sécurité des composants AD CS**. Tout scénario décrit dans la section "[Escalade de domaine](domain-escalation.md)" pourrait être mis en œuvre de manière malveillante par un attaquant ayant un accès élevé, ainsi que l'ajout de "droits de contrôle" (c'est-à-dire WriteOwner/WriteDACL/etc.) à des composants sensibles. Cela inclut :

* L'objet **ordinateur AD** du serveur CA
* Le **serveur RPC/DCOM du serveur CA**
* Tout **objet ou conteneur AD descendant** dans le conteneur **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur de modèles de certificats, le conteneur d'autorités de certification, l'objet NTAuthCertificates, etc.)
* **Groupes AD délégués pour contrôler AD CS par défaut ou par l'organisation actuelle** (par exemple, le groupe Cert Publishers intégré et l'un de ses membres)

Par exemple, un attaquant ayant des **permissions élevées** dans le domaine pourrait ajouter la permission **`WriteOwner`** au modèle de certificat **`User`** par défaut, où l'attaquant est le principal pour le droit. Pour abuser de cela à un moment ultérieur, l'attaquant modifierait d'abord la propriété du modèle **`User`** pour qu'elle leur appartienne, puis **définirait** **`mspki-certificate-name-flag`** sur **1** sur le modèle pour activer **`ENROLLEE_SUPPLIES_SUBJECT`** (c'est-à-dire permettant à un utilisateur de fournir un nom alternatif de sujet dans la demande). L'attaquant pourrait ensuite s'**inscrire** dans le **modèle**, en spécifiant un nom d'administrateur de domaine comme nom alternatif, et utiliser le certificat résultant pour l'authentification en tant que DA.

## Références

* Toutes les informations de cette page ont été prises à partir de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
