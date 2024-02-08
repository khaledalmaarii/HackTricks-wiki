# Persistance de domaine AD CS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Il s'agit d'un résumé des techniques de persistance de domaine partagées dans [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Consultez-le pour plus de détails.

## Falsification de certificats avec des certificats CA volés - DPERSIST1

Comment pouvez-vous dire qu'un certificat est un certificat CA?

Il peut être déterminé qu'un certificat est un certificat CA si plusieurs conditions sont remplies :

- Le certificat est stocké sur le serveur CA, avec sa clé privée sécurisée par le DPAPI de la machine, ou par du matériel tel qu'un TPM/HSM si le système d'exploitation le prend en charge.
- Les champs Émetteur et Sujet du certificat correspondent au nom distinctif du CA.
- Une extension "Version CA" est présente exclusivement dans les certificats CA.
- Le certificat ne contient pas de champs d'utilisation étendue de la clé (EKU).

Pour extraire la clé privée de ce certificat, l'outil `certsrv.msc` sur le serveur CA est la méthode prise en charge via l'interface graphique intégrée. Néanmoins, ce certificat ne diffère pas des autres stockés dans le système ; ainsi, des méthodes telles que la technique [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent être appliquées pour l'extraction.

Le certificat et la clé privée peuvent également être obtenus en utilisant Certipy avec la commande suivante:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Une fois que vous avez acquis le certificat CA et sa clé privée au format `.pfx`, des outils comme [ForgeCert](https://github.com/GhostPack/ForgeCert) peuvent être utilisés pour générer des certificats valides :
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
L'utilisateur ciblé pour la falsification de certificat doit être actif et capable de s'authentifier dans Active Directory pour que le processus réussisse. Falsifier un certificat pour des comptes spéciaux comme krbtgt est inefficace.
{% endhint %}

Ce certificat falsifié sera **valide** jusqu'à la date de fin spécifiée et aussi **longtemps que le certificat de l'autorité de certification racine est valide** (généralement de 5 à **10+ ans**). Il est également valide pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir une persistance sur n'importe quelle machine de domaine** aussi longtemps que le certificat de l'autorité de certification est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** car l'autorité de certification n'en est pas consciente.

## Faire confiance aux certificats CA malveillants - DPERSIST2

L'objet `NTAuthCertificates` est défini pour contenir un ou plusieurs **certificats d'autorité de certification** dans son attribut `cacertificate`, que Active Directory (AD) utilise. Le processus de vérification par le **contrôleur de domaine** implique de vérifier l'objet `NTAuthCertificates` pour une entrée correspondant à l'**autorité de certification spécifiée** dans le champ Émetteur du **certificat** d'authentification. L'authentification se poursuit si une correspondance est trouvée.

Un certificat d'autorité de certification auto-signé peut être ajouté à l'objet `NTAuthCertificates` par un attaquant, à condition qu'il ait le contrôle sur cet objet AD. Normalement, seuls les membres du groupe **Administrateurs d'entreprise**, ainsi que les **Administrateurs de domaine** ou les **Administrateurs** du **domaine racine de la forêt**, ont l'autorisation de modifier cet objet. Ils peuvent modifier l'objet `NTAuthCertificates` en utilisant `certutil.exe` avec la commande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou en utilisant l'outil [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Cette capacité est particulièrement pertinente lorsqu'elle est utilisée en conjonction avec une méthode précédemment décrite impliquant ForgeCert pour générer dynamiquement des certificats.

## Mauvaise configuration malveillante - DPERSIST3

Les opportunités de **persistance** grâce aux **modifications des descripteurs de sécurité des composants AD CS** sont nombreuses. Les modifications décrites dans la section "[Élévation de domaine](domain-escalation.md)" peuvent être mises en œuvre de manière malveillante par un attaquant ayant un accès élevé. Cela inclut l'ajout de "droits de contrôle" (par exemple, WriteOwner/WriteDACL/etc.) à des composants sensibles tels que :

- L'objet ordinateur AD du **serveur CA**
- Le serveur RPC/DCOM du **serveur CA**
- Tout **objet ou conteneur AD descendant** dans **`CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur Modèles de certificats, le conteneur Autorités de certification, l'objet NTAuthCertificates, etc.)
- **Groupes AD ayant des droits délégués pour contrôler AD CS** par défaut ou par l'organisation (comme le groupe Cert Publishers intégré et l'un de ses membres)

Un exemple de mise en œuvre malveillante impliquerait un attaquant, ayant des **permissions élevées** dans le domaine, ajoutant la permission **`WriteOwner`** au modèle de certificat **`Utilisateur`** par défaut, l'attaquant étant le principal pour ce droit. Pour exploiter cela, l'attaquant changerait d'abord la propriété du modèle **`Utilisateur`** pour lui-même. Ensuite, le **`mspki-certificate-name-flag`** serait défini sur **1** sur le modèle pour activer **`ENROLLEE_SUPPLIES_SUBJECT`**, permettant à un utilisateur de fournir un nom alternatif de sujet dans la demande. Ensuite, l'attaquant pourrait **s'inscrire** en utilisant le **modèle**, en choisissant un nom d'administrateur de domaine comme nom alternatif, et utiliser le certificat acquis pour l'authentification en tant qu'AD.
