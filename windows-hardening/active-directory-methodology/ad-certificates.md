# Certificats AD

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

### Parties d'un certificat

* **Sujet** - Le propriétaire du certificat.
* **Clé Publique** - Associe le Sujet à une clé privée stockée séparément.
* **Dates NotBefore et NotAfter** - Définissent la durée de validité du certificat.
* **Numéro de Série** - Un identifiant pour le certificat attribué par l'AC.
* **Émetteur** - Identifie qui a émis le certificat (généralement une AC).
* **SubjectAlternativeName** - Définit un ou plusieurs noms alternatifs que le Sujet peut utiliser. (_Voir ci-dessous_)
* **Contraintes de Base** - Identifie si le certificat est une AC ou une entité finale, et s'il y a des contraintes lors de l'utilisation du certificat.
* **Utilisations Clés Étendues (EKUs)** - Identificateurs d'objets (OIDs) qui décrivent **comment le certificat sera utilisé**. Également connu sous le nom d'Utilisation Clé Améliorée dans le jargon de Microsoft. Les OIDs EKU courants incluent :
* Signature de Code (OID 1.3.6.1.5.5.7.3.3) - Le certificat est pour la signature de code exécutable.
* Système de Fichiers de Chiffrement (OID 1.3.6.1.4.1.311.10.3.4) - Le certificat est pour le chiffrement de systèmes de fichiers.
* Email Sécurisé (1.3.6.1.5.5.7.3.4) - Le certificat est pour le chiffrement d'email.
* Authentification Client (OID 1.3.6.1.5.5.7.3.2) - Le certificat est pour l'authentification à un autre serveur (par exemple, vers AD).
* Connexion par Carte à Puce (OID 1.3.6.1.4.1.311.20.2.2) - Le certificat est pour l'utilisation dans l'authentification par carte à puce.
* Authentification Serveur (OID 1.3.6.1.5.5.7.3.1) - Le certificat est pour l'identification de serveurs (par exemple, certificats HTTPS).
* **Algorithme de Signature** - Spécifie l'algorithme utilisé pour signer le certificat.
* **Signature** - La signature du corps des certificats faite en utilisant la clé privée de l'émetteur (par exemple, une AC).

#### Noms Alternatifs du Sujet

Un **Nom Alternatif du Sujet** (SAN) est une extension X.509v3. Il permet **d'ajouter des identités supplémentaires** à un **certificat**. Par exemple, si un serveur web héberge **du contenu pour plusieurs domaines**, **chaque** domaine applicable pourrait être **inclus** dans le **SAN** afin que le serveur web n'ait besoin que d'un seul certificat HTTPS.

Par défaut, lors de l'authentification basée sur des certificats, une des méthodes qu'AD utilise pour mapper les certificats aux comptes utilisateurs est basée sur un UPN spécifié dans le SAN. Si un attaquant peut **spécifier un SAN arbitraire** lors de la demande d'un certificat qui a un **EKU permettant l'authentification client**, et que l'AC crée et signe un certificat en utilisant le SAN fourni par l'attaquant, **l'attaquant peut devenir n'importe quel utilisateur dans le domaine**.

### AC

AD CS définit les certificats d'AC que la forêt AD fait confiance dans quatre emplacements sous le conteneur `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`, chacun différant par leur objectif :

* Le conteneur **Certification Authorities** définit **les certificats d'AC racine de confiance**. Ces AC sont au **sommet de la hiérarchie de l'arbre PKI** et sont la base de la confiance dans les environnements AD CS. Chaque AC est représentée comme un objet AD à l'intérieur du conteneur où l'**objectClass** est défini à **`certificationAuthority`** et la propriété **`cACertificate`** contient les **octets** du **certificat de l'AC**. Windows propage ces certificats d'AC aux magasins de certificats d'Autorités de Certification Racines de Confiance sur **chaque machine Windows**. Pour qu'AD considère un certificat comme **de confiance**, la chaîne de confiance du certificat doit finalement **se terminer** avec **l'une des AC racines** définies dans ce conteneur.
* Le conteneur **Enrolment Services** définit chaque **AC d'Entreprise** (c'est-à-dire, les AC créées dans AD CS avec le rôle d'AC d'Entreprise activé). Chaque AC d'Entreprise a un objet AD avec les attributs suivants :
* Un attribut **objectClass** défini à **`pKIEnrollmentService`**
* Un attribut **`cACertificate`** contenant les **octets du certificat de l'AC**
* Une propriété **`dNSHostName`** définissant l'**hôte DNS de l'AC**
* Un champ **certificateTemplates** définissant les **modèles de certificats activés**. Les modèles de certificats sont un "plan" de paramètres que l'AC utilise lors de la création d'un certificat, et incluent des choses telles que les EKUs, les permissions d'inscription, l'expiration du certificat, les exigences d'émission et les paramètres de cryptographie. Nous discuterons plus en détail des modèles de certificats plus tard.

{% hint style="info" %}
Dans les environnements AD, **les clients interagissent avec les AC d'Entreprise pour demander un certificat** basé sur les paramètres définis dans un modèle de certificat. Les certificats d'AC d'Entreprise sont propagés au magasin de certificats d'Autorités de Certification Intermédiaires sur chaque machine Windows
{% endhint %}

* L'objet AD **NTAuthCertificates** définit les certificats d'AC qui permettent l'authentification à AD. Cet objet a un **objectClass** de **`certificationAuthority`** et la propriété **`cACertificate`** de l'objet définit un tableau de **certificats d'AC de confiance**. Les machines Windows jointes à AD propagent ces AC au magasin de certificats d'Autorités de Certification Intermédiaires sur chaque machine. Les **applications clientes** peuvent **s'authentifier** à AD en utilisant un certificat seulement si l'une des **AC définies par l'objet NTAuthCertificates** a **signé** le certificat du client authentifiant.
* Le conteneur **AIA** (Authority Information Access) contient les objets AD des AC intermédiaires et croisées. **Les AC intermédiaires sont des "enfants" des AC racines** dans la hiérarchie de l'arbre PKI ; en tant que tel, ce conteneur existe pour aider à **valider les chaînes de certificats**. Comme le conteneur Certification Authorities, chaque **AC est représentée comme un objet AD** dans le conteneur AIA où l'attribut objectClass est défini à certificationAuthority et la propriété **`cACertificate`** contient les **octets** du **certificat de l'AC**. Ces AC sont propagées au magasin de certificats d'Autorités de Certification Intermédiaires sur chaque machine Windows.

### Flux de Demande de Certificat Client

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

C'est le processus pour **obtenir un certificat** d'AD CS. À un niveau élevé, lors de l'inscription, les clients trouvent d'abord une **AC d'Entreprise** basée sur les **objets dans le conteneur Enrolment Services** discuté ci-dessus.

1. Les clients génèrent ensuite une **paire de clés publique-privée** et
2. placent la clé publique dans un message de **demande de signature de certificat (CSR)** avec d'autres détails tels que le sujet du certificat et le **nom du modèle de certificat**. Les clients signent ensuite le CSR avec leur clé privée et envoient le CSR à un serveur AC d'Entreprise.
3. Le serveur **AC** vérifie si le client **peut demander des certificats**. Si c'est le cas, il détermine s'il émettra un certificat en consultant l'objet AD du **modèle de certificat** spécifié dans le CSR. L'AC vérifiera si l'objet AD du modèle de certificat a des **permissions permettant** au compte authentifiant d'**obtenir un certificat**.
4. Si c'est le cas, l'**AC génère un certificat** en utilisant les paramètres "plan" définis par le **modèle de certificat** (par exemple, EKUs, paramètres de cryptographie et exigences d'émission) et en utilisant les autres informations fournies dans le CSR si autorisé par les paramètres du modèle de certificat. L'**AC signe le certificat** en utilisant sa clé privée, puis le retourne au client.

### Modèles de Certificats

AD CS stocke les modèles de certificats disponibles comme objets AD avec un **objectClass** de **`pKICertificateTemplate`** situé dans le conteneur suivant :

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

Les attributs d'un objet de modèle de certificat AD **définissent ses paramètres, et son descripteur de sécurité contrôle** quels **principaux peuvent s'inscrire** au certificat ou **modifier** le modèle de certificat.

L'attribut **`pKIExtendedKeyUsage`** sur un objet de modèle de certificat AD contient un **tableau d'OIDs** activés dans le modèle. Ces OIDs EKU affectent **à quoi le certificat peut être utilisé.** Vous pouvez trouver une [liste des OIDs possibles ici](https://www.pkisolutions.com/object-identifiers-oid-in-pki/).

#### OIDs d'Authentification

* `1.3.6.1.5.5.7.3.2`: Authentification Client
* `1.3.6.1.5.2.3.4`: Authentification Client PKINIT (à ajouter manuellement)
* `1.3.6.1.4.1.311.20.2.2`: Connexion par Carte à Puce
* `2.5.29.37.0`: Tout usage
* `(pas d'EKUs)`: SubCA
* Un OID EKU supplémentaire que nous avons trouvé que nous pourrions abuser est l'OID d'Agent de Demande de Certificat (`1.3.6.1.4.1.311.20.2.1`). Les certificats avec cet OID peuvent être utilisés pour **demander des certificats au nom d'un autre utilisateur** à moins que des restrictions spécifiques ne soient mises en place.

## Inscription de Certificat

Un administrateur doit **créer le modèle de certificat** puis une **AC d'Entreprise "publie"** le modèle, le rendant disponible aux clients pour s'inscrire. AD CS spécifie qu'un modèle de certificat est activé sur une AC d'Entreprise en **ajoutant le nom du modèle au champ `certificatetemplates`** de l'objet AD.

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
AD CS définit les droits d'inscription - quels **principaux peuvent demander** un certificat – en utilisant deux descripteurs de sécurité : un sur l'objet AD du **modèle de certificat** et un autre sur l'**AC d'Entreprise elle-même**.\
Un client doit être autorisé dans les deux descripteurs de sécurité pour pouvoir demander un certificat.
{% endhint %}

### Droits d'Inscription des Modèles de Certificats

* **L'ACE accorde à un principal le droit étendu Certificate-Enrollment**. L'ACE brut accorde au principal le droit d'accès `RIGHT_DS_CONTROL_ACCESS45` où l'**ObjectType** est défini à `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. Ce GUID correspond au droit étendu **Certificate-Enrolment**.
* **L'ACE accorde à un principal le droit étendu Certificate-AutoEnrollment**. L'ACE brut accorde au principal le droit d'accès `RIGHT_DS_CONTROL_ACCESS48` où l'**ObjectType** est défini à `a05b8cc2-17bc-4802-a710-e7c15ab866a249`. Ce GUID correspond au droit étendu **Certificate-AutoEnrollment**.
* **Un ACE accorde à un principal tous les ExtendedRights**. L'ACE brut active le droit d'accès `RIGHT_DS_CONTROL_ACCESS` où l'**ObjectType** est défini à `00000000-0000-0000-0000-000000000000`. Ce GUID correspond à **tous les droits étendus**.
* **Un ACE accorde à un principal FullControl/GenericAll**. L'ACE brut active le droit d'accès FullControl/GenericAll.

### Droits d'Inscription de l'AC d'Entreprise

Le **descripteur de sécurité** configuré sur l'**AC d'Entreprise** définit ces droits et est **visible** dans le snap-in MMC de l'Autorité de Certification `certsrv.msc` en cliquant avec le bouton droit sur l'AC → Propriétés → Sécurité.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

Cela finit par définir la valeur de registre Security dans la clé **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`** sur le serveur CA. Nous avons rencontré plusieurs serveurs AD CS qui accordent aux utilisateurs peu privilégiés un accès à distance à cette clé via le registre à distance :

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

Les utilisateurs peu privilégiés peuvent également **énumérer cela via DCOM** en utilisant l'interface COM `ICertAdminD2` et sa méthode `GetCASecurity`. Cependant, les clients Windows normaux doivent installer les Outils d'administration de serveur distant (RSAT) pour l'utiliser puisque l'interface COM et tous les objets COM qui l'implémentent ne sont pas présents sur Windows par défaut.

### Exigences d'Émission

D'autres exigences pourraient être en place pour contrôler qui peut obtenir un certificat.

#### Approbation du Gestionnaire

**L'approbation du gestionnaire de certificats de l'AC** résulte dans le modèle de certificat définissant le bit `CT_FLAG_PEND_ALL_REQUESTS` (0x2) sur l'attribut `msPKI-EnrollmentFlag` de l'objet AD. Cela met toutes
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## Références

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
