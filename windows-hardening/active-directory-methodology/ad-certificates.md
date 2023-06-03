# Certificats AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

### Parties d'un certificat

* **Sujet** - Le propriétaire du certificat.
* **Clé publique** - Associe le sujet à une clé privée stockée séparément.
* **Dates de début et de fin** - Définissent la durée de validité du certificat.
* **Numéro de série** - Un identifiant pour le certificat attribué par l'AC.
* **Émetteur** - Identifie qui a émis le certificat (généralement une AC).
* **SubjectAlternativeName** - Définit un ou plusieurs noms alternatifs que le sujet peut utiliser. (_Voir ci-dessous_)
* **Contraintes de base** - Identifie si le certificat est une AC ou une entité finale, et s'il existe des contraintes lors de l'utilisation du certificat.
* **Utilisations étendues des clés (EKU)** - Identificateurs d'objet (OID) qui décrivent **comment le certificat sera utilisé**. Également connu sous le nom d'Enhanced Key Usage dans le jargon de Microsoft. Les EKU courants incluent :
  * Signature de code (OID 1.3.6.1.5.5.7.3.3) - Le certificat est destiné à la signature de code exécutable.
  * Système de fichiers chiffré (OID 1.3.6.1.4.1.311.10.3.4) - Le certificat est destiné au chiffrement des systèmes de fichiers.
  * Courrier électronique sécurisé (1.3.6.1.5.5.7.3.4) - Le certificat est destiné au chiffrement des e-mails.
  * Authentification client (OID 1.3.6.1.5.5.7.3.2) - Le certificat est destiné à l'authentification auprès d'un autre serveur (par exemple, à AD).
  * Connexion par carte à puce (OID 1.3.6.1.4.1.311.20.2.2) - Le certificat est destiné à être utilisé dans l'authentification par carte à puce.
  * Authentification du serveur (OID 1.3.6.1.5.5.7.3.1) - Le certificat est destiné à l'identification des serveurs (par exemple, les certificats HTTPS).
* **Algorithme de signature** - Spécifie l'algorithme utilisé pour signer le certificat.
* **Signature** - La signature du corps des certificats effectuée à l'aide de la clé privée de l'émetteur (par exemple, d'une AC).

#### Noms alternatifs de sujet

Un **nom alternatif de sujet** (SAN) est une extension X.509v3. Il permet de lier des **identités supplémentaires** à un **certificat**. Par exemple, si un serveur Web héberge du **contenu pour plusieurs domaines**, **chaque** domaine **applicable** pourrait être **inclus** dans le **SAN** de sorte que le serveur Web n'ait besoin que d'un seul certificat HTTPS.

Par défaut, lors de l'authentification basée sur des certificats, AD
### Droits d'inscription de modèles de certificats

* **L'ACE accorde à un principal le droit étendu d'inscription de certificat**. L'ACE brut accorde au principal le droit d'accès `RIGHT_DS_CONTROL_ACCESS45` où le **ObjectType** est défini sur `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. Ce GUID correspond au droit étendu d'inscription de certificat.
* **L'ACE accorde à un principal le droit étendu d'inscription automatique de certificat**. L'ACE brut accorde au principal le droit d'accès `RIGHT_DS_CONTROL_ACCESS48` où le **ObjectType** est défini sur `a05b8cc2-17bc-4802-a710-e7c15ab866a249`. Ce GUID correspond au droit étendu d'inscription automatique de certificat.
* **Un ACE accorde à un principal tous les droits étendus**. L'ACE brut active le droit d'accès `RIGHT_DS_CONTROL_ACCESS` où le **ObjectType** est défini sur `00000000-0000-0000-0000-000000000000`. Ce GUID correspond à **tous les droits étendus**.
* **Un ACE accorde à un principal FullControl/GenericAll**. L'ACE brut active le droit d'accès FullControl/GenericAll.

### Droits d'inscription de CA d'entreprise

Le **descripteur de sécurité** configuré sur le **CA d'entreprise** définit ces droits et est **visible** dans la console MMC de l'autorité de certification `certsrv.msc` en cliquant avec le bouton droit sur le CA → Propriétés → Sécurité.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

Cela finit par définir la valeur de registre de sécurité dans la clé **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<NOM DU CA>`** sur le serveur CA. Nous avons rencontré plusieurs serveurs AD CS qui accordent aux utilisateurs à faible privilège un accès distant à cette clé via le registre distant :

<figure><img src="../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Les utilisateurs à faible privilège peuvent également **énumérer cela via DCOM** en utilisant la méthode `GetCASecurity` de l'interface COM `ICertAdminD2`. Cependant, les clients Windows normaux doivent installer les outils d'administration de serveur distant (RSAT) pour l'utiliser car l'interface COM et tous les objets COM qui l'implémentent ne sont pas présents sur Windows par défaut.

### Exigences de délivrance

D'autres exigences pourraient être en place pour contrôler qui peut obtenir un certificat.

#### Approbation du gestionnaire

L'approbation du **gestionnaire de certificat CA** entraîne le paramétrage du modèle de certificat en définissant le bit `CT_FLAG_PEND_ALL_REQUESTS` (0x2) sur l'attribut `msPKI-EnrollmentFlag` de l'objet AD. Cela met toutes les **demandes de certificat** basées sur le modèle dans l'état **en attente** (visible dans la section "Demandes en attente" dans `certsrv.msc`), ce qui nécessite qu'un gestionnaire de certificat **approuve ou refuse** la demande avant que le certificat ne soit délivré :

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### Agents d'inscription, signatures autorisées et politiques d'application

**Ce nombre de signatures autorisées** et la **politique d'application**. Le premier contrôle le **nombre de signatures requises** dans le CSR pour que le CA l'accepte. Le second définit les **OID EKU que le certificat de signature CSR doit avoir**.

Une utilisation courante de ces paramètres est pour les **agents d'inscription**. Un agent d'inscription est un terme AD CS donné à une entité qui peut **demander des certificats au nom d'un autre utilisateur**. Pour ce faire, le CA doit émettre à l'agent d'inscription un certificat contenant au moins le **EKU de l'agent de demande de certificat** (OID 1.3.6.1.4.1.311.20.2.1). Une fois émis, l'agent d'inscription peut alors **signer des CSR et demander des certificats au nom d'autres utilisateurs**. Le CA émettra le certificat de l'agent d'inscription en tant qu'**autre utilisateur** uniquement dans l'ensemble non exhaustif suivant de **conditions** (implémenté principalement dans le module de stratégie par défaut `certpdef.dll`) :

* L'utilisateur Windows s'authentifiant auprès du CA dispose des droits d'inscription sur le modèle de certificat cible.
* Si la version de schéma du modèle de certificat est 1, le CA exigera que les certificats de signature aient l'OID de l'agent de demande de certificat avant de délivrer le certificat. La version de schéma du modèle est spécifiée dans la propriété msPKI-Template-Schema-Version de son objet AD.
* Si la version de schéma du modèle de certificat est 2 :
  * Le modèle doit définir le paramètre "Ce nombre de signatures autorisées" et le nombre spécifié d'agents d'inscription doit signer le CSR (l'attribut AD mspkira-signature du modèle définit ce paramètre). En d'autres termes, ce paramètre spécifie combien d'agents d'inscription doivent signer un CSR avant que le CA ne considère même la délivrance d'un certificat.
## Énumération AD CS

Tout comme pour la plupart des éléments d'AD, toutes les informations couvertes jusqu'à présent sont disponibles en interrogeant LDAP en tant qu'utilisateur authentifié de domaine, mais autrement non privilégié.

Si nous voulons **énumérer les AC d'entreprise** et leurs paramètres, on peut interroger LDAP en utilisant le filtre LDAP `(objectCategory=pKIEnrollmentService)` sur la base de recherche `CN=Configuration,DC=<domain>,DC=<com>` (cette base de recherche correspond au contexte de nom de Configuration de la forêt AD). Les résultats identifieront le nom d'hôte DNS du serveur CA, le nom de la CA elle-même, les dates de début et de fin du certificat, divers indicateurs, les modèles de certificat publiés, et plus encore.

**Outils pour énumérer les certificats vulnérables :**

* [**Certify**](https://github.com/GhostPack/Certify) est un outil C# qui peut **énumérer des informations de configuration et d'infrastructure utiles sur les environnements AD CS** et peut demander des certificats de différentes manières.
* [**Certipy**](https://github.com/ly4k/Certipy) est un outil **python** pour pouvoir **énumérer et abuser** des services de certificats Active Directory (**AD CS**) **à partir de n'importe quel système** (avec accès au DC) qui peut générer une sortie pour BloodHound créée par [**Lyak**](https://twitter.com/ly4k\_) (bonne personne, meilleur hacker).
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
