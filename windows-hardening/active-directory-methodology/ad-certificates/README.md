# Certificats AD

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Introduction

### Composants d'un certificat

- Le **Sujet** du certificat désigne son propriétaire.
- Une **Clé publique** est associée à une clé détenue en privé pour lier le certificat à son propriétaire légitime.
- La **Période de validité**, définie par les dates **NotBefore** et **NotAfter**, marque la durée d'efficacité du certificat.
- Un **Numéro de série** unique, fourni par l'autorité de certification (CA), identifie chaque certificat.
- L'**Émetteur** fait référence à la CA qui a délivré le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires pour le sujet, améliorant la flexibilité d'identification.
- Les **Contraintes de base** identifient si le certificat est pour une CA ou une entité finale et définissent les restrictions d'utilisation.
- Les **Usages étendus des clés (EKUs)** délimitent les objectifs spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, à travers des Identifiants d'Objet (OID).
- L'**Algorithme de signature** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'émetteur, garantit l'authenticité du certificat.

### Considérations spéciales

- Les **Noms alternatifs du sujet (SANs)** étendent l'applicabilité d'un certificat à de multiples identités, essentiel pour les serveurs avec plusieurs domaines. Des processus d'émission sécurisés sont vitaux pour éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.

### Autorités de certification (CA) dans Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD à travers des conteneurs désignés, chacun remplissant des rôles uniques :

- Le conteneur **Autorités de certification** contient les certificats de CA racine de confiance.
- Le conteneur **Services d'inscription** détaille les CA d'entreprise et leurs modèles de certificat.
- L'objet **NTAuthCertificates** inclut les certificats de CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec des certificats intermédiaires et croisés.

### Acquisition de certificats : Flux de demande de certificat client

1. Le processus de demande commence avec les clients trouvant une CA d'entreprise.
2. Une CSR est créée, contenant une clé publique et d'autres détails, après la génération d'une paire de clés publique-privée.
3. La CA évalue la CSR par rapport aux modèles de certificat disponibles, délivrant le certificat en fonction des autorisations du modèle.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.

### Modèles de certificats

Définis dans AD, ces modèles détaillent les paramètres et autorisations pour la délivrance de certificats, y compris les EKUs autorisés et les droits d'inscription ou de modification, essentiels pour la gestion de l'accès aux services de certificats.

## Inscription de certificats

Le processus d'inscription des certificats est initié par un administrateur qui **crée un modèle de certificat**, ensuite **publié** par une Autorité de Certification d'Entreprise (CA). Cela rend le modèle disponible pour l'inscription des clients, une étape réalisée en ajoutant le nom du modèle au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client puisse demander un certificat, des **droits d'inscription** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le modèle de certificat et la CA d'entreprise elle-même. Les autorisations doivent être accordées aux deux emplacements pour qu'une demande soit réussie.

### Droits d'inscription de modèle

Ces droits sont spécifiés via des entrées de contrôle d'accès (ACE), détaillant des autorisations telles que :
- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- Les **ExtendedRights**, permettant toutes les autorisations étendues.
- **FullControl/GenericAll**, fournissant un contrôle complet sur le modèle.

### Droits d'inscription de CA d'entreprise

Les droits de la CA sont définis dans son descripteur de sécurité, accessible via la console de gestion de l'Autorité de Certification. Certains paramètres permettent même aux utilisateurs à faibles privilèges un accès distant, ce qui pourrait poser un problème de sécurité.

### Contrôles d'émission supplémentaires

Certains contrôles peuvent s'appliquer, tels que :
- **Approbation du gestionnaire** : Place les demandes en attente jusqu'à ce qu'elles soient approuvées par un gestionnaire de certificat.
- **Agents d'inscription et signatures autorisées** : Spécifient le nombre de signatures requises sur une CSR et les OID de politique d'application nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés via :
1. Le **Protocole d'inscription de certificat client Windows** (MS-WCCE), en utilisant des interfaces DCOM.
2. Le **Protocole distant ICertPassage** (MS-ICPR), via des tubes nommés ou TCP/IP.
3. L'**interface web d'inscription de certificat**, avec le rôle d'inscription web de l'Autorité de Certification installé.
4. Le **Service d'inscription de certificat** (CES), en conjonction avec le service de politique d'inscription de certificat (CEP).
5. Le **Service d'inscription de périphériques réseau** (NDES) pour les périphériques réseau, en utilisant le Protocole d'Inscription de Certificat Simple (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande `Get-Certificate` de PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un Ticket Granting Ticket (TGT) d'un utilisateur est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette demande subit plusieurs validations par le contrôleur de domaine, notamment la **validité**, le **chemin** et le **statut de révocation** du certificat. Les validations incluent également la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le magasin de certificats **NTAUTH**. Des validations réussies entraînent la délivrance d'un TGT. L'objet **`NTAuthCertificates`** dans AD, situé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est essentiel pour établir la confiance pour l'authentification par certificat.

### Authentification du canal sécurisé (Schannel)

Schannel facilite les connexions sécurisées TLS/SSL, où lors d'une poignée de main, le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. La correspondance d'un certificat à un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Nom alternatif du sujet (SAN)** du certificat, parmi d'autres méthodes.

### Énumération des services de certificats AD

Les services de certificats AD peuvent être énumérés à travers des requêtes LDAP, révélant des informations sur les **Autorités de certification d'entreprise (CA)** et leurs configurations. Cela est accessible par n'importe quel utilisateur authentifié de domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation de vulnérabilités dans les environnements AD CS.

Les commandes pour utiliser ces outils incluent :
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Références

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
