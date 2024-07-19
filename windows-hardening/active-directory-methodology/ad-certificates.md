# AD Certificates

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

## Introduction

### Components of a Certificate

- Le **Sujet** du certificat désigne son propriétaire.
- Une **Clé Publique** est associée à une clé privée pour lier le certificat à son propriétaire légitime.
- La **Période de Validité**, définie par les dates **NotBefore** et **NotAfter**, marque la durée effective du certificat.
- Un **Numéro de Série** unique, fourni par l'Autorité de Certification (CA), identifie chaque certificat.
- L'**Émetteur** fait référence à la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires pour le sujet, améliorant la flexibilité d'identification.
- **Basic Constraints** identifient si le certificat est destiné à une CA ou à une entité finale et définissent les restrictions d'utilisation.
- Les **Utilisations de Clé Étendues (EKUs)** délimitent les objectifs spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, à travers des Identifiants d'Objet (OIDs).
- L'**Algorithme de Signature** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'émetteur, garantit l'authenticité du certificat.

### Special Considerations

- Les **Noms Alternatifs de Sujet (SANs)** étendent l'applicabilité d'un certificat à plusieurs identités, crucial pour les serveurs avec plusieurs domaines. Des processus d'émission sécurisés sont vitaux pour éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS reconnaît les certificats CA dans une forêt AD à travers des conteneurs désignés, chacun ayant des rôles uniques :

- Le conteneur **Certification Authorities** contient des certificats CA racines de confiance.
- Le conteneur **Enrolment Services** détaille les CAs d'entreprise et leurs modèles de certificats.
- L'objet **NTAuthCertificates** inclut les certificats CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec des certificats CA intermédiaires et croisés.

### Certificate Acquisition: Client Certificate Request Flow

1. Le processus de demande commence par la recherche d'une CA d'entreprise par les clients.
2. Un CSR est créé, contenant une clé publique et d'autres détails, après la génération d'une paire de clés publique-privée.
3. La CA évalue le CSR par rapport aux modèles de certificats disponibles, émettant le certificat en fonction des autorisations du modèle.
4. Une fois approuvé, la CA signe le certificat avec sa clé privée et le renvoie au client.

### Certificate Templates

Définis dans AD, ces modèles décrivent les paramètres et les autorisations pour l'émission de certificats, y compris les EKUs autorisés et les droits d'inscription ou de modification, critiques pour gérer l'accès aux services de certificats.

## Certificate Enrollment

Le processus d'inscription pour les certificats est initié par un administrateur qui **crée un modèle de certificat**, qui est ensuite **publié** par une Autorité de Certification (CA) d'entreprise. Cela rend le modèle disponible pour l'inscription des clients, étape réalisée en ajoutant le nom du modèle au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client demande un certificat, des **droits d'inscription** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le modèle de certificat et la CA d'entreprise elle-même. Les autorisations doivent être accordées dans les deux emplacements pour qu'une demande soit réussie.

### Template Enrollment Rights

Ces droits sont spécifiés par des Entrées de Contrôle d'Accès (ACEs), détaillant des autorisations telles que :
- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, permettant toutes les autorisations étendues.
- **FullControl/GenericAll**, fournissant un contrôle complet sur le modèle.

### Enterprise CA Enrollment Rights

Les droits de la CA sont décrits dans son descripteur de sécurité, accessible via la console de gestion de l'Autorité de Certification. Certains paramètres permettent même aux utilisateurs à faibles privilèges d'accéder à distance, ce qui pourrait poser un problème de sécurité.

### Additional Issuance Controls

Certaines contrôles peuvent s'appliquer, tels que :
- **Approbation du Manager** : Place les demandes dans un état en attente jusqu'à approbation par un gestionnaire de certificats.
- **Agents d'Inscription et Signatures Autorisées** : Spécifient le nombre de signatures requises sur un CSR et les OIDs de Politique d'Application nécessaires.

### Methods to Request Certificates

Les certificats peuvent être demandés via :
1. Le **Protocole d'Inscription de Certificat Client Windows** (MS-WCCE), utilisant des interfaces DCOM.
2. Le **Protocole à Distance ICertPassage** (MS-ICPR), à travers des pipes nommés ou TCP/IP.
3. L'**interface web d'inscription de certificats**, avec le rôle d'Inscription Web de l'Autorité de Certification installé.
4. Le **Service d'Inscription de Certificat** (CES), en conjonction avec le service de Politique d'Inscription de Certificat (CEP).
5. Le **Service d'Inscription de Dispositif Réseau** (NDES) pour les dispositifs réseau, utilisant le Protocole Simple d'Inscription de Certificat (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande `Get-Certificate` de PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette demande subit plusieurs validations par le contrôleur de domaine, y compris la **validité**, le **chemin** et le **statut de révocation** du certificat. Les validations incluent également la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **magasin de certificats NTAUTH**. Des validations réussies entraînent l'émission d'un TGT. L'objet **`NTAuthCertificates`** dans AD, trouvé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est central à l'établissement de la confiance pour l'authentification par certificat.

### Authentification Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées, où, lors d'une poignée de main, le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. La correspondance d'un certificat à un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Nom Alternatif du Sujet (SAN)** du certificat, entre autres méthodes.

### Énumération des Services de Certificat AD

Les services de certificat AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Autorités de Certification (CA) d'Entreprise** et leurs configurations. Cela est accessible par tout utilisateur authentifié de domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation des vulnérabilités dans les environnements AD CS.

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

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
