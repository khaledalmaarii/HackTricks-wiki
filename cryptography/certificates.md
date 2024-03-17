# Certificats

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Qu'est-ce qu'un certificat

Un **certificat de clé publique** est une identité numérique utilisée en cryptographie pour prouver que quelqu'un possède une clé publique. Il inclut les détails de la clé, l'identité du propriétaire (le sujet) et une signature numérique d'une autorité de confiance (l'émetteur). Si le logiciel fait confiance à l'émetteur et que la signature est valide, une communication sécurisée avec le propriétaire de la clé est possible.

Les certificats sont principalement délivrés par des [autorités de certification](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) dans une configuration d'infrastructure à clé publique (PKI). Une autre méthode est le [réseau de confiance](https://en.wikipedia.org/wiki/Web\_of\_trust), où les utilisateurs vérifient directement les clés les uns des autres. Le format commun des certificats est [X.509](https://en.wikipedia.org/wiki/X.509), qui peut être adapté à des besoins spécifiques comme décrit dans la RFC 5280.

## Champs courants de x509

### **Champs courants dans les certificats x509**

Dans les certificats x509, plusieurs **champs** jouent des rôles critiques pour garantir la validité et la sécurité du certificat. Voici un aperçu de ces champs :

* Le **Numéro de version** indique la version du format x509.
* Le **Numéro de série** identifie de manière unique le certificat au sein du système d'une autorité de certification (CA), principalement pour le suivi des révocations.
* Le champ **Sujet** représente le propriétaire du certificat, qui peut être une machine, un individu ou une organisation. Il inclut des identifications détaillées telles que :
* **Nom commun (CN)** : Domaines couverts par le certificat.
* **Pays (C)**, **Localité (L)**, **État ou Province (ST, S, ou P)**, **Organisation (O)** et **Unité organisationnelle (OU)** fournissent des détails géographiques et organisationnels.
* Le **Nom distingué (DN)** encapsule l'identification complète du sujet.
* L'**Émetteur** détaille qui a vérifié et signé le certificat, incluant des sous-champs similaires au Sujet pour la CA.
* La **Période de validité** est marquée par les horodatages **Non Avant** et **Non Après**, garantissant que le certificat n'est pas utilisé avant ou après une certaine date.
* La section **Clé publique**, cruciale pour la sécurité du certificat, spécifie l'algorithme, la taille et d'autres détails techniques de la clé publique.
* Les **extensions x509v3** améliorent la fonctionnalité du certificat, spécifiant l'**Utilisation de la clé**, l'**Utilisation étendue de la clé**, le **Nom alternatif du sujet** et d'autres propriétés pour affiner l'application du certificat.

#### **Utilisation de la clé et extensions**

* L'**Utilisation de la clé** identifie les applications cryptographiques de la clé publique, comme la signature numérique ou le chiffrement de clé.
* L'**Utilisation étendue de la clé** restreint davantage les cas d'utilisation du certificat, par exemple, pour l'authentification du serveur TLS.
* Le **Nom alternatif du sujet** et la **Contrainte de base** définissent les noms d'hôte supplémentaires couverts par le certificat et s'il s'agit d'un certificat d'entité finale ou d'une CA, respectivement.
* Des identifiants comme l'**Identifiant de clé du sujet** et l'**Identifiant de clé de l'autorité** garantissent l'unicité et la traçabilité des clés.
* L'**Accès aux informations de l'autorité** et les **Points de distribution de la liste de révocation (CRL)** fournissent des chemins pour vérifier l'autorité de délivrance et vérifier l'état de révocation du certificat.
* Les **SCT des précertificats CT** offrent des journaux de transparence, cruciaux pour la confiance publique dans le certificat.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Différence entre les points de distribution OCSP et CRL**

**OCSP** (**RFC 2560**) implique un client et un répondant travaillant ensemble pour vérifier si un certificat de clé publique numérique a été révoqué, sans avoir besoin de télécharger le **CRL** complet. Cette méthode est plus efficace que le **CRL** traditionnel, qui fournit une liste de numéros de série de certificat révoqués mais nécessite le téléchargement d'un fichier potentiellement volumineux. Les CRL peuvent inclure jusqu'à 512 entrées. Plus de détails sont disponibles [ici](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Qu'est-ce que la transparence des certificats**

La transparence des certificats aide à lutter contre les menaces liées aux certificats en garantissant que l'émission et l'existence des certificats SSL sont visibles pour les propriétaires de domaines, les AC et les utilisateurs. Ses objectifs sont :

* Empêcher les AC d'émettre des certificats SSL pour un domaine sans la connaissance du propriétaire du domaine.
* Établir un système d'audit ouvert pour suivre les certificats émis par erreur ou de manière malveillante.
* Protéger les utilisateurs contre les certificats frauduleux.

#### **Journaux de certificats**

Les journaux de certificats sont des enregistrements publics, vérifiables et en ajout seulement de certificats, maintenus par des services réseau. Ces journaux fournissent des preuves cryptographiques à des fins d'audit. Les autorités d'émission et le public peuvent soumettre des certificats à ces journaux ou les interroger pour vérification. Bien que le nombre exact de serveurs de journaux ne soit pas fixe, il est censé être inférieur à mille à l'échelle mondiale. Ces serveurs peuvent être gérés de manière indépendante par des AC, des FAI ou toute entité intéressée.

#### **Interrogation**

Pour explorer les journaux de transparence des certificats pour un domaine, visitez [https://crt.sh/](https://crt.sh).

Différents formats existent pour stocker des certificats, chacun ayant ses propres cas d'utilisation et compatibilité. Ce résumé couvre les principaux formats et fournit des conseils sur la conversion entre eux.

## **Formats**

### **Format PEM**

* Format le plus largement utilisé pour les certificats.
* Nécessite des fichiers séparés pour les certificats et les clés privées, encodés en Base64 ASCII.
* Extensions courantes : .cer, .crt, .pem, .key.
* Principalement utilisé par Apache et des serveurs similaires.

### **Format DER**

* Un format binaire de certificats.
* Ne contient pas les déclarations "BEGIN/END CERTIFICATE" que l'on trouve dans les fichiers PEM.
* Extensions courantes : .cer, .der.
* Souvent utilisé avec les plates-formes Java.

### **Format P7B/PKCS#7**

* Stocké en Base64 ASCII, avec les extensions .p7b ou .p7c.
* Contient uniquement des certificats et des certificats de chaîne, excluant la clé privée.
* Pris en charge par Microsoft Windows et Java Tomcat.

### **Format PFX/P12/PKCS#12**

* Un format binaire qui encapsule les certificats de serveur, les certificats intermédiaires et les clés privées dans un seul fichier.
* Extensions : .pfx, .p12.
* Principalement utilisé sur Windows pour l'importation et l'exportation de certificats.

### **Conversion de formats**

Les **conversions PEM** sont essentielles pour la compatibilité :

* **x509 vers PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM to DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER vers PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM to P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 to PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Les conversions PFX** sont cruciales pour la gestion des certificats sur Windows:

* **PFX vers PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** implique deux étapes :
1. Convertir le PFX en PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convert PEM to PKCS8

To convert a PEM-encoded private key to PKCS8 format, you can use the following OpenSSL command:

```bash
openssl pkcs8 -topk8 -inform PEM -outform DER -in private-key.pem -out private-key.pkcs8 -nocrypt
```

This command will convert the private key from PEM format to PKCS8 format without encryption.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B vers PFX** nécessite également deux commandes :
1. Convertir P7B en CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Convertir un certificat CER et une clé privée en PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez-y aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
