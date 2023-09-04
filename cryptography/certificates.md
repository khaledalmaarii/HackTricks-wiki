# Certificats

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour créer et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Qu'est-ce qu'un certificat

En cryptographie, un **certificat de clé publique**, également connu sous le nom de **certificat numérique** ou **certificat d'identité**, est un document électronique utilisé pour prouver la propriété d'une clé publique. Le certificat contient des informations sur la clé, des informations sur l'identité de son propriétaire (appelé le sujet) et la signature numérique d'une entité qui a vérifié le contenu du certificat (appelée l'émetteur). Si la signature est valide et que le logiciel examinant le certificat fait confiance à l'émetteur, il peut utiliser cette clé pour communiquer en toute sécurité avec le sujet du certificat.

Dans un schéma d'infrastructure à clé publique (PKI) typique, l'émetteur du certificat est une autorité de certification (CA), généralement une entreprise qui facture aux clients l'émission de certificats pour eux. En revanche, dans un schéma de toile de confiance, les individus signent directement les clés des autres, dans un format qui remplit une fonction similaire à celle d'un certificat de clé publique.

Le format le plus courant pour les certificats de clé publique est défini par [X.509](https://en.wikipedia.org/wiki/X.509). Étant donné que X.509 est très général, le format est en outre contraint par des profils définis pour certains cas d'utilisation, tels que [Infrastructure à clé publique (X.509)](https://en.wikipedia.org/wiki/PKIX) tel que défini dans la RFC 5280.

## Champs communs x509

* **Numéro de version** : Version du format x509.
* **Numéro de série** : Utilisé pour identifier de manière unique le certificat au sein des systèmes d'une CA. En particulier, cela est utilisé pour suivre les informations de révocation.
* **Sujet** : L'entité à laquelle appartient un certificat : une machine, un individu ou une organisation.
* **Nom commun** : Domaines affectés par le certificat. Peut être 1 ou plus et peut contenir des caractères génériques.
* **Pays (C)** : Pays
* **Nom distinctif (DN)** : Le sujet complet : `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **Localité (L)** : Lieu local
* **Organisation (O)** : Nom de l'organisation
* **Unité organisationnelle (OU)** : Division d'une organisation (comme "Ressources humaines").
* **État ou province (ST, S ou P)** : Liste des noms d'état ou de province
* **Émetteur** : L'entité qui a vérifié les informations et signé le certificat.
* **Nom commun (CN)** : Nom de l'autorité de certification
* **Pays (C)** : Pays de l'autorité de certification
* **Nom distinctif (DN)** : Nom distinctif de l'autorité de certification
* **Localité (L)** : Lieu local où l'organisation peut être trouvée.
* **Organisation (O)** : Nom de l'organisation
* **Unité organisationnelle (OU)** : Division d'une organisation (comme "Ressources humaines").
* **Non avant** : La date et l'heure les plus précoces à partir desquelles le certificat est valide. Généralement défini quelques heures ou jours avant le moment où le certificat a été émis, pour éviter les problèmes de décalage horaire.
* **Non après** : La date et l'heure après lesquelles le certificat n'est plus valide.
* **Clé publique** : Une clé publique appartenant au sujet du certificat. (C'est l'une des principales parties car c'est ce qui est signé par la CA)
* **Algorithme de clé publique** : Algorithme utilisé pour générer la clé publique. Comme RSA.
* **Courbe de clé publique** : La courbe utilisée par l'algorithme de clé publique à courbe elliptique (si applicable). Comme nistp521.
* **Exposant de clé publique** : Exposant utilisé pour dériver la clé publique (si applicable). Comme 65537.
* **Taille de clé publique** : La taille de l'espace de clé publique en bits. Comme 2048.
* **Algorithme de signature** : L'algorithme utilisé pour signer le certificat de clé publique.
* **Signature** : Une signature du corps du certificat par la clé privée de l'émetteur.
* **Extensions x509v3**
* **Utilisation de la clé** : Les utilisations cryptographiques valides de la clé publique du certificat. Les valeurs courantes incluent la validation de la signature numérique, le chiffrement de clé et la signature de certificat.
* Dans un certificat Web, cela apparaîtra comme une _extension X509v3_ et aura la valeur `Signature numérique`
* **Utilisation étendue de la clé** : Les applications dans lesquelles le certificat peut être utilisé. Les valeurs courantes incluent l'authentification du serveur TLS, la protection des e-mails et la signature de code.
* Dans un certificat Web, cela apparaîtra comme une _extension X509v3_ et aura la valeur `Authentification du serveur Web TLS`
* **Nom alternatif du sujet** : Permet aux utilisateurs de spécifier des **noms** d'hôte supplémentaires pour un seul **certificat** SSL. L'utilisation de l'extension SAN est une pratique courante pour les certificats SSL et elle est en passe de remplacer l'utilisation du **nom** commun.
* **Contrainte de base** : Cette extension décrit si le certificat est un certificat de CA ou un certificat d'entité finale. Un certificat de CA est quelque chose qui signe les certificats des autres et un certificat d'entité finale est le certificat utilisé dans une page Web, par exemple (la dernière partie de la chaîne).
* **Identifiant de clé du sujet** (SKI) : Cette extension déclare un **identifiant** unique pour la **clé** publique dans le certificat. Elle est requise sur tous les certificats de CA. Les CA propagent leur propre SKI à l'extension Identifiant de clé de l'émetteur (AKI)
* **Identifiant de clé d'autorité** : Il contient un identifiant de clé dérivé de la clé publique dans le certificat émetteur. C'est le hachage de la clé publique de l'émetteur.
* **Accès aux informations de l'autorité** (AIA) : Cette extension contient au maximum deux types d'informations :
* Informations sur **comment obtenir l'émetteur de ce certificat** (méthode d'accès à l'émetteur de CA)
* Adresse du **répondeur OCSP où la révocation de ce certificat** peut être vérifiée (méthode d'accès OCSP).
* **Points de distribution de la liste de révocation (CRL)** : Cette extension identifie l'emplacement de la CRL à partir de laquelle la révocation de ce certificat peut être vérifiée. L'application qui traite le certificat peut obtenir l'emplacement de la CRL à partir de cette extension, télécharger la CRL, puis vérifier la révocation de ce certificat.
* **CT Precertificate SCTs** : Journaux de transparence des certificats concernant le certificat

### Différence entre OCSP et les points de distribution de la liste de révocation (CRL)

**OCSP** (RFC 2560) est un protocole standard qui comprend un **client OCSP et un répondeur OCSP**. Ce protocole **détermine l'état de révocation d'un certificat de clé publique numérique donné** **sans** avoir à **télécharger** la **liste de révocation complète**.\
**CRL** est la **méthode traditionnelle** de vérification de la validité du certificat. Une **CRL fournit une liste de numéros de série de certificats** qui ont été révoqués ou ne sont plus valides. Les CRL permettent au vérificateur de vérifier l'état de révocation du certificat présenté lors de sa vérification. Les CRL sont limitées à 512 entrées.\
À partir de [ici](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### Qu'est-ce que la transparence des certificats

La transparence des certificats vise à remédier aux menaces basées sur les certificats en **rendant l'émission et l'existence des certificats SSL accessibles à l'examen des propriétaires de domaines, des AC et des utilisateurs de domaines**. Plus précisément, la transparence des certificats a trois objectifs principaux :

* Rendre impossible (ou du moins très difficile) pour une AC de **délivrer un certificat SSL pour un domaine sans que le propriétaire** de ce domaine **puisse le voir**.
* Fournir un **système d'audit et de surveillance ouvert** permettant à tout propriétaire de domaine ou à toute AC de déterminer si des certificats ont été délivrés par erreur ou de manière malveillante.
* **Protéger les utilisateurs** (autant que possible) contre les certificats délivrés par erreur ou de manière malveillante.

#### **Journaux de certificats**

Les journaux de certificats sont des services réseau simples qui conservent des **enregistrements de certificats garantis cryptographiquement, vérifiables publiquement et en ajout seulement**. **N'importe qui peut soumettre des certificats à un journal**, bien que les autorités de certification soient susceptibles d'être les principaux soumissionnaires. De même, n'importe qui peut interroger un journal pour obtenir une preuve cryptographique, qui peut être utilisée pour vérifier que le journal se comporte correctement ou vérifier qu'un certificat particulier a été enregistré. Le nombre de serveurs de journaux n'a pas besoin d'être élevé (disons, beaucoup moins d'un millier dans le monde entier), et chacun pourrait être exploité indépendamment par une AC, un FAI ou toute autre partie intéressée.

#### Requête

Vous pouvez interroger les journaux de transparence des certificats de n'importe quel domaine sur [https://crt.sh/](https://crt.sh).

## Formats

Il existe différents formats pouvant être utilisés pour stocker un certificat.

#### **Format PEM**

* C'est le format le plus couramment utilisé pour les certificats.
* La plupart des serveurs (par exemple, Apache) s'attendent à ce que les certificats et la clé privée soient dans des fichiers séparés.\
\- Habituellement, ils sont des fichiers ASCII encodés en Base64.\
\- Les extensions utilisées pour les certificats PEM sont .cer, .crt, .pem, .key.\
\- Apache et des serveurs similaires utilisent des certificats au format PEM.

#### **Format DER**

* Le format DER est la forme binaire du certificat.
* Tous les types de certificats et de clés privées peuvent être encodés au format DER.
* Les certificats au format DER ne contiennent pas les déclarations "BEGIN CERTIFICATE/END CERTIFICATE".
* Les certificats au format DER utilisent le plus souvent les extensions '.cer' et '.der'.
* DER est généralement utilisé dans les plates-formes Java.

#### **Format P7B/PKCS#7**

* Le format PKCS#7 ou P7B est stocké au format ASCII Base64 et a une extension de fichier .p7b ou .p7c.
* Un fichier P7B ne contient que des certificats et des certificats de chaîne (AC intermédiaires), pas la clé privée.
* Les plates-formes les plus courantes qui prennent en charge les fichiers P7B sont Microsoft Windows et Java Tomcat.

#### **Format PFX/P12/PKCS#12**

* Le format PKCS#12 ou PFX/P12 est un format binaire pour stocker le certificat du serveur, les certificats intermédiaires et la clé privée dans un seul fichier chiffrable.
* Ces fichiers ont généralement des extensions telles que .pfx et .p12.
* Ils sont généralement utilisés sur les machines Windows pour importer et exporter des certificats et des clés privées.

### Conversions de formats

**Convertir x509 en PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
To convert a PEM (Privacy Enhanced Mail) certificate file to DER (Distinguished Encoding Rules) format, you can use the OpenSSL command-line tool. The following command can be used for the conversion:

```bash
openssl x509 -in certificate.pem -outform der -out certificate.der
```

This command takes the input file `certificate.pem` in PEM format and converts it to DER format, saving the output as `certificate.der`.
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
To convert a DER (Distinguished Encoding Rules) certificate to PEM (Privacy Enhanced Mail) format, you can use the OpenSSL command-line tool. The following command can be used:

```bash
openssl x509 -inform der -in certificate.der -out certificate.pem
```

Replace `certificate.der` with the path to your DER certificate file. After running the command, a new PEM certificate file named `certificate.pem` will be created.

**Convert PEM to DER**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Convertir PEM en P7B**

**Remarque :** Le format PKCS#7 ou P7B est stocké au format ASCII Base64 et a une extension de fichier .p7b ou .p7c. Un fichier P7B ne contient que des certificats et des certificats de chaîne (CA intermédiaires), pas la clé privée. Les plateformes les plus courantes qui prennent en charge les fichiers P7B sont Microsoft Windows et Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
To convert a PKCS7 file to PEM format, you can use the OpenSSL command-line tool. The PKCS7 file contains certificates and/or CRLs (Certificate Revocation Lists) in a binary format, while the PEM format is a base64-encoded ASCII representation of the same data.

Here's the command to convert a PKCS7 file to PEM:

```plaintext
openssl pkcs7 -inform der -in input.p7b -out output.pem -print_certs
```

Replace `input.p7b` with the path to your PKCS7 file, and `output.pem` with the desired name for the PEM file.

This command uses the `pkcs7` command of OpenSSL, with the following options:
- `-inform der` specifies that the input file is in DER format.
- `-in input.p7b` specifies the input PKCS7 file.
- `-out output.pem` specifies the output PEM file.
- `-print_certs` instructs OpenSSL to print the certificates in the PKCS7 file.

After running the command, you will have a PEM file containing the certificates from the PKCS7 file.
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Convertir pfx en PEM**

**Remarque :** Le format PKCS#12 ou PFX est un format binaire permettant de stocker le certificat du serveur, les certificats intermédiaires et la clé privée dans un seul fichier chiffrable. Les fichiers PFX ont généralement des extensions telles que .pfx et .p12. Les fichiers PFX sont généralement utilisés sur les machines Windows pour importer et exporter des certificats et des clés privées.
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**Convertir PFX en PKCS#8**\
**Remarque :** Cela nécessite 2 commandes

**1- Convertir PFX en PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- Convertir PEM en PKCS8**

To convert a PEM (Privacy-Enhanced Mail) formatted file to PKCS8 (Public-Key Cryptography Standards #8) format, you can use the following OpenSSL command:

Pour convertir un fichier au format PEM (Privacy-Enhanced Mail) en format PKCS8 (Public-Key Cryptography Standards #8), vous pouvez utiliser la commande OpenSSL suivante :

```plaintext
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.pk8 -nocrypt
```

This command will convert the private key file `private_key.pem` from PEM format to PKCS8 format and save it as `private_key.pk8`. The `-topk8` option specifies that the output should be in PKCS8 format. The `-inform PEM` option specifies that the input file is in PEM format. The `-outform DER` option specifies that the output file should be in DER (Distinguished Encoding Rules) format, which is a binary format used by PKCS8. The `-nocrypt` option specifies that the private key should not be encrypted with a passphrase.

Cette commande convertira le fichier de clé privée `private_key.pem` du format PEM au format PKCS8 et le sauvegardera sous le nom `private_key.pk8`. L'option `-topk8` spécifie que la sortie doit être au format PKCS8. L'option `-inform PEM` spécifie que le fichier d'entrée est au format PEM. L'option `-outform DER` spécifie que le fichier de sortie doit être au format DER (Distinguished Encoding Rules), qui est un format binaire utilisé par PKCS8. L'option `-nocrypt` spécifie que la clé privée ne doit pas être chiffrée avec une phrase secrète.
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**Convertir P7B en PFX**\
**Remarque :** Cela nécessite 2 commandes

1- **Convertir P7B en CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- Convertir un fichier CER et une clé privée en PFX**

Pour convertir un fichier CER et une clé privée en format PFX, vous pouvez utiliser l'outil OpenSSL. Voici les étapes à suivre :

1. Assurez-vous d'avoir OpenSSL installé sur votre système.
2. Ouvrez une fenêtre de terminal ou une invite de commandes.
3. Naviguez jusqu'au répertoire où se trouvent les fichiers CER et la clé privée.
4. Exécutez la commande suivante pour convertir les fichiers en format PFX :

```plaintext
openssl pkcs12 -export -out cert.pfx -inkey private.key -in cert.cer
```

Assurez-vous de remplacer `private.key` par le nom de votre fichier de clé privée et `cert.cer` par le nom de votre fichier CER.

5. Lorsque vous exécutez la commande, OpenSSL vous demandera de définir un mot de passe pour le fichier PFX. Choisissez un mot de passe sécurisé et souvenez-vous-en.

Une fois la commande exécutée avec succès, vous aurez un fichier PFX contenant à la fois le certificat et la clé privée. Ce fichier peut être utilisé dans diverses applications et systèmes pour sécuriser les communications et les transactions.
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
