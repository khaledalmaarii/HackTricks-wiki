# Certificats

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Qu'est-ce qu'un certificat

En cryptographie, un **certificat de clé publique**, également connu sous le nom de **certificat numérique** ou de **certificat d'identité**, est un document électronique utilisé pour prouver la propriété d'une clé publique. Le certificat comprend des informations sur la clé, des informations sur l'identité de son propriétaire (appelé le sujet) et la signature numérique d'une entité qui a vérifié le contenu du certificat (appelée l'émetteur). Si la signature est valide et que le logiciel examinant le certificat fait confiance à l'émetteur, il peut utiliser cette clé pour communiquer en toute sécurité avec le sujet du certificat.

Dans un schéma d'infrastructure à clé publique (PKI) typique, l'émetteur de certificat est une autorité de certification (CA), généralement une entreprise qui facture des clients pour leur délivrer des certificats. En revanche, dans un schéma de toile de confiance, les individus signent directement les clés des autres, dans un format qui remplit une fonction similaire à celle d'un certificat de clé publique.

Le format le plus courant pour les certificats de clé publique est défini par X.509. Comme X.509 est très général, le format est en outre contraint par des profils définis pour certains cas d'utilisation, tels que l'infrastructure à clé publique (X.509) telle que définie dans la RFC 5280.

## Champs communs de x509

* **Numéro de version** : Version du format x509.
* **Numéro de série** : Utilisé pour identifier de manière unique le certificat dans les systèmes d'une CA. En particulier, cela est utilisé pour suivre les informations de révocation.
* **Sujet** : L'entité à laquelle appartient un certificat : une machine, un individu ou une organisation.
  * **Nom commun** : Domaines affectés par le certificat. Peut être 1 ou plusieurs et peut contenir des caractères génériques.
  * **Pays (C)** : Pays
  * **Nom distinctif (DN)** : Tout le sujet : `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
  * **Localité (L)** : Lieu local
  * **Organisation (O)** : Nom de l'organisation
  * **Unité organisationnelle (OU)** : Division d'une organisation (comme "Ressources humaines").
  * **État ou province (ST, S ou P)** : Liste des noms d'État ou de province
* **Émetteur** : L'entité qui a vérifié les informations et signé le certificat.
  * **Nom commun (CN)** : Nom de l'autorité de certification
  * **Pays (C)** : Pays de l'autorité de certification
  * **Nom distinctif (DN)** : Nom distinctif de l'autorité de certification
  * **Localité (L)** : Lieu local où l'organisation peut être trouvée.
  * **Organisation (O)** : Nom de l'organisation
  * **Unité organisationnelle (OU)** : Division d'une organisation (comme "Ress
#### **Format DER**

* Le format DER est la forme binaire du certificat
* Tous les types de certificats et de clés privées peuvent être encodés en format DER
* Les certificats formatés en DER ne contiennent pas les déclarations "BEGIN CERTIFICATE/END CERTIFICATE"
* Les certificats formatés en DER utilisent le plus souvent les extensions ".cer" et ".der"
* DER est généralement utilisé dans les plates-formes Java

#### **Format P7B/PKCS#7**

* Le format PKCS#7 ou P7B est stocké en format ASCII Base64 et a une extension de fichier ".p7b" ou ".p7c"
* Un fichier P7B ne contient que des certificats et des certificats de chaîne (CA intermédiaires), pas la clé privée
* Les plates-formes les plus courantes qui prennent en charge les fichiers P7B sont Microsoft Windows et Java Tomcat

#### **Format PFX/P12/PKCS#12**

* Le format PKCS#12 ou PFX/P12 est un format binaire pour stocker le certificat de serveur, les certificats intermédiaires et la clé privée dans un seul fichier chiffrable
* Ces fichiers ont généralement des extensions telles que ".pfx" et ".p12"
* Ils sont généralement utilisés sur les machines Windows pour importer et exporter des certificats et des clés privées

### Conversions de formats

**Convertir x509 en PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Convertir PEM en DER**

To convert a PEM certificate to DER format you can use the following command:

Pour convertir un certificat PEM en format DER, vous pouvez utiliser la commande suivante :

```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
```
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**Convertir DER en PEM**

Il est possible de convertir un certificat au format DER en format PEM en utilisant la commande suivante:

```
openssl x509 -inform der -in certificate.der -out certificate.pem
``` 

Cela convertira le certificat DER en un certificat PEM.
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Convertir PEM en P7B**

**Note:** Le format PKCS#7 ou P7B est stocké en format ASCII Base64 et a une extension de fichier .p7b ou .p7c. Un fichier P7B ne contient que des certificats et des certificats de chaîne (CA intermédiaires), pas la clé privée. Les plates-formes les plus courantes qui prennent en charge les fichiers P7B sont Microsoft Windows et Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Convertir PKCS7 en PEM**

Il est possible de convertir un certificat PKCS7 en format PEM en utilisant la commande suivante:

```
openssl pkcs7 -print_certs -in certificate.p7b -out certificate.pem
```

Cela va extraire tous les certificats contenus dans le fichier PKCS7 et les écrire dans un fichier PEM.
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Convertir un fichier pfx en PEM**

**Note:** Le format PKCS#12 ou PFX est un format binaire pour stocker le certificat du serveur, les certificats intermédiaires et la clé privée dans un seul fichier chiffrable. Les fichiers PFX ont généralement des extensions telles que .pfx et .p12. Les fichiers PFX sont généralement utilisés sur les machines Windows pour importer et exporter des certificats et des clés privées.
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**Convertir PFX en PKCS#8**\
**Note:** Cela nécessite 2 commandes

**1- Convertir PFX en PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- Convertir PEM en PKCS8**

Pour convertir un certificat PEM en format PKCS8, vous pouvez utiliser la commande suivante:

```
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.pk8
```

Cela convertira la clé privée du format PEM au format PKCS8 et la stockera dans le fichier `private_key.pk8`.
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**Convertir P7B en PFX**\
**Remarque:** Cela nécessite 2 commandes

1- **Convertir P7B en CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- Convertir CER et clé privée en PFX**

Pour convertir un certificat CER et une clé privée en un fichier PFX, vous pouvez utiliser la commande suivante:

```
openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.cer
```

Cela créera un fichier PFX nommé `certificate.pfx` qui contiendra le certificat et la clé privée. Vous devrez spécifier le chemin d'accès à la clé privée et au certificat CER dans la commande.
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.io/) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
