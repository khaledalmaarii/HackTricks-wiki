# Certificats

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Qu'est-ce qu'un Certificat

En cryptographie, un **certificat de clé publique**, également connu sous le nom de **certificat numérique** ou **certificat d'identité**, est un document électronique utilisé pour prouver la propriété d'une clé publique. Le certificat comprend des informations sur la clé, des informations sur l'identité de son propriétaire (appelé le sujet), et la signature numérique d'une entité qui a vérifié le contenu du certificat (appelé l'émetteur). Si la signature est valide et que le logiciel examinant le certificat fait confiance à l'émetteur, alors il peut utiliser cette clé pour communiquer en toute sécurité avec le sujet du certificat.

Dans un schéma typique d'infrastructure à clé publique (PKI), l'émetteur du certificat est une autorité de certification (CA), généralement une entreprise qui facture aux clients l'émission de certificats pour eux. En revanche, dans un schéma de toile de confiance, les individus signent directement les clés les uns des autres, dans un format qui remplit une fonction similaire à celle d'un certificat de clé publique.

Le format le plus courant pour les certificats de clé publique est défini par [X.509](https://en.wikipedia.org/wiki/X.509). Comme X.509 est très général, le format est davantage contraint par des profils définis pour certains cas d'utilisation, tels que [Infrastructure à clé publique (X.509)](https://en.wikipedia.org/wiki/PKIX) tel que défini dans la RFC 5280.

## Champs communs x509

* **Numéro de Version :** Version du format x509.
* **Numéro de Série :** Utilisé pour identifier de manière unique le certificat au sein des systèmes d'une CA. En particulier, cela sert à suivre les informations de révocation.
* **Sujet :** L'entité à laquelle appartient un certificat : une machine, un individu ou une organisation.
* **Nom Commun :** Domaines affectés par le certificat. Peut être 1 ou plusieurs et peut contenir des jokers.
* **Pays (C) :** Pays
* **Nom distinctif (DN) :** Tout le sujet : `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **Localité (L) :** Lieu local
* **Organisation (O) :** Nom de l'organisation
* **Unité Organisationnelle (OU) :** Division d'une organisation (comme "Ressources Humaines").
* **État ou Province (ST, S ou P) :** Liste des noms d'état ou de province
* **Émetteur :** L'entité qui a vérifié les informations et signé le certificat.
* **Nom Commun (CN) :** Nom de l'autorité de certification
* **Pays (C) :** Pays de l'autorité de certification
* **Nom distinctif (DN) :** Nom distinctif de l'autorité de certification
* **Localité (L) :** Lieu local où l'organisation peut être trouvée.
* **Organisation (O) :** Nom de l'organisation
* **Unité Organisationnelle (OU) :** Division d'une organisation (comme "Ressources Humaines").
* **Pas Avant :** La date et l'heure les plus précoces auxquelles le certificat est valide. Généralement fixé à quelques heures ou jours avant le moment où le certificat a été émis, pour éviter les problèmes de décalage horaire.
* **Pas Après :** La date et l'heure après lesquelles le certificat n'est plus valide.
* **Clé Publique :** Une clé publique appartenant au sujet du certificat. (C'est l'une des parties principales car c'est ce qui est signé par la CA)
* **Algorithme de Clé Publique :** Algorithme utilisé pour générer la clé publique. Comme RSA.
* **Courbe de Clé Publique :** La courbe utilisée par l'algorithme de clé publique à courbe elliptique (si applicable). Comme nistp521.
* **Exposant de Clé Publique :** Exposant utilisé pour dériver la clé publique (si applicable). Comme 65537.
* **Taille de Clé Publique :** La taille de l'espace de clé publique en bits. Comme 2048.
* **Algorithme de Signature :** L'algorithme utilisé pour signer le certificat de clé publique.
* **Signature :** Une signature du corps du certificat par la clé privée de l'émetteur.
* **extensions x509v3**
* **Usage de la Clé :** Les utilisations cryptographiques valides de la clé publique du certificat. Les valeurs courantes incluent la validation de signature numérique, le chiffrement de clé et la signature de certificat.
* Dans un certificat Web, cela apparaîtra comme une _extension X509v3_ et aura la valeur `Signature Numérique`
* **Usage Étendu de la Clé :** Les applications dans lesquelles le certificat peut être utilisé. Les valeurs courantes incluent l'authentification du serveur TLS, la protection des e-mails et la signature de code.
* Dans un certificat Web, cela apparaîtra comme une _extension X509v3_ et aura la valeur `Authentification du Serveur Web TLS`
* **Nom Alternatif du Sujet :** Permet aux utilisateurs de spécifier des **noms d'hôte** supplémentaires pour un seul **certificat SSL**. L'utilisation de l'extension SAN est une pratique standard pour les certificats SSL, et elle est en passe de remplacer l'utilisation du **nom commun**.
* **Contrainte de Base :** Cette extension décrit si le certificat est un certificat d'autorité de certification ou un certificat d'entité finale. Un certificat d'autorité de certification est quelque chose qui signe les certificats des autres et un certificat d'entité finale est le certificat utilisé dans une page Web par exemple (la dernière partie de la chaîne).
* **Identifiant de Clé du Sujet** (SKI) : Cette extension déclare un **identifiant unique** pour la **clé publique** dans le certificat. Il est requis sur tous les certificats d'autorité de certification. Les CA propagent leur propre SKI à l'extension Identifiant de **Clé de l'Autorité** (AKI) sur les certificats émis. C'est le hash de la clé publique du sujet.
* **Identifiant de Clé de l'Autorité** : Il contient un identifiant de clé qui est dérivé de la clé publique dans le certificat de l'émetteur. C'est le hash de la clé publique de l'émetteur.
* **Accès à l'Information de l'Autorité** (AIA) : Cette extension contient au plus deux types d'informations :
* Informations sur **comment obtenir l'émetteur de ce certificat** (méthode d'accès à l'émetteur de la CA)
* Adresse du **répondeur OCSP d'où la révocation de ce certificat** peut être vérifiée (méthode d'accès OCSP).
* **Points de Distribution CRL** : Cette extension identifie l'emplacement de la CRL à partir de laquelle la révocation de ce certificat peut être vérifiée. L'application qui traite le certificat peut obtenir l'emplacement de la CRL à partir de cette extension, télécharger la CRL, puis vérifier la révocation de ce certificat.
* **CT Precertificate SCTs** : Journaux de transparence des certificats concernant le certificat

### Différence entre OCSP et Points de Distribution CRL

**OCSP** (RFC 2560) est un protocole standard qui consiste en un **client OCSP et un répondeur OCSP**. Ce protocole **détermine le statut de révocation d'un certificat public de clé numérique donné** **sans** avoir à **télécharger** la **CRL complète**.\
**CRL** est la **méthode traditionnelle** de vérification de la validité des certificats. Une **CRL fournit une liste de numéros de série de certificats** qui ont été révoqués ou ne sont plus valides. Les CRL permettent au vérificateur de vérifier le statut de révocation du certificat présenté lors de sa vérification. Les CRL sont limitées à 512 entrées.\
Depuis [ici](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### Qu'est-ce que la Transparence des Certificats

La transparence des certificats vise à remédier aux menaces basées sur les certificats en **rendant l'émission et l'existence des certificats SSL ouverts à l'examen par les propriétaires de domaines, les CA et les utilisateurs de domaines**. Plus précisément, la transparence des certificats a trois objectifs principaux :

* Rendre impossible (ou du moins très difficile) pour une CA d'**émettre un certificat SSL pour un domaine sans que le certificat soit visible par le propriétaire** de ce domaine.
* Fournir un **système d'audit et de surveillance ouvert qui permet à tout propriétaire de domaine ou CA de déterminer si des certificats ont été émis par erreur ou de manière malveillante**.
* **Protéger les utilisateurs** (autant que possible) d'être dupés par des certificats qui ont été émis par erreur ou de manière malveillante.

#### **Journaux de Certificats**

Les journaux de certificats sont des services réseau simples qui maintiennent des enregistrements de certificats **cryptographiquement assurés, publiquement audibles et ajoutés uniquement**. **N'importe qui peut soumettre des certificats à un journal**, bien que les autorités de certification seront probablement les principaux soumissionnaires. De même, n'importe qui peut interroger un journal pour une preuve cryptographique, qui peut être utilisée pour vérifier que le journal se comporte correctement ou vérifier qu'un certificat particulier a été enregistré. Le nombre de serveurs de journaux n'a pas besoin d'être important (disons, bien moins d'un millier dans le monde entier), et chacun pourrait être exploité indépendamment par une CA, un FAI ou toute autre partie intéressée.

#### Requête

Vous pouvez interroger les journaux de transparence des certificats de n'importe quel domaine sur [https://crt.sh/](https://crt.sh).

## Formats

Il existe différents formats qui peuvent être utilisés pour stocker un certificat.

#### **Format PEM**

* C'est le format le plus courant utilisé pour les certificats
* La plupart des serveurs (Ex : Apache) attendent que les certificats et la clé privée soient dans des fichiers séparés\
\- Habituellement, ce sont des fichiers ASCII encodés en Base64\
\- Les extensions utilisées pour les certificats PEM sont .cer, .crt, .pem, .key\
\- Apache et des serveurs similaires utilisent des certificats au format PEM

#### **Format DER**

* Le format DER est la forme binaire du certificat
* Tous les types de certificats et de clés privées peuvent être encodés au format DER
* Les certificats au format DER ne contiennent pas les déclarations "BEGIN CERTIFICATE/END CERTIFICATE"
* Les certificats au format DER utilisent le plus souvent les extensions ‘.cer’ et '.der'
* DER est généralement utilisé dans les plateformes Java

#### **Format P7B/PKCS#7**

* Le format PKCS#7 ou P7B est stocké au format ASCII Base64 et a une extension de fichier de .p7b ou .p7c
* Un fichier P7B ne contient que des certificats et des certificats de chaîne (CAs intermédiaires), pas la clé privée
* Les plateformes les plus courantes qui prennent en charge les fichiers P7B sont Microsoft Windows et Java Tomcat

#### **Format PFX/P12/PKCS#12**

* Le format PKCS#12 ou PFX/P12 est un format binaire pour stocker le certificat du serveur, les certificats intermédiaires et la clé privée dans un seul fichier cryptable
* Ces fichiers ont généralement des extensions telles que .pfx et .p12
* Ils sont généralement utilisés sur les machines Windows pour importer et exporter des certificats et des clés privées

### Conversions de formats

**Convertir x509 en PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Convertir PEM en DER**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**Convertir DER en PEM**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Convertir PEM en P7B**

**Remarque :** Le format PKCS#7 ou P7B est stocké au format ASCII Base64 et a une extension de fichier .p7b ou .p7c. Un fichier P7B contient uniquement les certificats et les chaînes de certificats (Autorités de Certification Intermédiaires), et non la clé privée. Les plateformes les plus courantes qui prennent en charge les fichiers P7B sont Microsoft Windows et Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Convertir PKCS7 en PEM**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Convertir pfx en PEM**

**Remarque :** Le format PKCS#12 ou PFX est un format binaire pour stocker le certificat serveur, les certificats intermédiaires et la clé privée dans un seul fichier cryptable. Les fichiers PFX ont généralement des extensions telles que .pfx et .p12. Les fichiers PFX sont généralement utilisés sur les machines Windows pour importer et exporter des certificats et des clés privées.
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**Convertir PFX en PKCS#8**\
**Note :** Cela nécessite 2 commandes

**1- Convertir PFX en PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- Convertir PEM en PKCS8**
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**Convertir P7B en PFX**\
**Remarque :** Cela nécessite 2 commandes

1- **Convertir P7B en CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- Convertir CER et clé privée en PFX**
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
```markdown
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
