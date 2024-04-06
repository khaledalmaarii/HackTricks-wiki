# Sertifikate

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Wat is 'n Sertifikaat

'n **Openbare sleutel sertifikaat** is 'n digitale ID wat in kriptografie gebruik word om te bewys dat iemand 'n openbare sleutel besit. Dit sluit die sleutel se besonderhede, die eienaar se identiteit (die onderwerp), en 'n digitale handtekening van 'n vertroude gesag (die uitreiker) in. As die sagteware die uitreiker vertrou en die handtekening geldig is, is veilige kommunikasie met die sleuteleienaar moontlik.

Sertifikate word meestal uitgereik deur [sertifikaatowerhede](https://en.wikipedia.org/wiki/Certificate\_authority) (CA's) in 'n [openbare sleutelinfrastruktuur](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) opstelling. 'n Ander metode is die [web van vertroue](https://en.wikipedia.org/wiki/Web\_of\_trust), waar gebruikers direk mekaar se sleutels verifieer. Die algemene formaat vir sertifikate is [X.509](https://en.wikipedia.org/wiki/X.509), wat aangepas kan word vir spesifieke behoeftes soos uiteengesit in RFC 5280.

## x509 Algemene Velde

### **Algemene Velde in x509 Sertifikate**

In x509 sertifikate speel verskeie **velde** kritieke rolle om die sertifikaat se geldigheid en veiligheid te verseker. Hier is 'n uiteensetting van hierdie velde:

* Die **Weergawe Nommer** dui die weergawe van die x509-formaat aan.
* Die **Serienommer** identifiseer die sertifikaat uniek binne 'n Sertifikaatowerheid se (CA) stelsel, hoofsaaklik vir herroepingopsporing.
* Die **Onderwerp** veld verteenwoordig die sertifikaat se eienaar, wat 'n masjien, 'n individu, of 'n organisasie kan wees. Dit sluit gedetailleerde identifikasie in soos:
* **Gemeenskaplike Naam (CN)**: Domeine wat deur die sertifikaat gedek word.
* **Land (C)**, **Lokaliteit (L)**, **Staat of Provinsie (ST, S, of P)**, **Organisasie (O)**, en **Organisasie-eenheid (OU)** verskaf geografiese en organisatoriese besonderhede.
* **Onderskeidingsnaam (DN)** omvat die volledige onderwerpidentifikasie.
* **Uitreiker** besonderhede van wie die sertifikaat geverifieer en onderteken het, insluitend soortgelyke subvelde as die Onderwerp vir die CA.
* **Geldigheidsperiode** word gemerk deur **Nie Voor Nie** en **Nie Na Nie** tydstempels, wat verseker dat die sertifikaat nie voor of na 'n sekere datum gebruik word nie.
* Die **Openbare Sleutel** afdeling, krities vir die sertifikaat se veiligheid, spesifiseer die algoritme, grootte, en ander tegniese besonderhede van die openbare sleutel.
* **x509v3-uitbreidings** verbeter die sertifikaat se funksionaliteit, spesifiseer **Sleutelgebruik**, **Uitgebreide Sleutelgebruik**, **Onderwerp Alternatiewe Naam**, en ander eienskappe om die sertifikaat se toepassing fynaf te stem.

#### **Sleutelgebruik en Uitbreidings**

* **Sleutelgebruik** identifiseer kriptografiese toepassings van die openbare sleutel, soos digitale handtekening of sleutelversleuteling.
* **Uitgebreide Sleutelgebruik** versmalle verder die sertifikaat se gebruike, bv. vir TLS-bedienerverifikasie.
* **Onderwerp Alternatiewe Naam** en **Basiese Beperking** definieer addisionele gasheernaam wat deur die sertifikaat gedek word en of dit 'n CA- of eindentiteitsertifikaat is, onderskeidelik.
* Identifiseerders soos **Onderwerp Sleutelidentifiseerder** en **Uitreiker Sleutelidentifiseerder** verseker uniekheid en naspeurbaarheid van sleutels.
* **Uitreikerinligtings Toegang** en **CRL Verspreidingspunte** bied paaie om die uitreikende CA te verifieer en sertifikaatherroepingsstatus te kontroleer.
* **CT Voor-sertifikaat SCT's** bied deursigtigheidslêers, krities vir openbare vertroue in die sertifikaat.
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
### **Verskil tussen OCSP en CRL Verspreidingspunte**

**OCSP** (**RFC 2560**) behels 'n kliënt en 'n reageerder wat saamwerk om te kontroleer of 'n digitale openbare sleutel sertifikaat herroep is, sonder om die volle **CRL** af te laai. Hierdie metode is meer doeltreffend as die tradisionele **CRL**, wat 'n lys van herroepingsertifikaat serienommers verskaf, maar vereis die aflaai van 'n moontlik groot lêer. CRL's kan tot 512 inskrywings insluit. Meer besonderhede is beskikbaar [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Wat is Sertifikaat Deursigtigheid**

Sertifikaat Deursigtigheid help om sertifikaat-verwante bedreigings te beveg deur te verseker dat die uitreiking en bestaan van SSL-sertifikate sigbaar is vir domein-eienaars, CA's, en gebruikers. Die doelstellings is:

* Voorkoming dat CA's SSL-sertifikate vir 'n domein uitreik sonder die domein-eienaar se kennis.
* Daarstel van 'n oop ouditeringstelsel vir die opsporing van per abuis of booswillig uitgereikte sertifikate.
* Beskerming van gebruikers teen valse sertifikate.

#### **Sertifikaat Logboeke**

Sertifikaat logboeke is openlik ouditeerbare, net-byvoegbare rekords van sertifikate, onderhou deur netwerkdienste. Hierdie logboeke verskaf kriptografiese bewyse vir ouditeringsdoeleindes. Uitreikingsowerhede en die publiek kan sertifikate na hierdie logboeke indien of navraag daaroor doen vir verifikasie. Alhoewel die presiese aantal logbedieners nie vas is nie, word verwag dat dit wêreldwyd minder as 'n duisend sal wees. Hierdie bedieners kan onafhanklik bestuur word deur CA's, ISP's, of enige belanghebbende entiteit.

#### **Navraag**

Om Sertifikaat Deursigtigheid logboeke vir enige domein te ondersoek, besoek [https://crt.sh/](https://crt.sh).

Verskillende formate bestaan vir die stoor van sertifikate, elk met sy eie gebruike en verenigbaarheid. Hierdie opsomming dek die hoof formate en bied leiding oor die omskakeling tussen hulle.

## **Formate**

### **PEM Formaat**

* Mees algemeen gebruikte formaat vir sertifikate.
* Vereis aparte lêers vir sertifikate en privaatsleutels, gekodeer in Base64 ASCII.
* Gewone uitbreidings: .cer, .crt, .pem, .key.
* Primêr gebruik deur Apache en soortgelyke bedieners.

### **DER Formaat**

* 'n Binêre formaat van sertifikate.
* Ontbreek die "BEGIN/END SERTIFIKAAT" verklarings wat in PEM lêers gevind word.
* Gewone uitbreidings: .cer, .der.
* Dikwels gebruik met Java platforms.

### **P7B/PKCS#7 Formaat**

* Gestoor in Base64 ASCII, met uitbreidings .p7b of .p7c.
* Bevat slegs sertifikate en kettingsertifikate, met uitsluiting van die privaatsleutel.
* Ondersteun deur Microsoft Windows en Java Tomcat.

### **PFX/P12/PKCS#12 Formaat**

* 'n Binêre formaat wat bedienersertifikate, intermediêre sertifikate, en privaatsleutels in een lêer inkapsuleer.
* Uitbreidings: .pfx, .p12.
* Hoofsaaklik gebruik op Windows vir sertifikaat invoer en uitvoer.

### **Omskakeling van Formate**

**PEM omskakelings** is noodsaaklik vir verenigbaarheid:

* **x509 na PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM na DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER na PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM na P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 na PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX-omskakelings** is noodsaaklik vir die bestuur van sertifikate op Windows:

* **PFX na PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX na PKCS#8** behels twee stappe:
1. Omskep PFX na PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Omskep PEM na PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B na PFX** vereis ook twee bevele:
1. Omskep P7B na CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Omskep CER en Privaatsleutel na PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiseer werkstrome** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
