# Sertifikate

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repositoriums.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werksvloei** te bou met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Wat is 'n Sertifikaat

'n **Openbare sleutel sertifikaat** is 'n digitale ID wat in kriptografie gebruik word om te bewys dat iemand 'n openbare sleutel besit. Dit sluit die sleutel se besonderhede, die eienaar se identiteit (die onderwerp), en 'n digitale handtekening van 'n vertroude gesag (die uitreiker) in. As die sagteware die uitreiker vertrou en die handtekening geldig is, is veilige kommunikasie met die sleutel se eienaar moontlik.

Sertifikate word meestal uitgereik deur [sertifikaatowerhede](https://en.wikipedia.org/wiki/Certificate_authority) (SO's) in 'n [openbare sleutel infrastruktuur](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) opset. 'n Ander metode is die [web van vertroue](https://en.wikipedia.org/wiki/Web_of_trust), waar gebruikers mekaar se sleutels direk verifieer. Die algemene formaat vir sertifikate is [X.509](https://en.wikipedia.org/wiki/X.509), wat aangepas kan word vir spesifieke behoeftes soos uiteengesit in RFC 5280.

## x509 Algemene Velde

### **Algemene Velde in x509 Sertifikate**

In x509 sertifikate speel verskeie **velde** 'n kritieke rol om die geldigheid en veiligheid van die sertifikaat te verseker. Hier is 'n uiteensetting van hierdie velde:

- **Weergawenommer** dui die weergawe van die x509-formaat aan.
- **Serienommer** identifiseer die sertifikaat uniek binne 'n Sertifikaatowerheid (SO) se stelsel, hoofsaaklik vir herroepingstracking.
- Die **Onderwerp**-veld verteenwoordig die eienaar van die sertifikaat, wat 'n masjien, 'n individu, of 'n organisasie kan wees. Dit sluit gedetailleerde identifikasie in soos:
- **Gemeenskaplike Naam (CN)**: Domeine wat deur die sertifikaat gedek word.
- **Land (C)**, **Ligging (L)**, **Staat of Provinsie (ST, S, of P)**, **Organisasie (O)**, en **Organisasie-eenheid (OU)** verskaf geografiese en organisatoriese besonderhede.
- **Onderskeidende Naam (DN)** sluit die volledige onderwerpidentifikasie in.
- **Uitreiker** besonderhede van wie die sertifikaat geverifieer en onderteken het, insluitend soortgelyke subvelde as die Onderwerp vir die SO.
- **Geldigheidsperiode** word aangedui deur **Nie Voor** en **Nie Na** tydstempels, wat verseker dat die sertifikaat nie voor of na 'n sekere datum gebruik word nie.
- Die **Openbare Sleutel**-afdeling, wat krities is vir die veiligheid van die sertifikaat, spesifiseer die algoritme, grootte, en ander tegniese besonderhede van die openbare sleutel.
- **x509v3-uitbreidings** verbeter die funksionaliteit van die sertifikaat deur **Sleutelgebruik**, **Uitgebreide Sleutelgebruik**, **Alternatiewe Naam van Onderwerp**, en ander eienskappe te spesifiseer om die toepassing van die sertifikaat fynaf te stel.

#### **Sleutelgebruik en Uitbreidings**

- **Sleutelgebruik** identifiseer kriptografiese toepassings van die openbare sleutel, soos digitale handtekening of sleutelversleuteling.
- **Uitgebreide Sleutelgebruik** versmalle verder die gebruiksmoontlikhede van die sertifikaat, bv. vir TLS-bedienerverifikasie.
- **Alternatiewe Naam van Onderwerp** en **Basiese Beperking** definieer addisionele gasheernaam wat deur die sertifikaat gedek word en of dit 'n SO- of eindentiteit-sertifikaat is, onderskeidelik.
- Identifiseerders soos **Sleutelidentifiseerder van Onderwerp** en **Sleutelidentifiseerder van Gesag** verseker uniekheid en naspeurbaarheid van sleutels.
- **Gesaginligtings Toegang** en **CRL Verspreidingspunte** verskaf paaie om die uitreikende SO te verifieer en die sertifikaat-herroepingsstatus te kontroleer.
- **CT Voor-sertifikaat SCT's** bied deursigtigheidslêers, wat krities is vir openbare vertroue in die sertifikaat.
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
### **Verskil tussen OCSP en CRL-verspreidingspunte**

**OCSP** (**RFC 2560**) behels 'n kliënt en 'n responder wat saamwerk om te kontroleer of 'n digitale openbare sleutelsertifikaat herroep is, sonder om die volledige **CRL** af te laai. Hierdie metode is doeltreffender as die tradisionele **CRL**, wat 'n lys van herroepingsertifikaatserienommers verskaf, maar 'n potensieel groot lêer vereis om af te laai. CRL's kan tot 512 inskrywings insluit. Meer besonderhede is beskikbaar [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Wat is Sertifikaattransparansie**

Sertifikaattransparansie help om sertifikaatverwante bedreigings te beveg deur te verseker dat die uitreiking en bestaan van SSL-sertifikate sigbaar is vir domeineienaars, CA's en gebruikers. Die doelstellings is as volg:

* Voorkoming dat CA's SSL-sertifikate vir 'n domein uitreik sonder die domeineienaar se kennis.
* Daarstel van 'n oop ouditeringstelsel vir die opspoor van per abuis of booswillig uitgereikte sertifikate.
* Beskerming van gebruikers teen valse sertifikate.

#### **Sertifikaatjoernale**

Sertifikaatjoernale is openbaar ouditeerbare, net byvoegbare rekords van sertifikate wat deur netwerkdienste onderhou word. Hierdie joernale verskaf kriptografiese bewyse vir ouditeringsdoeleindes. Beide uitreikingsowerhede en die publiek kan sertifikate na hierdie joernale indien of dit ondersoek vir verifikasie. Alhoewel die presiese aantal joernaalbedieners nie vasstaan nie, word verwag dat dit wêreldwyd minder as 'n duisend sal wees. Hierdie bedieners kan onafhanklik deur CA's, ISP's of enige belanghebbende entiteit bestuur word.

#### **Ondersoek**

Om Sertifikaattransparansiejoernale vir enige domein te ondersoek, besoek [https://crt.sh/](https://crt.sh).

Verskillende formate bestaan vir die stoor van sertifikate, elk met sy eie gebruiksscenario's en verenigbaarheid. Hierdie opsomming dek die belangrikste formate en bied leiding oor die omskakeling tussen hulle.

## **Formate**

### **PEM-formaat**
- Die mees algemeen gebruikte formaat vir sertifikate.
- Vereis afsonderlike lêers vir sertifikate en privaatsleutels, gekodeer in Base64 ASCII.
- Gewone uitbreidings: .cer, .crt, .pem, .key.
- Primêr gebruik deur Apache en soortgelyke bedieners.

### **DER-formaat**
- 'n Binêre formaat van sertifikate.
- Ontbreek die "BEGIN/END CERTIFICATE"-verklarings wat in PEM-lêers gevind word.
- Gewone uitbreidings: .cer, .der.
- Word dikwels gebruik met Java-platforms.

### **P7B/PKCS#7-formaat**
- Gestoor in Base64 ASCII, met uitbreidings .p7b of .p7c.
- Bevat slegs sertifikate en kettingsertifikate, sonder die privaatsleutel.
- Ondersteun deur Microsoft Windows en Java Tomcat.

### **PFX/P12/PKCS#12-formaat**
- 'n Binêre formaat wat bedienersertifikate, tussenliggende sertifikate en privaatsleutels in een lêer inkapsuleer.
- Uitbreidings: .pfx, .p12.
- Hoofsaaklik gebruik op Windows vir die invoer en uitvoer van sertifikate.

### **Omskakeling van Formate**

**PEM-omskakelings** is noodsaaklik vir verenigbaarheid:

- **x509 na PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM na DER**

PEM (Privacy-Enhanced Mail) en DER (Distinguished Encoding Rules) is twee verskillende formaatstandaarde vir sertifikate. PEM is 'n Base64-gekodeerde formaat wat gewoonlik gebruik word vir die stoor en oordrag van sertifikate. DER is 'n binêre formaat wat gebruik word vir die verwerking van sertifikate deur programme.

Om 'n PEM-sertifikaat na DER-formaat om te skakel, kan die volgende opdrag gebruik word:

```bash
openssl x509 -in certificate.pem -outform der -out certificate.der
```

Hierdie opdrag sal die PEM-sertifikaat wat in die `certificate.pem`-lêer gestoor is, omskakel na DER-formaat en dit in die `certificate.der`-lêer stoor.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER na PEM**

Om 'n DER-sertifikaat na PEM-formaat om te skakel, kan die volgende stappe gevolg word:

1. Gebruik die OpenSSL-hulpmiddel om die DER-sertifikaat te ontleed en die openbare sleutel daaruit te verkry:

   ```plaintext
   openssl x509 -inform der -in certificate.der -pubkey -noout > public_key.pem
   ```

2. Gebruik die OpenSSL-hulpmiddel om die DER-sertifikaat na PEM-formaat om te skakel:

   ```plaintext
   openssl x509 -inform der -in certificate.der -out certificate.pem
   ```

Die DER-sertifikaat sal nou suksesvol na PEM-formaat omgeskakel word.
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM na P7B**

Om 'n PEM-sertifikaatlêer na 'n P7B-formaat om te skakel, kan die volgende stappe gevolg word:

1. Maak 'n nuwe tekslêer en kopieer die inhoud van die PEM-lêer daarin.
2. Verander die lêernaam na 'n .p7b-lêeruitbreiding.
3. Stoor die lêer en dit sal nou in die P7B-formaat wees.

Dit is belangrik om daarop te let dat die P7B-formaat 'n binêre formaat is en nie die sertifikaat se privaat sleutel bevat nie. Die P7B-lêer bevat slegs die sertifikaatketting.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 na PEM**

Om 'n PKCS7-sertifikaat na PEM-formaat om te skakel, kan die volgende stappe gevolg word:

1. Skep 'n nuwe tekslêer en kopieer die inhoud van die PKCS7-sertifikaat daarin.
2. Verwyder enige lynafbrekings of wit spasies in die tekslêer.
3. Voeg die volgende lyn by die begin van die tekslêer: `-----BEGIN PKCS7-----`.
4. Voeg die volgende lyn by die einde van die tekslêer: `-----END PKCS7-----`.
5. Stoor die tekslêer met die `.pem`-lêeruitbreiding.

Die PKCS7-sertifikaat is nou suksesvol omgeskakel na PEM-formaat.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX-omskakelings** is noodsaaklik vir die bestuur van sertifikate op Windows:

- **PFX na PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX na PKCS#8** behels twee stappe:
1. Omskakel PFX na PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Omskep PEM na PKCS8

Om 'n PEM-sertifikaat na PKCS8-formaat om te skakel, kan jy die volgende stappe volg:

1. Installeer die OpenSSL-hulpmiddel as dit nog nie op jou stelsel geïnstalleer is nie.
2. Open 'n opdragvenster en navigeer na die plek waar die PEM-sertifikaat geleë is.
3. Voer die volgende opdrag in om die PEM-sertifikaat na PKCS8-formaat om te skakel:

   ```plaintext
   openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.pk8 -nocrypt
   ```

   Hier moet jy die korrekte naam van die PEM-sertifikaat vervang met die naam van jou eie sertifikaat.

4. Nadat die opdrag suksesvol uitgevoer is, sal jy 'n nuwe PKCS8-sertifikaat met die naam "private.pk8" hê.

Met hierdie stappe kan jy 'n PEM-sertifikaat na PKCS8-formaat omskep.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B na PFX** vereis ook twee opdragte:
1. Omskakel P7B na CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Omskep CER en Privaatsleutel na PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werksvloeie te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
