# Sertifikati

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Danas dobijte pristup:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Šta je sertifikat

**Sertifikat javnog ključa** je digitalni ID koji se koristi u kriptografiji kako bi se dokazalo da neko poseduje javni ključ. Uključuje detalje ključa, identitet vlasnika (subjekta) i digitalni potpis od pouzdane autoritete (izdavaoca). Ako softver veruje izdavaocu i potpis je validan, moguća je sigurna komunikacija sa vlasnikom ključa.

Sertifikati se uglavnom izdaju od strane [sertifikacionih autoriteta](https://en.wikipedia.org/wiki/Certificate_authority) (CA) u okviru [infrastrukture javnih ključeva](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Drugi metod je [mreža poverenja](https://en.wikipedia.org/wiki/Web_of_trust), gde korisnici direktno verifikuju ključeve jedni drugih. Uobičajeni format za sertifikate je [X.509](https://en.wikipedia.org/wiki/X.509), koji se može prilagoditi specifičnim potrebama kako je opisano u RFC 5280.

## x509 Uobičajena polja

### **Uobičajena polja u x509 sertifikatima**

U x509 sertifikatima, nekoliko **polja** igraju ključnu ulogu u osiguravanju validnosti i sigurnosti sertifikata. Evo pregleda ovih polja:

- **Broj verzije** označava verziju x509 formata.
- **Seriski broj** jedinstveno identifikuje sertifikat unutar sistema Sertifikacione Autoritete (CA), uglavnom za praćenje povlačenja.
- Polje **Subjekat** predstavlja vlasnika sertifikata, koji može biti mašina, pojedinac ili organizacija. Uključuje detaljne identifikacije kao što su:
- **Uobičajeno ime (CN)**: Domeni obuhvaćeni sertifikatom.
- **Država (C)**, **Lokalitet (L)**, **Država ili Pokrajina (ST, S ili P)**, **Organizacija (O)** i **Organizaciona jedinica (OU)** pružaju geografske i organizacione detalje.
- **Distinguished Name (DN)** sadrži punu identifikaciju subjekta.
- **Izdavalac** detalji o tome ko je verifikovao i potpisao sertifikat, uključujući slična podpolja kao i Subjekat za CA.
- **Period važenja** obeležen je vremenskim oznakama **Not Before** i **Not After**, osiguravajući da sertifikat nije korišćen pre ili posle određenog datuma.
- Odeljak **Javni ključ**, ključan za sigurnost sertifikata, specificira algoritam, veličinu i druge tehničke detalje javnog ključa.
- **x509v3 ekstenzije** poboljšavaju funkcionalnost sertifikata, specificirajući **Upotrebu ključa**, **Proširenu upotrebu ključa**, **Alternativno ime subjekta** i druge osobine radi fino podešavanja primene sertifikata.

#### **Upotreba ključa i ekstenzije**

- **Upotreba ključa** identifikuje kriptografske primene javnog ključa, poput digitalnog potpisa ili šifrovanja ključem.
- **Proširena upotreba ključa** dodatno sužava upotrebu sertifikata, na primer, za autentifikaciju TLS servera.
- **Alternativno ime subjekta** i **Osnovno ograničenje** definišu dodatna imena hostova obuhvaćena sertifikatom i da li je to CA ili sertifikat entiteta.
- Identifikatori poput **Identifikatora ključa subjekta** i **Identifikatora ključa izdavaoca** obezbeđuju jedinstvenost i mogućnost praćenja ključeva.
- **Pristup informacijama o autoritetu** i **Tačke distribucije CRL** obezbeđuju putanje za verifikaciju izdavača CA i proveru statusa povlačenja sertifikata.
- **CT Precertificate SCTs** nude transparentne logove, ključne za javno poverenje u sertifikat.
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
### **Razlika između OCSP i CRL Distribution Points**

**OCSP** (**RFC 2560**) uključuje saradnju između klijenta i odgovorača kako bi se proverilo da li je digitalni javni ključ sertifikata povučen, bez potrebe za preuzimanjem celog **CRL**-a. Ovaj metod je efikasniji od tradicionalnog **CRL**-a, koji pruža listu serijskih brojeva povučenih sertifikata, ali zahteva preuzimanje potencijalno velike datoteke. CRL-ovi mogu sadržati do 512 unosa. Više detalja možete pronaći [ovde](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Šta je Certificate Transparency**

Certificate Transparency pomaže u borbi protiv pretnji vezanih za sertifikate tako što osigurava da izdavanje i postojanje SSL sertifikata budu vidljivi vlasnicima domena, CA-ovima i korisnicima. Njegovi ciljevi su:

* Sprječavanje CA-ova da izdaju SSL sertifikate za domen bez znanja vlasnika domena.
* Uspostavljanje otvorenog sistema za reviziju za praćenje greškom ili zlonamerno izdatih sertifikata.
* Zaštita korisnika od lažnih sertifikata.

#### **Certificate Logs**

Certificate logs su javno proverljivi, samo-dodatni zapisi o sertifikatima, koje održavaju mrežne usluge. Ovi zapisi pružaju kriptografske dokaze u svrhu revizije. Izdavatelji sertifikata i javnost mogu podneti sertifikate ovim logovima ili ih pretraživati radi verifikacije. Iako tačan broj log servera nije fiksan, očekuje se da ih ima manje od hiljadu širom sveta. Ovi serveri mogu biti nezavisno upravljani od strane CA-ova, ISP-ova ili bilo koje zainteresovane entitete.

#### **Pretraga**

Za istraživanje Certificate Transparency logova za bilo koji domen, posetite [https://crt.sh/](https://crt.sh).

Postoje različiti formati za skladištenje sertifikata, pri čemu svaki ima svoje upotrebe i kompatibilnost. Ovaj sažetak obuhvata glavne formate i pruža smernice za konverziju između njih.

## **Formati**

### **PEM Format**
- Najčešće korišćen format za sertifikate.
- Zahteva odvojene datoteke za sertifikate i privatne ključeve, kodirane u Base64 ASCII.
- Uobičajene ekstenzije: .cer, .crt, .pem, .key.
- Pretežno se koristi za Apache i slične servere.

### **DER Format**
- Binarni format sertifikata.
- Ne sadrži "BEGIN/END CERTIFICATE" izjave koje se nalaze u PEM datotekama.
- Uobičajene ekstenzije: .cer, .der.
- Često se koristi sa Java platformama.

### **P7B/PKCS#7 Format**
- Smešten u Base64 ASCII, sa ekstenzijama .p7b ili .p7c.
- Sadrži samo sertifikate i lančane sertifikate, bez privatnog ključa.
- Podržan od strane Microsoft Windows-a i Java Tomcat-a.

### **PFX/P12/PKCS#12 Format**
- Binarni format koji u jednoj datoteci sadrži serverske sertifikate, međusertifikate i privatne ključeve.
- Ekstenzije: .pfx, .p12.
- Pretežno se koristi na Windows-u za uvoz i izvoz sertifikata.

### **Konverzija formata**

**PEM konverzije** su neophodne radi kompatibilnosti:

- **x509 u PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM u DER**

Da biste konvertovali PEM format u DER format, možete koristiti OpenSSL komandu:

```plaintext
openssl x509 -outform der -in certificate.pem -out certificate.der
```

Gde `certificate.pem` predstavlja putanju do PEM sertifikata koji želite da konvertujete, a `certificate.der` predstavlja putanju do izlaznog DER sertifikata.

Ova komanda će konvertovati sertifikat iz PEM formata u DER format.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER u PEM**

Da biste konvertirali DER format u PEM format, možete koristiti OpenSSL alat. Koristite sljedeću naredbu:

```plaintext
openssl x509 -inform der -in certificate.der -out certificate.pem
```

Ova naredba će konvertirati certifikat iz DER formata (certificate.der) u PEM format (certificate.pem).
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM u P7B**

Da biste konvertovali PEM format sertifikata u P7B format, možete koristiti OpenSSL alat. Sledeća komanda će vam pomoći da izvršite konverziju:

```plaintext
openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b
```

Gde `certificate.pem` predstavlja putanju do vašeg PEM sertifikata, a `certificate.p7b` je ime izlaznog P7B fajla. Nakon izvršavanja ove komande, dobićete P7B format sertifikata.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 u PEM**

PKCS7 format je standardni format za enkodiranje i potpisivanje digitalnih sertifikata. PEM format, sa druge strane, je često korišćen format za čuvanje i razmenu kriptografskih ključeva i sertifikata. Da biste konvertovali PKCS7 format u PEM format, možete koristiti sledeću komandu:

```plaintext
openssl pkcs7 -print_certs -in input.p7b -out output.pem
```

Ova komanda će izvršiti konverziju PKCS7 datoteke `input.p7b` u PEM format i sačuvati rezultat u datoteku `output.pem`.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX konverzije** su ključne za upravljanje sertifikatima na Windows operativnom sistemu:

- **PFX u PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX u PKCS#8** uključuje dva koraka:
1. Konvertuj PFX u PEM format.
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konvertuj PEM u PKCS8

Da biste konvertovali PEM format u PKCS8 format, možete koristiti OpenSSL komandu `pkcs8`. Evo kako to možete uraditi:

```plaintext
openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem
```

Ova komanda će konvertovati privatni ključ u PEM formatu (`private_key.pem`) u PKCS8 format i sačuvati ga kao `private_key_pkcs8.pem`.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B u PFX** takođe zahteva dve komande:
1. Konvertuj P7B u CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konvertujte CER i privatni ključ u PFX format

Da biste konvertovali CER i privatni ključ u PFX format, možete koristiti alat kao što je OpenSSL. Evo kako to možete uraditi:

1. Prvo, otvorite terminal i unesite sledeću komandu:

   ```
   openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.cer
   ```

   Ova komanda će kreirati PFX fajl sa nazivom "certificate.pfx" koristeći privatni ključ "private.key" i CER fajl "certificate.cer".

2. Kada pokrenete komandu, bićete upitani da unesete lozinku za PFX fajl. Unesite željenu lozinku i pritisnite Enter.

3. Nakon što unesete lozinku, OpenSSL će generisati PFX fajl koji sadrži CER i privatni ključ.

Sada imate PFX fajl koji možete koristiti za razne svrhe, kao što je instalacija SSL sertifikata na serveru.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
