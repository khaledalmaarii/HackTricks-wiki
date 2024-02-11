# Vyeti

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** zinazotumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Nini ni Cheti

**Cheti cha muhimili wa umma** ni kitambulisho cha dijiti kinachotumiwa katika kriptografia kuthibitisha kuwa mtu fulani anamiliki muhimili wa umma. Cheti hicho kinajumuisha maelezo ya muhimili, utambulisho wa mmiliki (mada), na saini ya dijiti kutoka kwa mamlaka iliyoaminika (mtoa cheti). Ikiwa programu inaamini mtoa cheti na saini ni sahihi, mawasiliano salama na mmiliki wa muhimili yanawezekana.

Vyeti kwa kawaida hutolewa na [mamlaka za vyeti](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) katika mfumo wa [miundombinu ya muhimili wa umma](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Njia nyingine ni [wavuti ya uaminifu](https://en.wikipedia.org/wiki/Web_of_trust), ambapo watumiaji wanathibitishana moja kwa moja. Muundo wa kawaida wa vyeti ni [X.509](https://en.wikipedia.org/wiki/X.509), ambao unaweza kubadilishwa kulingana na mahitaji maalum kama ilivyoelezwa katika RFC 5280.

## Sehemu za Kawaida za x509

### **Sehemu za Kawaida katika Vyeti vya x509**

Katika vyeti vya x509, sehemu kadhaa **zina jukumu muhimu** katika kuhakikisha uhalali na usalama wa cheti. Hapa kuna maelezo ya sehemu hizi:

- **Nambari ya Toleo** inaonyesha toleo la muundo wa x509.
- **Nambari ya Serial** inatambua kipekee cheti ndani ya mfumo wa Mamlaka ya Cheti (CA), hasa kwa kufuatilia kufutwa.
- Sehemu ya **Mada** inawakilisha mmiliki wa cheti, ambaye anaweza kuwa mashine, mtu binafsi, au shirika. Inajumuisha utambulisho wa kina kama vile:
- **Jina la Kawaida (CN)**: Anwani za kikoa zinazofunikwa na cheti.
- **Nchi (C)**, **Eneo (L)**, **Jimbo au Mkoa (ST, S, au P)**, **Shirika (O)**, na **Kitengo cha Shirika (OU)** hutoa maelezo ya kijiografia na ya shirika.
- **Jina la Kipekee (DN)** linajumuisha utambulisho kamili wa mada.
- **Mtoa Cheti** anaelezea nani alithibitisha na kusaini cheti, pamoja na sehemu kama hizo za Mada kwa CA.
- **Kipindi cha Uhalali** kina alama za wakati wa **Haijafika Bado** na **Haijafika Baadaye**, kuhakikisha cheti halitumiwi kabla au baada ya tarehe fulani.
- Sehemu ya **Muhimili wa Umma**, muhimu kwa usalama wa cheti, inaelezea algorithm, ukubwa, na maelezo mengine ya kiufundi ya muhimili wa umma.
- **Vipengele vya x509v3** huongeza utendaji wa cheti, kwa kufafanua **Matumizi ya Muhimili**, **Matumizi ya Muhimili Yaliyopanuliwa**, **Jina Mbadala la Mada**, na mali nyingine za kufinaisha matumizi ya cheti.

#### **Matumizi ya Muhimili na Vipengele**

- **Matumizi ya Muhimili** yanatambua matumizi ya kriptografia ya muhimili wa umma, kama saini ya dijiti au kuficha ufunguo.
- **Matumizi ya Muhimili Yaliyopanuliwa** yanapunguza zaidi matumizi ya cheti, kwa mfano, kwa uthibitishaji wa seva za TLS.
- **Jina Mbadala la Mada** na **Kizuizi cha Msingi** hufafanua anwani za ziada zinazofunikwa na cheti na ikiwa ni cheti cha CA au mwisho-mwili.
- Vitambulisho kama **Kitambulisho cha Muhimili wa Mada** na **Kitambulisho cha Muhimili wa Mamlaka** huhakikisha kipekee na ufuatiliaji wa funguo.
- **Maelezo ya Kufikia Mamlaka** na **Vituo vya Usambazaji vya CRL** hutoa njia za kuthibitisha CA inayotoa na kuangalia hali ya kufutwa kwa cheti.
- **CT Precertificate SCTs** hutoa kumbukumbu za uwazi, muhimu kwa imani ya umma kwa cheti.
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
### **Tofauti kati ya OCSP na CRL Distribution Points**

**OCSP** (**RFC 2560**) inahusisha mteja na mtoaji wa majibu kufanya kazi pamoja ili kuthibitisha ikiwa cheti cha umma cha ufunguo wa dijiti kimebatilishwa, bila haja ya kupakua **CRL** kamili. Njia hii ni bora zaidi kuliko **CRL** ya jadi, ambayo hutoa orodha ya nambari za kisiri za vyeti vilivyobatilishwa lakini inahitaji kupakua faili kubwa inayowezekana. CRLs inaweza kuwa na hadi vitu 512. Maelezo zaidi yanapatikana [hapa](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Nini ni Certificate Transparency**

Certificate Transparency inasaidia kupambana na vitisho vinavyohusiana na vyeti kwa kuhakikisha utoaji na uwepo wa vyeti vya SSL unaweza kuonekana na wamiliki wa kikoa, CAs, na watumiaji. Lengo lake ni:

* Kuzuia CAs kutolea vyeti vya SSL kwa kikoa bila idhini ya mmiliki wa kikoa.
* Kuweka mfumo wa ukaguzi wazi kwa kufuatilia vyeti vilivyotolewa kwa makosa au kwa nia mbaya.
* Kulinda watumiaji dhidi ya vyeti vya udanganyifu.

#### **Rekodi za Cheti**

Rekodi za cheti ni rekodi zinazoweza kukaguliwa hadharani, zisizoweza kubadilishwa, za vyeti, zinazosimamiwa na huduma za mtandao. Rekodi hizi zinatoa ushahidi wa kriptografia kwa madhumuni ya ukaguzi. Mamlaka za utoaji na umma wanaweza kuwasilisha vyeti kwa rekodi hizi au kuuliza kwa ajili ya uthibitisho. Ingawa idadi halisi ya seva za rekodi haijafungwa, inatarajiwa kuwa chini ya elfu kote ulimwenguni. Seva hizi zinaweza kusimamiwa kwa kujitegemea na CAs, ISPs, au taasisi yoyote inayohusika.

#### **Utafutaji**

Ili kutafuta rekodi za Certificate Transparency kwa kikoa chochote, tembelea [https://crt.sh/](https://crt.sh).

Kuna muundo tofauti kwa kuhifadhi vyeti, kila moja ikiwa na matumizi yake na utangamano wake. Muhtasari huu unashughulikia muundo mkuu na hutoa mwongozo juu ya jinsi ya kubadilisha kati yao.

## **Muundo**

### **Muundo wa PEM**
- Muundo unaotumiwa sana kwa vyeti.
- Unahitaji faili tofauti kwa vyeti na funguo za kibinafsi, zilizohifadhiwa kwa msimbo wa Base64 ASCII.
- Vifungu vya kawaida: .cer, .crt, .pem, .key.
- Hutumiwa hasa na Apache na seva kama hizo.

### **Muundo wa DER**
- Muundo wa kibayoteki wa vyeti.
- Hauna taarifa za "BEGIN/END CERTIFICATE" zinazopatikana katika faili za PEM.
- Vifungu vya kawaida: .cer, .der.
- Mara nyingi hutumiwa na majukwaa ya Java.

### **Muundo wa P7B/PKCS#7**
- Unahifadhiwa kwa msimbo wa Base64 ASCII, na vifungu vya .p7b au .p7c.
- Una vyeti tu na vyeti vya mnyororo, bila kujumuisha funguo za kibinafsi.
- Inasaidiwa na Microsoft Windows na Java Tomcat.

### **Muundo wa PFX/P12/PKCS#12**
- Muundo wa kibayoteki unaofunga vyeti vya seva, vyeti vya kati, na funguo za kibinafsi katika faili moja.
- Vifungu: .pfx, .p12.
- Hutumiwa hasa kwenye Windows kwa kuagiza na kuuza vyeti.

### **Kubadilisha Muundo**

**Ubunifu wa PEM** ni muhimu kwa utangamano:

- **x509 kwenda PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM kuwa DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER hadi PEM**

Ili kubadilisha cheti cha muundo wa DER kwenda PEM, unaweza kutumia zana ya OpenSSL. Fuata hatua zifuatazo:

1. Pakua cheti la DER kwenye mfumo wako.
2. Fungua terminal na tumia amri ifuatayo:

   ```plaintext
   openssl x509 -inform der -in certificate.der -out certificate.pem
   ```

   Badilisha "certificate.der" na jina la faili la cheti la DER ulilopakua.

3. Baada ya kutekeleza amri hiyo, cheti lako la DER litabadilishwa na kuwa cheti la PEM. Unaweza kupata cheti la PEM katika faili la "certificate.pem".

Kwa njia hii, unaweza kubadilisha cheti la muundo wa DER kwenda PEM kwa urahisi.
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM hadi P7B**

Ili kubadilisha faili ya PEM kuwa P7B, unaweza kutumia zana ya OpenSSL. Fuata hatua zifuatazo:

1. Pakua na usakinishe OpenSSL kwenye mfumo wako.
2. Fungua terminal au amri ya msingi na nenda kwenye saraka ambapo faili ya PEM iko.
3. Tumia amri ifuatayo kubadilisha faili ya PEM kuwa P7B:

   ```plaintext
   openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b -certfile ca.pem
   ```

   Hakikisha kubadilisha "certificate.pem" na jina la faili ya PEM unayotumia, na "ca.pem" na jina la faili ya CA ikiwa ni lazima.

4. Baada ya kukamilisha, faili ya P7B itaundwa katika saraka hiyo hiyo. Unaweza sasa kutumia faili hii kwa madhumuni yako ya kificho.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 hadi PEM**

PKCS7 ni muundo wa cheti ambao unaweza kutumiwa kwa kusaini na kusimbua data. Ili kubadilisha cheti cha PKCS7 kuwa muundo wa PEM, unaweza kufuata hatua zifuatazo:

1. Fungua faili ya PKCS7 kwa kutumia programu ya kusimba data.
2. Tafuta sehemu ya cheti cha PKCS7 ndani ya faili.
3. Nakili cheti hicho na uweke kwenye faili mpya.
4. Badilisha jina la faili mpya kuwa na ugani wa ".pem".

Baada ya hatua hizi, utakuwa umebadilisha cheti cha PKCS7 kuwa muundo wa PEM. Cheti hicho kinaweza kutumiwa kwa shughuli zingine za usalama wa mtandao.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Ubadilishaji wa PFX** ni muhimu katika kusimamia vyeti kwenye Windows:

- **PFX kwenda PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX hadi PKCS#8** inahusisha hatua mbili:
1. Geuza PFX kuwa PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Badilisha PEM kuwa PKCS8

Unaweza kubadilisha faili ya PEM kuwa PKCS8 kwa kutumia zana ya OpenSSL. Hapa kuna hatua za kufuata:

1. Fungua terminal yako na tumia amri ifuatayo:

   ```plaintext
   openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem -nocrypt
   ```

   Badilisha `private_key.pem` na njia ya faili yako ya PEM ya kibinafsi na `private_key_pkcs8.pem` na njia ya faili ya PKCS8 ambayo unataka kuunda.

2. Baada ya kutekeleza amri hiyo, faili yako ya PEM itabadilishwa kuwa PKCS8 na itahifadhiwa kwenye faili mpya ya PKCS8.

Kwa kufuata hatua hizi, utaweza kubadilisha faili ya PEM kuwa PKCS8 kwa urahisi.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B hadi PFX** pia inahitaji amri mbili:
1. Geuza P7B kuwa CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Badilisha CER na Private Key kuwa PFX

```plaintext
To convert a CER file and a private key to a PFX file, you can use the OpenSSL tool. Here's the command you can use:

```bash
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.cer
```

This command will create a PFX file called `certificate.pfx` by combining the private key from `private.key` and the certificate from `certificate.cer`. Make sure you have OpenSSL installed on your system before running this command.

Once the command is executed successfully, you will have the PFX file that contains both the private key and the certificate. This file can be used for various purposes, such as importing it into a web server or using it for digital signing.

Remember to keep the PFX file secure, as it contains sensitive information.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** na kutumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
