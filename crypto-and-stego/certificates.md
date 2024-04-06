# Vyeti

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa kutumia zana za jamii za **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Vyeti ni nini

**Cheti cha muhimu cha umma** ni kitambulisho cha dijiti kinachotumiwa katika kriptografia kuthibitisha kwamba mtu fulani anamiliki funguo ya umma. Cheti hicho kinajumuisha maelezo ya funguo, utambulisho wa mmiliki (mada), na saini ya dijiti kutoka kwa mamlaka iliyosadikika (mwanzilishi). Ikiwa programu inaamini mwanzilishi na saini ni halali, mawasiliano salama na mmiliki wa funguo inawezekana.

Vyeti kwa kawaida hutolewa na [mamlaka ya vyeti](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) katika muundo wa [miundombinu ya funguo ya umma](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Njia nyingine ni [wavuti ya imani](https://en.wikipedia.org/wiki/Web\_of\_trust), ambapo watumiaji wanathibitisha moja kwa moja funguo za wengine. Muundo wa kawaida wa vyeti ni [X.509](https://en.wikipedia.org/wiki/X.509), ambao unaweza kubadilishwa kulingana na mahitaji maalum kama ilivyoelezwa katika RFC 5280.

## Sehemu za Kawaida za x509

### **Sehemu za Kawaida katika Vyeti vya x509**

Katika vyeti vya x509, **sehemu** kadhaa zina jukumu muhimu katika kuhakikisha uhalali na usalama wa cheti. Hapa kuna maelezo ya sehemu hizi:

* Nambari ya **Toleo** inaashiria toleo la muundo wa x509.
* Nambari ya **Serial** inatambulisha kipekee cheti ndani ya mfumo wa Mamlaka ya Cheti (CA), hasa kwa kufuatilia kufutwa.
* Sehemu ya **Mada** inawakilisha mmiliki wa cheti, ambaye anaweza kuwa mashine, mtu binafsi, au shirika. Inajumuisha utambulisho wa kina kama:
* **Jina la Kawaida (CN)**: Anwani za kikoa zilizofunikwa na cheti.
* **Nchi (C)**, **Eneo (L)**, **Jimbo au Mkoa (ST, S, au P)**, **Shirika (O)**, na **Kitengo cha Shirika (OU)** hutoa maelezo ya kijiografia na ya shirika.
* **Jina la Kipekee (DN)** linafunga utambulisho kamili wa mada.
* **Mwanzilishi** anaelezea ni nani aliyethibitisha na kusaini cheti, pamoja na sehemu kama hizo za Mada kwa CA.
* **Kipindi cha Uhalali** kimeashiriwa na alama za **Sio Kabla** na **Sio Baada ya** kuhakikisha cheti halitumiwi kabla au baada ya tarehe fulani.
* Sehemu ya **Funguo ya Umma**, muhimu kwa usalama wa cheti, inabainisha algorithm, saizi, na maelezo mengine ya kiufundi ya funguo ya umma.
* **Vipanuzi vya x509v3** huongeza utendaji wa cheti, kuelekeza **Matumizi ya Funguo**, **Matumizi ya Funguo Yaliyopanuliwa**, **Jina Mbadala la Mada**, na mali nyingine kufafanua matumizi ya cheti.

#### **Matumizi ya Funguo na Vipanuzi**

* **Matumizi ya Funguo** inatambua matumizi ya kriptografia ya funguo ya umma, kama saini ya dijiti au kuficha funguo.
* **Matumizi Yaliyopanuliwa ya Funguo** inapunguza zaidi matumizi ya cheti, k.m., kwa uwakilishi wa seva ya TLS.
* **Jina Mbadala la Mada** na **Kizuizi cha Msingi** hufafanua anwani za ziada zilizofunikwa na cheti na ikiwa ni cheti cha CA au mwisho wa mwili, mtawalia.
* Vitambulisho kama **Kitambulisho cha Funguo cha Mada** na **Kitambulisho cha Funguo cha Mamlaka** hakikisha upekee na ufuatiliaji wa funguo.
* **Maelezo ya Kufikia Mamlaka** na **Vipindi vya Usambazaji wa CRL** hutoa njia za kuthibitisha CA inayotoa na kuangalia hali ya kufutwa kwa cheti.
* **CT Precertificate SCTs** hutoa magogo ya uwazi, muhimu kwa imani ya umma kwa cheti.
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

**OCSP** (**RFC 2560**) inahusisha mteja na mwitikiaji kufanya kazi pamoja kuchunguza ikiwa cheti cha kielektroniki cha funguo ya umma kimebatilishwa, bila haja ya kupakua **CRL** kamili. Mbinu hii ni ufanisi zaidi kuliko **CRL** ya jadi, ambayo hutoa orodha ya nambari za mfululizo za vyeti vilivyobatilishwa lakini inahitaji kupakua faili kubwa inayowezekana. CRLs inaweza kujumuisha hadi viingilio 512. Maelezo zaidi yanapatikana [hapa](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Nini ni Certificate Transparency**

Certificate Transparency husaidia kupambana na vitisho vinavyohusiana na vyeti kwa kuhakikisha utoaji na uwepo wa vyeti vya SSL unaweza kuonekana na wamiliki wa kikoa, CAs, na watumiaji. Malengo yake ni:

* Kuzuia CAs kutoa vyeti vya SSL kwa kikoa bila idhini ya mmiliki wa kikoa.
* Kuweka mfumo wa ukaguzi wazi kufuatilia vyeti vilivyotolewa kimakosa au kwa nia mbaya.
* Kulinda watumiaji dhidi ya vyeti vya udanganyifu.

#### **Rekodi za Cheti**

Rekodi za cheti ni rekodi za vyeti zinazoweza kukaguliwa hadharani, zisizoweza kubadilishwa, zinazohifadhiwa na huduma za mtandao. Rekodi hizi hutoa uthibitisho wa kryptografia kwa madhumuni ya ukaguzi. Mamlaka za utoaji na umma wanaweza kuwasilisha vyeti kwa rekodi hizi au kuzitafuta kwa uthibitisho. Ingawa idadi kamili ya seva za rekodi haijafungwa, inatarajiwa kuwa chini ya elfu moja kimataifa. Seva hizi zinaweza kusimamiwa kivyake na CAs, ISPs, au taasisi yoyote inayohusika.

#### **Utafutaji**

Kutafuta rekodi za Certificate Transparency kwa kikoa chochote, tembelea [https://crt.sh/](https://crt.sh).

## **Miundo**

### **Muundo wa PEM**

* Muundo unaotumiwa sana kwa vyeti.
* Unahitaji faili tofauti kwa vyeti na funguo za faragha, zilizoandikwa kwa Base64 ASCII.
* Vipanuzi vya kawaida: .cer, .crt, .pem, .key.
* Kutumika hasa na seva za Apache na zingine zinazofanana.

### **Muundo wa DER**

* Muundo wa binary wa vyeti.
* Haujumuishi taarifa za "BEGIN/END CERTIFICATE" zilizo katika faili za PEM.
* Vipanuzi vya kawaida: .cer, .der.
* Mara nyingi hutumiwa na majukwaa ya Java.

### **Muundo wa P7B/PKCS#7**

* Uhifadhiwa kwa Base64 ASCII, na vipanuzi .p7b au .p7c.
* Una vyeti tu na vyeti vya mnyororo, bila funguo ya faragha.
* Inaungwa mkono na Microsoft Windows na Java Tomcat.

### **Muundo wa PFX/P12/PKCS#12**

* Muundo wa binary unaofunga vyeti vya seva, vyeti vya kati, na funguo za faragha katika faili moja.
* Vipanuzi: .pfx, .p12.
* Kutumika hasa kwenye Windows kwa uingizaji na kuuza vyeti.
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM hadi DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER hadi PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM hadi P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 hadi PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Ubadilishaji wa PFX** ni muhimu kwa usimamizi wa vyeti kwenye Windows:

* **PFX hadi PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX hadi PKCS#8** inahusisha hatua mbili:
1. Geuza PFX hadi PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
### 2. Badilisha PEM kuwa PKCS8

Ili kubadilisha faili ya PEM kwenda PKCS8, unaweza kutumia zana kama OpenSSL. Kutumia amri ifuatayo:

```bash
openssl pkcs8 -topk8 -inform PEM -outform DER -in key.pem -out key.pk8 -nocrypt
```
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B hadi PFX** pia inahitaji amri mbili:
1. Geuza P7B hadi CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Geuza CER na Private Key kuwa PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia** mifumo ya kazi kwa urahisi ikiwa na zana za **jamii za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
