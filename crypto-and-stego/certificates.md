# Vyeti

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa kutumia zana za jamii za **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ni Nini Cheti

**Cheti cha muhimili wa umma** ni kitambulisho cha kidijitali kinachotumiwa katika kriptografia kuthibitisha kwamba mtu fulani anamiliki muhimili wa umma. Cheti hicho kinajumuisha maelezo ya muhimili, utambulisho wa mmiliki (mada), na saini ya kidijitali kutoka kwa mamlaka iliyosadikika (mwanzilishi). Ikiwa programu inaamini mwanzilishi na saini ni halali, mawasiliano salama na mmiliki wa muhimili unawezekana.

Vyeti kwa kawaida hutolewa na [mamlaka ya vyeti](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) katika mfumo wa [miundombinu ya muhimili wa umma](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Njia nyingine ni [wavuti ya imani](https://en.wikipedia.org/wiki/Web\_of\_trust), ambapo watumiaji wanathibitisha moja kwa moja funguo za kila mmoja. Muundo wa kawaida wa vyeti ni [X.509](https://en.wikipedia.org/wiki/X.509), ambao unaweza kubadilishwa kulingana na mahitaji maalum kama ilivyoelezwa katika RFC 5280.

## Sehemu za Kawaida za x509

### **Sehemu za Kawaida katika Vyeti vya x509**

Katika vyeti vya x509, **sehemu** kadhaa zina jukumu muhimu katika kuhakikisha uhalali na usalama wa cheti. Hapa kuna maelezo ya sehemu hizi:

* Nambari ya **Toleo** inaashiria toleo la muundo wa x509.
* Nambari ya **Serial** inatambulisha kipekee cheti ndani ya mfumo wa Mamlaka ya Cheti (CA), hasa kwa kufuatilia kufutwa.
* Sehemu ya **Mada** inawakilisha mmiliki wa cheti, ambaye anaweza kuwa mashine, mtu binafsi, au shirika. Inajumuisha utambulisho wa kina kama vile:
* **Jina la Kawaida (CN)**: Vikoa vinavyofunikwa na cheti.
* **Nchi (C)**, **Eneo (L)**, **Jimbo au Mkoa (ST, S, au P)**, **Shirika (O)**, na **Kitengo cha Shirika (OU)** hutoa maelezo ya kijiografia na ya shirika.
* **Jina la Kipekee (DN)** linafunga utambulisho kamili wa mada.
* **Mwanzilishi** anaelezea ni nani aliyethibitisha na kusaini cheti, pamoja na sehemu kama hizo kama Mada kwa CA.
* **Kipindi cha Uhalali** kimeainishwa na alama za **Sio Kabla** na **Sio Baada** kuhakikisha cheti halitumiwi kabla au baada ya tarehe fulani.
* Sehemu ya **Muhimili wa Umma**, muhimu kwa usalama wa cheti, inabainisha algorithm, ukubwa, na maelezo mengine ya kiufundi ya muhimili wa umma.
* **Vipanuzi vya x509v3** huongeza utendaji wa cheti, kuelekeza **Matumizi ya Muhimili**, **Matumizi ya Muhimili Yaliyopanuliwa**, **Jina Mbadala la Mada**, na mali nyingine kufafanua matumizi ya cheti.

#### **Matumizi ya Muhimili na Vipanuzi**

* **Matumizi ya Muhimili** inatambua matumizi ya kriptografia ya muhimili wa umma, kama saini ya kidijitali au kuficha muhimili.
* **Matumizi Yaliyopanuliwa ya Muhimili** yanapunguza zaidi matumizi ya cheti, k.m., kwa uwakilishi wa seva ya TLS.
* **Jina Mbadala la Mada** na **Kizuizi cha Msingi** hufafanua majina ya ziada ya mwenyeji yanayofunikwa na cheti na ikiwa ni cheti cha CA au mwisho wa chombo, mtawalia.
* Vitambulisho kama **Kitambulisho cha Muhimili wa Mada** na **Kitambulisho cha Mamlaka ya Muhimili** hakikisha upekee na ufuatiliaji wa funguo.
* **Maelezo ya Upatikanaji wa Mamlaka** na **Vipindi vya Usambazaji wa CRL** hutoa njia za kuthibitisha CA inayotoa na kuangalia hali ya kufutwa kwa cheti.
* **CT Precertificate SCTs** hutoa magogo ya uwazi, muhimu kwa imani ya umma kwenye cheti.
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
### **Tofauti kati ya OCSP na Pointi za Usambazaji wa CRL**

**OCSP** (**RFC 2560**) inahusisha mteja na mwitikiaji kufanya kazi pamoja kuchunguza ikiwa cheti cha umma cha kidijitali kimebatilishwa, bila haja ya kupakua **CRL** kamili. Mbinu hii ni ufanisi zaidi kuliko **CRL** ya jadi, ambayo hutoa orodha ya nambari za mfululizo za vyeti vilivyobatilishwa lakini inahitaji kupakua faili kubwa inayowezekana. CRLs inaweza kujumuisha hadi viingilio 512. Maelezo zaidi yanapatikana [hapa](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Nini ni Uwazi wa Cheti**

Uwazi wa Cheti husaidia kupambana na vitisho vinavyohusiana na vyeti kwa kuhakikisha utoaji na uwepo wa vyeti vya SSL unaweza kuonekana na wamiliki wa kikoa, CAs, na watumiaji. Malengo yake ni:

* Kuzuia CAs kutoa vyeti vya SSL kwa kikoa bila idhini ya mmiliki wa kikoa.
* Kuweka mfumo wa ukaguzi wazi kufuatilia vyeti vilivyotolewa kimakosa au kwa nia mbaya.
* Kulinda watumiaji dhidi ya vyeti vya udanganyifu.

#### **Vicheti vya Uwazi**

Vicheti vya uwazi ni rekodi zinazoweza kukaguliwa hadharani, zisizoweza kubadilishwa, za vyeti, zinazosimamiwa na huduma za mtandao. Vicheti hivi hutoa uthibitisho wa kryptografia kwa madhumuni ya ukaguzi. Mamlaka za utoaji na umma wanaweza kuwasilisha vyeti kwa vicheti hivi au kuuliza kwa uthibitisho. Ingawa idadi kamili ya seva za kuingiza haijafungwa, inatarajiwa kuwa chini ya elfu moja kimataifa. Seva hizi zinaweza kusimamiwa kivyake na CAs, ISPs, au chombo chochote kinachohusika.

#### **Utafutaji**

Ili kuchunguza vicheti vya Uwazi wa Cheti kwa kikoa chochote, tembelea [https://crt.sh/](https://crt.sh).

## **Miundo**

### **Muundo wa PEM**

* Muundo unaotumiwa sana kwa vyeti.
* Unahitaji faili tofauti kwa vyeti na funguo za kibinafsi, zilizoandikwa kwa Base64 ASCII.
* Vipanuzi vya kawaida: .cer, .crt, .pem, .key.
* Kutumika hasa na seva za Apache na zingine zinazofanana.

### **Muundo wa DER**

* Muundo wa binary wa vyeti.
* Haujajumuisha taarifa za "ANZA/ISHA VYETI" zilizopatikana kwenye faili za PEM.
* Vipanuzi vya kawaida: .cer, .der.
* Mara nyingi hutumiwa na majukwaa ya Java.

### **Muundo wa P7B/PKCS#7**

* Imehifadhiwa kwa Base64 ASCII, na vipanuzi .p7b au .p7c.
* Ina vyeti tu na vyeti vya mnyororo, ikiondoa funguo ya kibinafsi.
* Inaungwa mkono na Microsoft Windows na Java Tomcat.

### **Muundo wa PFX/P12/PKCS#12**

* Muundo wa binary unaojumuisha vyeti vya seva, vyeti vya kati, na funguo za kibinafsi kwenye faili moja.
* Vipanuzi: .pfx, .p12.
* Kutumika hasa kwenye Windows kwa uingizaji na kuuza vyeti.

### **Kubadilisha Miundo**

**Mabadiliko ya PEM** ni muhimu kwa utangamano:

* **x509 kwenda PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM kwenda DER**
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
2. Badilisha PEM kuwa PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B hadi PFX** pia inahitaji amri mbili:
1. Geuza P7B hadi CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Badilisha CER na Private Key kuwa PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii **zinazoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
