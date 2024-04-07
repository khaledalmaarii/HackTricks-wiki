# Algorithms za Kriptografia/Ukandamizaji

## Algorithms za Kriptografia/Ukandamizaji

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kutambua Algorithms

Ikiwa unakutana na msimbo **ukiwa na mabadiliko ya haki na kushoto, xors na shughuli kadhaa za hisabati** ni uwezekano mkubwa kwamba ni utekelezaji wa **algorithm ya kriptografia**. Hapa tutaelezea njia kadhaa za **kutambua algorithm inayotumiwa bila kuhitaji kugeuza kila hatua**.

### Vipengele vya API

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kugundua ni **algorithm gani inatumika** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (153).png>)

Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inakandamiza na kufyatua data iliyopewa.

**CryptAcquireContext**

Kutoka [kwenye nyaraka](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** hutumiwa kupata kushikilia kwa chombo maalum cha funguo ndani ya mtoaji maalum wa huduma ya kriptografia (CSP). **Kushikilia hiki kilichorudiwa hutumiwa katika wito wa kazi za CryptoAPI** zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha kuhesabu ya data. Ikiwa kazi hii inatumika, unaweza kugundua ni **algorithm gani inatumika** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (546).png>)

\
Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Vipengele vya Msimbo

Maranyingi ni rahisi kutambua algorithm kwa sababu inahitaji kutumia thamani maalum na ya kipekee.

![](<../../.gitbook/assets/image (830).png>)

Ikiwa utatafuta kwa thamani ya kwanza kwenye Google hii ndio unayopata:

![](<../../.gitbook/assets/image (526).png>)

Hivyo, unaweza kudhani kuwa kazi iliyodecompiled ni **mchambuzi wa sha256.**\
Unaweza kutafuta moja ya thamani nyingine na utapata (labda) matokeo sawa.

### Taarifa za Data

Ikiwa msimbo haujai thamani muhimu inaweza kuwa **inapakia taarifa kutoka sehemu ya .data**.\
Unaweza kupata data hiyo, **kundi la neno la kwanza** na kutafuta kwenye Google kama tulivyofanya katika sehemu iliyotangulia:

![](<../../.gitbook/assets/image (528).png>)

Katika kesi hii, ukichunguza **0xA56363C6** unaweza kugundua kuwa inahusiana na **meza za algorithm ya AES**.

## RC4 **(Kriptografia ya Symmetric)**

### Sifa

Ina sehemu 3 kuu:

* **Hatua ya Uanzishaji/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (jumla ya 256bytes, 0x100). Meza hii mara nyingi huitwa **Substitution Box** (au SBox).
* **Hatua ya Kuchanganya**: Itapita **meza** iliyoundwa hapo awali (mzunguko wa 0x100, tena) ikibadilisha kila thamani na **baiti za nusu-random**. Ili kuunda byte hizi za nusu-random, **funguo wa RC4 unatumika**. **Funguo za RC4** zinaweza kuwa **kati ya 1 na 256 bytes kwa urefu**, hata hivyo kawaida inapendekezwa iwe zaidi ya 5 bytes. Kawaida, funguo za RC4 ni urefu wa 16 bytes.
* **Hatua ya XOR**: Mwishowe, maandishi ya wazi au maandishi ya siri yanafanyiwa **XOR na thamani zilizoundwa hapo awali**. Kazi ya kufichua na kufichua ni sawa. Kwa hili, mzunguko kupitia bytes 256 zilizoundwa utafanyika mara nyingi kama inavyohitajika. Hii kawaida inatambulika katika msimbo uliodecompiled na **%256 (mod 256)**.

{% hint style="info" %}
**Ili kutambua RC4 katika msimbo uliopanguliwa/uliochambuliwa unaweza kuangalia kwa mizunguko 2 ya saizi ya 0x100 (ikiwa na matumizi ya funguo) na kisha XOR ya data ya kuingia na thamani 256 zilizoundwa hapo awali katika mizunguko 2 labda kutumia %256 (mod 256)**
{% endhint %}

### **Hatua ya Uanzishaji/Substitution Box:** (Tazama nambari 256 iliyotumiwa kama kuhesabu na jinsi 0 inavyoandikwa kila mahali kati ya herufi 256)

![](<../../.gitbook/assets/image (581).png>)

### **Hatua ya Kuchanganya:**

![](<../../.gitbook/assets/image (832).png>)

### **Hatua ya XOR:**

![](<../../.gitbook/assets/image (901).png>)

## **AES (Kriptografia ya Symmetric)**

### **Sifa**

* Matumizi ya **meza za kubadilisha na meza za kutafuta**
* Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za meza za kutafuta** (thamani za kudumu). _Tafadhali kumbuka kuwa **thamani ya kudumu** inaweza kuwa **imehifadhiwa** kwenye binary **au kuundwa**_ _**kwa njia ya kudumu**._
* **Funguo la kufichua** lazima liwe **linaweza kugawanywa** na **16** (kawaida 32B) na kawaida IV ya 16B hutumiwa.

### Thamani za SBox

![](<../../.gitbook/assets/image (205).png>)

## Nyoka **(Kriptografia ya Symmetric)**

### Sifa

* Ni nadra kupata zisizo zinazotumia lakini kuna mifano (Ursnif)
* Rahisi kutambua ikiwa algorithm ni Nyoka au la kulingana na urefu wake (kazi ndefu sana)

### Kutambua

Katika picha ifuatayo angalia jinsi thamani ya kudumu **0x9E3779B9** inavyotumiwa (tambua kuwa thamani hii pia hutumiwa na algorithms zingine za kriptografia kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa mzunguko** (**132**) na **idadi ya operesheni za XOR** katika maagizo ya **uchambuzi** na katika mfano wa **msimbo**:

![](<../../.gitbook/assets/image (544).png>)

Kama ilivyotajwa awali, msimbo huu unaweza kuonekana ndani ya chombo chochote cha kuchambua kama **kazi ndefu sana** kwani **hakuna kuruka** ndani yake. Msimbo uliochambuliwa unaweza kuonekana kama ifuatavyo:

![](<../../.gitbook/assets/image (510).png>)

Hivyo, ni rahisi kutambua algorithm hii kwa kuangalia **nambari ya kichawi** na **XORs za awali**, kuona **kazi ndefu sana** na **kulinganisha** baadhi ya **maagizo** ya kazi ndefu **na utekelezaji** (kama vile kushift kushoto kwa 7 na kuzungusha kushoto kwa 22).
## RSA **(Ufumaji wa Asimetriki)**

### Tabia

* Ngumu zaidi kuliko algorithmi za symmetric
* Hakuna constants! (utekelezaji wa desturi ni mgumu kugundua)
* KANAL (mchambuzi wa crypto) hushindwa kuonyesha viashiria kwenye RSA kwani inategemea constants.

### Kutambua kwa kulinganisha

![](<../../.gitbook/assets/image (1110).png>)

* Katika mstari wa 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na mstari wa 35 (kulia): `+7) / 8`
* Mstari wa 12 (kushoto) unachunguza ikiwa `modulus_len < 0x040` na kwenye mstari wa 36 (kulia) inachunguza ikiwa `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Tabia

* 3 kazi: Init, Update, Final
* Kazi za kuanzisha zinafanana

### Kutambua

**Init**

Unaweza kutambua zote mbili kwa kuchunguza constants. Kumbuka kwamba sha\_init ina constant 1 ambayo MD5 haina:

![](<../../.gitbook/assets/image (403).png>)

**MD5 Transform**

Tambua matumizi ya constants zaidi

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (hash)

* Ndogo na yenye ufanisi zaidi kwani kazi yake ni kupata mabadiliko ya bahati mbaya katika data
* Hutumia meza za kutafuta (hivyo unaweza kutambua constants)

### Kutambua

Angalia **constants za meza za kutafuta**:

![](<../../.gitbook/assets/image (505).png>)

Algorithmi ya hash ya CRC inaonekana kama:

![](<../../.gitbook/assets/image (387).png>)

## APLib (Ufupishaji)

### Tabia

* Hakuna constants zinazoweza kutambulika
* Unaweza jaribu kuandika algorithmi hiyo kwa python na kutafuta vitu sawa mtandaoni

### Kutambua

Grafu ni kubwa:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Angalia **malinganisho 3 kuitambua**:

![](<../../.gitbook/assets/image (427).png>)
