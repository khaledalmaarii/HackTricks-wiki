# Algorithms za Kriptografia/Ukandamizaji

## Algorithms za Kriptografia/Ukandamizaji

{% hint style="success" %}
Jifunze & zoezi AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Kutambua Algorithms

Ikiwa unamaliza katika kanuni **ikiwa inatumia mizunguko ya kulia na kushoto, xors na operesheni kadhaa za hisabati** ni uwezekano mkubwa kwamba ni utekelezaji wa **algorithm ya kriptografia**. Hapa kutakuwa na njia kadhaa za **kutambua algorithm inayotumiwa bila kuhitaji kugeuza kila hatua**.

### Vipengele vya API

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kupata ni **algorithm gani inatumika** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (156).png>)

Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inapunguza na kufuta data iliyopewa.

**CryptAcquireContext**

Kutoka [kwenye nyaraka](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** hutumiwa kupata kushikilia kwa chombo maalum cha funguo ndani ya mtoaji wa huduma ya kriptografia maalum (CSP). **Kushikilia hii iliyorudiwa hutumiwa katika wito kwa kazi za CryptoAPI** zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha kuhesabu ya data. Ikiwa kazi hii inatumika, unaweza kupata ni **algorithm gani inatumika** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (549).png>)

\
Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Vipengele vya Kanuni

Maranyingi ni rahisi kutambua algorithm kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../.gitbook/assets/image (833).png>)

Ikiwa utatafuta kwa thamani ya kwanza kwenye Google hii ndio unayopata:

![](<../../.gitbook/assets/image (529).png>)

Hivyo, unaweza kudhani kwamba kazi iliyodekompiliwa ni **kikokotozi wa sha256.**\
Unaweza kutafuta moja ya thamani nyingine na utapata (labda) matokeo sawa.

### Taarifa za Data

Ikiwa kanuni haina thamani muhimu, inaweza kuwa ina **pata taarifa kutoka sehemu ya .data**.\
Unaweza kupata data hiyo, **kundi la neno la kwanza** na kutafuta kwenye Google kama tulivyofanya katika sehemu iliyotangulia:

![](<../../.gitbook/assets/image (531).png>)

Katika kesi hii, ikiwa utatafuta **0xA56363C6** unaweza kupata kuwa inahusiana na **meza za algorithm ya AES**.

## RC4 **(Kriptografia ya Symmetric)**

### Sifa

Ina sehemu 3 kuu:

* **Hatua ya Uanzishaji/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (jumla ya 256bytes, 0x100). Meza hii mara nyingi huitwa **Substitution Box** (au SBox).
* **Hatua ya Kuchanganya**: Itapita **meza** iliyoundwa hapo awali (mzunguko wa 0x100, tena) ikibadilisha kila thamani na **bayti za nusu-random**. Ili kuunda bayti hizi za nusu-random, **ufunguo wa RC4 unatumika**. **Ufunguo wa RC4** unaweza kuwa **kati ya bayti 1 na 256 za urefu**, hata hivyo kawaida inapendekezwa iwe zaidi ya bayti 5. Kawaida, ufunguo wa RC4 ni bayti 16 za urefu.
* **Hatua ya XOR**: Mwishowe, maandishi ya wazi au maandishi ya siri yanafanyiwa **XOR na thamani zilizoundwa hapo awali**. Kazi ya kuficha na kufichua ni sawa. Kwa hili, **mzunguko kupitia bayti 256 zilizoundwa** utafanywa mara nyingi kama inavyohitajika. Hii kawaida inatambulika katika kanuni iliyodekompiliwa na **%256 (mod 256)**.

{% hint style="info" %}
**Ili kutambua RC4 katika kanuni ya disassembly/decompiled unaweza kuangalia mizunguko 2 ya saizi 0x100 (ikiwa na matumizi ya ufunguo) na kisha XOR ya data ya kuingia na thamani 256 zilizoundwa hapo awali katika mizunguko 2 labda kutumia %256 (mod 256)**
{% endhint %}

### **Hatua ya Uanzishaji/Substitution Box:** (Tazama nambari 256 iliyotumiwa kama kuhesabu na jinsi 0 inavyoandikwa kila mahali kati ya herufi 256)

![](<../../.gitbook/assets/image (584).png>)

### **Hatua ya Kuchanganya:**

![](<../../.gitbook/assets/image (835).png>)

### **Hatua ya XOR:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (Kriptografia ya Symmetric)**

### **Sifa**

* Matumizi ya **masanduku ya kubadilisha na meza za kutafuta**
* Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za meza za kutafuta** (thamani za kudumu). _Tambua kwamba **thamani ya kudumu** inaweza kuwa **imehifadhiwa** kwenye binary **au kuundwa**_ _**kwa njia ya kudumu**._
* **Ufunguo wa kuficha** lazima uwe **unaweza kugawanywa** na **16** (kawaida 32B) na kawaida IV ya 16B hutumiwa.

### Thamani za SBox

![](<../../.gitbook/assets/image (208).png>)

## Nyoka **(Kriptografia ya Symmetric)**

### Sifa

* Ni nadra kupata zisizo zinazotumia lakini kuna mifano (Ursnif)
* Rahisi kutambua ikiwa algorithm ni Nyoka au la kulingana na urefu wake (kazi ndefu sana)

### Kutambua

Katika picha ifuatayo angalia jinsi thamani **0x9E3779B9** inavyotumiwa (tambua kwamba thamani hii pia hutumiwa na algorithms zingine za kriptografia kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa mzunguko** (**132**) na **idadi ya operesheni za XOR** katika maagizo ya **disassembly** na katika mfano wa **kanuni**:

![](<../../.gitbook/assets/image (547).png>)

Kama ilivyotajwa awali, kanuni hii inaweza kuonekana ndani ya kikokotozi chochote kama **kazi ndefu sana** kwani **hakuna kuruka** ndani yake. Kanuni iliyodekompiliwa inaweza kuonekana kama ifuatavyo:

![](<../../.gitbook/assets/image (513).png>)

Hivyo, ni rahisi kutambua algorithm hii kwa kuangalia **nambari ya kichawi** na **XORs za awali**, kuona **kazi ndefu sana** na **kulinganisha** baadhi ya **maagizo** ya kazi ndefu **na utekelezaji** (kama vile mizunguko ya kushoto kwa 7 na mzunguko wa kushoto kwa 22).
## RSA **(Ufichaji wa Asimetriki)**

### Tabia

* Ngumu zaidi kuliko algorithmi za symmetric
* Hakuna constants! (utekelezaji wa desturi ni mgumu kugundua)
* KANAL (mchambuzi wa crypto) hushindwa kuonyesha viashiria kwenye RSA kwani inategemea constants.

### Kutambua kwa kulinganisha

![](<../../.gitbook/assets/image (1113).png>)

* Katika mstari wa 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na mstari wa 35 (kulia): `+7) / 8`
* Mstari wa 12 (kushoto) unachunguza ikiwa `modulus_len < 0x040` na kwenye mstari wa 36 (kulia) inachunguza ikiwa `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Tabia

* 3 kazi: Init, Update, Final
* Kazi za kuanzisha zinafanana

### Kutambua

**Init**

Unaweza kutambua zote mbili kwa kuchunguza constants. Kumbuka kwamba sha\_init ina constant 1 ambayo MD5 haina:

![](<../../.gitbook/assets/image (406).png>)

**MD5 Transform**

Tambua matumizi ya constants zaidi

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (hash)

* Ndogo na yenye ufanisi zaidi kwani kazi yake ni kupata mabadiliko ya bahati katika data
* Hutumia meza za kutafuta (hivyo unaweza kutambua constants)

### Kutambua

Angalia **constants za meza za kutafuta**:

![](<../../.gitbook/assets/image (508).png>)

Algorithmi ya hash ya CRC inaonekana kama:

![](<../../.gitbook/assets/image (391).png>)

## APLib (Ufupishaji)

### Tabia

* Hakuna constants zinazoweza kutambulika
* Unaweza kujaribu kuandika algorithmi hiyo kwa python na kutafuta vitu sawa mtandaoni

### Kutambua

Grafu ni kubwa:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Angalia **milinganisho 3 kuitambua**:

![](<../../.gitbook/assets/image (430).png>)
