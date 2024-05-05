# Algorithms za Kriptografia/Ukandamizaji

## Algorithms za Kriptografia/Ukandamizaji

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kutambua Algorithms

Ikiwa unamaliza kwenye nambari **ikiwa inatumia mizunguko ya kulia na kushoto, xors na operesheni kadhaa za hisabati** ni jambo la kawaida kwamba ni utekelezaji wa **algorithm ya kriptografia**. Hapa kutakuwa na njia kadhaa za ** kutambua algorithm inayotumiwa bila haja ya kugeuza kila hatua**.

### Vipengele vya API

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kugundua ni **algorithm gani inatumika** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (156).png>)

Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inapunguza na kufuta data iliyopewa.

**CryptAcquireContext**

Kutoka [kwenye nyaraka](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** hutumiwa kupata kushikilia kwa chombo maalum cha ufunguo ndani ya mtoaji wa huduma ya kriptografia maalum (CSP). **Kushikilia hii iliyorudiwa hutumiwa katika wito wa kazi za CryptoAPI** zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha kuhesabu data. Ikiwa kazi hii inatumika, unaweza kugundua ni **algorithm gani inatumika** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (549).png>)

\
Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Vipengele vya Kanuni

Maranyingi ni rahisi kutambua algorithm kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../.gitbook/assets/image (833).png>)

Ikiwa utatafuta kwa mara ya kwanza kwenye Google hii ndio unayopata:

![](<../../.gitbook/assets/image (529).png>)

Hivyo, unaweza kudhani kwamba kazi iliyodecompiled ni **sha256 calculator.**\
Unaweza kutafuta moja ya thamani nyingine na utapata (labda) matokeo sawa.

### Taarifa za Data

Ikiwa nambari haina thamani muhimu, inaweza kuwa ina **taarifa inayopakia kutoka sehemu ya .data**.\
Unaweza kupata data hiyo, **kundi la neno la kwanza** na kutafuta kwenye Google kama tulivyofanya katika sehemu iliyotangulia:

![](<../../.gitbook/assets/image (531).png>)

Katika kesi hii, ikiwa utatafuta **0xA56363C6** unaweza kugundua kuwa inahusiana na **meza za algorithm ya AES**.

## RC4 **(Kriptografia ya Symmetric)**

### Tabia

Ina sehemu 3 kuu:

* **Hatua ya Uanzishaji/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (jumla ya 256bytes, 0x100). Meza hii mara nyingi huitwa **Substitution Box** (au SBox).
* **Hatua ya Kuchanganya**: Itapita **meza** iliyoundwa hapo awali (mzunguko wa 0x100, tena) ikibadilisha kila thamani na **byte za nusu-random**. Ili kuunda byte hizi za nusu-random, **ufunguo wa RC4 unatumika**. **Ufunguo wa RC4** unaweza kuwa **kati ya 1 na 256 bytes kwa urefu**, hata hivyo kawaida inapendekezwa iwe zaidi ya 5 bytes. Kawaida, ufunguo wa RC4 ni urefu wa 16 bytes.
* **Hatua ya XOR**: Mwishowe, maandishi ya wazi au maandishi ya siri yanafanywa **XORed na thamani zilizoundwa hapo awali**. Kazi ya kufunga na kufungua ni sawa. Kwa hili, **mzunguko kupitia 256 bytes zilizoundwa** utafanywa mara nyingi kama inavyohitajika. Hii kawaida inatambulika katika nambari iliyodecompiled na **%256 (mod 256)**.

{% hint style="info" %}
**Ili kutambua RC4 katika nambari ya disassembly/decompiled unaweza kuangalia mizunguko 2 ya saizi 0x100 (ikiwa na matumizi ya ufunguo) na kisha XOR ya data ya kuingia na thamani 256 zilizoundwa hapo awali katika mizunguko 2 labda kutumia %256 (mod 256)**
{% endhint %}

### **Hatua ya Uanzishaji/Substitution Box:** (Tazama nambari 256 inayotumiwa kama kuhesabu na jinsi 0 inavyoandikwa kila mahali kati ya herufi 256)

![](<../../.gitbook/assets/image (584).png>)

### **Hatua ya Kuchanganya:**

![](<../../.gitbook/assets/image (835).png>)

### **Hatua ya XOR:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (Kriptografia ya Symmetric)**

### **Tabia**

* Matumizi ya **meza za kubadilisha na meza za kutafuta**
* Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za meza za kutafuta** (thamani za kudumu). _Tambua kwamba **thamani ya kudumu** inaweza kuwa **imehifadhiwa** kwenye binary **au kuundwa**_ _**kwa njia ya kudumu**._
* **Ufunguo wa kufunga** lazima uwe **unaweza kugawanywa** na **16** (kawaida 32B) na kawaida IV ya 16B hutumiwa.

### Thamani za SBox

![](<../../.gitbook/assets/image (208).png>)

## Nyoka **(Kriptografia ya Symmetric)**

### Tabia

* Ni nadra kupata zisizo zinazotumia lakini kuna mifano (Ursnif)
* Rahisi kutambua ikiwa algorithm ni Nyoka au la kulingana na urefu wake (kazi ndefu sana)

### Kutambua

Katika picha ifuatayo, angalia jinsi thamani ya kudumu **0x9E3779B9** inatumika (tambua kwamba thamani hii pia hutumiwa na algorithms zingine za crypto kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa mizunguko** (**132**) na **idadi ya operesheni za XOR** katika maagizo ya **disassembly** na katika mfano wa **nambari**:

![](<../../.gitbook/assets/image (547).png>)

Kama ilivyotajwa awali, nambari hii inaweza kuonekana ndani ya decompiler yoyote kama **kazi ndefu sana** kwani **hakuna kuruka** ndani yake. Nambari iliyodecompiled inaweza kuonekana kama ifuatavyo:

![](<../../.gitbook/assets/image (513).png>)

Hivyo, ni rahisi kutambua algorithm hii kwa kuangalia **nambari ya uchawi** na **XORs za awali**, kuona **kazi ndefu sana** na **kulinganisha** baadhi ya **maagizo** ya kazi ndefu **na utekelezaji** (kama mzunguko wa kushoto kwa 7 na mzunguko wa kulia kwa 22).
## RSA **(Ufichaji wa Asimetriki)**

### Tabia

* Ngumu zaidi kuliko algorithmu za symmetric
* Hakuna constants! (utekelezaji wa desturi ni mgumu kugundua)
* KANAL (mchambuzi wa crypto) hushindwa kuonyesha viashiria kwenye RSA na inategemea constants.

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

* Ndogo na yenye ufanisi zaidi kwani kazi yake ni kupata mabadiliko ya bahati mbaya katika data
* Hutumia meza za kutafuta (hivyo unaweza kutambua constants)

### Kutambua

Angalia **constants za meza za kutafuta**:

![](<../../.gitbook/assets/image (508).png>)

Algorithmu ya hash ya CRC inaonekana kama:

![](<../../.gitbook/assets/image (391).png>)

## APLib (Ufupishaji)

### Tabia

* Hakuna constants zinazoweza kutambulika
* Unaweza jaribu kuandika algorithmu hiyo kwa python na kutafuta vitu sawa mtandaoni

### Kutambua

Grafu ni kubwa:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Angalia **malinganisho 3 kuitambua**:

![](<../../.gitbook/assets/image (430).png>)
