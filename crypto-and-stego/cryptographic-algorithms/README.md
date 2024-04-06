# Algorithms za Kriptografia/Ukandamizaji

## Algorithms za Kriptografia/Ukandamizaji

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kutambua Algorithms

Ikiwa unakuta nambari **inatumia mabadiliko ya kulia na kushoto, xors na shughuli za hisabati kadhaa** ni uwezekano mkubwa kuwa ni utekelezaji wa **algorithm ya kriptografia**. Hapa tutaelezea njia kadhaa za **kutambua algorithm inayotumiwa bila kuhitaji kurejesha hatua kwa hatua**.

### API functions

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kupata **algorithm inayotumiwa** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inapunguza na kurejesha data iliyopewa.

**CryptAcquireContext**

Kutoka [nyaraka](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** hutumiwa kupata kushughulikia kwa chombo fulani cha ufungaji ndani ya mtoaji fulani wa huduma ya kriptografia (CSP). **Kushughulikia hili lililopokelewa hutumiwa katika wito wa kazi za CryptoAPI** ambazo hutumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha kuhesabu hash ya mtiririko wa data. Ikiwa kazi hii inatumika, unaweza kupata **algorithm inayotumiwa** kwa kuangalia thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (376).png>)

\
Angalia hapa jedwali la algorithms inayowezekana na thamani zao zilizopewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constants za Nambari

Marafiki mara nyingi ni rahisi kutambua algorithm kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../.gitbook/assets/image (370).png>)

Ikiwa utatafuta kwa sababu ya kwanza kwenye Google hii ndio unayopata:

![](<../../.gitbook/assets/image (371).png>)

Kwa hivyo, unaweza kudhani kuwa kazi iliyopasuliwa ni **sha256 calculator.**\
Unaweza kutafuta moja ya marafiki wengine na utapata (labda) matokeo sawa.

### habari ya data

Ikiwa nambari haina kikwazo kikubwa, inaweza kuwa **inapakia habari kutoka sehemu ya .data**.\
Unaweza kupata data hiyo, **kikundi cha dword cha kwanza** na utafute kwenye Google kama tulivyofanya katika sehemu iliyotangulia:

![](<../../.gitbook/assets/image (372).png>)

Katika kesi hii, ikiangalia **0xA56363C6** unaweza kupata kuwa inahusiana na **meza za algorithm za AES**.

## RC4 **(Kriptografia ya Symmetric)**

### Tabia

Ina sehemu 3 kuu:

* **Hatua ya Uanzishaji/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (jumla ya 256bytes, 0x100). Meza hii kawaida huitwa **Substitution Box** (au SBox).
* **Hatua ya Kuchanganya**: Itapita **kupitia meza** iliyoandaliwa hapo awali (mzunguko wa 0x100, tena) ikibadilisha kila thamani na **baiti za nusu-random**. Ili kuunda byte hizi za nusu-random, RC4 **ufunguo hutumiwa**. Vipengele vya RC4 vinaweza kuwa **kati ya 1 na 256 bytes kwa urefu**, ingawa kawaida inapendekezwa kuwa juu ya 5 bytes. Kawaida, vipengele vya RC4 ni 16 bytes kwa urefu.
* **Hatua ya XOR**: Hatimaye, maandishi wazi au maandishi ya siri yana **XORed na thamani zilizoandaliwa hapo awali**. Kazi ya kusimbua na kusimbua ni sawa. Kwa hivyo, mzunguko kupitia byte 256 zilizoandaliwa hapo awali utafanywa mara nyingi kama inavyohitajika. Hii kawaida inatambuliwa katika nambari iliyopasuliwa na **%256 (mod 256)**.

{% hint style="info" %}
**Ili kutambua RC4 katika nambari iliyopasuliwa/iliyopasuliwa unaweza kuangalia kwa mizunguko 2 ya ukubwa wa 0x100 (kwa kutumia ufunguo) na kisha XOR ya data ya kuingiza na thamani 256 zilizoandaliwa hapo awali katika mizunguko 2 labda kwa kutumia %256 (mod 256)**
{% endhint %}

### **Hatua ya Uanzishaji/Substitution Box:** (Angalia nambari 256 inayotumiwa kama kuhesabu na jinsi 0 inavyoandikwa mahali pa herufi 256)

![](<../../.gitbook/assets/image (377).png>)

### **Hatua ya Kuchanganya:**

![](<../../.gitbook/assets/image (378).png>)

### **Hatua ya XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Kriptografia ya Symmetric)**

### **Tabia**

* Matumizi ya **meza za kubadilisha na meza za kutafuta**
* Inawezekana **kutofautisha AES kwa sababu ya matumizi ya thamani maalum za meza za kutafuta** (thamani za kudumu). _Kumbuka kwamba **thamani ya kudumu** inaweza **kuhifadhiwa** kwenye binary **au kuundwa**_ _**kwa kudumu**._
* **Ufunguo wa kusimbua** lazima uwe **unaweza kugawanywa** na **16** (kawaida 32B) na kawaida IV ya 16B hutumiwa.

### SBox constants

![](<../../.gitbook/assets/image (380).png>)

## Nyoka **(Kriptografia ya Symmetric)**

### Tabia

* Ni nadra kupata programu hasidi inayoitumia lakini kuna mifano (Ursnif)
* Rahisi kut
## RSA **(Asymmetric Crypt)**

### Tabia

* Ngumu zaidi kuliko algorithmu za symmetric
* Hakuna constants! (utekelezaji wa desturi ni vigumu kubaini)
* KANAL (mtambuzi wa crypto) hushindwa kuonyesha viashiria vya RSA kwani inategemea constants.

### Kutambua kwa kulinganisha

![](<../../.gitbook/assets/image (383).png>)

* Katika mstari wa 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na mstari wa 35 (kulia): `+7) / 8`
* Mstari wa 12 (kushoto) unachunguza ikiwa `modulus_len < 0x040` na katika mstari wa 36 (kulia) inachunguza ikiwa `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Tabia

* 3 kazi: Init, Update, Final
* Kazi za kuanzisha zinafanana

### Kutambua

**Init**

Unaweza kutambua zote mbili kwa kuchunguza constants. Kumbuka kuwa sha\_init ina constant 1 ambayo MD5 haina:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Tazama matumizi ya constants zaidi

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Ndogo na yenye ufanisi zaidi kwani kazi yake ni kupata mabadiliko ya bahati katika data
* Hutumia lookup tables (hivyo unaweza kutambua constants)

### Kutambua

Angalia **constants za lookup table**:

![](<../../.gitbook/assets/image (387).png>)

Algorithmu ya hash ya CRC inaonekana kama:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compression)

### Tabia

* Hakuna constants zinazoweza kutambulika
* Unaweza kujaribu kuandika algorithmu kwa python na kutafuta vitu sawa mtandaoni

### Kutambua

Grafu ni kubwa sana:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Angalia **ulinganisho wa 3 ili kutambua**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
