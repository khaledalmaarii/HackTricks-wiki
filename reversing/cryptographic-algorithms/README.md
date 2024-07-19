# Algorithimu za Kijamii/Kubana

## Algorithimu za Kijamii/Kubana

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Kutambua Algorithimu

Ikiwa unamaliza katika msimbo **ukitumia shift kulia na kushoto, xors na operesheni kadhaa za hesabu** kuna uwezekano mkubwa kwamba ni utekelezaji wa **algorithimu ya kijamii**. Hapa kuna njia kadhaa za **kutambua algorithimu inayotumika bila kuhitaji kubadilisha kila hatua**.

### API functions

**CryptDeriveKey**

Ikiwa kazi hii inatumika, unaweza kupata ni **algorithimu ipi inatumika** ukichunguza thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Angalia hapa jedwali la algorithimu zinazowezekana na thamani zao zilizotolewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Inabana na kufungua buffer fulani ya data.

**CryptAcquireContext**

Kutoka [nyaraka](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Kazi ya **CryptAcquireContext** inatumika kupata mkono wa chombo maalum cha funguo ndani ya mtoa huduma maalum wa kijamii (CSP). **Mkono huu uliorejeshwa unatumika katika wito wa kazi za CryptoAPI** zinazotumia CSP iliyochaguliwa.

**CryptCreateHash**

Inaanzisha hashing ya mtiririko wa data. Ikiwa kazi hii inatumika, unaweza kupata ni **algorithimu ipi inatumika** ukichunguza thamani ya parameter ya pili:

![](<../../.gitbook/assets/image (376).png>)

\
Angalia hapa jedwali la algorithimu zinazowezekana na thamani zao zilizotolewa: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Mifano ya msimbo

Wakati mwingine ni rahisi sana kutambua algorithimu kutokana na ukweli kwamba inahitaji kutumia thamani maalum na ya kipekee.

![](<../../.gitbook/assets/image (370).png>)

Ikiwa unatafuta mfano wa kwanza kwenye Google hii ndiyo unayopata:

![](<../../.gitbook/assets/image (371).png>)

Hivyo, unaweza kudhani kwamba kazi iliyotolewa ni **sha256 calculator.**\
Unaweza kutafuta yoyote ya mifano mingine na utapata (labda) matokeo sawa.

### taarifa za data

Ikiwa msimbo huna mfano wowote muhimu unaweza kuwa **ukipakia taarifa kutoka sehemu ya .data**.\
Unaweza kufikia data hiyo, **ungana dword ya kwanza** na utafute kwenye google kama tulivyofanya katika sehemu iliyopita:

![](<../../.gitbook/assets/image (372).png>)

Katika kesi hii, ikiwa utaangalia **0xA56363C6** unaweza kupata kwamba inahusiana na **meza za algorithimu ya AES**.

## RC4 **(Kijamii Crypt)**

### Sifa

Inajumuisha sehemu 3 kuu:

* **Hatua ya Uanzishaji/**: Inaunda **meza ya thamani kutoka 0x00 hadi 0xFF** (256bytes kwa jumla, 0x100). Meza hii kwa kawaida inaitwa **Sanduku la Kubadilisha** (au SBox).
* **Hatua ya Kuchanganya**: Itafanya **mzunguko kupitia meza** iliyoundwa hapo awali (mzunguko wa 0x100, tena) ikibadilisha kila thamani kwa **bytes za nadharia**. Ili kuunda hizi bytes za nadharia, funguo za RC4 **zinatumika**. Funguo za RC4 zinaweza kuwa **kati ya 1 na 256 bytes kwa urefu**, hata hivyo kawaida inapendekezwa kuwa juu ya 5 bytes. Kwa kawaida, funguo za RC4 ni 16 bytes kwa urefu.
* **Hatua ya XOR**: Hatimaye, maandiko ya wazi au maandiko ya cipher **yanapigwa XOR na thamani zilizoundwa hapo awali**. Kazi ya kuandika na kufungua ni ile ile. Kwa hili, **mzunguko kupitia bytes 256 zilizoundwa** utafanywa mara nyingi kadri inavyohitajika. Hii kwa kawaida inatambuliwa katika msimbo uliotolewa na **%256 (mod 256)**.

{% hint style="info" %}
**Ili kutambua RC4 katika msimbo wa disassembly/uliotolewa unaweza kuangalia mizunguko 2 za ukubwa 0x100 (kwa kutumia funguo) na kisha XOR ya data ya ingizo na thamani 256 zilizoundwa hapo awali katika mizunguko 2 labda kwa kutumia %256 (mod 256)**
{% endhint %}

### **Hatua ya Uanzishaji/Sanduku la Kubadilisha:** (Angalia nambari 256 inayotumika kama hesabu na jinsi 0 inavyoandikwa katika kila mahali pa wahusika 256)

![](<../../.gitbook/assets/image (377).png>)

### **Hatua ya Kuchanganya:**

![](<../../.gitbook/assets/image (378).png>)

### **Hatua ya XOR:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Kijamii Crypt)**

### **Sifa**

* Matumizi ya **sanduku za kubadilisha na meza za kutafuta**
* Inawezekana **kutofautisha AES kutokana na matumizi ya thamani maalum za meza za kutafuta** (mifano). _Kumbuka kwamba **thamani** inaweza **kuhifadhiwa** katika **binary** _au _**kuundwa**_ _**kwa njia ya kidinamikali**._
* **Funguo ya kuandika** lazima iwe **inaweza kugawanywa** na **16** (kawaida 32B) na kawaida **IV** ya 16B inatumika.

### Mifano ya SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Kijamii Crypt)**

### Sifa

* Ni nadra kupata malware fulani ikitumia lakini kuna mifano (Ursnif)
* Rahisi kubaini ikiwa algorithimu ni Serpent au la kulingana na urefu wake (kazi ndefu sana)

### Kutambua

Katika picha ifuatayo angalia jinsi mfano **0x9E3779B9** unavyotumika (kumbuka kwamba mfano huu pia unatumika na algorithimu nyingine za crypto kama **TEA** -Tiny Encryption Algorithm).\
Pia angalia **ukubwa wa mzunguko** (**132**) na **idadi ya operesheni za XOR** katika **maelekezo ya disassembly** na katika **mfano wa msimbo**:

![](<../../.gitbook/assets/image (381).png>)

Kama ilivyotajwa hapo awali, msimbo huu unaweza kuonyeshwa ndani ya decompiler yoyote kama **kazi ndefu sana** kwani **hakuna kuruka** ndani yake. Msimbo uliotolewa unaweza kuonekana kama ifuatavyo:

![](<../../.gitbook/assets/image (382).png>)

Hivyo, inawezekana kutambua algorithimu hii kwa kuangalia **nambari ya kichawi** na **XORs za awali**, kuona **kazi ndefu sana** na **kulinganisha** baadhi ya **maelekezo** ya kazi ndefu **na utekelezaji** (kama vile shift kushoto kwa 7 na kuzungusha kushoto kwa 22).

## RSA **(Kijamii Crypt)**

### Sifa

* Ngumu zaidi kuliko algorithimu za kijamii
* Hakuna mifano! (utekelezaji wa kawaida ni mgumu kubaini)
* KANAL (mchambuzi wa crypto) inashindwa kuonyesha vidokezo juu ya RSA na inategemea mifano.

### Kutambua kwa kulinganisha

![](<../../.gitbook/assets/image (383).png>)

* Katika mstari wa 11 (kushoto) kuna `+7) >> 3` ambayo ni sawa na katika mstari wa 35 (kulia): `+7) / 8`
* Mstari wa 12 (kushoto) unakagua ikiwa `modulus_len < 0x040` na katika mstari wa 36 (kulia) inakagua ikiwa `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Sifa

* Kazi 3: Anza, Sasisha, Mwisho
* Kazi za kuanzisha zinazofanana

### Tambua

**Anza**

Unaweza kutambua zote mbili ukichunguza mifano. Kumbuka kwamba sha\_init ina mfano 1 ambao MD5 haina:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Kumbuka matumizi ya mifano zaidi

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Ndogo na yenye ufanisi zaidi kwani kazi yake ni kupata mabadiliko yasiyokusudiwa katika data
* Inatumia meza za kutafuta (hivyo unaweza kutambua mifano)

### Tambua

Angalia **mifano ya meza za kutafuta**:

![](<../../.gitbook/assets/image (387).png>)

Algorithimu ya hash ya CRC inaonekana kama:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kubana)

### Sifa

* Hakuna mifano inayotambulika
* Unaweza kujaribu kuandika algorithimu hiyo katika python na kutafuta mambo yanayofanana mtandaoni

### Tambua

Grafu ni kubwa sana:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Angalia **kulinganisha 3 kutambua**:

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
