# Kugundua Udukuzi wa Phishing

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

Ili kugundua jaribio la udukuzi wa phishing, ni muhimu **kuelewa mbinu za phishing zinazotumiwa siku hizi**. Kwenye ukurasa wa mzazi wa chapisho hili, unaweza kupata habari hii, kwa hivyo ikiwa haujui mbinu gani zinazotumiwa leo, napendekeza uende kwenye ukurasa wa mzazi na usome angalau sehemu hiyo.

Chapisho hili linategemea wazo kwamba **wahalifu watajaribu kwa njia fulani kuiga au kutumia jina la kikoa cha mwathirika**. Ikiwa kikoa chako kinaitwa `example.com` na unadukuliwa kwa kutumia jina la kikoa kabisa tofauti kwa sababu fulani kama `youwonthelottery.com`, mbinu hizi hazitafunua hilo.

## Mabadiliko ya Jina la Kikoa

Ni **rahisi kidogo** kugundua **jaribio la udukuzi** ambalo litatumia **jina la kikoa kama hicho** ndani ya barua pepe.\
Inatosha **kuunda orodha ya majina ya udukuzi yanayowezekana zaidi** ambayo mhalifu anaweza kutumia na **kuangalia** ikiwa **imeandikishwa** au tu kuangalia ikiwa kuna **IP** yoyote inayoitumia.

### Kupata Vichwa vya Kikoa Vinavyoshukiwa

Kwa kusudi hili, unaweza kutumia moja ya zana zifuatazo. Kumbuka kuwa zana hizi pia zitafanya ombi la DNS kiotomatiki kuangalia ikiwa kikoa kina IP yoyote iliyopewa:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Unaweza kupata maelezo mafupi ya mbinu hii kwenye ukurasa wa mzazi. Au soma utafiti halisi kwenye [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

Kwa mfano, mabadiliko ya bit 1 katika kikoa cha microsoft.com yanaweza kubadilisha kuwa _windnws.com._\
**Wahalifu wanaweza kujiandikisha kama vichwa vingi vya bit-flipping iwezekanavyo vinavyohusiana na mwathirika ili kupelekeza watumiaji halali kwenye miundombinu yao**.

**Vichwa vyote vya kikoa vinavyowezekana vya bit-flipping pia vinapaswa kufuatiliwa.**

### Uchunguzi wa Msingi

Marafiki unapopata orodha ya majina ya uwezekano ya kikoa kinachoshukiwa unapaswa **kuvichunguza** (haswa bandari za HTTP na HTTPS) ili **kuona ikiwa wanatumia fomu ya kuingia inayofanana** na moja ya kikoa cha mwathirika.\
Unaweza pia kuangalia bandari 3333 kuona ikiwa imefunguliwa na inaendesha kipengele cha `gophish`.\
Ni muhimu pia kujua **umri wa kila kikoa kinachoshukiwa kilichogunduliwa**, kadri kinavyokuwa kipya, ndivyo hatari zaidi.\
Unaweza pia kupata **picha za skrini** za ukurasa wa wavuti wa HTTP na / au HTTPS ili kuona ikiwa ni shuki na katika kesi hiyo **ufikie ili uchunguze zaidi**.

### Uchunguzi wa Juu

Ikiwa unataka kwenda hatua moja mbele, ningekushauri **kufuatilia vichwa vya kikoa vinavyoshukiwa na kutafuta zaidi** mara kwa mara (kila siku? inachukua sekunde / dakika chache tu). Unapaswa pia **kuangalia** bandari **zilizofunguliwa** za IP zinazohusiana na **kutafuta mifano ya `gophish` au zana kama hizo** (ndio, wahalifu pia hufanya makosa) na **kufuatilia kurasa za wavuti za HTTP na HTTPS za vichwa vya kikoa na vikoa vidogo vinavyoshukiwa** ili kuona ikiwa wameiga fomu yoyote ya kuingia kutoka kwenye kurasa za wavuti za mwathirika.\
Ili **kuautomatisha hii**, ningependekeza kuwa na orodha ya fomu za kuingia za vikoa vya mwathirika, tembelea kurasa za wavuti za vichwa vya kikoa vinavyoshukiwa na kulinganisha kila fomu ya kuingia iliyopatikana ndani ya vichwa vya kikoa vinavyoshukiwa na kila fomu ya kuingia ya kikoa cha mwathirika kwa kutumia kitu kama `ssdeep`.\
Ikiwa umepata fomu za kuingia za vichwa vya kikoa vinavyoshukiwa, unaweza kujaribu **kupeleka vitambulisho visivyo sahihi** na **kuangalia ikiwa inakuelekeza kwenye kikoa cha mwathirika**.

## Majina ya Kikoa yanayotumia Maneno muhimu

Ukurasa wa mzazi pia unataja mbinu ya mabadiliko ya jina la kikoa ambayo inajumuisha kuweka **jina la kikoa cha mwathirika ndani ya kikoa kikubwa** (kwa mfano, paypal-financial.com kwa paypal.com).

### Uwazi wa Cheti

Haiwezekani kutumia njia ya "Brute-Force" hapo awali lakini kwa kweli **inawezekana kugundua jaribio la udukuzi kama huo** pia kwa sababu ya uwazi wa cheti. Kila wakati cheti kinapotolewa na CA, maelezo yanafanywa kuwa ya umma. Hii inamaanisha kwamba kwa kusoma uwazi wa cheti au hata kufuatilia, ni **inawezekana kupata vichwa vya kikoa vinavyotumia neno muhimu ndani ya jina lake**. Kwa mfano, ikiwa mhalifu anazalisha cheti cha [https://paypal-financial.com](https://paypal-financial.com), kwa kuona cheti ni rahisi kupata neno muhimu "paypal" na kujua kuwa barua pepe shuki inatumika.

Chapisho [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) inapendekeza unaweza kutumia Censys kutafuta vyeti vinavyoathiri neno muhimu maalum na kuchuja kwa tarehe (vyeti "vipya" tu) na kwa CA inayotoa "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

Walakini, unaweza kufanya "vile vile" kwa kutumia wavuti ya bure [**crt.sh**](https://crt.sh). Unaweza **kutafuta neno muhimu**
### **Domains Mpya**

**Chaguo la mwisho** ni kukusanya orodha ya **domaini zilizosajiliwa hivi karibuni** kwa baadhi ya TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) hutoa huduma kama hiyo) na **angalia maneno muhimu katika domaini hizi**. Hata hivyo, domaini ndefu kawaida hutumia subdomaini moja au zaidi, kwa hiyo neno muhimu halitaonekana ndani ya FLD na hautaweza kupata subdomaini ya ulaghai.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
