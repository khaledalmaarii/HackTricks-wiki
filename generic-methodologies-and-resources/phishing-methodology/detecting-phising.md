# Kugundua Udukuzi wa Mtandao

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Utangulizi

Kugundua jaribio la udukuzi ni muhimu kuelewa **mbinu za udukuzi zinazotumiwa leo**. Kwenye ukurasa wa mzazi wa chapisho hili, unaweza kupata habari hii, kwa hivyo ikiwa haujui ni mbinu gani zinazotumiwa leo, napendekeza uende kwenye ukurasa wa mzazi na usome angalau sehemu hiyo.

Chapisho hili linategemea wazo kwamba **wahalifu watjaribu kwa njia fulani kufanana au kutumia jina la kikoa cha muathiriwa**. Ikiwa kikoa chako kinaitwa `mfano.com` na unadukuliwa ukitumia kikoa tofauti kabisa kwa sababu fulani kama `umeshindalottery.com`, mbinu hizi hazitafunua hilo.

## Mabadiliko ya Majina ya Kikoa

Ni **rahisi** kufunua **jaribio la udukuzi** ambalo litatumia **jina la kikoa kama hicho** ndani ya barua pepe.\
Inatosha **kuunda orodha ya majina ya udukuzi yanayoweza kutumiwa na mshambuliaji** na **kuangalia** ikiwa ime **sajiliwa** au tu kuangalia ikiwa kuna **IP** inayotumia.

### Kupata vikoa vinavyoshukiwa

Kwa madhumuni haya, unaweza kutumia moja ya zana zifuatazo. Kumbuka kuwa zana hizi pia zitafanya maombi ya DNS kiotomatiki kuchunguza ikiwa kikoa kina IP yoyote iliyopewa:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Unaweza kupata maelezo mafupi ya mbinu hii kwenye ukurasa wa mzazi. Au soma utafiti halisi kwenye** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Kwa mfano, mabadiliko ya bit 1 kwenye kikoa cha microsoft.com yanaweza kugeuza kuwa _windnws.com._\
**Wahalifu wanaweza kusajili vikoa vingi vya bit-flipping iwezekanavyo vinavyohusiana na muathiriwa kupeleka watumiaji halali kwenye miundombinu yao**.

**Vikoa vyote vinavyowezekana vya bit-flipping pia vinapaswa kufuatiliwa.**

### Uchunguzi wa Msingi

Unapokuwa na orodha ya majina ya kikoa vinavyoshukiwa unapaswa **kuvichunguza** (hasa bandari za HTTP na HTTPS) kuona ikiwa wanatumia fomu ya kuingia inayofanana na moja ya kikoa cha muathiriwa.\
Unaweza pia kuangalia bandari 3333 kuona ikiwa imefunguliwa na inaendesha kipengee cha `gophish`.\
Ni muhimu pia kujua **umri wa kila kikoa kilichogunduliwa kuwa shukiwa**, kadri kinavyokuwa kipya ndivyo hatari inavyokuwa kubwa.\
Unaweza pia kupata **picha za skrini** za ukurasa wa wavuti wa HTTP na/au HTTPS ili kuona ikiwa ni shukiwa na kwa hali hiyo **ufikie kuangalia kwa undani**.

### Uchunguzi wa Kina

Ikiwa unataka kwenda hatua moja mbele ningependekeza **kufuatilia vikoa hivyo vinavyoshukiwa na kutafuta zaidi** mara kwa mara (kila siku? inachukua sekunde/chini ya dakika chache tu). Unapaswa pia **kuangalia** bandari **zilizofunguliwa** za IP zinazohusiana na **kutafuta mifano ya `gophish` au zana kama hizo** (ndio, wahalifu pia hufanya makosa) na **kufuatilia kurasa za wavuti za HTTP na HTTPS za vikoa vinavyoshukiwa na subdomains** kuona ikiwa wameiga fomu yoyote ya kuingia kutoka kwenye kurasa za wavuti za muathiriwa.\
Ili **kuatekeleza hii kiotomatiki** ningependekeza kuwa na orodha ya fomu za kuingia za vikoa vya muathiriwa, kutambaa kurasa za wavuti za shaka na kulinganisha kila fomu ya kuingia iliyopatikana ndani ya vikoa vinavyoshukiwa na kila fomu ya kuingia ya kikoa cha muathiriwa kwa kutumia kitu kama `ssdeep`.\
Ikiwa umepata fomu za kuingia za vikoa vinavyoshukiwa, unaweza **jaribu kutuma vitambulisho visivyo sahihi** na **kuangalia ikiwa inakurejesha kwenye kikoa cha muathiriwa**.

## Majina ya Kikoa yanayotumia Maneno muhimu

Ukurasa wa mzazi pia unataja mbinu ya mabadiliko ya jina la kikoa ambayo inajumuisha kuweka **jina la kikoa cha muathiriwa ndani ya kikoa kikubwa** (k.m. paypal-financial.com kwa paypal.com).

### Uwazi wa Cheti

Haiwezekani kuchukua njia ya awali ya "Brute-Force" lakini ni kweli **inawezekana kufunua majaribio kama hayo ya udukuzi** pia shukrani kwa uwazi wa cheti. Kila wakati cheti kinapotolewa na CA, maelezo yanafanywa kuwa ya umma. Hii inamaanisha kwamba kwa kusoma uwazi wa cheti au hata kufuatilia, ni **inawezekana kupata vikoa vinavyotumia neno muhimu ndani ya jina lake** Kwa mfano, ikiwa mshambuliaji anazalisha cheti cha [https://paypal-financial.com](https://paypal-financial.com), kwa kusoma cheti ni rahisi kupata neno muhimu "paypal" na kujua kuwa barua pepe shukiwa inatumika.

Chapisho [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) inapendekeza unaweza kutumia Censys kutafuta vyeti vinavyoathiri neno maalum na kufuta kwa tarehe (vyeti "vipya" tu) na kwa mtoaji wa CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1112).png>)

Hata hivyo, unaweza kufanya "vilevile" kwa kutumia wavuti huru [**crt.sh**](https://crt.sh). Unaweza **kutafuta neno muhimu** na **kufuta** matokeo **kwa tarehe na CA** ikiwa unataka.

![](<../../.gitbook/assets/image (516).png>)

Kwa kutumia chaguo hili la mwisho unaweza hata kutumia uga wa Kulinganisha Utambulisho kuona ikiwa utambulisho wowote kutoka kwa kikoa halisi unalingana na mojawapo ya vikoa vinavyoshukiwa (kumbuka kwamba kikoa shukiwa kinaweza kuwa matokeo ya uwongo).

**Chaguo lingine** ni mradi mzuri unaoitwa [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream hutoa mtiririko wa moja kwa moja wa vyeti vilivyozalishwa hivi karibuni ambavyo unaweza kutumia kugundua maneno maalum (karibu) kwa wakati halisi. Kwa kweli, kuna mradi unaitwa [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) ambao unafanya hivyo.
### **Domeini mpya**

**Chaguo la mwisho** ni kukusanya orodha ya **domeini zilizosajiliwa hivi karibuni** kwa baadhi ya TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) hutoa huduma kama hiyo) na **kuchunguza maneno muhimu katika domeini hizi**. Hata hivyo, domeini ndefu kawaida hutumia moja au zaidi ya subdomain, hivyo neno muhimu halitaonekana ndani ya FLD na hutaweza kupata subdomain ya ulaghai.
