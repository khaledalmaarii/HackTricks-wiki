# macOS MDM

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Kujifunza kuhusu macOS MDMs angalia:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Misingi

### **Muhtasari wa MDM (Usimamizi wa Kifaa cha Simu)**

[Usimamizi wa Kifaa cha Simu](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) hutumiwa kusimamia vifaa vya watumiaji mbalimbali kama simu za mkononi, kompyuta ndogo, na vidonge. Hasa kwa majukwaa ya Apple (iOS, macOS, tvOS), inajumuisha seti ya huduma maalum, APIs, na mazoea. Uendeshaji wa MDM unategemea seva ya MDM inayofaa, ambayo inapatikana kibiashara au chanzo wazi, na lazima iweze kusaidia [Itifaki ya MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Mambo muhimu ni pamoja na:

* Udhibiti uliogawanywa wa vifaa.
* Kitegemea kwenye seva ya MDM inayofuata itifaki ya MDM.
* Uwezo wa seva ya MDM kutuma amri mbalimbali kwa vifaa, kwa mfano, kufuta data kijijini au usakinishaji wa usanidi.

### **Misingi ya DEP (Mpango wa Usajili wa Kifaa)**

[Programu ya Usajili wa Kifaa](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) inayotolewa na Apple inarahisisha ushirikishaji wa Usimamizi wa Kifaa cha Simu (MDM) kwa kusaidia usanidi wa kugusa sifuri kwa vifaa vya iOS, macOS, na tvOS. DEP inaharakisha mchakato wa usajili, kuruhusu vifaa kuwa tayari kutumika mara tu kutoka kwenye sanduku, bila kuingilia kati kidogo kutoka kwa mtumiaji au msimamizi. Mambo muhimu ni pamoja na:

* Inawezesha vifaa kujiandikisha kiotomatiki kwenye seva ya MDM iliyopangwa mapema baada ya kuanzishwa kwa mara ya kwanza.
* Hasa inafaa kwa vifaa vipya, lakini pia inafaa kwa vifaa vinavyopitia upya usanidi.
* Inarahisisha usanidi wa moja kwa moja, ikifanya vifaa kuwa tayari kwa matumizi ya shirika haraka.

### **Uzingatiaji wa Usalama**

Ni muhimu kuzingatia kuwa urahisi wa usajili uliotolewa na DEP, ingawa ni faida, inaweza pia kuleta hatari za usalama. Ikiwa hatua za kinga hazitekelezwi ipasavyo kwa usajili wa MDM, wadukuzi wanaweza kutumia mchakato huu uliohaririwa kusajili kifaa chao kwenye seva ya MDM ya shirika, wakijifanya kuwa kifaa cha kampuni.

{% hint style="danger" %}
**Onyo la Usalama**: Usajili rahisi wa DEP unaweza kuruhusu usajili usiohalali wa kifaa kwenye seva ya MDM ya shirika ikiwa hatua sahihi za kinga hazijawekwa.
{% endhint %}

### Misingi Ni nini SCEP (Itifaki ya Usajili Rahisi wa Cheti)?

* Itifaki ya zamani, iliyoanzishwa kabla ya TLS na HTTPS kuenea.
* Hutoa wateja njia iliyostandardi ya kutuma **Ombi la Kusaini Cheti** (CSR) kwa lengo la kupewa cheti. Mteja atamwomba serveri kumpa cheti kilichosainiwa.

### Ni nini Mipangilio ya Usanidi (inayoitwa mobileconfigs)?

* Njia rasmi ya Apple ya **kuweka/kutekeleza usanidi wa mfumo.**
* Muundo wa faili unaweza kuwa na malipo mengi.
* Kulingana na orodha za mali (aina ya XML).
* "inaweza kusainiwa na kusimbwa ili kuthibitisha asili yao, kuhakikisha usahihi wao, na kulinda maudhui yao." Misingi — Ukurasa 70, Mwongozo wa Usalama wa iOS, Januari 2018.

## Itifaki

### MDM

* Mchanganyiko wa APNs (**Seva za Apple**) + RESTful API (**Seva za muuzaji wa MDM**)
* **Mawasiliano** hufanyika kati ya **kifaa** na seva inayohusiana na **bidhaa ya usimamizi wa kifaa**
* **Amri** zinazotolewa kutoka kwa MDM kwenda kwa kifaa katika **orodha za plist-encoded**
* Yote juu ya **HTTPS**. Seva za MDM zinaweza kuwa (na kawaida) zimefungwa.
* Apple inatoa cheti cha **APNs** kwa muuzaji wa MDM kwa uthibitisho

### DEP

* **3 APIs**: 1 kwa wauzaji, 1 kwa wauzaji wa MDM, 1 kwa kitambulisho cha kifaa (hakijaelezwa):
* Inayoitwa [API ya "huduma ya wingu" ya DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Hii hutumiwa na seva za MDM kuunganisha maelezo ya DEP na vifaa maalum.
* [API ya DEP inayotumiwa na Wauzaji wa Kitaalam wa Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) kusajili vifaa, kuchunguza hali ya usajili, na kuchunguza hali ya shughuli.
* API ya kibinafsi ya DEP isiyoelezwa. Hutumiwa na Vifaa vya Apple kuomba maelezo yao ya DEP. Kwenye macOS, binary ya `cloudconfigurationd` ndiyo inayohusika na mawasiliano kupitia API hii.
* Zaidi ya kisasa na inategemea **JSON** (tofauti na plist)
* Apple inatoa **kitambulisho cha OAuth** kwa muuzaji wa MDM

**API ya "huduma ya wingu" ya DEP**

* RESTful
* kusawazisha rekodi za vifaa kutoka Apple kwenda kwa seva ya MDM
* kusawazisha "maelezo ya DEP" kwa Apple kutoka kwa seva ya MDM (yatakayotolewa na Apple kwa kifaa baadaye)
* Mwakilishi wa DEP ina:
* URL ya seva ya muuzaji wa MDM
* Vyeti vya kuaminika zaidi kwa URL ya seva (pinning hiari)
* Mipangilio ya ziada (k.m. ni skrini zipi za kupita katika Msaidizi wa Usanidi)

## Nambari ya Serial

Vifaa vya Apple vilivyotengenezwa baada ya 2010 kwa ujumla vina **nambari za serial zenye herufi 12 na tarakimu**, na **tarakimu tatu za kwanza zikionyesha eneo la utengenezaji**, zifuatazo **mbili** zikionyesha **mwaka** na **wiki** ya utengenezaji, tarakimu zinazofuata **tatu** zinatoa **kitambulisho** **cha kipekee**, na **tarakimu nne za mwisho** zinaonyesha **namba ya mfano**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Hatua za usajili na usimamizi

1. Uundaji wa rekodi ya kifaa (Muuzaji, Apple): Rekodi ya kifaa kipya inaundwa
2. Uteuzi wa rekodi ya kifaa (Mteja): Kifaa kinapewa seva ya MDM
3. Ufungaji wa rekodi ya kifaa (Muuzaji wa MDM): MDM inasawazisha rekodi za kifaa na kusukuma maelezo ya DEP kwa Apple
4. Ukaguzi wa DEP (Kifaa): Kifaa kinapata maelezo yake ya DEP
5. Upatikanaji wa maelezo (Kifaa)
6. Usakinishaji wa maelezo (Kifaa) a. pamoja na malipo ya MDM, SCEP na CA ya msingi
7. Kutolewa kwa amri ya MDM (Kifaa)

![](<../../../.gitbook/assets/image (691).png>)

Faili `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` inaorodhesha kazi ambazo zinaweza kuchukuliwa kama **"hatua" za kiwango cha juu** za mchakato wa usajili.
### Hatua ya 4: Ukaguzi wa DEP - Kupata Rekodi ya Uanzishaji

Sehemu hii ya mchakato hutokea wakati **mtumiaji anapowasha Mac kwa mara ya kwanza** (au baada ya kufuta kabisa)

![](<../../../.gitbook/assets/image (1041).png>)

au wakati wa kutekeleza `sudo profiles show -type enrollment`

* Thibitisha **iwapo kifaa kimeamilishwa kwa DEP**
* Rekodi ya Uanzishaji ni jina la ndani la **DEP "profile"**
* Inaanza mara tu kifaa kinapounganishwa na Mtandao
* Inaendeshwa na **`CPFetchActivationRecord`**
* Imetekelezwa na **`cloudconfigurationd`** kupitia XPC. **"Msaidizi wa Usanidi**" (wakati kifaa kinawashwa kwa mara ya kwanza) au amri ya **`profiles`** ita**wasiliana na kifaa hiki** ili kupata rekodi ya uanzishaji.
* LaunchDaemon (huendeshwa kama root)

Inafuata hatua chache kupata Rekodi ya Uanzishaji iliyotekelezwa na **`MCTeslaConfigurationFetcher`**. Mchakato huu hutumia encryption inayoitwa **Absinthe**

1. Pata **cheti**
1. PATA [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Anzisha** hali kutoka kwa cheti (**`NACInit`**)
1. Hutumia data mbalimbali maalum ya kifaa (yaani **Namba ya Serial kupitia `IOKit`**)
3. Pata **ufunguo wa kikao**
1. TUMA [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Thibitisha kikao (**`NACKeyEstablishment`**)
5. Fanya ombi
1. TUMA kwa [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) ukituma data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Mzigo wa JSON umefichwa kwa kutumia Absinthe (**`NACSign`**)
3. Maombi yote kupitia HTTPs, vyeti vya mizizi vilivyojengwa hutumiwa

![](<../../../.gitbook/assets/image (566) (1).png>)

Jibu ni kamusi ya JSON na data muhimu kama:

* **url**: URL ya mwenyeji wa muuzaji wa MDM kwa profile ya uanzishaji
* **anchor-certs**: Safu ya vyeti vya DER vinavyotumiwa kama mizizi ya kuaminiwa

### **Hatua ya 5: Upatikanaji wa Wasifu**

![](<../../../.gitbook/assets/image (441).png>)

* Ombi linalotumwa kwa **url iliyotolewa katika wasifu wa DEP**.
* **Vyeti vya mizizi** hutumiwa kwa **kutathmini uaminifu** ikiwa imepatikana.
* Kumbusho: mali ya **anchor\_certs** ya wasifu wa DEP
* **Ombi ni .plist rahisi** na kitambulisho cha kifaa
* Mifano: **UDID, toleo la OS**.
* CMS-iliyosainiwa, DER-iliyofungwa
* Imesainiwa kwa kutumia **cheti cha kitambulisho cha kifaa (kutoka APNS)**
* **Mnyororo wa vyeti** unajumuisha **Apple iPhone Device CA** iliyopita

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Hatua ya 6: Usanidi wa Wasifu

* Mara baada ya kupatikana, **wasifu huo hujumuishwa kwenye mfumo**
* Hatua hii huanza moja kwa moja (ikiwa katika **msaidizi wa usanidi**)
* Inaendeshwa na **`CPInstallActivationProfile`**
* Imetekelezwa na mdmclient kupitia XPC
* LaunchDaemon (kama root) au LaunchAgent (kama mtumiaji), kulingana na muktadha
* Wasifu wa usanidi una malipo mengi ya kusakinisha
* Mfumo una usanidi wa msingi wa programu-jalizi kwa kusakinisha mizigo
* Kila aina ya malipo inahusishwa na programu-jalizi
* Inaweza kuwa XPC (katika mfumo) au Cocoa ya kawaida (katika ManagedClient.app)
* Mfano:
* Malipo ya Cheti hutumia CertificateService.xpc

Kawaida, **wasifu wa uanzishaji** uliotolewa na muuzaji wa MDM utajumuisha **malipo yafuatayo**:

* `com.apple.mdm`: kwa **kujiandikisha** kifaa kwa MDM
* `com.apple.security.scep`: kutoa kwa usalama **cheti cha mteja** kwa kifaa.
* `com.apple.security.pem`: kwa **kusakinisha vyeti vya CA vinavyoaminika** kwenye Kitambulisho cha Mfumo wa kifaa.
* Kusakinisha malipo ya MDM sawa na **MDM check-in katika nyaraka**
* Malipo **yana mali muhimu**:
*
* URL ya MDM Check-In (**`CheckInURL`**)
* URL ya Kupiga Mipira ya Amri ya MDM (**`ServerURL`**) + mada ya APNs kuchochea
* Ili kusakinisha malipo ya MDM, ombi hutumwa kwa **`CheckInURL`**
* Imetekelezwa katika **`mdmclient`**
* Malipo ya MDM yanaweza kutegemea malipo mengine
* Inaruhusu **maombi kuambatishwa kwenye vyeti maalum**:
* Mali: **`CheckInURLPinningCertificateUUIDs`**
* Mali: **`ServerURLPinningCertificateUUIDs`**
* Iliyotolewa kupitia malipo ya PEM
* Inaruhusu kifaa kuambatishwa na cheti cha kitambulisho:
* Mali: IdentityCertificateUUID
* Iliyotolewa kupitia malipo ya SCEP

### **Hatua ya 7: Kusikiliza Amri za MDM**

* Baada ya MDM check-in kukamilika, muuzaji anaweza **kutoa arifa za kushinikiza kwa kutumia APNs**
* Baada ya kupokea, inashughulikiwa na **`mdmclient`**
* Ili kupiga kura kwa amri za MDM, ombi hutumwa kwa ServerURL
* Inatumia malipo ya MDM yaliyosakinishwa hapo awali:
* **`ServerURLPinningCertificateUUIDs`** kwa kufunga ombi
* **`IdentityCertificateUUID`** kwa cheti cha mteja cha TLS

## Mashambulizi

### Kujiandikisha Kifaa katika Mashirika Mengine

Kama ilivyotajwa awali, ili kujaribu kujiandikisha kifaa katika shirika **inahitajika Namba ya Serial inayomilikiwa na Shirika hilo**. Mara baada ya kifaa kujiandikisha, mashirika kadhaa yataweza kusakinisha data nyeti kwenye kifaa kipya: vyeti, programu, nywila za WiFi, mipangilio ya VPN [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Hivyo, hii inaweza kuwa njia hatari kwa wachomaji ikiwa mchakato wa usajili haujalindwa kwa usahihi:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>Jifunze kuhusu kuchomwa kwa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuchoma kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
