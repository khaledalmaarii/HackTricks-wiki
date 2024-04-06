# macOS MDM

<details>

<summary><strong>Jifunze kuhusu macOS MDMs kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Ili kujifunza kuhusu macOS MDMs angalia:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Misingi

### **Muhtasari wa MDM (Mobile Device Management)**

[Usimamizi wa Kifaa cha Simu](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) hutumiwa kusimamia vifaa mbalimbali vya watumiaji kama simu za mkononi, kompyuta ndogo, na vidonge. Hasa kwa majukwaa ya Apple (iOS, macOS, tvOS), inajumuisha seti ya huduma maalum, APIs, na mazoea. Uendeshaji wa MDM unategemea seva ya MDM inayofaa, ambayo inapatikana kibiashara au chanzo wazi, na lazima iweze kusaidia [Itifaki ya MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Mambo muhimu ni pamoja na:

* Udhibiti uliojumuishwa juu ya vifaa.
* Utegemezi kwa seva ya MDM inayofuata itifaki ya MDM.
* Uwezo wa seva ya MDM kutuma amri mbalimbali kwa vifaa, kwa mfano, kufuta data kwa mbali au usanidi wa usakinishaji.

### **Misingi ya DEP (Programu ya Usajili wa Kifaa)**

[Programu ya Usajili wa Kifaa](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) inayotolewa na Apple inasaidia ushirikiano wa Usimamizi wa Kifaa cha Simu (MDM) kwa kusaidia usanidi wa kugusa sifuri kwa vifaa vya iOS, macOS, na tvOS. DEP inafanya usajili kuwa wa moja kwa moja, kuruhusu vifaa kuwa tayari kutumika mara tu baada ya kufunguliwa, bila kuingilia kati kwa mtumiaji au utawala. Mambo muhimu ni pamoja na:

* Inawezesha vifaa kujiandikisha kiotomatiki na seva ya MDM iliyopangwa mapema baada ya kuanzishwa kwa mara ya kwanza.
* Inafaa hasa kwa vifaa vipya, lakini pia inatumika kwa vifaa vinavyopitia upya usanidi.
* Inarahisisha usanidi rahisi, kufanya vifaa kuwa tayari kwa matumizi ya shirika kwa haraka.

### **Uzingatiaji wa Usalama**

Ni muhimu kuzingatia kuwa urahisi wa usajili uliotolewa na DEP, ingawa ni wa manufaa, pia unaweza kuleta hatari za usalama. Ikiwa hatua za kinga hazitekelezwi ipasavyo kwa usajili wa MDM, wadukuzi wanaweza kutumia mchakato huu uliofupishwa kujiandikisha kifaa chao kwenye seva ya MDM ya shirika, wakijifanya kuwa kifaa cha kampuni.

{% hint style="danger" %}
**Tahadhari ya Usalama**: Usajili uliofupishwa wa DEP unaweza kuruhusu usajili usiohalali wa kifaa kwenye seva ya MDM ya shirika ikiwa hatua sahihi za usalama hazijawekwa.
{% endhint %}

### Misingi Je! Ni nini SCEP (Itifaki ya Usajili Rahisi wa Cheti)?

* Itifaki ya zamani, iliyoanzishwa kabla ya TLS na HTTPS kuenea.
* Inawapa wateja njia iliyostandardi ya kutuma **Ombi la Kusaini Cheti** (CSR) kwa lengo la kupewa cheti. Mteja atamwomba server kumpa cheti kilichosainiwa.

### Je! Ni nini Mipangilio ya Usanidi (inayojulikana kama mobileconfigs)?

* Njia rasmi ya Apple ya **kuweka/kutekeleza usanidi wa mfumo.**
* Muundo wa faili ambao unaweza kuwa na malipo mengi.
* Inategemea orodha za mali (aina ya XML).
* "inaweza kusainiwa na kusimbwa ili kuthibitisha asili yao, kuhakikisha uadilifu wao, na kulinda maudhui yao." Misingi - Ukurasa 70, Mwongozo wa Usalama wa iOS, Januari 2018.

## Itifaki

### MDM

* Uunganisho wa APNs (**seva za Apple**) + API ya RESTful (**seva za wauzaji wa MDM**)
* **Mawasiliano** yanatokea kati ya **kifaa** na seva inayohusiana na **bidhaa ya usimamizi wa kifaa**
* **Amri** zinazotolewa kutoka MDM kwenda kifaa katika **orodha za plist-encoded**
* Yote juu ya **HTTPS**. Seva za MDM zinaweza kuwa (na kawaida) zimefungwa.
* Apple inatoa cheti cha **APNs** kwa muuzaji wa MDM kwa uthibitisho

### DEP

* **API 3**: 1 kwa wauzaji, 1 kwa wauzaji wa MDM, 1 kwa kitambulisho cha kifaa (hakijadiliwa):
* Inayoitwa [DEP "huduma ya wingu" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Hii hutumiwa na seva za MDM kuunganisha maelezo ya DEP na vifaa maalum.
* [API ya DEP inayotumiwa na Wauzaji wa Kuidhinishwa na Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) kujiandikisha vifaa, kuchunguza hali ya usajili, na kuchunguza hali ya shughuli.
* API ya DEP isiyojulikana. Hii hutumiwa na Vifaa vya Apple kuomba maelezo yao ya DEP. Kwenye macOS, faili ya `cloudconfigurationd` inahusika na mawasiliano kupitia API hii.
* Inategemea zaidi na **JSON** (tofauti na plist)
* Apple inatoa **kitufe cha OAuth** kwa muuzaji wa MDM

**DEP "huduma ya wingu" API**

* RESTful
* kusawazisha rekodi za kifaa kutoka Apple kwenda seva ya MDM
* kusawazisha "maelezo ya DEP" kwa Apple kutoka seva ya MDM (yaliyotolewa na Apple kwa kifaa baadaye)
* "Maelezo ya DEP" yanajumuisha:
* URL ya seva ya muuzaji wa MDM
* Vyeti vya kuaminika zaidi kwa URL ya seva (pia pinning hiari)
* Mipangilio ya ziada (k.m. skrini zipi za kupitisha katika Msaidizi wa Usanidi)

## Nambari ya Serial

V

### Hatua ya 4: Ukaguzi wa DEP - Kupata Rekodi ya Ufunguzi

Sehemu hii ya mchakato inatokea wakati **mtumiaji anapobootisha Mac kwa mara ya kwanza** (au baada ya kufuta kabisa)

![](<../../../.gitbook/assets/image (568).png>)

au wakati wa kutekeleza `sudo profiles show -type enrollment`

* Tathmini **iwapo kifaa kina DEP imewezeshwa**
* Rekodi ya Ufunguzi ni jina la ndani la **"profile" ya DEP**
* Inaanza mara tu kifaa kinapounganishwa na mtandao
* Inasukumwa na **`CPFetchActivationRecord`**
* Imetekelezwa na **`cloudconfigurationd`** kupitia XPC. **"Msaidizi wa Usanidi**" (wakati kifaa kinabootiwa kwa mara ya kwanza) au amri ya **`profiles`** itawasiliana na daemon huyu ili kupata rekodi ya ufunguzi.
* LaunchDaemon (daima inaendeshwa kama root)

Inafuata hatua chache za kupata Rekodi ya Ufunguzi iliyotekelezwa na **`MCTeslaConfigurationFetcher`**. Mchakato huu hutumia encryption inayoitwa **Absinthe**

1. Pata **cheti**
2. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
3. **Anzisha** hali kutoka kwa cheti (**`NACInit`**)
4. Inatumia data mbalimbali maalum ya kifaa (kwa mfano **Nambari ya Serial kupitia `IOKit`**)
5. Pata **funguo la kikao**
6. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
7. Anzisha kikao (**`NACKeyEstablishment`**)
8. Fanya ombi
9. POST kwa [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) ukituma data `{ "action": "RequestProfileConfiguration", "sn": "" }`
10. Mzigo wa JSON umefichwa kwa kutumia Absinthe (**`NACSign`**)
11. Ombi zote zinafanywa kupitia HTTPs, vyeti vya mizizi iliyojengwa ndani hutumiwa

![](<../../../.gitbook/assets/image (566).png>)

Jibu ni kamusi ya JSON na data muhimu kama vile:

* **url**: URL ya mwenyeji wa muuzaji wa MDM kwa ajili ya profile ya ufunguzi
* **anchor-certs**: Safu ya vyeti vya DER vinavyotumiwa kama vyeti vya kuaminika

### **Hatua ya 5: Upatikanaji wa Profile**

![](<../../../.gitbook/assets/image (567).png>)

* Ombi linatumwa kwa **url iliyotolewa katika profile ya DEP**.
* **Vyeti vya kiungo** hutumiwa kwa **kutathmini uaminifu** ikiwa vimepatikana.
* Kumbuka: mali ya **anchor\_certs** ya profile ya DEP
* **Ombi ni .plist rahisi** lenye kitambulisho cha kifaa
* Mifano: **UDID, toleo la OS**.
* Imesainiwa na CMS, imekodishwa kwa DER
* Imesainiwa kwa kutumia **cheti cha kitambulisho cha kifaa (kutoka APNS)**
* **Mnyororo wa vyeti** unajumuisha **Apple iPhone Device CA** iliyopita muda wake

![](https://github.com/carlospolop/hacktricks/blob/sw/.gitbook/assets/image%20\(567\)%20\(1\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(2\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(1\)%20\(7\).png)

### Hatua ya 6: Usakinishaji wa Profile

* Mara baada ya kupatikana, **profile inahifadhiwa kwenye mfumo**
* Hatua hii inaanza moja kwa moja (ikiwa katika **msaidizi wa usanidi**)
* Inasukumwa na **`CPInstallActivationProfile`**
* Imetekelezwa na mdmclient kupitia XPC
* LaunchDaemon (kama root) au LaunchAgent (kama mtumiaji), kulingana na muktadha
* Vipengele vya usanidi vina malipo mengi ya kusakinisha
* Mfumo una usanifu unaotegemea programu-jalizi kwa ajili ya kusakinisha vipengele vya usanidi
* Kila aina ya malipo inahusishwa na programu-jalizi
* Inaweza kuwa XPC (katika mfumo) au Cocoa ya kawaida (katika ManagedClient.app)
* Mfano:
* Malipo ya Cheti hutumia CertificateService.xpc

Kwa kawaida, **profile ya ufunguzi** inayotolewa na muuzaji wa MDM ita **kuhusisha malipo yafuatayo**:

* `com.apple.mdm`: kwa **kujiandikisha** kifaa katika MDM
* `com.apple.security.scep`: kutoa kwa usalama **cheti cha mteja** kwa kifaa.
* `com.apple.security.pem`: kusakinisha vyeti vya CA vinavyoaminika kwenye Kitufe cha Mfumo cha kifaa.
* Kusakinisha malipo ya MDM sawa na **kujiandikisha kwa MDM katika nyaraka**
* Malipo **yana mali muhimu**:
*
* URL ya Kujiandikisha MDM (**`CheckInURL`**)
* URL ya Kupiga Ombi la Amri ya MDM (**`ServerURL`**) + mada ya APNs kuichomoa
* Kusakinisha malipo ya MDM, ombi linatumwa kwa **`CheckInURL`**
* Imetekelezwa katika **`mdmclient`**
* Malipo ya MDM yanaweza kulingana na malipo mengine
* Inaruhusu **ombi kuwa imewekwa kwenye vyeti maalum**:
* Mali: **`CheckInURLPinningCertificateUUIDs`**
* Mali: **`ServerURLPinningCertificateUUIDs`**
* Inayotolewa kupitia malipo ya PEM
* Inaruhusu kifaa kuwa na cheti cha kitambulisho:
* Mali: IdentityCertificateUUID
* Inayotolewa kupitia malipo ya SCEP

### **Hatua ya 7: Kusikiliza Amri za MDM**

* Baada ya ukaguzi wa MDM kukamilika, muuzaji anaweza **kutoa arifa za itifaki za push kwa kutumia APNs**
* Baada ya kupokea, inashughulikiwa na **`mdmclient`**
* Kupiga ombi la amri za MDM, ombi linatumwa kwa ServerURL
* Inatumia malipo ya MDM yaliyosakinishwa hapo awali:
* **`ServerURLPinningCertificateUUIDs`** kwa ombi la kuweka
* **`IdentityCertificateUUID`** kwa cheti cha mteja cha TLS

## Mashambulizi

### Kujiandikisha Kifaa katika Mashirika Mengine

Kama ilivyosemwa hapo awali, ili kujaribu kujiandikisha kifaa katika shirika **inahitajika tu Nambari ya Serial inayomilikiwa na Shirika hilo**. Mara kifaa kinapojiandikisha, mashirika kadhaa yataweka data nyeti kwenye kifaa kipya: vyeti, programu, nywila za WiFi, mipangilio ya VPN [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Kwa hivyo, hii inaweza kuwa njia hatari kwa wadukuzi ikiwa mchakato wa kujiandikisha haujalindwa kwa usahihi:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong></summary>



</details>
