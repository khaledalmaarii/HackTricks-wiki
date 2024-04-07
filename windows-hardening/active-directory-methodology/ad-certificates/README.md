# Vyeti vya AD

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

### Vipengele vya Cheti

- **Mada** ya cheti inaonyesha mmiliki wake.
- **Ufunguo wa Umma** unalinganishwa na ufunguo uliohifadhiwa kibinafsi ili kuunganisha cheti na mmiliki wake halali.
- **Kipindi cha Uhalali**, kilichofafanuliwa na tarehe za **NotBefore** na **NotAfter**, hupima muda halali wa cheti.
- Nambari ya kipekee ya **Serial**, iliyotolewa na Mamlaka ya Cheti (CA), inatambua kila cheti.
- **Mtoaji** hurejelea CA ambayo imetoa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa mada, ikiboresha uwezo wa kutambua.
- **Vikwazo vya Msingi** vinatambua ikiwa cheti ni kwa CA au kifaa cha mwisho na kufafanua vizuizi vya matumizi.
- **Matumizi ya Upanuzi wa Ufunguo (EKUs)** yanafafanua madhumuni maalum ya cheti, kama vile kusaini kanuni au encryption ya barua pepe, kupitia Identifiers ya Vitu (OIDs).
- **Algorithimu ya Saini** inabainisha njia ya kusaini cheti.
- **Saini**, iliyoumbwa na ufunguo wa kibinafsi wa mtoaji, inahakikisha uhalali wa cheti.

### Mambo Maalum

- **Mada za Alternatifu za Majina (SANs)** huongeza ufanisi wa cheti kwa vitambulisho vingi, muhimu kwa seva zenye uwanja mwingi. Mchakato salama wa utoaji ni muhimu kuepuka hatari ya udanganyifu na wadukuzi wanaobadilisha maelezo ya SAN.

### Mamlaka za Cheti (CAs) katika Active Directory (AD)

AD CS inatambua vyeti vya CA katika msitu wa AD kupitia vyombo vilivyotengwa, kila moja ikitoa majukumu ya kipekee:

- Kontena ya **Mamlaka ya Uthibitisho** inashikilia vyeti vya mizizi ya CA inayotegemewa.
- Kontena za **Huduma za Usajili** zinafafanua CA za Kampuni na templeti zao za vyeti.
- Kitu cha **NTAuthCertificates** kina vyeti vya CA vilivyoidhinishwa kwa uthibitisho wa AD.
- Kontena ya **AIA (Mamlaka ya Kufikia Taarifa)** inarahisisha uthibitisho wa mnyororo wa vyeti na vyeti vya kati na vya msalaba.

### Upatikanaji wa Cheti: Mchakato wa Ombi la Cheti la Mteja

1. Mchakato wa ombi huanza na wateja kupata CA ya Kampuni.
2. CSR inaundwa, ikijumuisha ufunguo wa umma na maelezo mengine, baada ya kuzalisha jozi ya ufunguo wa umma-binafsi.
3. CA inachambua CSR dhidi ya templeti za vyeti zilizopo, ikitoa cheti kulingana na ruhusa za templeti.
4. Baada ya idhini, CA inasaini cheti kwa ufunguo wake wa kibinafsi na kuirudisha kwa mteja.

### Templeti za Cheti

Zilizofafanuliwa ndani ya AD, templeti hizi hupanga mipangilio na ruhusa za kutoa vyeti, ikiwa ni pamoja na EKUs zilizoruhusiwa na haki za usajili au marekebisho, muhimu kwa usimamizi wa upatikanaji wa huduma za cheti.

## Usajili wa Cheti

Mchakato wa usajili wa vyeti huanzishwa na msimamizi ambaye **anaunda templeti ya cheti**, ambayo kisha **inachapishwa** na Mamlaka ya Cheti ya Kampuni (CA). Hii inafanya templeti ipatikane kwa usajili wa mteja, hatua inayofikiwa kwa kuongeza jina la templeti kwenye uga wa `certificatetemplates` wa kitu cha Active Directory.

Ili mteja aombe cheti, **haki za usajili** lazima zitolewe. Haki hizi zinafafanuliwa na maelezo ya usalama kwenye templeti ya cheti na Mamlaka ya Cheti ya Kampuni yenyewe. Ruhusa lazima itolewe katika maeneo yote mawili ili ombi liweze kufanikiwa.

### Haki za Usajili wa Templeti

Haki hizi zinafafanuliwa kupitia Viingilio vya Kudhibiti Upatikanaji (ACEs), ikieleza ruhusa kama vile:
- Haki za **Kibali cha Cheti** na **Kibali cha Kiotomatiki cha Cheti**, kila moja ikihusishwa na GUID maalum.
- **Haki za Upanuzi**, zikiruhusu ruhusa zote za upanuzi.
- **FullControl/GenericAll**, zinazotoa udhibiti kamili juu ya templeti.

### Haki za Usajili wa Mamlaka ya Cheti ya Kampuni

Haki za CA zinafafanuliwa katika maelezo yake ya usalama, yanayopatikana kupitia konsoli ya usimamizi wa Mamlaka ya Cheti. Baadhi ya mipangilio hata inaruhusu watumiaji wenye mamlaka ya chini upatikanaji wa mbali, ambao unaweza kuwa wasiwasi wa usalama.

### Udhibiti wa Utoaji wa Ziada

Mipangilio fulani inaweza kutumika, kama vile:
- **Idhini ya Meneja**: Inaweka maombi katika hali ya kusubiri hadi idhini itolewe na meneja wa cheti.
- **Mawakala wa Usajili na Saini Zilizoidhinishwa**: Hufafanua idadi ya saini zinazohitajika kwenye CSR na Sera muhimu za Maombi OIDs.

### Njia za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:
1. **Itifaki ya Usajili wa Cheti cha Mteja wa Windows** (MS-WCCE), ikatumia viunganishi vya DCOM.
2. **Itifaki ya Mbali ya ICertPassage** (MS-ICPR), kupitia mabomba yaliyopewa majina au TCP/IP.
3. **Kiolesura cha Wavuti cha Usajili wa Cheti**, ikiwa na jukumu la Usajili wa Wavuti wa Mamlaka ya Cheti uliowekwa.
4. **Huduma ya Usajili wa Cheti** (CES), pamoja na huduma ya Sera ya Usajili wa Cheti (CEP).
5. **Huduma ya Usajili wa Kifaa cha Mtandao** (NDES) kwa vifaa vya mtandao, ikatumia Itifaki Rahisi ya Usajili wa Cheti (SCEP).

Watumiaji wa Windows pia wanaweza kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za mstari wa amri (`certreq.exe` au amri ya `Get-Certificate` ya PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitisho wa Cheti

Active Directory (AD) inasaidia uthibitisho wa cheti, kwa kiasi kikubwa ikichangia itifaki za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitisho wa Kerberos

Katika mchakato wa uthibitisho wa Kerberos, ombi la mtumiaji la Tiketi ya Kutoa Tiketi (TGT) limesainiwa kwa kutumia **ufunguo wa faragha** wa cheti cha mtumiaji. Ombi hili linapitia uthibitisho kadhaa na mwenye kudhibiti kikoa, ikiwa ni pamoja na **uhalali**, **njia**, na **hali ya kufutwa** kwa cheti. Uthibitisho pia unajumuisha kuthibitisha kwamba cheti kinatoka kwa chanzo kinachotegemewa na kuthibitisha uwepo wa mtoaji katika **hifadhi ya cheti ya NTAUTH**. Uthibitisho wa mafanikio husababisha kutolewa kwa TGT. **`NTAuthCertificates`** kitu katika AD, kinapatikana kwenye:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### Kuanzisha Imani kwa Uthibitisho wa Cheti.

### Uthibitisho wa Mfumo wa Salama (Schannel)

Schannel inawezesha uhusiano salama wa TLS/SSL, ambapo wakati wa salamu, mteja hutoa cheti ambacho, ikiwa kithibitishwa kwa mafanikio, kinaruhusu ufikiaji. Kufanana kwa cheti na akaunti ya AD inaweza kuhusisha kazi ya **S4U2Self** ya Kerberos au **Jina mbadala la Mada (SAN)** ya cheti, miongoni mwa njia zingine.

### Uchambuzi wa Huduma za Cheti za AD

Huduma za cheti za AD zinaweza kuchambuliwa kupitia mizizi ya LDAP, ikifunua habari kuhusu **Mamlaka za Cheti za Kampuni (CAs)** na mipangilio yao. Hii inapatikana na mtumiaji yeyote aliyeathibitishwa kwenye kikoa bila mamlaka maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumiwa kwa uchambuzi na tathmini ya hatari katika mazingira ya AD CS.

Amri za kutumia zana hizi ni pamoja na:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Marejeo

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
