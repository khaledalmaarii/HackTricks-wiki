# Vyeti vya AD

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

### Vipengele vya Cheti

- **Mada** ya cheti inaonyesha mmiliki wake.
- **Ufunguo wa Umma** unalinganishwa na ufunguo uliohifadhiwa kibinafsi ili kuunganisha cheti na mmiliki wake halali.
- **Kipindi cha Halali**, kilichofafanuliwa na tarehe za **NotBefore** na **NotAfter**, kinaweka muda halali wa cheti.
- Nambari ya kipekee ya **Serial Number**, iliyotolewa na Mamlaka ya Cheti (CA), inatambua kila cheti.
- **Mtoaji** inahusu CA ambayo imetoa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa mada, kuongeza uwezo wa kutambua.
- **Vikwazo vya Msingi** vinatambua ikiwa cheti ni kwa CA au kifaa cha mwisho na kufafanua vizuizi vya matumizi.
- **Matumizi ya Msingi ya Upanuzi (EKUs)** yanabainisha madhumuni maalum ya cheti, kama kusaini nambari au kusimbua barua pepe, kupitia Kitambulisho cha Vitu (OIDs).
- **Alama ya Saini** inabainisha njia ya kusaini cheti.
- **Saini**, iliyoundwa na ufunguo wa kibinafsi wa mtoaji, inahakikisha uhalali wa cheti.

### Mambo Maalum ya Kuzingatia

- **Subject Alternative Names (SANs)** huongeza uwezekano wa cheti kutumika kwa kitambulisho cha vitambulisho vingi, muhimu kwa seva zenye uwanja mwingi. Mchakato salama wa utoaji ni muhimu ili kuepuka hatari ya udanganyifu na wadukuzi wanaobadilisha maelezo ya SAN.

### Mamlaka za Cheti (CAs) katika Active Directory (AD)

AD CS inatambua vyeti vya CA katika msitu wa AD kupitia vyombo vilivyotengwa, kila kimoja kikitoa majukumu tofauti:

- Kontena ya **Mamlaka za Uthibitisho** inashikilia vyeti vya CA ya mizizi iliyoaminika.
- Kontena ya **Huduma za Usajili** inaelezea CA za Kampuni na templeti zao za vyeti.
- Kitu cha **NTAuthCertificates** kinajumuisha vyeti vya CA vilivyoidhinishwa kwa uthibitisho wa AD.
- Kontena ya **AIA (Maelezo ya Upatikanaji wa Mamlaka)** inawezesha uthibitisho wa mnyororo wa vyeti na vyeti vya kati na msalaba.

### Upatikanaji wa Cheti: Mchakato wa Ombi la Cheti la Mteja

1. Mchakato wa ombi unaanza na wateja kupata CA ya Kampuni.
2. CSR inaundwa, ikijumuisha ufunguo wa umma na maelezo mengine, baada ya kuzalisha jozi ya ufunguo wa umma-kibinafsi.
3. CA inachunguza CSR dhidi ya templeti za vyeti zilizopo, ikitoa cheti kulingana na ruhusa za templeti.
4. Baada ya idhini, CA inasaini cheti kwa ufunguo wake wa kibinafsi na kuirudisha kwa mteja.

### Templeti za Cheti

Zilizoelezwa ndani ya AD, templeti hizi zinaelezea mipangilio na ruhusa za kutoa vyeti, pamoja na EKUs zilizoruhusiwa na haki za usajili au ubadilishaji, muhimu kwa kusimamia upatikanaji wa huduma za vyeti.

## Usajili wa Cheti

Mchakato wa usajili wa vyeti unaanzishwa na msimamizi ambaye **anaunda templeti ya cheti**, ambayo kisha **inachapishwa** na Mamlaka ya Cheti ya Kampuni (CA). Hii inafanya templeti ipatikane kwa usajili wa wateja, hatua inayofanikiwa kwa kuongeza jina la templeti kwenye uga wa `certificatetemplates` ya kitu cha Active Directory.

Ili mteja aweze kuomba cheti, **haki za usajili** lazima zitolewe. Haki hizi zinatambuliwa na maelezo ya usalama kwenye templeti ya cheti na Mamlaka ya Cheti ya Kampuni yenyewe. Ruhusa lazima itolewe katika maeneo yote mawili ili ombi liweze kufanikiwa.

### Haki za Usajili wa Templeti

Haki hizi zinatajwa kupitia Viingilio vya Kudhibiti Upatikanaji (ACEs), ikielezea ruhusa kama vile:
- Haki za **Certificate-Enrollment** na **Certificate-AutoEnrollment**, kila moja ikihusishwa na GUID maalum.
- **Haki za Upanuzi**, kuruhusu ruhusa zote za ziada.
- **FullControl/GenericAll**, kutoa udhibiti kamili juu ya templeti.

### Haki za Usajili wa Mamlaka ya Kampuni

Haki za CA zinaelezewa katika maelezo yake ya usalama, yanayopatikana kupitia konsoli ya usimamizi wa Mamlaka ya Cheti. Baadhi ya mipangilio hata inaruhusu watumiaji wenye haki za chini kupata kijijini, ambayo inaweza kuwa wasiwasi wa usalama.

### Udhibiti wa Utoaji wa Ziada

Mipangilio fulani inaweza kutumika, kama vile:
- **Idhini ya Meneja**: Inaweka maombi katika hali ya kusubiri hadi idhinishwe na meneja wa cheti.
- **Mawakala wa Usajili na Saini Zilizoidhinishwa**: Hufafanua idadi ya saini zinazohitajika kwenye CSR na Sera ya Maombi ya lazima ya Maombi.

### Njia za Kuomba Vyeti

Vyeti vinaweza kuombwa kupitia:
1. **Itifaki ya Usajili wa Cheti cha Mteja wa Windows** (MS-WCCE), kwa kutumia interface za DCOM.
2. **Itifaki ya Mbali ya ICertPassage** (MS-ICPR), kupitia mabomba yaliyopewa majina au TCP/IP.
3. **Kiolesura cha wavuti cha usajili wa vyeti**, na jukumu la Usajili wa Mamlaka ya Cheti imewekwa.
4. **Huduma ya Usajili wa Vyeti** (CES), kwa ushirikiano na huduma ya Sera ya Usajili wa Vyeti (CEP).
5. **Huduma ya Usajili wa Kifaa cha Mtandao** (NDES) kwa vifaa vya mtandao, kwa kutumia Itifaki Rahisi ya Usajili wa Vyeti (SCEP).

Watumiaji wa Windows pia wanaweza kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za mstari wa amri (`certreq.exe` au amri ya `Get-Certificate` ya PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitishaji wa Cheti

Active Directory (AD) inasaidia uthibitishaji wa cheti, hasa kwa kutumia itifaki za **Kerberos** na **Secure Channel (Schannel)**.

### Mchakato wa Uthibitishaji wa Kerberos

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Tiketi ya Kutoa Tiketi (TGT) limesainiwa kwa kutumia **ufunguo wa faragha** wa cheti cha mtumiaji. Ombi hili linapitia uthibitisho kadhaa na seva ya kudhibiti kikoa, ikiwa ni pamoja na **uthabiti**, **njia**, na **hali ya kufutwa** ya cheti. Uthibitisho pia ni pamoja na kuhakikisha kuwa cheti kinatoka kwa chanzo kilichosadikika na kuthibitisha uwepo wa msambazaji katika **hifadhi ya cheti ya NTAUTH**. Uthibitisho uliofanikiwa husababisha kutolewa kwa TGT. **`NTAuthCertificates`** kifaa katika AD, kinapatikana kwenye:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### Uhakiki wa Cheti cha AD

Uhakiki wa cheti cha AD ni muhimu katika kuanzisha imani kwa uthibitisho wa cheti.

### Uhakiki wa Kituo Salama (Schannel)

Schannel inawezesha uhusiano salama wa TLS/SSL, ambapo wakati wa mazungumzo, mteja hutoa cheti ambacho, ikiwa kinaidhinishwa kwa mafanikio, kinaruhusu ufikiaji. Ulinganishaji wa cheti na akaunti ya AD unaweza kuhusisha kazi ya **S4U2Self** ya Kerberos au **Jina Badala la Mada (SAN)** ya cheti, miongoni mwa njia zingine.

### Uchunguzi wa Huduma za Cheti za AD

Huduma za cheti za AD zinaweza kuchunguzwa kupitia maswali ya LDAP, ambayo hufichua habari kuhusu **Mamlaka za Cheti za Kampuni (CAs)** na mipangilio yao. Hii inapatikana kwa mtumiaji yeyote aliye na uthibitisho wa kikoa bila mamlaka maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** hutumiwa kwa uchunguzi na tathmini ya hatari katika mazingira ya AD CS.

Amri za kutumia zana hizi ni:
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

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
