# AD Certificates

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Introduction

### Components of a Certificate

- **Mada** ya cheti inaonyesha mmiliki wake.
- **Funguo ya Umma** inashirikishwa na funguo ya kibinafsi kuunganisha cheti na mmiliki wake halali.
- **Muda wa Uhalali**, ulioainishwa na tarehe za **NotBefore** na **NotAfter**, unaashiria muda wa ufanisi wa cheti.
- Nambari ya **Serial** ya kipekee, inayotolewa na Mamlaka ya Cheti (CA), inatambulisha kila cheti.
- **Mtoaji** inahusisha CA ambayo imetoa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa mada, ikiongeza kubadilika kwa utambuzi.
- **Misingi ya Msingi** inatambulisha ikiwa cheti ni kwa CA au kitengo cha mwisho na kuainisha vizuizi vya matumizi.
- **Matumizi ya Funguo ya Kupanua (EKUs)** yanaelezea madhumuni maalum ya cheti, kama vile kusaini msimbo au usimbaji wa barua pepe, kupitia Vitambulisho vya Kitu (OIDs).
- **Algorithimu ya Saini** inaelezea njia ya kusaini cheti.
- **Saini**, iliyoundwa kwa funguo ya kibinafsi ya mtoaji, inahakikisha uhalali wa cheti.

### Special Considerations

- **Majina Alternatif ya Mada (SANs)** yanapanua matumizi ya cheti kwa vitambulisho vingi, muhimu kwa seva zenye maeneo mengi. Mchakato wa kutoa cheti kwa usalama ni muhimu ili kuepuka hatari za kujifanya kwa washambuliaji wanaoshughulikia spesifikas za SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS inatambua vyeti vya CA katika msitu wa AD kupitia kontena zilizotengwa, kila moja ikihudumu majukumu ya kipekee:

- Kontena ya **Mamlaka ya Cheti** inashikilia vyeti vya CA vya mizizi vinavyotambulika.
- Kontena ya **Huduma za Usajili** inaelezea CAs za Biashara na templeti zao za cheti.
- Kituo cha **NTAuthCertificates** kinajumuisha vyeti vya CA vilivyothibitishwa kwa uthibitisho wa AD.
- Kontena ya **AIA (Upatikanaji wa Taarifa za Mamlaka)** inarahisisha uthibitishaji wa mnyororo wa cheti na vyeti vya CA vya kati na vya msalaba.

### Certificate Acquisition: Client Certificate Request Flow

1. Mchakato wa ombi huanza na wateja wakitafuta CA ya Biashara.
2. CSR inaundwa, ikiwa na funguo ya umma na maelezo mengine, baada ya kuunda jozi ya funguo ya umma na ya kibinafsi.
3. CA inakagua CSR dhidi ya templeti za cheti zilizopo, ikitoa cheti kulingana na ruhusa za templeti.
4. Baada ya kuidhinishwa, CA inasaini cheti kwa funguo yake ya kibinafsi na kuirudisha kwa mteja.

### Certificate Templates

Zimeainishwa ndani ya AD, templeti hizi zinaelezea mipangilio na ruhusa za kutoa vyeti, ikiwa ni pamoja na EKUs zinazoruhusiwa na haki za usajili au mabadiliko, muhimu kwa usimamizi wa ufikiaji wa huduma za cheti.

## Certificate Enrollment

Mchakato wa usajili wa vyeti huanzishwa na msimamizi ambaye **anaunda templeti ya cheti**, ambayo kisha **inasambazwa** na Mamlaka ya Cheti ya Biashara (CA). Hii inafanya templeti ipatikane kwa usajili wa mteja, hatua inayofikiwa kwa kuongeza jina la templeti kwenye uwanja wa `certificatetemplates` wa kitu cha Active Directory.

Ili mteja aombe cheti, **haki za usajili** lazima zipewe. Haki hizi zinaainishwa na waelekezi wa usalama kwenye templeti ya cheti na CA ya Biashara yenyewe. Ruhusa lazima zipewe katika maeneo yote mawili ili ombi liwe na mafanikio.

### Template Enrollment Rights

Haki hizi zinaainishwa kupitia Kuingilia kwa Udhibiti wa Ufikiaji (ACEs), zikielezea ruhusa kama:
- Haki za **Usajili wa Cheti** na **Usajili wa Kiotomatiki wa Cheti**, kila moja ikihusishwa na GUID maalum.
- **Haki za Kupanua**, zinazoruhusu ruhusa zote za kupanua.
- **Udhibiti Kamili/GenericAll**, ukitoa udhibiti kamili juu ya templeti.

### Enterprise CA Enrollment Rights

Haki za CA zinaelezwa katika waelekezi wake wa usalama, zinazopatikana kupitia console ya usimamizi wa Mamlaka ya Cheti. Mipangilio mingine hata inaruhusu watumiaji wenye mamlaka ya chini kupata mbali, ambayo inaweza kuwa wasiwasi wa usalama.

### Additional Issuance Controls

Madhara fulani yanaweza kutumika, kama:
- **Idhini ya Meneja**: Inaweka maombi katika hali ya kusubiri hadi idhini itolewe na meneja wa cheti.
- **Wakala wa Usajili na Saini Zilizothibitishwa**: Kuainisha idadi ya saini zinazohitajika kwenye CSR na OIDs za Sera ya Maombi zinazohitajika.

### Methods to Request Certificates

Vyeti vinaweza kuombwa kupitia:
1. **Protokali ya Usajili wa Cheti ya Mteja wa Windows** (MS-WCCE), ikitumia interfaces za DCOM.
2. **Protokali ya ICertPassage Remote** (MS-ICPR), kupitia mabomba yaliyopewa majina au TCP/IP.
3. Kiolesura cha wavuti cha **usajili wa cheti**, na jukumu la Usajili wa Wavuti wa Mamlaka ya Cheti lililosakinishwa.
4. **Huduma ya Usajili wa Cheti** (CES), kwa kushirikiana na huduma ya Sera ya Usajili wa Cheti (CEP).
5. **Huduma ya Usajili wa Vifaa vya Mtandao** (NDES) kwa vifaa vya mtandao, ikitumia Protokali ya Usajili wa Cheti Rahisi (SCEP).

Watumiaji wa Windows wanaweza pia kuomba vyeti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za mstari wa amri (`certreq.exe` au amri ya PowerShell `Get-Certificate`).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitisho wa Cheti

Active Directory (AD) inasaidia uthibitisho wa cheti, hasa ikitumia **Kerberos** na **Secure Channel (Schannel)** protokali.

### Mchakato wa Uthibitisho wa Kerberos

Katika mchakato wa uthibitisho wa Kerberos, ombi la mtumiaji la Tiketi ya Kutoa Tiketi (TGT) linatiwa saini kwa kutumia **funguo ya faragha** ya cheti cha mtumiaji. Ombi hili hupitia uthibitisho kadhaa na msimamizi wa eneo, ikiwa ni pamoja na **halali** ya cheti, **njia**, na **hali ya kufutwa**. Uthibitisho pia unajumuisha kuangalia kwamba cheti kinatoka kwa chanzo kinachotegemewa na kuthibitisha uwepo wa mtoaji katika **duka la cheti la NTAUTH**. Uthibitisho uliofanikiwa unapelekea utoaji wa TGT. Kitu cha **`NTAuthCertificates`** katika AD, kinapatikana kwenye:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is central to establishing trust for certificate authentication.

### Secure Channel (Schannel) Authentication

Schannel inasaidia muunganisho salama wa TLS/SSL, ambapo wakati wa mkutano, mteja anawasilisha cheti ambacho, ikiwa kimefanikiwa kuthibitishwa, kinatoa ruhusa ya ufikiaji. Mchoro wa cheti kwa akaunti ya AD unaweza kujumuisha kazi ya Kerberos **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, miongoni mwa mbinu nyingine.

### AD Certificate Services Enumeration

Huduma za cheti za AD zinaweza kuhesabiwa kupitia maswali ya LDAP, zikifunua habari kuhusu **Enterprise Certificate Authorities (CAs)** na mipangilio yao. Hii inapatikana na mtumiaji yeyote aliyeidhinishwa na kikoa bila ruhusa maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** zinatumika kwa ajili ya kuhesabu na tathmini ya udhaifu katika mazingira ya AD CS.

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
## References

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
