# AD CS Uthabiti wa Kikoa

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Hii ni muhtasari wa mbinu za uthabiti wa kikoa zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Angalia kwa maelezo zaidi.

## Kufanya Udanganyifu wa Vyeti na Vyeti vya CA Vilivyoporwa - DPERSIST1

Unawezaje kujua kwamba cheti ni cheti cha CA?

Inaweza kubainika kwamba cheti ni cheti cha CA ikiwa hali kadhaa zinakidhi:

- Cheti hicho kimehifadhiwa kwenye seva ya CA, na ufunguo wake wa kibinafsi umelindwa na DPAPI ya kifaa, au na vifaa kama TPM/HSM ikiwa mfumo wa uendeshaji unaiunga mkono.
- Vipengele vya Issuer na Subject vya cheti vinalingana na jina la kipekee la CA.
- Kuna kipengele cha "CA Version" kinachopatikana kwa vyeti vya CA pekee.
- Cheti halina uga wa Matumizi ya Upanuzi wa Muhimu (EKU).

Ili kuchimbua ufunguo wa kibinafsi wa cheti hiki, zana ya `certsrv.msc` kwenye seva ya CA ndiyo njia inayoungwa mkono kupitia GUI iliyojengwa. Walakini, cheti hiki hakina tofauti na vyeti vingine vilivyohifadhiwa ndani ya mfumo; kwa hivyo, njia kama [tekinolojia ya THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) inaweza kutumika kwa uchimbaji.

Cheti na ufunguo wa kibinafsi pia yanaweza kupatikana kwa kutumia Certipy na amri ifuatayo:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata cheti cha CA na ufunguo wake wa kibinafsi katika muundo wa `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kuzalisha vyeti halali:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Mtumiaji anayelengwa kwa udanganyifu wa cheti lazima awe hai na aweze kuthibitisha katika Active Directory ili mchakato ufanikiwe. Udanganyifu wa cheti kwa akaunti maalum kama krbtgt haufanikiwi.
{% endhint %}

Cheti hiki kilichodanganywa kitakuwa **halali** hadi tarehe ya mwisho iliyotajwa na **muda mrefu kama cheti cha CA kina halali** (kawaida kwa miaka 5 hadi **10+**). Pia ni halali kwa **mashine**, kwa hivyo ikishirikiana na **S4U2Self**, mshambuliaji anaweza **kuendelea kuwa na uwepo kwenye kifaa chochote cha kikoa** kwa muda mrefu kama cheti cha CA kina halali. 
Zaidi ya hayo, **vyeti vilivyozalishwa** kwa njia hii **haviwezi kufutwa** kwani CA haijui kuhusu vyeti hivyo.

## Kuamini Cheti za CA za Udanganyifu - DPERSIST2

Kitu cha `NTAuthCertificates` kimeainishwa kuwa na cheti kimoja au zaidi cha **CA** ndani ya sifa yake ya `cacertificate`, ambayo Active Directory (AD) inatumia. Mchakato wa uthibitisho na **kudhibiti kikoa** unahusisha kuangalia kitu cha `NTAuthCertificates` kwa kuingia kulingana na **CA iliyotajwa** katika uga wa Mtoa Cheti wa cheti cha kuthibitisha. Uthibitisho unaendelea ikiwa kuna kulingana.

Mshambuliaji anaweza kuongeza cheti cha CA kilichojisaini kwenye kitu cha `NTAuthCertificates`, ikiwa ana udhibiti juu ya kitu hiki cha AD. Kawaida, ni wanachama wa kikundi cha **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **kikoa cha mizizi cha msitu**, wanaopewa ruhusa ya kuhariri kitu hiki. Wanaweza kuhariri kitu cha `NTAuthCertificates` kwa kutumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Uwezo huu ni muhimu sana unapotumiwa pamoja na njia iliyoelezwa hapo awali inayohusisha ForgeCert kuzalisha vyeti kwa njia ya kudumu.

## Usanidi Mbaya wa Nia Mbaya - DPERSIST3

Fursa za **kudumu** kupitia **marekebisho ya maelezo ya usalama ya sehemu za AD CS** ni nyingi. Marekebisho yaliyoelezwa katika sehemu ya "[Kuongezeka kwa Kikoa](domain-escalation.md)" yanaweza kutekelezwa kwa nia mbaya na mshambuliaji mwenye ufikiaji wa juu. Hii ni pamoja na kuongeza "haki za kudhibiti" (k.m., WriteOwner/WriteDACL/n.k.) kwa sehemu nyeti kama vile:

- Kitu cha kompyuta cha AD cha **seva ya CA**
- Seva ya **RPC/DCOM ya seva ya CA**
- Kitu au chombo cha AD cha **mzao wa chini** katika **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, chombo cha Templeti za Cheti, chombo cha Mamlaka za Uthibitishaji, kitu cha NTAuthCertificates, n.k.)
- **Vikundi vya AD vilivyopewa haki za kudhibiti AD CS** kwa chaguo-msingi au na shirika (kama kikundi cha kujengwa cha Cert Publishers na wanachama wake)

Mfano wa utekelezaji mbaya unaweza kuhusisha mshambuliaji, ambaye ana **ruhusa za juu** katika kikoa, kuongeza ruhusa ya **`WriteOwner`** kwenye templeti ya cheti ya **`User`** ya chaguo-msingi, na mshambuliaji kuwa mkuu wa haki hiyo. Ili kutumia hii, mshambuliaji kwanza angebadilisha umiliki wa templeti ya **`User`** kuwa yeye mwenyewe. Baada ya hapo, **`mspki-certificate-name-flag`** ingewekwa kuwa **1** kwenye templeti kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, kuruhusu mtumiaji kutoa Jina mbadala la Mada katika ombi. Kufuatia hilo, mshambuliaji anaweza **kujiandikisha** kwa kutumia **templeti**, kuchagua jina la **msimamizi wa kikoa** kama jina mbadala, na kutumia cheti kilichopatikana kwa uthibitisho kama DA.
