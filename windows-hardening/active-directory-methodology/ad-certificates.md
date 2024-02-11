# AD Sertifikate

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Onderwerp** van die sertifikaat dui sy eienaar aan.
- 'n **Openbare Sleutel** word gekoppel aan 'n privaat gehoue sleutel om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Geldigheidsperiode**, gedefinieer deur **NieVoor** en **NieNa** datums, dui die sertifikaat se effektiewe duur aan.
- 'n Unieke **Serienommer**, verskaf deur die Sertifikaatowerheid (CA), identifiseer elke sertifikaat.
- Die **Uitreiker** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** maak voorsiening vir addisionele name vir die onderwerp, wat die identifikasie buigsaamheid verbeter.
- **Basiese Beperkings** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruikbeperkings.
- **Uitgebreide Sleutelgebruik (EKUs)** onderskei die sertifikaat se spesifieke doeleindes, soos kodesondertekening of e-posversleuteling, deur middel van Objekidentifiseerders (OIDs).
- Die **Handtekeningalgoritme** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Handtekening**, geskep met die uitreiker se privaatsleutel, waarborg die egtheid van die sertifikaat.

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid uit na verskeie identiteite, wat noodsaaklik is vir bedieners met verskeie domeine. Veilige uitreikprosesse is noodsaaklik om impersonasie-risiko's te voorkom deur aanvallers wat die SAN-spesifikasie manipuleer.

### Sertifikaatowerhede (CA's) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD-bos deur middel van aangewese houers wat elkeen unieke rolle vervul:

- Die **Sertifiseringsowerhede**-houer bevat vertroude wortel-CA-sertifikate.
- Die **Inschrywingsdienste**-houer beskryf Enterprise-CA's en hul sertifikaatsjablone.
- Die **NTAuthCertificates**-voorwerp bevat CA-sertifikate wat gemagtig is vir AD-outentisering.
- Die **AIA (Authority Information Access)**-houer fasiliteer sertifikaatkettingvalidering met tussenliggende en kruis-CA-sertifikate.

### Sertifikaatverkryging: Vloei van Kliëntsertifikaatversoek

1. Die versoekproses begin met kliënte wat 'n Enterprise-CA vind.
2. 'n CSR word geskep, wat 'n openbare sleutel en ander besonderhede bevat, nadat 'n openbare-privaat sleutelpaar gegenereer is.
3. Die CA evalueer die CSR teen beskikbare sertifikaatsjablone en reik die sertifikaat uit op grond van die sjabloon se toestemmings.
4. Nadat dit goedgekeur is, onderteken die CA die sertifikaat met sy privaatsleutel en stuur dit terug na die kliënt.

### Sertifikaatsjablone

Gedefinieer binne AD, beskryf hierdie sjablone die instellings en toestemmings vir die uitreiking van sertifikate, insluitend toegelate EKUs en inskrywings- of wysigingsregte, wat krities is vir die bestuur van toegang tot sertifikaatdienste.

## Sertifikaatinskrywing

Die inskrywingsproses vir sertifikate word geïnisieer deur 'n administrateur wat 'n sertifikaatsjabloon **skep**, wat dan deur 'n Enterprise-sertifikaatowerheid (CA) **gepubliseer** word. Dit maak die sjabloon beskikbaar vir kliëntinskrywing, 'n stap wat bereik word deur die naam van die sjabloon by die `certificatetemplates`-veld van 'n Active Directory-voorwerp te voeg.

Om 'n sertifikaat aan te vra, moet **inskrywingsregte** verleen word. Hierdie regte word gedefinieer deur sekuriteitsbeskrywers op die sertifikaatsjabloon en die Enterprise-CA self. Regte moet in beide plekke verleen word vir 'n versoek om suksesvol te wees.

### Inskrywingsregte vir Sjabloon

Hierdie regte word gespesifiseer deur middel van Toegangsbeheerinskrywings (ACE's), wat toestemmings soos volg beskryf:
- **Certificate-Enrollment** en **Certificate-AutoEnrollment**-regte, elk geassosieer met spesifieke GUID's.
- **ExtendedRights**, wat alle uitgebreide toestemmings toelaat.
- **FullControl/GenericAll**, wat volledige beheer oor die sjabloon bied.

### Inskrywingsregte vir Enterprise-CA

Die regte van die CA word beskryf in sy sekuriteitsbeskrywer, wat toeganklik is via die Sertifikaatowerheidbestuurskonsol. Sommige instellings maak selfs laagbevoorregte gebruikers moontlik remote toegang, wat 'n veiligheidskwessie kan wees.

### Addisionele Uitreikingsbeheer

Sekere beheermaatreëls kan van toepassing wees, soos:
- **Bestuursgoedkeuring**: Plaas versoek in 'n hangende toestand totdat dit deur 'n sertifikaatbestuurder goedgekeur word.
- **Inskrywingsagente en Gemagtigde Handtekeninge**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Aansoekbeleid-OIDs.

### Metodes om Sertifikate aan te vra

Sertifikate kan aangevra word deur middel van:
1. **Windows-kliëntsertifikaatinskrywingsprotokol** (MS-WCCE), met behulp van DCOM-koppelvlakke.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur middel van genoemde pype of TCP/IP.
3. Die **sertifikaatinskrywingswebkoppelvlak**, met die Sertifikaatowerheid Web Inskrywing rol geïnstalleer.
4. Die **Sertifikaatinskrywingsdiens** (CES), in samewerking met die Sertifikaatinskrywingsbeleid (CEP)-diens.
5. Die **Netwerktoestelinskrywingsdiens** (NDES) vir netwerktoestelle, met behulp van die Eenvoudige Sertifikaatinskrywingsprotokol (SCEP).

Windows-gebruikers kan ook sertifikate aanvra deur middel van die GUI (`certmgr.msc` of `certlm.msc`) of opdraggereelgereedskap (`certreq.exe` of PowerShell se `Get-Certificate`-opdrag).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur gebruik te maak van die **Kerberos** en **Secure Channel (Schannel)** protokolle.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) onderteken met behulp van die **privaatsleutel** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie validerings deur die domeinbeheerder, insluitend die **geldigheid**, **pad** en **herroepingstatus** van die sertifikaat. Validerings sluit ook in om te bevestig dat die sertifikaat afkomstig is van 'n betroubare bron en om die uitreiker se teenwoordigheid in die **NTAUTH-sertifikaatstoor** te bevestig. Suksesvolle validerings lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`**-voorwerp in AD, te vind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### Sekuriteitskanaal (Schannel) Verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindinge, waar tydens 'n handskud die klient 'n sertifikaat voorlê wat, as dit suksesvol gevalideer word, toegang magtig. Die kartering van 'n sertifikaat na 'n AD-rekening mag Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** insluit, onder andere metodes.

### AD Sertifikaatdienste Enumerasie

AD se sertifikaatdienste kan deur middel van LDAP-navrae geënumereer word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies openbaar. Dit is toeganklik vir enige domein-geverifieerde gebruiker sonder spesiale voorregte. Hulpmiddels soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsassessering in AD CS-omgewings.

Opdragte vir die gebruik van hierdie hulpmiddels sluit in:
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
## Verwysings

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
