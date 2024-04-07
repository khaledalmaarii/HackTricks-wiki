# AD Sertifikate

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Onderwerp** van die sertifikaat dui sy eienaar aan.
- 'n **Openbare Sleutel** word gepaard met 'n privaat gehoue sleutel om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Geldigheidsperiode**, gedefinieer deur **NieVoor** en **NieNa** datums, merk die sertifikaat se effektiewe duur.
- 'n Unieke **Serienommer**, voorsien deur die Sertifikaatowerheid (CA), identifiseer elke sertifikaat.
- Die **Uitreiker** verwys na die CA wat die sertifikaat uitgereik het.
- **OnderwerpAlternatieweNaam** maak voorsiening vir addisionele name vir die onderwerp, wat identifikasie buigsaamheid verbeter.
- **Basiese Beperkings** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruikbeperkings.
- **Uitgebreide Sleutelgebruike (EKUs)** dui die spesifieke doeleindes van die sertifikaat aan, soos kodesondertekening of e-posversleuteling, deur middel van Objekidentifiseerders (OIDs).
- Die **Handtekeningalgoritme** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Handtekening**, geskep met die uitreiker se privaatsleutel, waarborg die egtheid van die sertifikaat.

### Spesiale Oorwegings

- **Onderwerp Alternatiewe Name (SANs)** brei 'n sertifikaat se toepaslikheid uit na verskeie identiteite, wat noodsaaklik is vir bedieners met verskeie domeine. Veilige uitreikingsprosesse is noodsaaklik om te verhoed dat aanvallers die SAN-spesifikasie manipuleer en hulself voordoen.

### Sertifikaatowerhede (CAs) in Aktiewe Gids (AD)

AD CS erken CA-sertifikate in 'n AD-bos deur aangewese houers, wat elkeen unieke rolle vervul:

- Die **Sertifikaatowerhede**-houer bevat vertroude wortel-CA-sertifikate.
- Die **Inskrywingsdienste**-houer beskryf Ondernemings-CA's en hul sertifikaatsjablone.
- Die **NTAuthSertifikate**-voorwerp sluit CA-sertifikate in wat gemagtig is vir AD-outentifisering.
- Die **AIA (Gesaginligtings Toegang)**-houer fasiliteer sertifikaatkettingvalidering met tussengangers- en kruis-CA-sertifikate.

### Sertifikaatverkryging: Kliëntsertifikaataanvraagvloei

1. Die aanvraagproses begin met kliënte wat 'n Ondernemings-CA vind.
2. 'n CSR word geskep, wat 'n openbare sleutel en ander besonderhede bevat, nadat 'n openbare-privaat sleutelpaar gegenereer is.
3. Die CA evalueer die CSR teen beskikbare sertifikaatsjablone, en reik die sertifikaat uit op grond van die sjabloon se toestemmings.
4. Na goedkeuring onderteken die CA die sertifikaat met sy privaatsleutel en stuur dit terug na die kliënt.

### Sertifikaatsjablone

Gedefinieer binne AD, hierdie sjablone skets die instellings en toestemmings vir die uitreiking van sertifikate, insluitend toegestane EKUs en inskrywings- of wysigingsregte, krities vir die bestuur van toegang tot sertifikaatdienste.

## Sertifikaatinskrywing

Die inskrywingsproses vir sertifikate word geïnisieer deur 'n administrateur wat 'n sertifikaatsjabloon **skep**, wat dan deur 'n Ondernemingsertifikaatowerheid (CA) **gepubliseer** word. Dit maak die sjabloon beskikbaar vir kliëntinskrywing, 'n stap wat bereik word deur die naam van die sjabloon by te voeg aan die `certificatetemplates`-veld van 'n Aktiewe Gids-voorwerp.

Vir 'n kliënt om 'n sertifikaat aan te vra, moet **inskrywingsregte** verleen word. Hierdie regte word gedefinieer deur sekuriteitsbeskrywings op die sertifikaatsjabloon en die Ondernemings-CA self. Toestemmings moet op beide plekke verleen word vir 'n aanvraag om suksesvol te wees.

### Sjablooninskrywingsregte

Hierdie regte word gespesifiseer deur Toegangsbeheerinskrywings (ACE's), wat toestemmings soos:
- **Sertifikaatinskrywing** en **Sertifikaat-OutomatieseInskrywing**-regte, elk geassosieer met spesifieke GUID's.
- **UitgebreideRegte**, wat alle uitgebreide toestemmings toelaat.
- **VolleBeheer/GenerieseAlles**, wat volledige beheer oor die sjabloon bied.

### Ondernemings-CA Inskrywingsregte

Die CA se regte word uiteengesit in sy sekuriteitsbeskrywing, toeganklik via die Sertifikaatowerheid-bestuurskonsol. Sommige instellings laat selfs laagbevoorregte gebruikers afstandstoegang toe, wat 'n sekuriteitskwessie kan wees.

### Addisionele Uitreikingsbeheer

Sekere beheermaatreëls mag van toepassing wees, soos:
- **Bestuurdergoedkeuring**: Plaas aanvrae in 'n wagtoestand totdat dit deur 'n sertifikaatbestuurder goedgekeur word.
- **Inskrywingsagente en Gemagtigde Handtekeninge**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Aansoekbeleid-OIDs.

### Metodes om Sertifikate aan te vra

Sertifikate kan aangevra word deur:
1. **Windows Kliëntsertifikaatinskrywingsprotokol** (MS-WCCE), deur gebruik te maak van DCOM-koppelvlakke.
2. **ICertPassage Remote Protokol** (MS-ICPR), deur benoemde pype of TCP/IP.
3. Die **sertifikaatinskrywingswebkoppelvlak**, met die Sertifikaatowerheid Web Inskrywing rol geïnstalleer.
4. Die **Sertifikaatinskrywingsdiens** (CES), saam met die Sertifikaatinskrywingsbeleid (CEP) diens.
5. Die **Netwerktoestelinskrywingsdiens** (NDES) vir netwerktoestelle, deur die Eenvoudige Sertifikaatinskrywingsprotokol (SCEP) te gebruik.

Windows-gebruikers kan ook sertifikate aanvra deur die GUI (`certmgr.msc` of `certlm.msc`) of opdraggereelgereedskap (`certreq.exe` of PowerShell se `Get-Certificate`-opdrag) te gebruik.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaat-verifikasie

Aktiewe Gids (AD) ondersteun sertifikaat-verifikasie, hoofsaaklik deur die gebruik van die **Kerberos** en **Secure Channel (Schannel)** protokolle.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek vir 'n Kaartverleningkaartjie (TGT) onderteken met die **privaatsleutel** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie validerings deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad**, en **herroepingstatus**. Validerings sluit ook in om te bevestig dat die sertifikaat van 'n betroubare bron afkomstig is en om die teenwoordigheid van die uitreiker in die **NTAUTH-sertifikaatstoor** te bevestig. Suksesvolle validerings lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`** objek in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.

### Sekuriteitskanaal (Schannel) Verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindinge, waar tydens 'n handdruk die klient 'n sertifikaat voorlê wat, indien suksesvol gevalideer, toegang magtig. Die koppeling van 'n sertifikaat aan 'n AD-rekening mag Kerberos se **S4U2Self**-funksie of die sertifikaat se **Onderwerp Alternatiewe Naam (SAN)**, onder ander metodes, betrek.

### AD Sertifikaatdiensopname

AD se sertifikaatdienste kan deur LDAP-navrae opgesom word, wat inligting oor **Ondernemingsertifikaatowerhede (CAs)** en hul konfigurasies onthul. Dit is toeganklik vir enige domein-geautentiseerde gebruiker sonder spesiale voorregte. Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir opname en kwesbaarheidsevaluering in AD CS-omgewings.

Opdragte vir die gebruik van hierdie gereedskap sluit in:
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

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
