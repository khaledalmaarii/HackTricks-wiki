# AD CS Rekening Volharding

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

**Hierdie is 'n klein opsomming van die volhardingshoofstukke van die fantastiese navorsing van [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Begrip van aktiewe gebruikersgeloofdiefstal met sertifikate - PERSIST1**

In 'n scenario waar 'n sertifikaat wat domeinverifikasie moontlik maak deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat te **versoek** en **steel** om volharding op 'n netwerk te behou. Standaard laat die `User`-sjabloon in Active Directory sulke versoek toe, alhoewel dit soms gedeaktiveer kan word.

Met behulp van 'n hulpmiddel genaamd [**Certify**](https://github.com/GhostPack/Certify), kan 'n persoon soek na geldige sertifikate wat volgehoue toegang moontlik maak:
```bash
Certify.exe find /clientauth
```
Dit word beklemtoon dat 'n sertifikaat se krag lê in sy vermoë om as die gebruiker te **verifieer** waartoe dit behoort, ongeag enige wagwoordveranderinge, solank die sertifikaat **geldig** bly.

Sertifikate kan aangevra word deur middel van 'n grafiese koppelvlak met behulp van `certmgr.msc` of deur die opdraglyn met `certreq.exe`. Met **Certify** word die proses om 'n sertifikaat aan te vra vereenvoudig soos volg:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Na 'n suksesvolle versoek word 'n sertifikaat saam met sy privaatsleutel in `.pem`-formaat gegenereer. Om dit na 'n `.pfx`-lêer om te skakel, wat bruikbaar is op Windows-stelsels, word die volgende opdrag gebruik:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Die `.pfx` lêer kan dan op 'n teikensisteem gelaai word en gebruik word saam met 'n instrument genaamd [**Rubeus**](https://github.com/GhostPack/Rubeus) om 'n Ticket Granting Ticket (TGT) vir die gebruiker aan te vra, wat die aanvaller se toegang verleng solank die sertifikaat **geldig** is (gewoonlik een jaar):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
'n Belangrike waarskuwing word gedeel oor hoe hierdie tegniek, in kombinasie met 'n ander metode wat in die **THEFT5**-afdeling uitgelig word, 'n aanvaller in staat stel om volhardend 'n rekening se **NTLM-hash** te verkry sonder om met die Local Security Authority Subsystem Service (LSASS) te kommunikeer, en vanuit 'n nie-verhoogde konteks, wat 'n sluwer metode bied vir langtermyn-geloofsbrieffrustrasie.

## **Verkryging van Masjien Volharding met Sertifikate - PERSIST2**

'n Ander metode behels die inskrywing van 'n gekompromitteerde stelsel se masjienrekening vir 'n sertifikaat, deur gebruik te maak van die verstek `Machine`-sjabloon wat sulke aksies toelaat. As 'n aanvaller verhoogde bevoegdhede op 'n stelsel verwerf, kan hulle die **SYSTEM**-rekening gebruik om sertifikate aan te vra, wat 'n vorm van **volharding** bied:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Hierdie toegang stel die aanvaller in staat om te verifieer na **Kerberos** as die masjienrekening en **S4U2Self** te gebruik om Kerberos-dienskaartjies vir enige diens op die gasheer te verkry, wat die aanvaller effektiewe volgehoue toegang tot die masjien verleen.

## **Uitbreiding van Volgehoue Toegang deur Sertifikaatvernieuwing - PERSIST3**

Die laaste metode wat bespreek word, behels die benutting van die **geldigheid** en **vernieuwingsperiodes** van sertifikaatsjablone. Deur 'n sertifikaat voor sy verval te **vernieu, kan 'n aanvaller verifikasie behou tot Active Directory sonder die nodigheid van addisionele kaartinskrywings, wat spore op die Sertifikaatowerheid (CA) bediener kan agterlaat.

Hierdie benadering maak voorsiening vir 'n **uitgebreide volgehoue toegang**-metode, wat die risiko van opsporing verminder deur minder interaksies met die CA-bediener en die voorkoming van die generering van artefakte wat administrateurs op die indringing kan attent maak.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
