# AD CS Account Persistence

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

**Dit is 'n klein opsomming van die masjien volharding hoofstukke van die wonderlike navorsing van [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Begrip van Aktiewe Gebruiker Kredensiaal Diefstal met Sertifikate – PERSIST1**

In 'n scenario waar 'n sertifikaat wat domeinverifikasie toelaat deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat te **aanspreek** en te **steel** om **volharding** op 'n netwerk te **onderhou**. Standaard laat die `User` sjabloon in Active Directory sulke versoeke toe, alhoewel dit soms gedeaktiveer kan wees.

Deur 'n hulpmiddel genaamd [**Certify**](https://github.com/GhostPack/Certify) te gebruik, kan 'n mens soek na geldige sertifikate wat volhardende toegang moontlik maak:
```bash
Certify.exe find /clientauth
```
Dit word beklemtoon dat 'n sertifikaat se krag lê in sy vermoë om **as die gebruiker** wat dit behoort te **authentiseer**, ongeag enige wagwoordveranderings, solank die sertifikaat **geldend** bly.

Sertifikate kan aangevra word deur 'n grafiese koppelvlak met `certmgr.msc` of deur die opdraglyn met `certreq.exe`. Met **Certify** word die proses om 'n sertifikaat aan te vra vereenvoudig soos volg:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Upon successful request, a certificate along with its private key is generated in `.pem` format. To convert this into a `.pfx` file, which is usable on Windows systems, the following command is utilized:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Die `.pfx`-lêer kan dan na 'n teikenstelsel opgelaai word en gebruik word met 'n hulpmiddel genaamd [**Rubeus**](https://github.com/GhostPack/Rubeus) om 'n Ticket Granting Ticket (TGT) vir die gebruiker aan te vra, wat die aanvaller se toegang verleng solank die sertifikaat **geld** (tipies een jaar):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
'n Belangrike waarskuwing word gedeel oor hoe hierdie tegniek, gekombineer met 'n ander metode wat in die **THEFT5** afdeling uiteengesit word, 'n aanvaller in staat stel om volhoubaar 'n rekening se **NTLM hash** te verkry sonder om met die Local Security Authority Subsystem Service (LSASS) te kommunikeer, en vanuit 'n nie-verhoogde konteks, wat 'n meer stil metode vir langtermyn geloofsbriefdiefstal bied.

## **Masjien Volhoubaarheid Verkry met Sertifikate - PERSIST2**

'n Ander metode behels die inskrywing van 'n gecompromitteerde stelsel se masjienrekening vir 'n sertifikaat, wat die standaard `Machine` sjabloon gebruik wat sulke aksies toelaat. As 'n aanvaller verhoogde voorregte op 'n stelsel verkry, kan hulle die **SYSTEM** rekening gebruik om sertifikate aan te vra, wat 'n vorm van **volhoubaarheid** bied:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
This access enables the attacker to authenticate to **Kerberos** as the machine account and utilize **S4U2Self** to obtain Kerberos service tickets for any service on the host, effectively granting the attacker persistent access to the machine.

## **Uitbreiding van Volharding deur Sertifikaat Vernuwing - PERSIST3**

Die finale metode wat bespreek word, behels die benutting van die **geldigheid** en **vernuwingperiodes** van sertifikaat sjablone. Deur 'n sertifikaat te **vernuwe** voordat dit verval, kan 'n aanvaller die autentisering na Active Directory handhaaf sonder die behoefte aan addisionele kaartregistrasies, wat spore op die Sertifikaatowerheid (CA) bediener kan agterlaat.

Hierdie benadering stel 'n **verlengde volharding** metode in staat, wat die risiko van opsporing minimaliseer deur minder interaksies met die CA bediener en die generering van artefakte te vermy wat administrateurs op die indringing kan waarsku.

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
