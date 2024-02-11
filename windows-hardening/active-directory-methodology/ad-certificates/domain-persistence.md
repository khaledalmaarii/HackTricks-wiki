# AD CS Domein Volharding

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

**Hierdie is 'n opsomming van die domein-volhardingstegnieke wat gedeel is in [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Kyk daarvoor vir verdere besonderhede.

## Sertifikate vervals met gesteelde CA-sertifikate - DPERSIST1

Hoe kan jy sien dat 'n sertifikaat 'n CA-sertifikaat is?

Dit kan bepaal word dat 'n sertifikaat 'n CA-sertifikaat is as verskeie voorwaardes voldoen word:

- Die sertifikaat word op die CA-bediener gestoor, met sy privaatsleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM as die bedryfstelsel dit ondersteun.
- Beide die Uitreiker- en Onderwerpvelde van die sertifikaat stem ooreen met die onderskeidende naam van die CA.
- 'n "CA-weergawe"-uitbreiding is eksklusief teenwoordig in die CA-sertifikate.
- Die sertifikaat het nie Uitgebreide Sleutelgebruik (EKU)-velde nie.

Om die privaatsleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc`-instrument op die CA-bediener die ondersteunde metode via die ingeboude GUI. Nietemin verskil hierdie sertifikaat nie van ander wat binne die stelsel gestoor word nie; dus kan metodes soos die [THEFT2-tegniek](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) toegepas word vir onttrekking.

Die sertifikaat en privaatsleutel kan ook verkry word deur Certipy te gebruik met die volgende bevel:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nadat die CA-sertifikaat en sy privaatsleutel in `.pfx` formaat bekom is, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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
Die gebruiker wat geteiken word vir sertifikaatvervalsing moet aktief wees en in staat wees om in Active Directory te verifieer vir die proses om suksesvol te wees. Om 'n sertifikaat vir spesiale rekeninge soos krbtgt te vervals, is ondoeltreffend.
{% endhint %}

Hierdie vervalste sertifikaat sal **geldig** wees tot die einddatum gespesifiseer en solank die wortel-CA-sertifikaat **geldig is** (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, so saam met **S4U2Self** kan 'n aanvaller **volharding handhaaf op enige domeinmasjien** solank die CA-sertifikaat geldig is.\
Verder kan die **sertifikate wat gegenereer** word met hierdie metode **nie herroep word** nie, aangesien die CA nie daarvan bewus is nie.

## Vertroue in Rogue CA-sertifikate - DPERSIST2

Die `NTAuthCertificates`-voorwerp is gedefinieer om een of meer **CA-sertifikate** binne sy `cacertificate`-eienskap te bevat, wat deur Active Directory (AD) gebruik word. Die verifikasieproses deur die **domeinbeheerder** behels die nagaan van die `NTAuthCertificates`-voorwerp vir 'n inskrywing wat ooreenstem met die **CA wat gespesifiseer** is in die Uitreiker-veld van die verifieerende **sertifikaat**. Verifikasie gaan voort as 'n ooreenstemming gevind word.

'n Selfondertekende CA-sertifikaat kan deur 'n aanvaller by die `NTAuthCertificates`-voorwerp gevoeg word, op voorwaarde dat hulle beheer oor hierdie AD-voorwerp het. Normaalweg word slegs lede van die **Enterprise Admin**-groep, tesame met **Domain Admins** of **Administrators** in die **boswortel se domein**, toestemming verleen om hierdie voorwerp te wysig. Hulle kan die `NTAuthCertificates`-voorwerp wysig deur `certutil.exe` te gebruik met die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

Hierdie vermoë is veral relevant wanneer dit saam met 'n voorheen uiteengesette metode gebruik word wat ForgeCert betrek om sertifikate dinamies te genereer.

## Boosaardige Foutkonfigurasie - DPERSIST3

Geleenthede vir **volharding** deur **sekuriteitsbeskryweringsmodifikasies van AD CS**-komponente is volop. Modifikasies wat in die afdeling "[Domain Escalation](domain-escalation.md)" beskryf word, kan deur 'n aanvaller met verhoogde toegang boosaardig geïmplementeer word. Dit sluit die byvoeging van "beheerregte" (bv. WriteOwner/WriteDACL/ensovoorts) by sensitiewe komponente soos in:

- Die **AD-rekenaarvoorwerp van die CA-bediener**
- Die **RPC/DCOM-bediener van die CA-bediener**
- Enige **afstammeling AD-voorwerp of houer** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld die Certificate Templates-houer, Certification Authorities-houer, die NTAuthCertificates-voorwerp, ens.)
- **AD-groepe wat standaard of deur die organisasie regte aan AD CS toeken** (soos die ingeboude Cert Publishers-groep en enige van sy lede)

'n Voorbeeld van boosaardige implementering sou 'n aanvaller betrek wat **verhoogde regte** in die domein het en die **`WriteOwner`-reg** by die verstek **`User`-sertifikaatsjabloon** voeg, met die aanvaller as die beginsel vir die reg. Om hiervan gebruik te maak, sou die aanvaller eers die eienaarskap van die **`User`-sjabloon** na hulself verander. Hierna sou die **`mspki-certificate-name-flag`** op die sjabloon op **1** gestel word om **`ENROLLEE_SUPPLIES_SUBJECT`** moontlik te maak, wat 'n gebruiker in staat stel om 'n Alternatiewe Naam vir die versoek te voorsien. Vervolgens sou die aanvaller kan **inskryf** met behulp van die **sjabloon**, 'n **domeinadministrateur**-naam as 'n alternatiewe naam kies, en die verkryde sertifikaat vir verifikasie as die DA gebruik.
