# AD CS Sertifikaatdiefstal

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

**Hierdie is 'n klein opsomming van die Diefstalhoofstukke van die fantastiese navorsing van [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Wat kan ek doen met 'n sertifikaat

Voordat jy kyk hoe om die sertifikate te steel, hier is 'n paar inligting oor hoe om uit te vind waarvoor die sertifikaat nuttig is:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Uitvoer van Sertifikate met behulp van die Crypto API's - DIEFSTAL1

In 'n **interaktiewe lessenaar-sessie** kan 'n gebruikers- of masjien-sertifikaat, tesame met die privaat sleutel, maklik uitgevoer word, veral as die **privaat sleutel uitvoerbaar is**. Dit kan bereik word deur na die sertifikaat in `certmgr.msc` te navigeer, daarop te klik met die regterknoppie en `Alle Take → Uitvoer` te kies om 'n wagwoord-beskermde .pfx-lêer te genereer.

Vir 'n **programmatiese benadering**, is daar gereedskap soos die PowerShell `ExportPfxCertificate` cmdlet of projekte soos [TheWover se CertStealer C#-projek](https://github.com/TheWover/CertStealer) beskikbaar. Hierdie maak gebruik van die **Microsoft CryptoAPI** (CAPI) of die Cryptography API: Next Generation (CNG) om met die sertifikaatstoor te kommunikeer. Hierdie API's bied 'n verskeidenheid kriptografiese dienste, insluitend dié wat nodig is vir sertifikaatberging en outentisering.

As 'n privaat sleutel as nie-uitvoerbaar ingestel is, sal beide CAPI en CNG normaalweg die uitvoer van sulke sertifikate blokkeer. Om hierdie beperking te omseil, kan gereedskap soos **Mimikatz** gebruik word. Mimikatz bied `crypto::capi` en `crypto::cng` opdragte om die onderskeie API's te verander, sodat privaat sleutels uitgevoer kan word. Spesifiek verander `crypto::capi` die CAPI binne die huidige proses, terwyl `crypto::cng` die geheue van **lsass.exe** teiken vir verandering.

## Diefstal van Gebruikersertifikaat via DPAPI - DIEFSTAL2

Meer inligting oor DPAPI in:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows word **sertifikaat privaat sleutels beskerm deur DPAPI**. Dit is belangrik om te besef dat die **bergingsplekke vir gebruikers- en masjien privaat sleutels** verskillend is, en die lêerstrukture wissel afhangende van die kriptografiese API wat deur die bedryfstelsel gebruik word. **SharpDPAPI** is 'n gereedskap wat hierdie verskille outomaties kan hanteer wanneer die DPAPI-blobs ontsluit word.

**Gebruikersertifikate** word hoofsaaklik in die register onder `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` geberg, maar sommige kan ook in die `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` gids gevind word. Die ooreenstemmende **privaat sleutels** vir hierdie sertifikate word gewoonlik geberg in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` vir **CAPI**-sleutels en `%APPDATA%\Microsoft\Crypto\Keys\` vir **CNG**-sleutels.

Om 'n sertifikaat en die ooreenstemmende privaat sleutel te **onttrek**, behels die proses die volgende:

1. **Die teiken sertifikaat kies** uit die gebruiker se stoor en die sleutelstoor se naam ophaal.
2. **Die vereiste DPAPI-meestersleutel vind** om die ooreenstemmende privaat sleutel te ontsluit.
3. **Die privaat sleutel ontsluit** deur die platte tekst DPAPI-meestersleutel te gebruik.

Vir die **verkryging van die platte tekst DPAPI-meestersleutel**, kan die volgende benaderings gebruik word:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Om die ontsleuteling van meester sleutel lêers en privaat sleutel lêers te stroomlyn, is die `certificates` bevel van [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) voordelig. Dit aanvaar `/pvk`, `/mkfile`, `/password`, of `{GUID}:KEY` as argumente om die privaat sleutels en gekoppelde sertifikate te ontsleutel, en genereer dan 'n `.pem` lêer.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Masjien Sertifikaat Diefstal via DPAPI - THEFT3

Masjien sertifikate wat deur Windows in die register by `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` gestoor word, en die geassosieerde private sleutels wat in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (vir CAPI) en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (vir CNG) geleë is, word versleutel met behulp van die masjien se DPAPI-meestersleutels. Hierdie sleutels kan nie met die domein se DPAPI-rugsteunsleutel ontsluit word nie; in plaas daarvan word die **DPAPI_SYSTEM LSA-geheim**, wat slegs die SYSTEM-gebruiker kan benader, vereis.

Handmatige ontsleuteling kan bereik word deur die `lsadump::secrets`-opdrag in **Mimikatz** uit te voer om die DPAPI_SYSTEM LSA-geheim te onttrek, en vervolgens hierdie sleutel te gebruik om die masjien se meestersleutels te ontsluit. Alternatiewelik kan die `crypto::certificates /export /systemstore:LOCAL_MACHINE`-opdrag van Mimikatz gebruik word nadat CAPI/CNG soos voorheen beskryf gepatch is.

**SharpDPAPI** bied 'n meer geoutomatiseerde benadering met sy sertifikate-opdrag. Wanneer die `/machine`-vlag met verhoogde regte gebruik word, eskaleer dit na SYSTEM, dump die DPAPI_SYSTEM LSA-geheim, gebruik dit om die masjien se DPAPI-meestersleutels te ontsluit, en gebruik dan hierdie platte sleutels as 'n soektabel om enige masjien sertifikaat private sleutels te ontsluit.


## Vind Sertifikaatlêers - THEFT4

Sertifikate word soms direk binne die lêersisteem gevind, soos in lêerdeling of die Aflaaifolder. Die mees algemeen aangetrofde tipes sertifikaatlêers wat op Windows-omgewings gemik is, is `.pfx` en `.p12` lêers. Alhoewel minder gereeld, verskyn lêers met die uitbreidings `.pkcs12` en `.pem` ook. Addisionele noemenswaardige sertifikaatverwante lêeruitbreidings sluit in:
- `.key` vir private sleutels,
- `.crt`/`.cer` vir sertifikate alleen,
- `.csr` vir Sertifikaatondertekeningsversoeke, wat nie sertifikate of private sleutels bevat nie,
- `.jks`/`.keystore`/`.keys` vir Java Keystores, wat sertifikate tesame met private sleutels wat deur Java-toepassings gebruik word, kan bevat.

Hierdie lêers kan deur middel van PowerShell of die opdragpunt gesoek word deur na die genoemde uitbreidings te kyk.

In gevalle waar 'n PKCS#12 sertifikaatleer gevind word en dit deur 'n wagwoord beskerm word, is dit moontlik om die onttrekking van 'n huts te doen deur die gebruik van `pfx2john.py`, beskikbaar by [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Daarna kan JohnTheRipper gebruik word om te probeer om die wagwoord te kraak.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM-geloofsbrieffdiefstal via PKINIT - DIEFSTAL5

Die gegee inligting verduidelik 'n metode vir NTLM-geloofsbrieffdiefstal via PKINIT, spesifiek deur die diefstalmetode wat as DIEFSTAL5 geëtiketteer word. Hier is 'n herverduideliking in die passiewe vorm, met die inhoud geanonimiseer en waar toepaslik saamgevat:

Om NTLM-geloofsbriewe [MS-NLMP] te ondersteun vir toepassings wat nie Kerberos-geloofsbriewe fasiliteer nie, is die KDC ontwerp om die gebruiker se NTLM-eenrigtingsfunksie (OWF) binne die voorregsertifikaat (PAC), spesifiek in die `PAC_CREDENTIAL_INFO` buffer, terug te stuur wanneer PKCA gebruik word. Gevolglik, as 'n rekening deur middel van PKINIT outentiseer en 'n Tikkie-Verleningstikkie (TGT) verseker, word 'n meganisme inherente voorsien wat die huidige gasheer in staat stel om die NTLM-hash uit die TGT te onttrek om nalatenskap-outentiseringsprotokolle te handhaaf. Hierdie proses behels die dekripsie van die `PAC_CREDENTIAL_DATA`-struktuur, wat in wese 'n NDR-geserializeerde voorstelling van die NTLM-plain tekst is.

Die nut **Kekeo**, toeganklik by [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), word genoem as in staat om 'n TGT wat hierdie spesifieke data bevat, aan te vra, en sodoende die gebruiker se NTLM te herwin. Die gebruikte bevel is as volg:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Daarbenewens word daarop gewys dat Kekeo slimkaart-beskermde sertifikate kan verwerk, mits die PIN verkry kan word, met verwysing na [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Dieselfde vermoë word aangedui om ondersteun te word deur **Rubeus**, beskikbaar by [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Hierdie verduideliking omvat die proses en gereedskap wat betrokke is by die diefstal van NTLM-legitimasie deur middel van PKINIT, met die fokus op die verkryging van NTLM-hashes deur TGT wat met PKINIT verkry is, en die hulpmiddels wat hierdie proses fasiliteer.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
