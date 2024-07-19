# AD CS Sertifikaat Diefstal

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Dit is 'n klein opsomming van die Diefstal hoofstukke van die wonderlike navorsing van [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Wat kan ek met 'n sertifikaat doen

Voordat jy kyk hoe om die sertifikate te steel, het jy hier 'n paar inligting oor hoe om te vind waarvoor die sertifikaat nuttig is:
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
## Exporting Certificates Using the Crypto APIs – THEFT1

In 'n **interaktiewe lessenaar sessie** kan dit maklik gedoen word om 'n gebruiker of masjien sertifikaat, saam met die private sleutel, te onttrek, veral as die **private sleutel uitvoerbaar** is. Dit kan bereik word deur na die sertifikaat in `certmgr.msc` te navigeer, regsklik daarop te klik, en `All Tasks → Export` te kies om 'n wagwoord-beskermde .pfx-lêer te genereer.

Vir 'n **programmatiese benadering** is gereedskap soos die PowerShell `ExportPfxCertificate` cmdlet of projekte soos [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) beskikbaar. Hierdie gebruik die **Microsoft CryptoAPI** (CAPI) of die Cryptography API: Next Generation (CNG) om met die sertifikaatwinkel te kommunikeer. Hierdie APIs bied 'n reeks kriptografiese dienste, insluitend dié wat nodig is vir sertifikaatberging en -verifikasie.

As 'n private sleutel egter as nie-uitvoerbaar gestel is, sal beide CAPI en CNG normaalweg die onttrekking van sulke sertifikate blokkeer. Om hierdie beperking te omseil, kan gereedskap soos **Mimikatz** gebruik word. Mimikatz bied `crypto::capi` en `crypto::cng` opdragte om die onderskeie APIs te patch, wat die uitvoer van private sleutels moontlik maak. Spesifiek patch `crypto::capi` die CAPI binne die huidige proses, terwyl `crypto::cng` die geheue van **lsass.exe** te teiken vir patching.

## User Certificate Theft via DPAPI – THEFT2

Meer inligting oor DPAPI in:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows, **sertifikaat private sleutels word deur DPAPI beskerm**. Dit is belangrik om te erken dat die **berging plekke vir gebruiker en masjien private sleutels** verskillend is, en die lêerstrukture verskil afhangende van die kriptografiese API wat deur die bedryfstelsel gebruik word. **SharpDPAPI** is 'n gereedskap wat hierdie verskille outomaties kan navigeer wanneer dit die DPAPI blobs ontsleutel.

**Gebruiker sertifikate** is hoofsaaklik in die registrasie onder `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` gehuisves, maar sommige kan ook in die gids `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` gevind word. Die ooreenstemmende **private sleutels** vir hierdie sertifikate word tipies gestoor in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` vir **CAPI** sleutels en `%APPDATA%\Microsoft\Crypto\Keys\` vir **CNG** sleutels.

Om 'n **sertifikaat en sy geassosieerde private sleutel** te **onttrek**, behels die proses:

1. **Kies die teiken sertifikaat** uit die gebruiker se winkel en verkry sy sleutel winkel naam.
2. **Vind die vereiste DPAPI meester sleutel** om die ooreenstemmende private sleutel te ontsleutel.
3. **Ontsleutel die private sleutel** deur die platte teks DPAPI meester sleutel te gebruik.

Vir **die verkryging van die platte teks DPAPI meester sleutel**, kan die volgende benaderings gebruik word:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Om die ontsleuteling van masterkey-lêers en privaat sleutel-lêers te stroomlyn, bewys die `certificates` opdrag van [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) nuttig. Dit aanvaar `/pvk`, `/mkfile`, `/password`, of `{GUID}:KEY` as argumente om die privaat sleutels en gekoppelde sertifikate te ontsleutel, en genereer vervolgens 'n `.pem` lêer.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Masjien Sertifikaat Diefstal via DPAPI – THEFT3

Masjien sertifikate wat deur Windows in die register gestoor word by `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` en die geassosieerde private sleutels geleë in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (vir CAPI) en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (vir CNG) word geënkripteer met die masjien se DPAPI meester sleutels. Hierdie sleutels kan nie gedekripteer word met die domein se DPAPI rugsteun sleutel nie; eerder, die **DPAPI_SYSTEM LSA geheim**, waartoe slegs die SYSTEM gebruiker toegang het, is nodig.

Handmatige dekriptering kan bereik word deur die `lsadump::secrets` opdrag in **Mimikatz** uit te voer om die DPAPI_SYSTEM LSA geheim te onttrek, en daarna hierdie sleutel te gebruik om die masjien meester sleutels te dekripteer. Alternatiewelik kan Mimikatz se `crypto::certificates /export /systemstore:LOCAL_MACHINE` opdrag gebruik word na die patching van CAPI/CNG soos voorheen beskryf.

**SharpDPAPI** bied 'n meer geoutomatiseerde benadering met sy sertifikate opdrag. Wanneer die `/machine` vlag gebruik word met verhoogde toestemmings, eskaleer dit na SYSTEM, dump die DPAPI_SYSTEM LSA geheim, gebruik dit om die masjien DPAPI meester sleutels te dekripteer, en gebruik dan hierdie platte sleutels as 'n soektabel om enige masjien sertifikaat private sleutels te dekripteer.

## Vind Sertifikaat Lêers – THEFT4

Sertifikate word soms direk binne die lêerstelsel gevind, soos in lêer deel of die Downloads gids. Die mees algemeen aangetrefde tipes sertifikaat lêers wat op Windows omgewings teikens is, is `.pfx` en `.p12` lêers. Alhoewel minder gereeld, verskyn lêers met uitbreidings `.pkcs12` en `.pem` ook. Bykomende noemenswaardige sertifikaat-verwante lêer uitbreidings sluit in:
- `.key` vir private sleutels,
- `.crt`/`.cer` vir sertifikate slegs,
- `.csr` vir Sertifikaat Ondertekening Versoeke, wat nie sertifikate of private sleutels bevat nie,
- `.jks`/`.keystore`/`.keys` vir Java Keystores, wat sertifikate saam met private sleutels wat deur Java toepassings gebruik word, kan hou.

Hierdie lêers kan gesoek word met PowerShell of die opdragprompt deur te soek na die genoemde uitbreidings.

In gevalle waar 'n PKCS#12 sertifikaat lêer gevind word en dit deur 'n wagwoord beskerm word, is die onttrekking van 'n hash moontlik deur die gebruik van `pfx2john.py`, beskikbaar by [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Daarna kan JohnTheRipper gebruik word om te probeer om die wagwoord te kraak.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Die gegewe inhoud verduidelik 'n metode vir NTLM geloofsbriewe-diefstal via PKINIT, spesifiek deur die diefstal metode wat as THEFT5 geëtiketteer is. Hier is 'n herverduideliking in passiewe stem, met die inhoud geanonimiseer en saamgevat waar toepaslik:

Om NTLM-outeentiging [MS-NLMP] te ondersteun vir toepassings wat nie Kerberos-outeentiging fasiliteer nie, is die KDC ontwerp om die gebruiker se NTLM eenrigting funksie (OWF) binne die privilege-attribuut sertifikaat (PAC) terug te gee, spesifiek in die `PAC_CREDENTIAL_INFO` buffer, wanneer PKCA gebruik word. Gevolglik, indien 'n rekening autentiseer en 'n Ticket-Granting Ticket (TGT) via PKINIT verkry, word 'n meganisme inherente voorsien wat die huidige gasheer in staat stel om die NTLM-hash uit die TGT te onttrek om legacy-outeentigingsprotokolle te ondersteun. Hierdie proses behels die ontsleuteling van die `PAC_CREDENTIAL_DATA` struktuur, wat essensieel 'n NDR-geserialiseerde voorstelling van die NTLM-plaktekst is.

Die nut **Kekeo**, toeganklik by [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), word genoem as in staat om 'n TGT aan te vra wat hierdie spesifieke data bevat, en sodoende die onttrekking van die gebruiker se NTLM te fasiliteer. Die opdrag wat vir hierdie doel gebruik word, is soos volg:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Daarnaast word opgemerk dat Kekeo slimkaart-beskermde sertifikate kan verwerk, gegewe die pin kan verkry word, met verwysing na [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Dieselfde vermoë word aangedui as ondersteun deur **Rubeus**, beskikbaar by [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Hierdie verduideliking sluit die proses en gereedskap in wat betrokke is by NTLM geloofsbriewe-diefstal via PKINIT, met fokus op die verkryging van NTLM hashes deur TGT verkry met behulp van PKINIT, en die nutsmiddels wat hierdie proses fasiliteer.

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
