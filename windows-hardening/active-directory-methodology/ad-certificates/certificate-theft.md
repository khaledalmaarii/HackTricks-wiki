# AD CS Certificate Theft

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

**Ovo je kratak pregled poglavlja o krađi iz sjajnog istraživanja sa [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Šta mogu da uradim sa sertifikatom

Pre nego što proverite kako da ukradete sertifikate, ovde imate neke informacije o tome kako da saznate čemu sertifikat može da služi:
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

U **interaktivnoj desktop sesiji**, ekstrakcija korisničkog ili mašinskog sertifikata, zajedno sa privatnim ključem, može se lako izvršiti, posebno ako je **privatni ključ izvoziv**. To se može postići navigacijom do sertifikata u `certmgr.msc`, desnim klikom na njega i izborom `All Tasks → Export` za generisanje .pfx datoteke zaštićene lozinkom.

Za **programatski pristup**, dostupni su alati kao što su PowerShell `ExportPfxCertificate` cmdlet ili projekti poput [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Ovi alati koriste **Microsoft CryptoAPI** (CAPI) ili Cryptography API: Next Generation (CNG) za interakciju sa skladištem sertifikata. Ove API pružaju niz kriptografskih usluga, uključujući one potrebne za skladištenje i autentifikaciju sertifikata.

Međutim, ako je privatni ključ postavljen kao neizvoziv, CAPI i CNG obično će blokirati ekstrakciju takvih sertifikata. Da bi se zaobišla ova ograničenja, mogu se koristiti alati poput **Mimikatz**. Mimikatz nudi `crypto::capi` i `crypto::cng` komande za patchovanje odgovarajućih API, omogućavajući izvoz privatnih ključeva. Konkretno, `crypto::capi` patchuje CAPI unutar trenutnog procesa, dok `crypto::cng` cilja memoriju **lsass.exe** za patchovanje.

## User Certificate Theft via DPAPI – THEFT2

Više informacija o DPAPI u:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

U Windows-u, **privatni ključevi sertifikata su zaštićeni DPAPI**. Ključno je prepoznati da su **lokacije skladištenja privatnih ključeva korisnika i mašine** različite, a strukture datoteka variraju u zavisnosti od kriptografskog API koji koristi operativni sistem. **SharpDPAPI** je alat koji može automatski navigirati ovim razlikama prilikom dekriptovanja DPAPI blobova.

**Korisnički sertifikati** se pretežno nalaze u registru pod `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ali neki se takođe mogu naći u direktorijumu `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Odgovarajući **privatni ključevi** za ove sertifikate obično se skladište u `%APPDATA%\Microsoft\Crypto\RSA\User SID\` za **CAPI** ključeve i `%APPDATA%\Microsoft\Crypto\Keys\` za **CNG** ključeve.

Da bi se **izvadio sertifikat i njegov pripadajući privatni ključ**, proces uključuje:

1. **Izbor ciljnog sertifikata** iz korisničkog skladišta i preuzimanje njegovog imena skladišta ključeva.
2. **Lociranje potrebnog DPAPI masterključa** za dekriptovanje odgovarajućeg privatnog ključa.
3. **Dekriptovanje privatnog ključa** korišćenjem plaintext DPAPI masterključa.

Za **dobijanje plaintext DPAPI masterključa**, mogu se koristiti sledeći pristupi:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Da bi se pojednostavila dekripcija masterkey datoteka i datoteka privatnih ključeva, komanda `certificates` iz [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) se pokazuje korisnom. Prihvaća `/pvk`, `/mkfile`, `/password` ili `{GUID}:KEY` kao argumente za dekripciju privatnih ključeva i povezanih sertifikata, a zatim generiše `.pem` datoteku.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Krađa mašinskih sertifikata putem DPAPI – THEFT3

Mašinski sertifikati koje Windows čuva u registru na `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` i povezani privatni ključevi smešteni u `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (za CAPI) i `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (za CNG) su enkriptovani koristeći DPAPI master ključeve mašine. Ovi ključevi se ne mogu dekriptovati pomoću DPAPI rezervnog ključa domena; umesto toga, potreban je **DPAPI_SYSTEM LSA tajni**, kojem može pristupiti samo korisnik SYSTEM.

Ručno dekriptovanje može se postići izvršavanjem komande `lsadump::secrets` u **Mimikatz** za ekstrakciju DPAPI_SYSTEM LSA tajne, a zatim korišćenjem ovog ključa za dekriptovanje mašinskih master ključeva. Alternativno, Mimikatz-ova komanda `crypto::certificates /export /systemstore:LOCAL_MACHINE` može se koristiti nakon zakrivanja CAPI/CNG kao što je prethodno opisano.

**SharpDPAPI** nudi automatizovaniji pristup sa svojom komandom za sertifikate. Kada se koristi `/machine` zastavica sa povišenim dozvolama, ona se eskalira na SYSTEM, izbacuje DPAPI_SYSTEM LSA tajnu, koristi je za dekriptovanje mašinskih DPAPI master ključeva, a zatim koristi ove plaintext ključeve kao tabelu za pretragu za dekriptovanje bilo kojih privatnih ključeva mašinskih sertifikata.


## Pronalaženje sertifikat fajlova – THEFT4

Sertifikati se ponekad nalaze direktno unutar fajl sistema, kao što su u deljenim fajlovima ili u Downloads folderu. Najčešće vrste sertifikat fajlova koje se susreću u Windows okruženjima su `.pfx` i `.p12` fajlovi. Iako ređe, fajlovi sa ekstenzijama `.pkcs12` i `.pem` takođe se pojavljuju. Dodatne značajne ekstenzije fajlova vezanih za sertifikate uključuju:
- `.key` za privatne ključeve,
- `.crt`/`.cer` za samo sertifikate,
- `.csr` za Zahteve za potpisivanje sertifikata, koji ne sadrže sertifikate ili privatne ključeve,
- `.jks`/`.keystore`/`.keys` za Java Keystore, koji mogu sadržati sertifikate zajedno sa privatnim ključevima korišćenim od strane Java aplikacija.

Ovi fajlovi se mogu pretraživati koristeći PowerShell ili komandnu liniju tražeći pomenute ekstenzije.

U slučajevima kada se pronađe PKCS#12 sertifikat fajl i on je zaštićen lozinkom, ekstrakcija heša je moguća korišćenjem `pfx2john.py`, dostupnog na [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Nakon toga, JohnTheRipper se može koristiti za pokušaj otkrivanja lozinke.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Data objašnjava metodu krađe NTLM akreditiva putem PKINIT, posebno kroz metodu krađe označenu kao THEFT5. Evo ponovnog objašnjenja u pasivnom glasu, sa sadržajem anonimnim i sažetim gde je to primenljivo:

Da bi se podržala NTLM autentifikacija [MS-NLMP] za aplikacije koje ne omogućavaju Kerberos autentifikaciju, KDC je dizajniran da vrati NTLM jednosmernu funkciju (OWF) korisnika unutar sertifikata privilegija (PAC), posebno u `PAC_CREDENTIAL_INFO` baferu, kada se koristi PKCA. Shodno tome, ukoliko se nalog autentifikuje i obezbedi Ticket-Granting Ticket (TGT) putem PKINIT, inherentno je obezbeđen mehanizam koji omogućava trenutnom hostu da izvuče NTLM hash iz TGT-a kako bi podržao nasleđene autentifikacione protokole. Ovaj proces podrazumeva dekripciju `PAC_CREDENTIAL_DATA` strukture, koja je suštinski NDR serijalizovana predstava NTLM običnog teksta.

Alat **Kekeo**, dostupan na [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), pominje se kao sposoban da zatraži TGT koji sadrži ove specifične podatke, čime se olakšava preuzimanje NTLM-a korisnika. Komanda koja se koristi u tu svrhu je sledeća:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Dodatno, primećeno je da Kekeo može obraditi sertifikate zaštićene pametnom karticom, pod uslovom da se pin može dobiti, uz referencu na [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Ista sposobnost se navodi da podržava **Rubeus**, dostupan na [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Ovo objašnjenje obuhvata proces i alate uključene u krađu NTLM akreditiva putem PKINIT-a, fokusirajući se na preuzimanje NTLM heševa kroz TGT dobijen korišćenjem PKINIT-a, i alate koji olakšavaju ovaj proces.

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
