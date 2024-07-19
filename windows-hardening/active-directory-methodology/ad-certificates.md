# AD Certificates

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

## Introduction

### Components of a Certificate

- **Subjekt** sertifikata označava njegovog vlasnika.
- **Javni ključ** je uparen sa privatno držanim ključem kako bi povezao sertifikat sa njegovim pravim vlasnikom.
- **Period važenja**, definisan datumima **NotBefore** i **NotAfter**, označava efektivno trajanje sertifikata.
- Jedinstveni **serijski broj**, koji obezbeđuje Sertifikaciona vlast (CA), identifikuje svaki sertifikat.
- **Izdavac** se odnosi na CA koja je izdala sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subjekt, poboljšavajući fleksibilnost identifikacije.
- **Osnovna ograničenja** identifikuju da li je sertifikat za CA ili krajnji entitet i definišu ograničenja korišćenja.
- **Proširene svrhe korišćenja ključeva (EKUs)** razdvajaju specifične svrhe sertifikata, kao što su potpisivanje koda ili enkripcija e-pošte, kroz identifikatore objekata (OIDs).
- **Algoritam potpisa** specificira metodu za potpisivanje sertifikata.
- **Potpis**, kreiran sa izdavačevim privatnim ključem, garantuje autentičnost sertifikata.

### Special Considerations

- **Alternativna imena subjekta (SANs)** proširuju primenljivost sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su od vitalnog značaja kako bi se izbegli rizici od impersonacije od strane napadača koji manipulišu SAN specifikacijom.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS priznaje CA sertifikate u AD šumi kroz određene kontejnere, od kojih svaki ima jedinstvene uloge:

- **Kontejner sertifikacionih vlasti** sadrži poverljive root CA sertifikate.
- **Kontejner usluga upisa** detaljno opisuje Enterprise CA i njihove šablone sertifikata.
- **NTAuthCertificates** objekat uključuje CA sertifikate ovlašćene za AD autentifikaciju.
- **AIA (Informacije o pristupu vlasti)** kontejner olakšava validaciju lanca sertifikata sa međusobnim i prekograničnim CA sertifikatima.

### Certificate Acquisition: Client Certificate Request Flow

1. Proces zahteva počinje kada klijenti pronađu Enterprise CA.
2. CSR se kreira, sadrži javni ključ i druge detalje, nakon generisanja para javnog-privatnog ključa.
3. CA procenjuje CSR u odnosu na dostupne šablone sertifikata, izdajući sertifikat na osnovu dozvola šablona.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Certificate Templates

Definisani unutar AD, ovi šabloni opisuju podešavanja i dozvole za izdavanje sertifikata, uključujući dozvoljene EKUs i prava na upis ili modifikaciju, što je ključno za upravljanje pristupom uslugama sertifikata.

## Certificate Enrollment

Proces upisa sertifikata pokreće administrator koji **kreira šablon sertifikata**, koji zatim **objavljuje** Enterprise Sertifikaciona vlast (CA). Ovo čini šablon dostupnim za upis klijenata, što se postiže dodavanjem imena šablona u polje `certificatetemplates` objekta Active Directory.

Da bi klijent zatražio sertifikat, **prava na upis** moraju biti dodeljena. Ova prava definišu se sigurnosnim descriptorima na šablonu sertifikata i samoj Enterprise CA. Dozvole moraju biti dodeljene na oba mesta kako bi zahtev bio uspešan.

### Template Enrollment Rights

Ova prava su specificirana kroz unose kontrole pristupa (ACE), detaljno opisujući dozvole kao što su:
- **Prava na upis sertifikata** i **automatski upis sertifikata**, svako povezano sa specifičnim GUID-ovima.
- **Proširena prava**, omogućavajući sve proširene dozvole.
- **Potpuna kontrola/GenericAll**, pružajući potpunu kontrolu nad šablonom.

### Enterprise CA Enrollment Rights

Prava CA su opisana u njegovom sigurnosnom descriptoru, dostupnom putem konzole za upravljanje Sertifikacionom vlasti. Neka podešavanja čak omogućavaju korisnicima sa niskim privilegijama daljinski pristup, što može biti bezbednosna briga.

### Additional Issuance Controls

Određene kontrole mogu se primeniti, kao što su:
- **Odobrenje menadžera**: Postavlja zahteve u stanje čekanja dok ih ne odobri menadžer sertifikata.
- **Agenti za upis i ovlašćeni potpisi**: Specificiraju broj potrebnih potpisa na CSR-u i neophodne OIDs za aplikacione politike.

### Methods to Request Certificates

Sertifikati se mogu zatražiti putem:
1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), putem imenovanih cevi ili TCP/IP.
3. **Web interfejsa za upis sertifikata**, sa instaliranom ulogom Web upisa sertifikata.
4. **Usluge upisa sertifikata** (CES), u kombinaciji sa uslugom politike upisa sertifikata (CEP).
5. **Usluge upisa mrežnih uređaja** (NDES) za mrežne uređaje, koristeći Protokol jednostavnog upisa sertifikata (SCEP).

Windows korisnici takođe mogu zatražiti sertifikate putem GUI-a (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell-ove `Get-Certificate` komande).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikatska Autentifikacija

Active Directory (AD) podržava sertifikatsku autentifikaciju, prvenstveno koristeći **Kerberos** i **Secure Channel (Schannel)** protokole.

### Kerberos Proces Autentifikacije

U Kerberos procesu autentifikacije, zahtev korisnika za Ticket Granting Ticket (TGT) se potpisuje koristeći **privatni ključ** korisničkog sertifikata. Ovaj zahtev prolazi kroz nekoliko validacija od strane kontrolera domena, uključujući **validnost** sertifikata, **putanju** i **status opoziva**. Validacije takođe uključuju proveru da li sertifikat dolazi iz pouzdanog izvora i potvrđivanje prisustva izdavaoca u **NTAUTH sertifikat skladištu**. Uspešne validacije rezultiraju izdavanjem TGT-a. **`NTAuthCertificates`** objekat u AD, nalazi se na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is central to establishing trust for certificate authentication.

### Secure Channel (Schannel) Authentication

Schannel olakšava sigurne TLS/SSL veze, gde tokom rukovanja, klijent predstavlja sertifikat koji, ako je uspešno validiran, odobrava pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberosovu **S4U2Self** funkciju ili **Subject Alternative Name (SAN)** sertifikata, među drugim metodama.

### AD Certificate Services Enumeration

AD-ove sertifikacione usluge mogu se enumerisati putem LDAP upita, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno svakom korisniku koji je autentifikovan u domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** se koriste za enumeraciju i procenu ranjivosti u AD CS okruženjima.

Commands for using these tools include:
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
## References

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
