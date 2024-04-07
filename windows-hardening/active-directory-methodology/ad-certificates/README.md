# AD Sertifikati

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Uvod

### Komponente Sertifikata

- **Subject** sertifikata označava vlasnika.
- **Javni ključ** je uparen sa privatnim ključem kako bi se sertifikat povezao sa svojim pravim vlasnikom.
- **Period Važenja**, definisan datumima **NotBefore** i **NotAfter**, označava efektivni period sertifikata.
- Jedinstveni **Seriski Broj**, koji dodeljuje Sertifikacioni Autoritet (CA), identifikuje svaki sertifikat.
- **Izdavač** se odnosi na CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subjekta, poboljšavajući fleksibilnost identifikacije.
- **Osnovna Ograničenja** identifikuju da li je sertifikat za CA ili krajnje lice i definišu ograničenja korišćenja.
- **Proširene Namene Ključeva (EKU)** razgraničavaju specifične svrhe sertifikata, poput potpisa koda ili enkripcije email-ova, putem Identifikatora Objekata (OID).
- **Algoritam Potpisa** specificira metod potpisa sertifikata.
- **Potpis**, kreiran sa privatnim ključem izdavača, garantuje autentičnost sertifikata.

### Posebna Razmatranja

- **Subject Alternative Names (SANs)** proširuju primenljivost sertifikata na više identiteta, ključno za servere sa više domena. Važni su sigurni procesi izdavanja kako bi se izbegli rizici impersonacije od strane napadača koji manipulišu SAN specifikacijom.

### Sertifikacioni Autoriteti (CA) u Active Directory (AD)

AD CS priznaje CA sertifikate u AD šumi putem određenih kontejnera, pri čemu svaki obavlja jedinstvene uloge:

- Kontejner **Certification Authorities** čuva sertifikate poverenih korenskih CA.
- Kontejner **Enrolment Services** detaljiše Enterprise CA i njihove šablone sertifikata.
- Objekat **NTAuthCertificates** uključuje CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Authority Information Access)** olakšava validaciju lanca sertifikata sa posrednim i presečnim CA sertifikatima.

### Nabavka Sertifikata: Tok Zahteva za Klijentski Sertifikat

1. Proces zahteva počinje klijenti pronalaženjem Enterprise CA.
2. Kreira se CSR koji sadrži javni ključ i druge detalje, nakon generisanja para javnog-privatnog ključa.
3. CA procenjuje CSR u odnosu na dostupne šablone sertifikata, izdajući sertifikat na osnovu dozvola šablona.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Šabloni Sertifikata

Definisani unutar AD-a, ovi šabloni detaljno opisuju postavke i dozvole za izdavanje sertifikata, uključujući dozvoljene EKU i prava za upisivanje ili izmenu, što je ključno za upravljanje pristupom sertifikacionim uslugama.

## Upisivanje Sertifikata

Proces upisivanja sertifikata pokreće administrator koji **kreira šablon sertifikata**, koji zatim **objavljuje** Enterprise Sertifikacioni Autoritet (CA). Ovo čini šablon dostupnim za upisivanje klijenata, korak koji se postiže dodavanjem imena šablona u polje `certificatetemplates` objekta Active Directory-a.

Da bi klijent zatražio sertifikat, moraju mu biti dodeljena **prava upisivanja**. Ova prava se definišu sigurnosnim deskriptorima na šablonu sertifikata i samom Enterprise CA. Dozvole moraju biti dodeljene na oba mesta da bi zahtev bio uspešan.

### Prava Upisivanja na Šablonu

Ova prava se specificiraju putem Unosa Kontrole Pristupa (ACE), detaljišući dozvole poput:
- **Certificate-Enrollment** i **Certificate-AutoEnrollment** prava, svako povezano sa specifičnim GUID-ovima.
- **ExtendedRights**, dozvoljavajući sve proširene dozvole.
- **FullControl/GenericAll**, pružajući potpunu kontrolu nad šablonom.

### Prava Upisivanja na Enterprise CA

Prava CA su opisana u njegovom sigurnosnom deskriptoru, pristupačnom putem konzole za upravljanje Sertifikacionim Autoritetom. Neka podešavanja čak omogućavaju korisnicima sa niskim privilegijama dalji pristup, što može biti sigurnosna briga.

### Dodatne Kontrole Izdavanja

Mogu se primeniti određene kontrole, kao što su:
- **Odobrenje Menadžera**: Stavlja zahteve u stanje čekanja dok ih ne odobri menadžer sertifikata.
- **Agenti za Upisivanje i Ovlašćeni Potpisi**: Specificiraju broj potrebnih potpisa na CSR i neophodne Aplikacione Politike OID-ova.

### Metode zahteva za Sertifikate

Sertifikati se mogu zatražiti putem:
1. **Windows Protokol za Upisivanje Klijentskih Sertifikata** (MS-WCCE), korišćenjem DCOM interfejsa.
2. **ICertPassage Remote Protokol** (MS-ICPR), putem imenovanih cevi ili TCP/IP-a.
3. **Veb Interfejs za Upisivanje Sertifikata**, sa instaliranom ulogom Certificate Authority Web Enrollment.
4. **Servis za Upisivanje Sertifikata** (CES), u saradnji sa servisom za Politiku Upisivanja Sertifikata (CEP).
5. **Servis za Upisivanje Mrežnih Uređaja** (NDES) za mrežne uređaje, korišćenjem Protokola Jednostavnog Upisivanja Sertifikata (SCEP).

Windows korisnici takođe mogu zatražiti sertifikate putem GUI-a (`certmgr.msc` ili `certlm.msc`) ili alatki komandne linije (`certreq.exe` ili PowerShell-ove komande `Get-Certificate`).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Proces autentifikacije sertifikata

Active Directory (AD) podržava autentifikaciju putem sertifikata, koristeći pretežno protokole **Kerberos** i **Secure Channel (Schannel)**.

### Proces Kerberos autentifikacije

U procesu Kerberos autentifikacije, zahtev korisnika za Ticket Granting Ticket (TGT) potpisuje se korišćenjem **privatnog ključa** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko validacija od strane kontrolera domena, uključujući **validnost**, **putanju** i **status opoziva** sertifikata. Validacije takođe uključuju proveru da li sertifikat potiče od pouzdanog izvora i potvrdu prisustva izdavaoca u **NTAUTH skladištu sertifikata**. Uspešne validacije rezultiraju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD-u, nalazi se na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je ključno za uspostavljanje poverenja za autentikaciju sertifikata.

### Autentikacija sigurnosnog kanala (Schannel)

Schannel olakšava sigurne TLS/SSL veze, gde tokom rukovanja klijent predstavlja sertifikat koji, ako se uspešno validira, odobrava pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberosovu funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, među ostalim metodama.

### Enumeracija AD sertifikacionih servisa

AD-ovi sertifikacioni servisi mogu biti enumerisani putem LDAP upita, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno svakom korisniku autentifikovanom u domenu bez posebnih privilegija. Alati poput **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** se koriste za enumeraciju i procenu ranjivosti u okruženjima AD CS.

Komande za korišćenje ovih alata uključuju:
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
## Reference

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
