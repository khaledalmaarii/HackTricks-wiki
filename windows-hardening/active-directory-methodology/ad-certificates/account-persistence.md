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

**Ovo je kratak pregled poglavlja o postojanosti mašine iz sjajnog istraživanja sa [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## **Razumevanje krađe aktivnih korisničkih akreditiva pomoću sertifikata – PERSIST1**

U scenariju gde korisnik može da zatraži sertifikat koji omogućava autentifikaciju domena, napadač ima priliku da **zatraži** i **ukrade** ovaj sertifikat kako bi **održao postojanost** na mreži. Po defaultu, `User` šablon u Active Directory-ju omogućava takve zahteve, iako može ponekad biti onemogućen.

Korišćenjem alata pod nazivom [**Certify**](https://github.com/GhostPack/Certify), može se pretraživati za validnim sertifikatima koji omogućavaju postojan pristup:
```bash
Certify.exe find /clientauth
```
Istaknuto je da moć sertifikata leži u njegovoj sposobnosti da **autentifikuje kao korisnik** kojem pripada, bez obzira na bilo kakve promene lozinke, sve dok sertifikat ostaje **važeći**.

Sertifikati se mogu tražiti putem grafičkog interfejsa koristeći `certmgr.msc` ili putem komandne linije sa `certreq.exe`. Sa **Certify**, proces traženja sertifikata je pojednostavljen na sledeći način:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Upon successful request, a certificate along with its private key is generated in `.pem` format. Da biste to konvertovali u `.pfx` datoteku, koja se može koristiti na Windows sistemima, koristi se sledeća komanda:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Datoteka `.pfx` se zatim može otpremiti na ciljni sistem i koristiti sa alatom pod nazivom [**Rubeus**](https://github.com/GhostPack/Rubeus) za zahtev za Ticket Granting Ticket (TGT) za korisnika, produžavajući pristup napadača sve dok je sertifikat **važeći** (obično jednu godinu):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Važno upozorenje se deli o tome kako ova tehnika, u kombinaciji sa drugom metodom opisano u sekciji **THEFT5**, omogućava napadaču da trajno dobije **NTLM hash** naloga bez interakcije sa Local Security Authority Subsystem Service (LSASS), i iz neuzvišenog konteksta, pružajući diskretniju metodu za dugotrajno krađu akreditiva.

## **Sticanje mašinske postojanosti sa sertifikatima - PERSIST2**

Druga metoda uključuje registraciju mašinskog naloga kompromitovanog sistema za sertifikat, koristeći podrazumevani `Machine` šablon koji omogućava takve radnje. Ako napadač dobije uzvišene privilegije na sistemu, može koristiti **SYSTEM** nalog za zahtev sertifikata, pružajući oblik **postojanosti**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Ovaj pristup omogućava napadaču da se autentifikuje na **Kerberos** kao mašinski nalog i koristi **S4U2Self** da dobije Kerberos servisne karte za bilo koju uslugu na hostu, efektivno dajući napadaču postojan pristup mašini.

## **Produženje postojanosti kroz obnovu sertifikata - PERSIST3**

Poslednja metoda koja se razmatra uključuje korišćenje **važenja** i **perioda obnove** šablona sertifikata. Obnavljanjem sertifikata pre njegovog isteka, napadač može održati autentifikaciju na Active Directory bez potrebe za dodatnim upisima karata, što bi moglo ostaviti tragove na serveru sertifikacione vlasti (CA).

Ovaj pristup omogućava **produženu postojanost**, minimizirajući rizik od otkrivanja kroz manje interakcija sa CA serverom i izbegavajući generisanje artefakata koji bi mogli upozoriti administratore na upad.
