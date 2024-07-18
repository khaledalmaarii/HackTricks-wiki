# macOS MDM

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

**Za učenje o macOS MDM-ovima pogledajte:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Osnove

### **Pregled MDM-a (Upravljanje mobilnim uređajima)**

[Upravljanje mobilnim uređajima](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) se koristi za upravljanje različitim uređajima krajnjih korisnika poput pametnih telefona, laptopova i tableta. Posebno za Apple-ove platforme (iOS, macOS, tvOS), uključuje skup specijalizovanih funkcija, API-ja i praksi. Rad MDM-a zavisi od kompatibilnog MDM servera, koji je ili komercijalno dostupan ili open-source, i mora podržavati [MDM protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ključne tačke uključuju:

* Centralizovana kontrola nad uređajima.
* Zavisnost od MDM servera koji se pridržava MDM protokola.
* Mogućnost MDM servera da šalje različite komande uređajima, na primer, dalje brisanje podataka ili instalaciju konfiguracije.

### **Osnove DEP-a (Program za registraciju uređaja)**

[Program za registraciju uređaja](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) koji nudi Apple olakšava integraciju Upravljanja mobilnim uređajima (MDM) omogućavajući konfiguraciju bez dodira za iOS, macOS i tvOS uređaje. DEP automatizuje proces registracije, omogućavajući uređajima da budu operativni odmah po izlasku iz kutije, sa minimalnom intervencijom korisnika ili administratora. Bitni aspekti uključuju:

* Omogućava uređajima da se automatski registruju sa unapred definisanim MDM serverom prilikom prvog aktiviranja.
* Pogodno za potpuno nove uređaje, ali se takođe može primeniti i na uređaje koji se ponovno konfigurišu.
* Olakšava jednostavnu postavku, čineći uređaje spremnim za organizacionu upotrebu brzo.

### **Razmatranje bezbednosti**

Važno je napomenuti da olakšana registracija koju pruža DEP, iako korisna, može takođe predstavljati bezbednosne rizike. Ako zaštita prilikom registracije putem MDM-a nije adekvatno sprovedena, napadači bi mogli iskoristiti ovaj pojednostavljeni proces da registruju svoj uređaj na MDM serveru organizacije, predstavljajući se kao korporativni uređaj.

{% hint style="danger" %}
**Bezbednosno upozorenje**: Pojednostavljena registracija putem DEP-a može potencijalno dozvoliti neovlašćenu registraciju uređaja na MDM serveru organizacije ako odgovarajuće mere zaštite nisu na snazi.
{% endhint %}

### Osnove Šta je SCEP (Protokol za jednostavnu registraciju sertifikata)?

* Relativno stari protokol, kreiran pre nego što su TLS i HTTPS postali široko rasprostranjeni.
* Klijentima pruža standardizovan način slanja **Zahteva za potpisivanje sertifikata** (CSR) radi dobijanja sertifikata. Klijent će zatražiti od servera da mu izda potpisan sertifikat.

### Šta su Konfiguracioni profili (poznati i kao mobileconfigs)?

* Zvaničan način Apple-a za **postavljanje/primenu konfiguracije sistema.**
* Format datoteke koji može sadržati više nosilaca.
* Bazirano na listama svojstava (XML vrsta).
* "može biti potpisan i šifrovan kako bi se validirao njihov poreklo, obezbedila njihova celovitost i zaštitili njihov sadržaj." Osnove — Strana 70, Vodič za bezbednost iOS-a, januar 2018.

## Protokoli

### MDM

* Kombinacija APNs (**Apple servera**) + RESTful API (**MDM** **serveri proizvođača**)
* **Komunikacija** se odvija između **uređaja** i servera povezanog sa **proizvodom za upravljanje uređajima**
* **Komande** isporučene od strane MDM-a uređaju u **plist kodiranim rečnicima**
* Sve preko **HTTPS**. MDM serveri mogu biti (i obično jesu) prikačeni.
* Apple dodeljuje proizvođaču MDM-a **APNs sertifikat** za autentifikaciju

### DEP

* **3 API-ja**: 1 za prodavce, 1 za proizvođače MDM-a, 1 za identitet uređaja (nedokumentovano):
* Tako zvani [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Koristi se od strane MDM servera za povezivanje DEP profila sa određenim uređajima.
* [DEP API koji koriste ovlašćeni prodavci Apple-a](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) za registraciju uređaja, proveru statusa registracije i proveru statusa transakcije.
* Nedokumentovani privatni DEP API. Koristi se od strane Apple uređaja za zahtevanje njihovog DEP profila. Na macOS-u, binarni `cloudconfigurationd` je odgovoran za komunikaciju preko ovog API-ja.
* Moderniji i **JSON** baziran (za razliku od plist-a)
* Apple dodeljuje proizvođaču MDM-a **OAuth token**

**DEP "cloud service" API**

* RESTful
* sinhronizacija zapisa uređaja između Apple-a i MDM servera
* sinhronizacija "DEP profila" sa Apple-om sa MDM servera (isporučeno od strane Apple-a uređaju kasnije)
* DEP "profil" sadrži:
* URL MDM servera proizvođača
* Dodatni pouzdani sertifikati za URL servera (opciono prikačivanje)
* Dodatne postavke (npr. koje ekrane preskočiti u pomoćniku za podešavanje)

## Serijski broj

Apple uređaji proizvedeni posle 2010. godine generalno imaju **12-karakterni alfanumerički** serijski broj, pri čemu **prve tri cifre predstavljaju lokaciju proizvodnje**, sledeće **dve** označavaju **godinu** i **sedmicu** proizvodnje, naredne **tri** cifre pružaju **jedinstveni** **identifikator**, a **poslednje** **četiri** cifre predstavljaju **broj modela**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Koraci za registraciju i upravljanje

1. Kreiranje zapisa uređaja (Prodavac, Apple): Kreira se zapis za novi uređaj
2. Dodeljivanje zapisa uređaja (Kupac): Uređaj se dodeljuje MDM serveru
3. Sinhronizacija zapisa uređaja (Proizvođač MDM-a): MDM sinhronizuje zapise uređaja i šalje DEP profile Apple-u
4. DEP prijava (Uređaj): Uređaj dobija svoj DEP profil
5. Preuzimanje profila (Uređaj)
6. Instalacija profila (Uređaj) a. uključujući MDM, SCEP i nosioce root CA
7. Izdavanje MDM komande (Uređaj)

![](<../../../.gitbook/assets/image (694).png>)

Datoteka `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` izvozi funkcije koje se mogu smatrati **visokim "koracima"** procesa registracije.
### Korak 4: Provera DEP - Dobijanje aktivacionog zapisa

Ovaj deo procesa se dešava kada **korisnik prvi put pokrene Mac** (ili nakon potpunog brisanja)

![](<../../../.gitbook/assets/image (1044).png>)

ili prilikom izvršavanja `sudo profiles show -type enrollment`

* Utvrditi da li je uređaj omogućen za **DEP**
* Aktivacioni zapis je interni naziv za **DEP "profil"**
* Počinje čim se uređaj poveže na Internet
* Pokreće se pomoću **`CPFetchActivationRecord`**
* Implementiran od strane **`cloudconfigurationd`** putem XPC. **"Pomoćnik za podešavanje**" (kada se uređaj prvi put pokrene) ili komanda **`profiles`** će **kontaktirati ovaj demon** da bi dobio aktivacioni zapis.
* LaunchDaemon (uvek se izvršava kao root)

Sledi nekoliko koraka za dobijanje aktivacionog zapisa koje izvršava **`MCTeslaConfigurationFetcher`**. Ovaj proces koristi enkripciju nazvanu **Absinthe**

1. Dobavljanje **sertifikata**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicijalizacija** stanja iz sertifikata (**`NACInit`**)
1. Koristi različite podatke specifične za uređaj (npr. **Seriski broj putem `IOKit`**)
3. Dobavljanje **sesijskog ključa**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Uspostavljanje sesije (**`NACKeyEstablishment`**)
5. Slanje zahteva
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) slanjem podataka `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload je enkriptovan korišćenjem Absinthe (**`NACSign`**)
3. Svi zahtevi se šalju preko HTTPs, ugrađeni sertifikati su korišćeni

![](<../../../.gitbook/assets/image (566) (1).png>)

Odgovor je JSON rečnik sa nekim važnim podacima kao što su:

* **url**: URL MDM dobavljača hosta za aktivacioni profil
* **anchor-certs**: Niz DER sertifikata korišćenih kao pouzdani koreni

### **Korak 5: Dobavljanje profila**

![](<../../../.gitbook/assets/image (444).png>)

* Zahtev poslat na **url koji je naveden u DEP profilu**.
* **Anchor sertifikati** se koriste za **procenu poverenja** ako su dostupni.
* Napomena: svojstvo **anchor\_certs** DEP profila
* Zahtev je jednostavan .plist sa identifikacijom uređaja
* Primeri: **UDID, verzija OS-a**.
* CMS-potpisan, DER-enkodiran
* Potpisan korišćenjem **sertifikata identiteta uređaja (od APNS-a)**
* **Lanac sertifikata** uključuje istekli **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Korak 6: Instalacija profila

* Kada se dobije, **profil se čuva na sistemu**
* Ovaj korak se automatski pokreće (ako je u **pomoćniku za podešavanje**)
* Pokreće se pomoću **`CPInstallActivationProfile`**
* Implementiran od strane mdmclient preko XPC
* LaunchDaemon (kao root) ili LaunchAgent (kao korisnik), zavisno od konteksta
* Konfiguracioni profili imaju više tereta za instalaciju
* Okvir ima arhitekturu zasnovanu na pluginima za instaliranje profila
* Svaki tip tereta je povezan sa pluginom
* Može biti XPC (u okviru) ili klasični Cocoa (u ManagedClient.app)
* Primer:
* Tereti sertifikata koriste CertificateService.xpc

Tipično, **aktivacioni profil** koji pruža MDM dobavljač će **uključivati sledeće terete**:

* `com.apple.mdm`: za **upisivanje** uređaja u MDM
* `com.apple.security.scep`: za bezbedno obezbeđivanje **klijentskog sertifikata** uređaju.
* `com.apple.security.pem`: za **instaliranje pouzdanih CA sertifikata** u sistemski ključni lanac uređaja.
* Instaliranje tereta MDM ekvivalentno je **MDM proveri u dokumentaciji**
* Teret **sadrži ključna svojstva**:
*
* MDM URL provere (**`CheckInURL`**)
* URL za preuzimanje MDM komandi (**`ServerURL`**) + APNs tema za pokretanje
* Za instaliranje MDM tereta, zahtev se šalje na **`CheckInURL`**
* Implementirano u **`mdmclient`**
* MDM teret može zavisiti od drugih tereta
* Omogućava da **zahtevi budu vezani za određene sertifikate**:
* Svojstvo: **`CheckInURLPinningCertificateUUIDs`**
* Svojstvo: **`ServerURLPinningCertificateUUIDs`**
* Dostavljeno putem PEM tereta
* Omogućava uređaju da bude povezan sa sertifikatom identiteta:
* Svojstvo: IdentityCertificateUUID
* Dostavljeno putem SCEP tereta

### **Korak 7: Slušanje MDM komandi**

* Nakon što se MDM provera završi, dobavljač može **izdati push notifikacije koristeći APNs**
* Po prijemu, obrađeno od strane **`mdmclient`**
* Za preuzimanje MDM komandi, zahtev se šalje na ServerURL
* Koristi se prethodno instaliran MDM teret:
* **`ServerURLPinningCertificateUUIDs`** za vezivanje zahteva
* **`IdentityCertificateUUID`** za TLS klijentski sertifikat

## Napadi

### Upisivanje uređaja u druge organizacije

Kao što je ranije komentarisano, kako bi se pokušalo upisati uređaj u organizaciju **potreban je samo Serijski broj koji pripada toj Organizaciji**. Kada se uređaj upiše, nekoliko organizacija će instalirati osetljive podatke na novi uređaj: sertifikate, aplikacije, lozinke za WiFi, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Stoga, ovo bi mogao biti opasan ulaz za napadače ako proces upisa nije pravilno zaštićen:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
