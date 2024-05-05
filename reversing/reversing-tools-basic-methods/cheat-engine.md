# Cheat Engine

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje gde su važne vrednosti sačuvane u memoriji pokrenute igre i za njihovu promenu.\
Kada ga preuzmete i pokrenete, bićete **upoznati** sa **tutorialom** o tome kako koristiti alat. Ako želite da naučite kako koristiti alat, veoma je preporučljivo da ga završite.

## Šta tražite?

![](<../../.gitbook/assets/image (762).png>)

Ovaj alat je veoma koristan za pronalaženje **gde je neka vrednost** (obično broj) **sačuvana u memoriji** programa.\
**Obično se brojevi** čuvaju u **4 bajta** formi, ali ih možete pronaći i u formatima **double** ili **float**, ili možda želite tražiti nešto **različito od broja**. Iz tog razloga morate biti sigurni da **izaberete** šta želite **tražiti**:

![](<../../.gitbook/assets/image (324).png>)

Takođe možete naznačiti **različite** vrste **pretraga**:

![](<../../.gitbook/assets/image (311).png>)

Takođe možete označiti polje da **zaustavite igru dok skenirate memoriju**:

![](<../../.gitbook/assets/image (1052).png>)

### Prečice

U _**Edit --> Settings --> Hotkeys**_ možete postaviti različite **prečice** za različite svrhe kao što je **zaustavljanje** **igre** (što je korisno ako u nekom trenutku želite skenirati memoriju). Druge opcije su dostupne:

![](<../../.gitbook/assets/image (864).png>)

## Modifikovanje vrednosti

Kada **pronađete** gde se nalazi **vrednost** koju **tražite** (više o tome u sledećim koracima) možete je **modifikovati** dvostrukim klikom na nju, zatim dvostrukim klikom na njenu vrednost:

![](<../../.gitbook/assets/image (563).png>)

I na kraju označite polje da bi modifikacija bila izvršena u memoriji:

![](<../../.gitbook/assets/image (385).png>)

Promena u **memoriji** će biti odmah **primenjena** (imajte na umu da dok igra ne koristi ovu vrednost ponovo, vrednost **neće biti ažurirana u igri**).

## Pretraga vrednosti

Dakle, pretpostavićemo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite poboljšati, i tražite tu vrednost u memoriji)

### Kroz poznatu promenu

Pretpostavljajući da tražite vrednost 100, **izvršite skeniranje** tražeći tu vrednost i pronađete puno podudaranja:

![](<../../.gitbook/assets/image (108).png>)

Zatim, uradite nešto da se **vrednost promeni**, i **zaustavite** igru i **izvršite** **sledeće skeniranje**:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine će tražiti **vrednosti** koje su **prešle iz 100 u novu vrednost**. Čestitamo, **pronašli** ste **adresu** vrednosti koju ste tražili, sada je možete modifikovati.\
_Ako i dalje imate više vrednosti, uradite nešto da ponovo modifikujete tu vrednost, i izvršite još jedno "sledeće skeniranje" da biste filtrirali adrese._

### Nepoznata vrednost, poznata promena

U scenariju kada **ne znate vrednost** ali znate **kako je promeniti** (čak i vrednost promene) možete potražiti svoj broj.

Dakle, počnite sa izvođenjem skeniranja tipa "**Nepoznata početna vrednost**":

![](<../../.gitbook/assets/image (890).png>)

Zatim, promenite vrednost, naznačite **kako** se **vrednost** **promenila** (u mom slučaju smanjena je za 1) i izvršite **sledeće skeniranje**:

![](<../../.gitbook/assets/image (371).png>)

Biće vam prikazane **sve vrednosti koje su modifikovane na izabrani način**:

![](<../../.gitbook/assets/image (569).png>)

Kada pronađete svoju vrednost, možete je modifikovati.

Imajte na umu da postoji **mnogo mogućih promena** i možete raditi ove **korake koliko god želite** da biste filtrirali rezultate:

![](<../../.gitbook/assets/image (574).png>)

### Nasumična adresa memorije - Pronalaženje koda

Do sada smo naučili kako pronaći adresu koja čuva vrednost, ali je veoma verovatno da je u **različitim izvršenjima igre ta adresa na različitim mestima u memoriji**. Zato saznajmo kako uvek pronaći tu adresu.

Koristeći neke od pomenutih trikova, pronađite adresu gde vaša trenutna igra čuva važnu vrednost. Zatim (zaustavljajući igru ako želite) uradite **desni klik** na pronađenu **adresu** i izaberite "**Saznajte šta pristupa ovoj adresi**" ili "**Saznajte ko piše na ovoj adresi**":

![](<../../.gitbook/assets/image (1067).png>)

**Prva opcija** je korisna da znate koje **delovi** **koda** koriste ovu **adresu** (što je korisno za više stvari kao što je **znati gde možete modifikovati kod** igre).\
**Druga opcija** je konkretnija, i biće korisnija u ovom slučaju jer nas zanima **odakle se piše ova vrednost**.

Kada izaberete jednu od tih opcija, **debuger** će biti **povezan** sa programom i pojaviće se nova **prazna prozor**. Sada, **igrajte** **igru** i **modifikujte** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebalo da bude **popunjen** sa **adresama** koje **modifikuju** **vrednost**:

![](<../../.gitbook/assets/image (91).png>)

Sada kada ste pronašli adresu koja modifikuje vrednost, možete **modifikovati kod po vašem nahođenju** (Cheat Engine vam omogućava da ga brzo modifikujete za NOPs):

![](<../../.gitbook/assets/image (1057).png>)

Sada možete modifikovati tako da kod ne utiče na vaš broj, ili će uvek pozitivno uticati.
### Nasumična adresa memorije - Pronalaženje pokazivača

Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim, koristeći "**Saznajte šta piše na ovoj adresi**" saznajte koja adresa upisuje ovu vrednost i dvaput kliknite na nju da biste dobili prikaz rastavljanja:

![](<../../.gitbook/assets/image (1039).png>)

Zatim, izvršite novu pretragu **tražeći heksadecimalnu vrednost između "\[]"** (vrednost $edx u ovom slučaju):

![](<../../.gitbook/assets/image (994).png>)

(Ako se pojavi više njih, obično vam je potrebna ona sa najmanjom adresom)\
Sada smo **pronašli pokazivač koji će menjati vrednost koja nas zanima**.

Kliknite na "**Dodaj adresu ručno**":

![](<../../.gitbook/assets/image (990).png>)

Sada kliknite na polje za potvrdu "Pokazivač" i dodajte pronađenu adresu u polje za unos teksta (u ovom scenariju, pronađena adresa na prethodnoj slici bila je "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Pogledajte kako je prva "Adresa" automatski popunjena iz adrese pokazivača koju unosite)

Kliknite na OK i biće kreiran novi pokazivač:

![](<../../.gitbook/assets/image (308).png>)

Sada, svaki put kada promenite tu vrednost, **menjate važnu vrednost čak i ako je adresa memorije gde se vrednost nalazi drugačija.**

### Umetanje koda

Umetanje koda je tehnika gde ubacujete deo koda u ciljni proces, a zatim preusmeravate izvršenje koda da prolazi kroz vaš sopstveno napisani kod (kao što vam daje poene umesto oduzimanja).

Dakle, zamislite da ste pronašli adresu koja oduzima 1 životu vašeg igrača:

![](<../../.gitbook/assets/image (203).png>)

Kliknite na Prikaz rastavljača da biste dobili **rastavljeni kod**.\
Zatim, pritisnite **CTRL+a** da biste pozvali prozor za automatsko sastavljanje i izaberite _**Šablon --> Umetanje koda**_

![](<../../.gitbook/assets/image (902).png>)

Popunite **adresu instrukcije koju želite da izmenite** (ovo je obično automatski popunjeno):

![](<../../.gitbook/assets/image (744).png>)

Biće generisan šablon:

![](<../../.gitbook/assets/image (944).png>)

Zatim, ubacite svoj novi montažni kod u odeljak "**newmem**" i uklonite originalni kod iz odeljka "**originalcode**" ako ne želite da se izvrši\*\*.\*\* U ovom primeru, ubačeni kod će dodati 2 poena umesto oduzimanja 1:

![](<../../.gitbook/assets/image (521).png>)

**Kliknite na izvrši i tako dalje i vaš kod treba da bude umetnut u program menjajući ponašanje funkcionalnosti!**

## **Reference**

* **Cheat Engine tutorijal, završite ga da biste naučili kako da počnete sa Cheat Engine-om**
