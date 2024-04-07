# Cheat Engine

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) je koristan program za pronalaženje gde su važne vrednosti sačuvane u memoriji pokrenute igre i za njihovu promenu.\
Kada ga preuzmete i pokrenete, bićete **upoznati** sa **tutorialom** o korišćenju alata. Ako želite da naučite kako da koristite alat, veoma je preporučljivo da ga završite.

## Šta tražite?

![](<../../.gitbook/assets/image (759).png>)

Ovaj alat je veoma koristan za pronalaženje **gde je neka vrednost** (obično broj) **sačuvana u memoriji programa**.\
**Obično se brojevi** čuvaju u obliku **4 bajta**, ali ih možete pronaći i u formatima **double** ili **float**, ili možda želite da tražite nešto **različito od broja**. Iz tog razloga morate biti sigurni da **izaberete** šta želite da **tražite**:

![](<../../.gitbook/assets/image (321).png>)

Takođe možete naznačiti **različite** vrste **pretraga**:

![](<../../.gitbook/assets/image (307).png>)

Takođe možete označiti polje da **zaustavite igru dok skenirate memoriju**:

![](<../../.gitbook/assets/image (1049).png>)

### Prečice

U _**Edit --> Settings --> Hotkeys**_ možete postaviti različite **prečice** za različite svrhe kao što je **zaustavljanje** **igre** (što je korisno ako u nekom trenutku želite da skenirate memoriju). Druge opcije su dostupne:

![](<../../.gitbook/assets/image (861).png>)

## Modifikovanje vrednosti

Kada **pronađete** gde se nalazi **vrednost** koju **tražite** (više o tome u sledećim koracima) možete je **modifikovati** dvostrukim klikom na nju, zatim dvostrukim klikom na njenu vrednost:

![](<../../.gitbook/assets/image (560).png>)

I na kraju označite polje da bi modifikacija bila izvršena u memoriji:

![](<../../.gitbook/assets/image (382).png>)

Promena u **memoriji** će biti odmah **primenjena** (imajte na umu da dok igra ne koristi ovu vrednost ponovo, vrednost **neće biti ažurirana u igri**).

## Pretraga vrednosti

Dakle, pretpostavićemo da postoji važna vrednost (kao što je život vašeg korisnika) koju želite poboljšati, i tražite tu vrednost u memoriji)

### Kroz poznatu promenu

Pretpostavljajući da tražite vrednost 100, **izvršite skeniranje** tražeći tu vrednost i pronađete mnogo podudaranja:

![](<../../.gitbook/assets/image (105).png>)

Zatim, uradite nešto da se **vrednost promeni**, i **zaustavite** igru i **izvršite** **sledeće skeniranje**:

![](<../../.gitbook/assets/image (681).png>)

Cheat Engine će tražiti **vrednosti koje su prešle iz 100 na novu vrednost**. Čestitamo, **pronašli** ste **adresu** vrednosti koju ste tražili, sada je možete modifikovati.\
_Ako i dalje imate više vrednosti, uradite nešto da ponovo modifikujete tu vrednost, i izvršite još jedno "sledeće skeniranje" da biste filtrirali adrese._

### Nepoznata vrednost, poznata promena

U scenariju kada **ne znate vrednost** ali znate **kako da je promenite** (čak i vrednost promene) možete potražiti svoj broj.

Dakle, započnite sa skeniranjem tipa "**Nepoznata početna vrednost**":

![](<../../.gitbook/assets/image (887).png>)

Zatim, promenite vrednost, naznačite **kako** se **vrednost** **promenila** (u mom slučaju smanjena je za 1) i izvršite **sledeće skeniranje**:

![](<../../.gitbook/assets/image (368).png>)

Biće vam prikazane **sve vrednosti koje su modifikovane na izabrani način**:

![](<../../.gitbook/assets/image (566).png>)

Kada pronađete svoju vrednost, možete je modifikovati.

Imajte na umu da postoji **mnogo mogućih promena** i možete izvršiti ove **korake koliko god želite** da biste filtrirali rezultate:

![](<../../.gitbook/assets/image (571).png>)

### Nasumična adresa memorije - Pronalaženje koda

Do sada smo naučili kako pronaći adresu koja čuva vrednost, ali je veoma verovatno da je u **različitim izvršenjima igre ta adresa na različitim mestima u memoriji**. Zato saznajmo kako uvek pronaći tu adresu.

Koristeći neke od pomenutih trikova, pronađite adresu gde vaša trenutna igra čuva važnu vrednost. Zatim (zaustavljajući igru ako želite) uradite **desni klik** na pronađenu **adresu** i izaberite "**Saznajte šta pristupa ovoj adresi**" ili "**Saznajte ko piše na ovoj adresi**":

![](<../../.gitbook/assets/image (1064).png>)

**Prva opcija** je korisna da saznate koje **delovi** **koda** koriste ovu **adresu** (što je korisno za više stvari kao što je **znati gde možete modifikovati kod** igre).\
**Druga opcija** je konkretnija, i biće korisnija u ovom slučaju jer nas zanima **odakle se piše ova vrednost**.

Kada izaberete jednu od tih opcija, **debuger** će biti **povezan** sa programom i pojaviće se nova **prazna prozor**. Sada, **igrajte** **igru** i **modifikujte** tu **vrednost** (bez ponovnog pokretanja igre). **Prozor** bi trebalo da bude **popunjen** sa **adresama** koje **modifikuju** **vrednost**:

![](<../../.gitbook/assets/image (88).png>)

Sada kada ste pronašli adresu koja modifikuje vrednost, možete **modifikovati kod po vašem nahođenju** (Cheat Engine vam omogućava brzu modifikaciju za NOPs):

![](<../../.gitbook/assets/image (1054).png>)

Sada možete modifikovati kod tako da ne utiče na vaš broj, ili će uvek pozitivno uticati.
### Nasumična adresa memorije - Pronalaženje pokazivača

Prateći prethodne korake, pronađite gde se nalazi vrednost koja vas zanima. Zatim, koristeći "**Saznajte šta piše na ovoj adresi**" saznajte koja adresa upisuje ovu vrednost i dvaput kliknite na nju da biste dobili prikaz rastavljanja:

![](<../../.gitbook/assets/image (1036).png>)

Zatim, izvršite novu pretragu **tražeći heksadecimalnu vrednost između "\[]"** (vrednost $edx u ovom slučaju):

![](<../../.gitbook/assets/image (991).png>)

(Ako se pojavi više njih, obično vam je potrebna ona sa najmanjom adresom)\
Sada smo **pronašli pokazivač koji će menjati vrednost koja nas zanima**.

Kliknite na "**Dodaj adresu ručno**":

![](<../../.gitbook/assets/image (987).png>)

Sada kliknite na polje za potvrdu "Pokazivač" i dodajte pronađenu adresu u polje za unos teksta (u ovom scenariju, pronađena adresa na prethodnoj slici bila je "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (388).png>)

(Pogledajte kako je prva "Adresa" automatski popunjena iz adrese pokazivača koju unosite)

Kliknite na OK i biće kreiran novi pokazivač:

![](<../../.gitbook/assets/image (305).png>)

Sada, svaki put kada promenite tu vrednost, **menjate važnu vrednost čak i ako je adresa memorije gde se vrednost nalazi drugačija.**

### Ubacivanje koda

Ubacivanje koda je tehnika gde ubacujete deo koda u ciljni proces, a zatim preusmeravate izvršenje koda da prolazi kroz vaš sopstveno napisani kod (kao davanje poena umesto oduzimanja).

Dakle, zamislite da ste pronašli adresu koja oduzima 1 životu vašeg igrača:

![](<../../.gitbook/assets/image (200).png>)

Kliknite na Prikaz rastavljača da biste dobili **rastavljeni kod**.\
Zatim, pritisnite **CTRL+a** da biste pozvali prozor za automatsko sastavljanje i izaberite _**Šablon --> Ubacivanje koda**_

![](<../../.gitbook/assets/image (899).png>)

Popunite **adresu instrukcije koju želite da izmenite** (ovo je obično automatski popunjeno):

![](<../../.gitbook/assets/image (741).png>)

Biće generisan šablon:

![](<../../.gitbook/assets/image (941).png>)

Stoga, ubacite svoj novi montažni kod u odeljak "**newmem**" i uklonite originalni kod iz "**originalcode**" ako ne želite da se izvrši\*\*.\*\* U ovom primeru ubačeni kod će dodati 2 poena umesto oduzimanja 1:

![](<../../.gitbook/assets/image (518).png>)

**Kliknite na izvrši i tako dalje i vaš kod treba da bude ubačen u program menjajući ponašanje funkcionalnosti!**

## **Reference**

* **Cheat Engine tutorijal, završite ga da biste naučili kako da počnete sa Cheat Engine-om**
