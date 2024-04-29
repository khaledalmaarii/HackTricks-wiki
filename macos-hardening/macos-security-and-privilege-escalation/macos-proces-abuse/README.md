# Zloupotreba procesa na macOS-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodiču PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije o procesima

Proces je instanca pokrenutog izvršnog fajla, međutim procesi ne izvršavaju kod, to rade niti. Stoga **procesi su samo kontejneri za pokretanje niti** pružajući memoriju, deskriptore, portove, dozvole...

Tradicionalno, procesi su pokretani unutar drugih procesa (osim PID 1) pozivanjem **`fork`** koji bi kreirao tačnu kopiju trenutnog procesa, a zatim bi **dete proces** obično pozvao **`execve`** da učita novi izvršni fajl i pokrene ga. Zatim je uveden **`vfork`** da ubrza ovaj proces bez kopiranja memorije.\
Zatim je uveden **`posix_spawn`** kombinujući **`vfork`** i **`execve`** u jedan poziv i prihvatajući zastavice:

* `POSIX_SPAWN_RESETIDS`: Resetuje efektivne id-ove na realne id-ove
* `POSIX_SPAWN_SETPGROUP`: Postavlja pripadnost procesne grupe
* `POSUX_SPAWN_SETSIGDEF`: Postavlja podrazumevano ponašanje signala
* `POSIX_SPAWN_SETSIGMASK`: Postavlja masku signala
* `POSIX_SPAWN_SETEXEC`: Izvrši u istom procesu (kao `execve` sa više opcija)
* `POSIX_SPAWN_START_SUSPENDED`: Pokreni suspendovano
* `_POSIX_SPAWN_DISABLE_ASLR`: Pokreni bez ASLR-a
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Koristi libmalloc-ov Nano allocator
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Dozvoli `rwx` na segmentima podataka
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Zatvori sve deskriptore fajlova pri izvršavanju (exec(2)) podrazumevano
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Nasumično postavljanje visokih bitova ASLR klizača

Osim toga, `posix_spawn` omogućava da se specificira niz **`posix_spawnattr`** koji kontroliše neke aspekte spawnovanog procesa, i **`posix_spawn_file_actions`** za modifikaciju stanja deskriptora.

Kada proces umre, šalje **kôd povratka roditeljskom procesu** (ako je roditelj umro, novi roditelj je PID 1) sa signalom `SIGCHLD`. Roditelj mora da dobije ovu vrednost pozivajući `wait4()` ili `waitid()` i dok se to ne desi, dete ostaje u zombi stanju gde je još uvek navedeno ali ne troši resurse.

### PID-ovi

PID-ovi, identifikatori procesa, identifikuju jedinstveni proces. U XNU-u su **PID-ovi** od **64 bita** koji se monotonno povećavaju i **nikada se ne prepliću** (da bi se izbegle zloupotrebe).

### Grupe procesa, sesije i koalicije

**Procesi** mogu biti smešteni u **grupe** kako bi se olakšalo rukovanje njima. Na primer, komande u shell skripti će biti u istoj grupi procesa tako da je moguće **poslati im signal zajedno** koristeći kill na primer.\
Takođe je moguće **grupisati procese u sesije**. Kada proces pokrene sesiju (`setsid(2)`), deca procesi su smešteni unutar sesije, osim ako pokrenu svoju sopstvenu sesiju.

Koalicija je još jedan način grupisanja procesa u Darwinu. Proces koji se pridruži koaliciji omogućava mu pristup deljenim resursima, deljenje knjige ili suočavanje sa Jetsam-om. Koalicije imaju različite uloge: Lider, XPC servis, Proširenje.

### Akreditacije i Personae

Svaki proces poseduje **akreditacije** koje **identifikuju njegove privilegije** u sistemu. Svaki proces će imati jedan primarni `uid` i jedan primarni `gid` (mada može pripadati nekoliko grupa).\
Takođe je moguće promeniti korisnički i grupni id ako izvršni fajl ima bit `setuid/setgid`.\
Postoje različite funkcije za **postavljanje novih uid-ova/gid-ova**.

Sistemski poziv **`persona`** pruža **alternativni** set **akreditacija**. Usvajanje personae pretpostavlja njen uid, gid i članstva u grupi **odjednom**. U [**izvornom kodu**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) moguće je pronaći strukturu:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Osnovne informacije o nitima

1. **POSIX niti (pthreads):** macOS podržava POSIX niti (`pthreads`), koje su deo standardnog API-ja za niti za C/C++. Implementacija pthreads-a u macOS-u nalazi se u `/usr/lib/system/libsystem_pthread.dylib`, koji potiče iz javno dostupnog projekta `libpthread`. Ova biblioteka pruža neophodne funkcije za kreiranje i upravljanje nitima.
2. **Kreiranje niti:** Funkcija `pthread_create()` se koristi za kreiranje novih niti. Interno, ova funkcija poziva `bsdthread_create()`, koji je sistemski poziv nižeg nivoa specifičan za XNU jezgro (jezgro na kojem se zasniva macOS). Ovaj sistemski poziv koristi različite zastave izvedene iz `pthread_attr` (atributa) koji specificiraju ponašanje niti, uključujući rasporedjivanje politika i veličinu steka.
* **Podrazumevana veličina steka:** Podrazumevana veličina steka za nove niti je 512 KB, što je dovoljno za tipične operacije, ali može biti prilagođena putem atributa niti ako je potrebno više ili manje prostora.
3. **Inicijalizacija niti:** Funkcija `__pthread_init()` je ključna tokom postavljanja niti, koristeći argument `env[]` za parsiranje okružnih promenljivih koje mogu uključivati detalje o lokaciji i veličini steka.

#### Završetak niti u macOS-u

1. **Izlazak niti:** Niti se obično završavaju pozivom `pthread_exit()`. Ova funkcija omogućava niti da izađe čisto, obavljajući neophodno čišćenje i omogućavajući niti da pošalje povratnu vrednost svim pridruženim nitima.
2. **Čišćenje niti:** Po pozivu `pthread_exit()`, funkcija `pthread_terminate()` se poziva, koja rukuje uklanjanjem svih povezanih struktura niti. Dealocira Mach niti portove (Mach je podsistem komunikacije u XNU jezgru) i poziva `bsdthread_terminate`, sistemski poziv koji uklanja strukture na nivou jezgra povezane sa niti.

#### Mehanizmi sinhronizacije

Da bi upravljali pristupom deljenim resursima i izbegli trke za stanjem, macOS pruža nekoliko sinhronizacionih primitiva. Ovi su ključni u okruženjima sa više niti kako bi se osigurala integritet podataka i stabilnost sistema:

1. **Muteksi:**
* **Standardni Muteks (Potpis: 0x4D555458):** Standardni muteks sa memorijom od 60 bajtova (56 bajtova za muteks i 4 bajta za potpis).
* **Brzi Muteks (Potpis: 0x4d55545A):** Sličan standardnom muteksu, ali optimizovan za brže operacije, takođe veličine 60 bajtova.
2. **Uslovne promenljive:**
* Koriste se za čekanje da se određeni uslovi dese, sa veličinom od 44 bajta (40 bajtova plus 4-bajtni potpis).
* **Atributi Uslovne Promenljive (Potpis: 0x434e4441):** Konfiguracioni atributi za uslovne promenljive, veličine 12 bajtova.
3. **Jednokratne promenljive (Potpis: 0x4f4e4345):**
* Osigurava da se deo inicijalizacionog koda izvrši samo jednom. Veličina mu je 12 bajtova.
4. **Čitač-Pisac Brava:**
* Dozvoljava više čitača ili jednog pisca istovremeno, olakšavajući efikasan pristup deljenim podacima.
* **Čitač-Pisac Brava (Potpis: 0x52574c4b):** Veličine 196 bajtova.
* **Atributi Čitač-Pisac Brave (Potpis: 0x52574c41):** Atributi za čitač-pisac brave, veličine 20 bajtova.

{% hint style="success" %}
Poslednjih 4 bajta tih objekata se koriste za otkrivanje prekoračenja.
{% endhint %}

### Promenljive Lokalne za Nit (TLV)

**Promenljive Lokalne za Nit (TLV)** u kontekstu Mach-O fajlova (format za izvršne datoteke u macOS-u) se koriste za deklarisanje promenljivih koje su specifične za **svaku nit** u višenitnoj aplikaciji. Ovo osigurava da svaka nit ima svoju zasebnu instancu promenljive, pružajući način za izbegavanje konflikata i održavanje integriteta podataka bez potrebe za eksplicitnim mehanizmima sinhronizacije poput muteksa.

U C i srodnim jezicima, možete deklarisati promenljivu lokalnu za nit koristeći ključnu reč **`__thread`**. Evo kako to funkcioniše u vašem primeru:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Ovaj isječak definiše `tlv_var` kao promenljivu lokalnu za nit. Svaka nit koja izvršava ovaj kod će imati svoj `tlv_var`, i promene koje jedna nit napravi na `tlv_var` neće uticati na `tlv_var` u drugoj niti.

U Mach-O binarnom fajlu, podaci vezani za lokalne promenljive niti su organizovani u specifične sekcije:

* **`__DATA.__thread_vars`**: Ova sekcija sadrži metapodatke o lokalnim promenljivima niti, poput njihovih tipova i statusa inicijalizacije.
* **`__DATA.__thread_bss`**: Ova sekcija se koristi za lokalne promenljive niti koje nisu eksplicitno inicijalizovane. To je deo memorije rezervisan za podatke inicijalizovane na nulu.

Mach-O takođe pruža specifičan API nazvan **`tlv_atexit`** za upravljanje lokalnim promenljivima niti kada nit završi. Ovaj API vam omogućava da **registrujete destruktore** - posebne funkcije koje čiste lokalne podatke niti kada se nit završi.

### Prioriteti niti

Razumevanje prioriteta niti uključuje posmatranje načina na koji operativni sistem odlučuje koje niti pokrenuti i kada. Ova odluka je uticajna na osnovu nivoa prioriteta dodeljenih svakoj niti. U macOS-u i Unix-sličnim sistemima, ovo se rešava korišćenjem koncepata poput `nice`, `renice` i klasa kvaliteta usluge (QoS).

#### Nice i Renice

1. **Nice:**
* `Nice` vrednost procesa je broj koji utiče na njegov prioritet. Svaki proces ima `nice` vrednost u rasponu od -20 (najviši prioritet) do 19 (najniži prioritet). Podrazumevana `nice` vrednost kada se proces kreira je obično 0.
* Niža `nice` vrednost (bliža -20) čini proces više "sebičnim", dajući mu više vremena procesora u poređenju sa drugim procesima sa višim `nice` vrednostima.
2. **Renice:**
* `Renice` je komanda koja se koristi za promenu `nice` vrednosti već pokrenutog procesa. Ovo se može koristiti za dinamičko prilagođavanje prioriteta procesa, povećavajući ili smanjujući njihovu alokaciju vremena procesora na osnovu novih `nice` vrednosti.
* Na primer, ako proces privremeno treba više resursa procesora, možete smanjiti njegovu `nice` vrednost korišćenjem `renice`.

#### Klase kvaliteta usluge (QoS)

Klase kvaliteta usluge su moderniji pristup upravljanju prioritetima niti, posebno u sistemima poput macOS-a koji podržavaju **Grand Central Dispatch (GCD)**. Klase kvaliteta usluge omogućavaju programerima da **kategorizuju** rad u različite nivoe na osnovu njihove važnosti ili hitnosti. macOS automatski upravlja prioritetom niti na osnovu ovih klasa kvaliteta usluge:

1. **Korisnički interaktivno:**
* Ova klasa je za zadatke koji trenutno interaguju sa korisnikom ili zahtevaju odmah rezultate kako bi pružili dobro korisničko iskustvo. Ovi zadaci imaju najviši prioritet kako bi interfejs ostao responsivan (npr. animacije ili obrada događaja).
2. **Korisnički pokrenuto:**
* Zadaci koje korisnik pokreće i očekuje odmah rezultate, poput otvaranja dokumenta ili klikanja na dugme koje zahteva računanja. Ovi zadaci imaju visok prioritet, ali ispod korisnički interaktivnih.
3. **Uslužno:**
* Ovi zadaci traju dugo i obično prikazuju indikator napretka (npr. preuzimanje datoteka, uvoz podataka). Oni imaju niži prioritet od korisnički pokrenutih zadataka i ne moraju se odmah završiti.
4. **Pozadina:**
* Ova klasa je za zadatke koji rade u pozadini i nisu vidljivi korisniku. To mogu biti zadaci poput indeksiranja, sinhronizacije ili rezervnih kopija. Imaju najniži prioritet i minimalan uticaj na performanse sistema.

Korišćenjem klasa kvaliteta usluge, programeri ne moraju upravljati tačnim brojevima prioriteta, već se fokusiraju na prirodu zadatka, a sistem optimizuje resurse procesora u skladu s tim.

Pored toga, postoje različite **politike raspoređivanja niti** koje omogućavaju da se specificira skup parametara raspoređivanja koje će planer uzeti u obzir. Ovo se može uraditi korišćenjem `thread_policy_[set/get]`. Ovo može biti korisno u napadima na trku stanja.

## Zloupotreba procesa u MacOS-u

MacOS, kao i svaki drugi operativni sistem, pruža različite metode i mehanizme za **procese da međusobno interaguju, komuniciraju i dele podatke**. Iako su ove tehnike ključne za efikasno funkcionisanje sistema, mogu biti zloupotrebljene od napadača da **izvrše zlonamerne aktivnosti**.

### Umetanje biblioteke

Umetanje biblioteke je tehnika u kojoj napadač **prisiljava proces da učita zlonamernu biblioteku**. Jednom ubačena, biblioteka se izvršava u kontekstu ciljnog procesa, pružajući napadaču iste dozvole i pristup kao proces.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hakovanje funkcija

Hakovanje funkcija uključuje **interceptovanje poziva funkcija** ili poruka unutar softverskog koda. Hakovanjem funkcija, napadač može **modifikovati ponašanje** procesa, posmatrati osetljive podatke ili čak preuzeti kontrolu nad tokom izvršenja.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Komunikacija između procesa

Komunikacija između procesa (IPC) odnosi se na različite metode kojima odvojeni procesi **dijele i razmenjuju podatke**. Iako je IPC osnovan za mnoge legitimne aplikacije, može se zloupotrebiti kako bi se prekršila izolacija procesa, procurile osetljive informacije ili izvršile neovlaštene radnje.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Umetanje aplikacija zasnovanih na Electron-u

Aplikacije zasnovane na Electron-u izvršene sa određenim env varijablama mogu biti ranjive na ubacivanje procesa:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Umetanje u Chromium

Moguće je koristiti zastave `--load-extension` i `--use-fake-ui-for-media-stream` kako bi se izvršio **napad čoveka u pregledaču** koji omogućava krađu pritisaka tastera, saobraćaja, kolačića, ubacivanje skripti na stranice...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Prljavi NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršiti proizvoljne komande** i **Gatekeeper ne sprečava** već izvršenu aplikaciju da se izvrši ako je **NIB fajl modifikovan**. Stoga se mogu koristiti za izvršavanje proizvoljnih programa proizvoljnih komandi:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Umetanje Java aplikacija

Moguće je zloupotrebiti određene java mogućnosti (poput **`_JAVA_OPTS`** env varijable) kako bi se java aplikacija naterala da izvrši **proizvoljan kod/komande**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Umetanje .Net aplikacija

Moguće je ubaciti kod u .Net aplikacije **zloupotrebom funkcionalnosti .Net debagovanja** (koja nije zaštićena macOS zaštitama poput ojačavanja izvršavanja).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Umetanje Perla

Proverite različite opcije kako bi Perl skripta izvršila proizvoljan kod u:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Umetanje Ruby-a

Takođe je moguće zloupotrebiti ruby env varijable kako bi proizvolne skripte izvršile proizvoljan kod:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}
### Python Injection

Ako je promenljiva okoline **`PYTHONINSPECT`** postavljena, python proces će preći u python cli nakon završetka. Takođe je moguće koristiti **`PYTHONSTARTUP`** da naznači python skriptu koja će se izvršiti na početku interaktivne sesije.\
Međutim, imajte na umu da **`PYTHONSTARTUP`** skripta neće biti izvršena kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge promenljive okoline poput **`PYTHONPATH`** i **`PYTHONHOME`** takođe mogu biti korisne za izvršavanje proizvoljnog koda putem python komande.

Imajte na umu da izvršni fajlovi kompajlirani sa **`pyinstaller`** neće koristiti ove okoline promenljive čak i ako se pokreću koristeći ugrađeni python.

{% hint style="danger" %}
Uopšteno, nisam uspeo da pronađem način da python izvrši proizvoljni kod zloupotrebom promenljivih okoline.\
Međutim, većina ljudi instalira python koristeći **Hombrew**, koji će instalirati python na **zapisivu lokaciju** za podrazumevanog admin korisnika. Možete ga preuzeti nečim poput:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## Detekcija

### Štit

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) je aplikacija otvorenog koda koja može **detektovati i blokirati akcije ubacivanja procesa**:

- Korišćenje **Okružnih Promenljivih**: Pratiće prisustvo bilo koje od sledećih okružnih promenljivih: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** i **`ELECTRON_RUN_AS_NODE`**
- Korišćenje poziva **`task_for_pid`**: Pronalazi kada jedan proces želi da dobije **zadatak porta drugog** što omogućava ubacivanje koda u proces.
- **Parametri Electron aplikacija**: Neko može koristiti **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`** komandnu liniju da pokrene Electron aplikaciju u režimu debagovanja, i tako ubaci kod u nju.
- Korišćenje **simboličkih linkova** ili **čvrstih linkova**: Tipično najčešća zloupotreba je **postavljanje linka sa privilegijama našeg korisnika**, i **usmeravanje ka lokaciji sa višim privilegijama**. Detekcija je veoma jednostavna za oba čvrsta i simbolička linka. Ako proces koji kreira link ima **različit nivo privilegija** od ciljnog fajla, mi stvaramo **upozorenje**. Nažalost, u slučaju simboličkih linkova blokiranje nije moguće, jer nemamo informacije o destinaciji linka pre stvaranja. Ovo je ograničenje Apple-ovog EndpointSecuriy okvira.

### Pozivi koje vrše drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** da dobijete informacije o drugim **procesima koji ubacuju kod u proces** i zatim dobijete informacije o tom drugom procesu.

Imajte na umu da da biste pozvali tu funkciju morate biti **isti uid** kao onaj koji pokreće proces ili **root** (i vraća informacije o procesu, ne način za ubacivanje koda).

## Reference

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
