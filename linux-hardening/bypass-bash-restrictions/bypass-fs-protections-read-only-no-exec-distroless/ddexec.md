# DDexec / EverythingExec

{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Kontekst

U Linuxu, da bi se pokrenuo program, mora postojati kao datoteka, mora biti dostupan na neki način kroz hijerarhiju fajl sistema (ovo je samo kako `execve()` funkcioniše). Ova datoteka može biti smeštena na disku ili u memoriji (tmpfs, memfd) ali vam je potreban putanja do nje. Ovo je učinilo veoma lako kontrolisati šta se pokreće na Linux sistemu, olakšava otkrivanje pretnji i alata napadača ili sprečavanje njihovog pokušaja izvršavanja bilo čega svojstvenog (_npr._ ne dozvoljavajući neprivilegovanim korisnicima da postavljaju izvršne datoteke bilo gde).

Ali ova tehnika je tu da promeni sve to. Ako ne možete pokrenuti proces koji želite... **onda preuzmete kontrolu nad već postojećim**.

Ova tehnika vam omogućava da **zaobiđete uobičajene tehnike zaštite poput samo za čitanje, noexec, bela lista imena fajlova, bela lista hešova...**

## Zavisnosti

Konačni skript zavisi od sledećih alata da bi radio, oni moraju biti dostupni u sistemu koji napadate (podrazumevano ćete ih pronaći svuda):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Tehnika

Ako možete proizvoljno izmeniti memoriju procesa, možete ga preuzeti. Ovo se može koristiti za preuzimanje već postojećeg procesa i zamenjivanje sa drugim programom. To možemo postići ili korišćenjem `ptrace()` sistemskog poziva (što zahteva mogućnost izvršavanja sistemskih poziva ili prisustvo gdb-a na sistemu) ili, što je interesantnije, pisanjem u `/proc/$pid/mem`.

Fajl `/proc/$pid/mem` je jedan-na-jedan mapiranje celog adresnog prostora procesa (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` u x86-64). To znači da čitanje ili pisanje u ovaj fajl na offsetu `x` isto je kao čitanje ili menjanje sadržaja na virtuelnoj adresi `x`.

Sada, imamo četiri osnovna problema sa kojima se suočavamo:

* Generalno, samo root i vlasnik programa fajla mogu ga izmeniti.
* ASLR.
* Ako pokušamo čitati ili pisati na adresu koja nije mapirana u adresnom prostoru programa, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, su dobra:

* Većina shell interpretatora dozvoljava kreiranje file deskriptora koji će biti nasleđeni od strane child procesa. Možemo kreirati fd koji pokazuje na `mem` fajl šella sa dozvolama za pisanje... tako da će child procesi koji koriste taj fd moći da menjaju memoriju šella.
* ASLR čak nije problem, možemo proveriti `maps` fajl šella ili bilo koji drugi iz procfs-a kako bismo dobili informacije o adresnom prostoru procesa.
* Dakle, moramo koristiti `lseek()` preko fajla. Iz šella ovo ne može biti urađeno osim korišćenjem zloglasnog `dd`.

### Detaljnije

Koraci su relativno jednostavni i ne zahtevaju nikakvu vrstu ekspertize da biste ih razumeli:

* Parsirajte binarni fajl koji želimo da pokrenemo i loader kako biste saznali koje mapiranja im je potrebno. Zatim kreirajte "shell" kod koji će izvršiti, u najširem smislu, iste korake koje kernel obavlja prilikom svakog poziva `execve()`:
* Kreirajte navedena mapiranja.
* Učitajte binarne fajlove u njih.
* Postavite dozvole.
* Na kraju inicijalizujte stek sa argumentima za program i postavite pomoćni vektor (potreban od strane loadera).
* Skočite u loader i pustite ga da obavi ostalo (učitavanje potrebnih biblioteka za program).
* Dobijte iz fajla `syscall` adresu na koju će se proces vratiti nakon sistemskog poziva koji izvršava.
* Prepisati to mesto, koje će biti izvršno, sa našim shell kodom (kroz `mem` možemo menjati nepisive stranice).
* Prosledite program koji želimo da pokrenemo na stdin procesa (biće `read()` od strane navedenog "shell" koda).
* U ovom trenutku je na loaderu da učita potrebne biblioteke za naš program i skoči u njega.

**Pogledajte alat na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Postoje nekoliko alternativa za `dd`, od kojih je jedna, `tail`, trenutno podrazumevani program koji se koristi za `lseek()` kroz `mem` fajl (što je bila jedina svrha korišćenja `dd`). Pomenute alternative su:
```bash
tail
hexdump
cmp
xxd
```
Postavljanjem promenljive `SEEKER` možete promeniti korišćeni tražilac, _npr._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ako pronađete još jednog važećeg tražioca koji nije implementiran u skriptu, i dalje ga možete koristiti postavljanjem promenljive `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokiraj ovo, EDR-ovi.

## Reference
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)
