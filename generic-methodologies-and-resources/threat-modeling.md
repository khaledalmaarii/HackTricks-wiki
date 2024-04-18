# Model pretnje

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-web**-om koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji kradu informacije**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji kradu informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## Model pretnji

Dobrodošli u sveobuhvatni vodič HackTricks-a o Modeliranju pretnji! Krenite u istraživanje ovog ključnog aspekta kibernetičke bezbednosti, gde identifikujemo, razumemo i strategiziramo protiv potencijalnih ranjivosti u sistemu. Ova nit služi kao vodič korak po korak pun realnih primera, korisnog softvera i lako razumljivih objašnjenja. Idealno za početnike i iskusne praktičare koji žele ojačati svoje odbrambene mere kibernetičke bezbednosti.

### Često korišćeni scenariji

1. **Razvoj softvera**: Kao deo Sigurnog ciklusa razvoja softvera (SSDLC), modeliranje pretnji pomaže u **identifikaciji potencijalnih izvora ranjivosti** u ranim fazama razvoja.
2. **Testiranje proboja**: Standard izvršenja testiranja proboja (PTES) zahteva **modeliranje pretnji kako bi se razumele ranjivosti sistema** pre sprovođenja testa.

### Model pretnji ukratko

Model pretnji se obično predstavlja kao dijagram, slika ili neka druga vizuelna ilustracija koja prikazuje planiranu arhitekturu ili postojeću izgradnju aplikacije. Sličan je **dijagramu protoka podataka**, ali ključna razlika leži u njegovom dizajnu orijentisanom ka bezbednosti.

Modeli pretnji često sadrže elemente označene crvenom bojom, simbolizujući potencijalne ranjivosti, rizike ili prepreke. Da bi se olakšao proces identifikacije rizika, koristi se trijada CIA (Poverljivost, Integritet, Dostupnost), koja čini osnovu mnogih metodologija modeliranja pretnji, pri čemu je STRIDE jedna od najčešćih. Međutim, odabrana metodologija može varirati u zavisnosti od specifičnog konteksta i zahteva.

### Trijada CIA

Trijada CIA je široko priznat model u oblasti informacione bezbednosti, označavajući Poverljivost, Integritet i Dostupnost. Ova tri stuba čine osnovu na kojoj se grade mneme mere bezbednosti i politike, uključujući metodologije modeliranja pretnji.

1. **Poverljivost**: Osiguravanje da podaci ili sistem nisu dostupni neovlašćenim osobama. Ovo je centralni aspekt bezbednosti, zahtevajući odgovarajuće kontrole pristupa, enkripciju i druge mere kako bi se sprečili curenje podataka.
2. **Integritet**: Tačnost, doslednost i pouzdanost podataka tokom njihovog životnog ciklusa. Ovaj princip osigurava da podaci nisu izmenjeni ili manipulisani od strane neovlašćenih strana. Često uključuje kontrolne zbirove, heširanje i druge metode provere podataka.
3. **Dostupnost**: Ovo osigurava da podaci i usluge budu dostupni ovlašćenim korisnicima kada je potrebno. Često uključuje redundanciju, toleranciju na greške i konfiguracije visoke dostupnosti kako bi se sistemi održavali čak i u slučaju prekida.

### Metodologije modeliranja pretnji

1. **STRIDE**: Razvijen od strane Microsoft-a, STRIDE je akronim za **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Svaka kategorija predstavlja vrstu pretnje, a ova metodologija se često koristi u fazi dizajna programa ili sistema kako bi se identifikovale potencijalne pretnje.
2. **DREAD**: Ovo je još jedna metodologija od Microsoft-a koja se koristi za procenu rizika identifikovanih pretnji. DREAD označava **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Svaki od ovih faktora se ocenjuje, a rezultat se koristi za prioritetizaciju identifikovanih pretnji.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Ovo je sedmostepena, **rizikom usmerena** metodologija. Uključuje definisanje i identifikaciju sigurnosnih ciljeva, kreiranje tehničkog opsega, dekompoziciju aplikacije, analizu pretnji, analizu ranjivosti i procenu rizika/trijage.
4. **Trike**: Ovo je metodologija zasnovana na riziku koja se fokusira na odbranu imovine. Počinje iz perspektive **upravljanja rizikom** i posmatra pretnje i ranjivosti u tom kontekstu.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Ovaj pristup ima za cilj da bude pristupačniji i integriše se u Agile razvojna okruženja. Kombinuje elemente iz drugih metodologija i fokusira se na **vizuelne prikaze pretnji**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Razvijen od strane CERT Coordination Centra, ovaj okvir je usmeren ka **proceni organizacionih rizika umesto specifičnih sistema ili softvera**.

## Alati

Postoji nekoliko alata i softverskih rešenja dostupnih koji mogu **pomoći** u kreiranju i upravljanju modelima pretnji. Evo nekoliko koje možete razmotriti.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Napredni višefunkcionalni GUI veb pauk/crawler za profesionalce u oblasti kibernetičke bezbednosti. Spider Suite se može koristiti za mapiranje i analizu površine napada.

**Korišćenje**

1. Izaberite URL i pretražite

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Pogledajte grafikon

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Projekat otvorenog koda OWASP-a, Threat Dragon je i veb i desktop aplikacija koja uključuje dijagram sistema kao i pravilo motora za automatsko generisanje pretnji/mitigacija.

**Korišćenje**

1. Kreirajte novi projekat

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Ponekad može izgledati ovako:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Pokrenite novi projekat

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Sačuvajte novi projekat

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Kreirajte svoj model

Možete koristiti alate poput SpiderSuite Crawler-a da vam pruže inspiraciju, osnovni model bi izgledao nešto ovako

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Samo malo objašnjenja o entitetima:

* Proces (Sam entitet kao što su Veb server ili veb funkcionalnost)
* Akter (Osoba poput Posetioca veb sajta, Korisnika ili Administratora)
* Linija protoka podataka (Indikator interakcije)
* Granica poverenja (Različiti segmenti mreže ili opsezi.)
* Skladište (Mesta gde se podaci čuvaju, poput baza podataka)

5. Kreirajte pretnju (Korak 1)

Prvo morate odabrati sloj na koji želite dodati pretnju

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sada možete kreirati pretnju

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Imajte na umu da postoji razlika između Pretnji Aktera i Pretnji Procesa. Ako biste dodali pretnju Akteru, tada ćete moći izabrati samo "Spoofing" i "Repudiation". Međutim, u našem primeru dodajemo pretnju entitetu Procesa pa ćemo videti ovo u okviru kreiranja pretnje:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotovo

Sada bi vaš završeni model trebalo da izgleda nešto ovako. I to je kako napraviti jednostavan model pretnji sa OWASP Threat Dragon-om.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Ovo je besplatan alat od Microsoft-a koji pomaže u pronalaženju pretnji u fazi dizajna softverskih projekata. Koristi STRIDE metodologiju i posebno je pogodan za one koji razvijaju na Microsoft-ovoj platformi.


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade podatke**.

Njihov primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}
