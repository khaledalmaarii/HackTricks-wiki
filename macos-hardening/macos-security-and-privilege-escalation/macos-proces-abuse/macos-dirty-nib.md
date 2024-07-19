# macOS Dirty NIB

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

**Za više detalja o tehnici pogledajte originalni post sa: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Evo sažetak:

NIB datoteke, deo Apple-ovog razvojnog ekosistema, namenjene su definisanju **UI elemenata** i njihovim interakcijama u aplikacijama. One obuhvataju serijalizovane objekte kao što su prozori i dugmad, i učitavaju se u vreme izvođenja. I pored njihove stalne upotrebe, Apple sada preporučuje Storyboards za sveobuhvatniju vizualizaciju UI toka.

### Bezbednosne brige sa NIB datotekama
Važno je napomenuti da **NIB datoteke mogu predstavljati bezbednosni rizik**. One imaju potencijal da **izvrše proizvoljne komande**, a izmene u NIB datotekama unutar aplikacije ne sprečavaju Gatekeeper da izvrši aplikaciju, što predstavlja značajnu pretnju.

### Proces injekcije Dirty NIB
#### Kreiranje i postavljanje NIB datoteke
1. **Početna konfiguracija**:
- Kreirajte novu NIB datoteku koristeći XCode.
- Dodajte objekat u interfejs, postavljajući njegovu klasu na `NSAppleScript`.
- Konfigurišite početnu `source` osobinu putem korisnički definisanih runtime atributa.

2. **Gadget za izvršenje koda**:
- Konfiguracija omogućava pokretanje AppleScript-a na zahtev.
- Integrisati dugme za aktiviranje `Apple Script` objekta, posebno pokrećući `executeAndReturnError:` selektor.

3. **Testiranje**:
- Jednostavan Apple Script za testiranje:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Testirajte pokretanjem u XCode debageru i klikom na dugme.

#### Ciljanje aplikacije (Primer: Pages)
1. **Priprema**:
- Kopirajte ciljanju aplikaciju (npr. Pages) u poseban direktorijum (npr. `/tmp/`).
- Pokrenite aplikaciju da biste izbegli probleme sa Gatekeeper-om i keširali je.

2. **Prepisivanje NIB datoteke**:
- Zamenite postojeću NIB datoteku (npr. About Panel NIB) sa kreiranom DirtyNIB datotekom.

3. **Izvršenje**:
- Pokrenite izvršenje interakcijom sa aplikacijom (npr. odabirom `About` menija).

#### Dokaz koncepta: Pristup korisničkim podacima
- Izmenite AppleScript da pristupi i izvuče korisničke podatke, kao što su fotografije, bez pristanka korisnika.

### Uzorak koda: Maliciozna .xib datoteka
- Pristupite i pregledajte [**uzorak maliciozne .xib datoteke**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) koja demonstrira izvršavanje proizvoljnog koda.

### Rešavanje ograničenja pokretanja
- Ograničenja pokretanja sprečavaju izvršavanje aplikacija iz neočekivanih lokacija (npr. `/tmp`).
- Moguće je identifikovati aplikacije koje nisu zaštićene Ograničenjima pokretanja i ciljati ih za injekciju NIB datoteka.

### Dodatne zaštite macOS-a
Od macOS Sonoma nadalje, izmene unutar App bundle-a su ograničene. Međutim, ranije metode su uključivale:
1. Kopiranje aplikacije na drugo mesto (npr. `/tmp/`).
2. Preimenovanje direktorijuma unutar app bundle-a da bi se zaobišle početne zaštite.
3. Nakon pokretanja aplikacije da se registruje sa Gatekeeper-om, izmena app bundle-a (npr. zamena MainMenu.nib sa Dirty.nib).
4. Ponovno preimenovanje direktorijuma i ponovo pokretanje aplikacije da bi se izvršila injektovana NIB datoteka.

**Napomena**: Nedavne ažuriranja macOS-a su ublažila ovu eksploataciju sprečavanjem izmene datoteka unutar app bundle-a nakon keširanja Gatekeeper-a, čime je eksploatacija postala neefikasna.


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
