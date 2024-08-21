# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je **dark-web** pretraživač koji nudi **besplatne** funkcionalnosti za proveru da li je neka kompanija ili njeni klijenti **kompromitovani** od strane **stealer malvera**.

Njihov primarni cilj je da se bore protiv preuzimanja naloga i ransomware napada koji proizilaze iz malvera koji krade informacije.

Možete proveriti njihovu veb stranicu i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Glavni Keychains

* **User Keychain** (`~/Library/Keychains/login.keycahin-db`), koji se koristi za čuvanje **korisničkih kredencijala** kao što su lozinke za aplikacije, lozinke za internet, korisnički generisani sertifikati, lozinke za mrežu i korisnički generisani javni/privatni ključevi.
* **System Keychain** (`/Library/Keychains/System.keychain`), koji čuva **sistemske kredencijale** kao što su WiFi lozinke, sistemski root sertifikati, sistemski privatni ključevi i lozinke za sistemske aplikacije.

### Pristup Password Keychain-u

Ove datoteke, iako nemaju inherentnu zaštitu i mogu biti **preuzete**, su enkriptovane i zahtevaju **korisničku lozinku u čistom tekstu za dekripciju**. Alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za dekripciju.

## Zaštita Unosa u Keychain

### ACLs

Svaki unos u keychain-u je regulisan **Access Control Lists (ACLs)** koje određuju ko može da izvrši različite radnje na unosu keychain-a, uključujući:

* **ACLAuhtorizationExportClear**: Omogućava nosiocu da dobije čist tekst tajne.
* **ACLAuhtorizationExportWrapped**: Omogućava nosiocu da dobije čist tekst enkriptovan drugom datom lozinkom.
* **ACLAuhtorizationAny**: Omogućava nosiocu da izvrši bilo koju radnju.

ACLs su dodatno praćene **listom pouzdanih aplikacija** koje mogu izvršiti ove radnje bez traženja dozvole. Ovo može biti:

* **N`il`** (nije potrebna autorizacija, **svi su pouzdani**)
* **Prazna** lista (**niko** nije pouzdan)
* **Lista** specifičnih **aplikacija**.

Takođe, unos može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju **teamid, apple,** i **cdhash.**

* Ako je **teamid** specificiran, tada da bi se **pristupilo** vrednosti unosa **bez** **upita**, korišćena aplikacija mora imati **isti teamid**.
* Ako je **apple** specificiran, tada aplikacija mora biti **potpisana** od strane **Apple**.
* Ako je **cdhash** naznačen, tada **aplikacija** mora imati specifični **cdhash**.

### Kreiranje Unosa u Keychain

Kada se **novi** **unos** kreira koristeći **`Keychain Access.app`**, sledeća pravila se primenjuju:

* Sve aplikacije mogu enkriptovati.
* **Nijedna aplikacija** ne može izvesti/dekripovati (bez traženja dozvole od korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACLs.
* **partitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira unos u keychain**, pravila su malo drugačija:

* Sve aplikacije mogu enkriptovati.
* Samo **aplikacija koja kreira** (ili bilo koja druga aplikacija eksplicitno dodata) može izvesti/dekripovati (bez traženja dozvole od korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACLs.
* **partitionID** je postavljen na **`teamid:[teamID ovde]`**.

## Pristupanje Keychain-u

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
**Enumeracija i dumpovanje** tajni koje **neće generisati prompt** može se uraditi pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lista i dobijanje **informacija** o svakom unosu u keychain:

* API **`SecItemCopyMatching`** daje informacije o svakom unosu i postoje neki atributi koje možete postaviti prilikom korišćenja:
* **`kSecReturnData`**: Ako je tačno, pokušaće da dekriptuje podatke (postavite na netačno da biste izbegli potencijalne iskačuće prozore)
* **`kSecReturnRef`**: Takođe dobijate referencu na stavku keychain-a (postavite na tačno u slučaju da kasnije vidite da možete dekriptovati bez iskačućeg prozora)
* **`kSecReturnAttributes`**: Dobijate metapodatke o unosima
* **`kSecMatchLimit`**: Koliko rezultata da se vrati
* **`kSecClass`**: Koja vrsta unosa u keychain

Dobijanje **ACL**-ova svakog unosa:

* Sa API-jem **`SecAccessCopyACLList`** možete dobiti **ACL za stavku keychain-a**, i vratiće listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti) gde svaka lista ima:
* Opis
* **Lista pouzdanih aplikacija**. Ovo može biti:
* Aplikacija: /Applications/Slack.app
* Binarni fajl: /usr/libexec/airportd
* Grupa: group://AirPort

Izvoz podataka:

* API **`SecKeychainItemCopyContent`** dobija plaintext
* API **`SecItemExport`** izvozi ključeve i sertifikate, ali možda će biti potrebno postaviti lozinke za izvoz sadržaja enkriptovanog

I ovo su **zahtevi** da biste mogli da **izvezete tajnu bez prompta**:

* Ako su **1+ pouzdane** aplikacije navedene:
* Potrebne su odgovarajuće **autorizacije** (**`Nil`**, ili biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup tajnim informacijama)
* Potrebna je potpisna šifra koja se poklapa sa **PartitionID**
* Potrebna je potpisna šifra koja se poklapa sa jednom **pouzdanom aplikacijom** (ili biti član pravog KeychainAccessGroup)
* Ako su **sve aplikacije pouzdane**:
* Potrebne su odgovarajuće **autorizacije**
* Potrebna je potpisna šifra koja se poklapa sa **PartitionID**
* Ako **nema PartitionID**, onda ovo nije potrebno

{% hint style="danger" %}
Dakle, ako postoji **1 aplikacija navedena**, potrebno je **ubaciti kod u tu aplikaciju**.

Ako je **apple** naznačen u **partitionID**, mogli biste mu pristupiti pomoću **`osascript`**, tako da bilo šta što veruje svim aplikacijama sa apple u partitionID. **`Python`** se takođe može koristiti za ovo.
{% endhint %}

### Dva dodatna atributa

* **Nevidljivo**: To je boolean zastavica za **sakrivanje** unosa iz **UI** aplikacije Keychain
* **Opšte**: To je za čuvanje **metapodataka** (tako da nije ENKRIPTOVANO)
* Microsoft je čuvao u običnom tekstu sve osvežavajuće tokene za pristup osetljivim krajnjim tačkama.

## Reference

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je **dark-web** pokretan pretraživač koji nudi **besplatne** funkcionalnosti za proveru da li je neka kompanija ili njeni klijenti **kompromitovani** od strane **stealer malvera**.

Njihov primarni cilj WhiteIntel-a je da se bori protiv preuzimanja naloga i ransomware napada koji proizilaze iz malvera koji krade informacije.

Možete proveriti njihovu veb stranicu i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
