# macOS Keychain

{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks-u</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera za krađu**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Glavni Kešovi

* **Korisnički Keš** (`~/Library/Keychains/login.keycahin-db`), koji se koristi za čuvanje **specifičnih korisničkih podataka** poput lozinki aplikacija, internet lozinki, korisničkih generisanih sertifikata, mrežnih lozinki i korisničkih generisanih javnih/privatnih ključeva.
* **Sistemski Keš** (`/Library/Keychains/System.keychain`), koji čuva **sistemski široke podatke** kao što su WiFi lozinke, sistemski korenski sertifikati, sistemski privatni ključevi i sistemski lozinke aplikacija.

### Pristup Lozinki Keša

Ovi fajlovi, iako nemaju urođenu zaštitu i mogu biti **preuzeti**, su enkriptovani i zahtevaju **korisničku plaintext lozinku za dešifrovanje**. Alat poput [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za dešifrovanje.

## Zaštita Unosa Keša

### ACL-ovi

Svaki unos u kešu upravlja se **Listama Kontrole Pristupa (ACL-ovi)** koji određuju ko može izvršiti različite akcije na unosu keša, uključujući:

* **ACLAuhtorizationExportClear**: Dozvoljava nosiocu da dobije čisti tekst tajne.
* **ACLAuhtorizationExportWrapped**: Dozvoljava nosiocu da dobije šifrovan čisti tekst sa drugom pruženom lozinkom.
* **ACLAuhtorizationAny**: Dozvoljava nosiocu da izvrši bilo koju akciju.

ACL-ovi su dodatno praćeni **listom pouzdanih aplikacija** koje mogu izvršiti ove akcije bez upozorenja. To može biti:

* **N`il`** (nije potrebna autorizacija, **svi su pouzdani**)
* Prazna lista (**niko nije pouzdan**)
* **Lista** specifičnih **aplikacija**.

Takođe, unos može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju **teamid, apple,** i **cdhash.**

* Ako je naveden **teamid**, tada da bi se **pristupio vrednosti unosa** bez **upozorenja**, korišćena aplikacija mora imati **isti teamid**.
* Ako je naveden **apple**, tada aplikacija mora biti **potpisana** od strane **Apple**-a.
* Ako je naveden **cdhash**, tada aplikacija mora imati specifičan **cdhash**.

### Kreiranje Unosa Keša

Kada se **novi** **unos** kreira koristeći **`Keychain Access.app`**, primenjuju se sledeća pravila:

* Sve aplikacije mogu šifrovati.
* **Nijedna aplikacija** ne može izvoziti/dešifrovati (bez upozorenja korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACL-ove.
* **PartitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira unos u kešu**, pravila su malo drugačija:

* Sve aplikacije mogu šifrovati.
* Samo **kreirajuća aplikacija** (ili bilo koje druge aplikacije eksplicitno dodate) mogu izvoziti/dešifrovati (bez upozorenja korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACL-ove.
* **PartitionID** je postavljen na **`teamid:[ovde_teamID]`**.

## Pristup Kešu

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### API-ji

{% hint style="success" %}
**Enumeracija i iskopavanje** tajni **keychain-a** koje **neće generisati upitnik** mogu se obaviti pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lista i dobijanje **informacija** o svakom unosu u keychain:

* API **`SecItemCopyMatching`** pruža informacije o svakom unosu i postoje neki atributi koje možete postaviti prilikom korišćenja:
* **`kSecReturnData`**: Ako je tačno, pokušaće dešifrovati podatke (postavite na lažno da biste izbegli potencijalne iskačuće prozore)
* **`kSecReturnRef`**: Dobijte i referencu na stavku u keychain-u (postavite na tačno u slučaju da kasnije vidite da možete dešifrovati bez iskačućeg prozora)
* **`kSecReturnAttributes`**: Dobijte metapodatke o unosima
* **`kSecMatchLimit`**: Koliko rezultata vratiti
* **`kSecClass`**: Kakav je unos u keychain-u

Dobijanje **ACL-ova** svakog unosa:

* Pomoću API-ja **`SecAccessCopyACLList`** možete dobiti **ACL za stavku u keychain-u**, i vratiće listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti) gde svaka lista ima:
* Opis
* **Lista pouzdanih aplikacija**. To može biti:
* Aplikacija: /Applications/Slack.app
* Binarni fajl: /usr/libexec/airportd
* Grupa: group://AirPort

Izvoz podataka:

* API **`SecKeychainItemCopyContent`** dobija tekstualne podatke
* API **`SecItemExport`** izvozi ključeve i sertifikate ali možda morate postaviti lozinke da biste izvezli sadržaj šifrovan

I ovo su **zahtevi** da biste mogli **izvesti tajnu bez upitnika**:

* Ako je **1+ pouzdanih** aplikacija navedeno:
* Potrebne su odgovarajuće **autorizacije** (**`Nil`**, ili biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup tajnim informacijama)
* Potrebno je da se potpis koda poklapa sa **PartitionID**
* Potreban je potpis koda koji se poklapa sa onim od jedne **pouzdane aplikacije** (ili biti član odgovarajuće KeychainAccessGroup)
* Ako su **sve aplikacije pouzdane**:
* Potrebne su odgovarajuće **autorizacije**
* Potreban je potpis koda koji se poklapa sa **PartitionID**
* Ako nema **PartitionID**, onda ovo nije potrebno

{% hint style="danger" %}
Stoga, ako je navedena **1 aplikacija**, potrebno je **ubaciti kod u tu aplikaciju**.

Ako je **apple** naznačen u **partitionID**, možete pristupiti tome pomoću **`osascript`** tako da sve što veruje svim aplikacijama sa apple u partitionID. **`Python`** takođe može biti korišćen za ovo.
{% endhint %}

### Dva dodatna atributa

* **Nevidljivo**: To je boolean oznaka za **sakrivanje** unosa iz **UI** Keychain aplikacije
* **Opšte**: Služi za čuvanje **metapodataka** (tako da NIJE ŠIFROVANO)
* Microsoft je čuvao sve osvežene tokene za pristup osetljivim krajnjim tačkama u običnom tekstu.

## Reference

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač na **dark vebu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici bili **napadnuti** od **malvera za krađu**.

Primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks-u</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
