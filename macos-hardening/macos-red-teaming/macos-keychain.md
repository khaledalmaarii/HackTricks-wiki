# macOS Keychain

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu podataka**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb stranicu i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## Glavni Keychain-ovi

* **Ključnik korisnika** (`~/Library/Keychains/login.keycahin-db`), koji se koristi za čuvanje **specifičnih za korisnika kredencijala** poput lozinki aplikacija, internet lozinki, korisničkih generisanih sertifikata, mrežnih lozinki i korisničkih generisanih javnih/privatnih ključeva.
* **Sistemski Keychain** (`/Library/Keychains/System.keychain`), koji čuva **sistemski kredencijale** kao što su WiFi lozinke, sistemski root sertifikati, sistemski privatni ključevi i lozinke aplikacija sistema.

### Pristup Lozinki Keychain-a

Ovi fajlovi, iako nemaju urođenu zaštitu i mogu biti **preuzeti**, su enkriptovani i zahtevaju **korisničku plaintext lozinku za dešifrovanje**. Alat poput [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za dešifrovanje.

## Zaštita Unosa u Keychain-u

### ACL-ovi

Svaki unos u keychain-u upravlja se **Access Control Listama (ACL-ovima)** koji određuju ko može izvršiti različite akcije na unosu keychain-a, uključujući:

* **ACLAuhtorizationExportClear**: Dozvoljava nosiocu da dobije čisti tekst tajne.
* **ACLAuhtorizationExportWrapped**: Dozvoljava nosiocu da dobije šifrovan čisti tekst sa drugom pruženom lozinkom.
* **ACLAuhtorizationAny**: Dozvoljava nosiocu da izvrši bilo koju akciju.

ACL-ovi su dodatno praćeni **listom pouzdanih aplikacija** koje mogu izvršiti ove akcije bez upozorenja. To može biti:

* &#x20;**N`il`** (nije potrebna autorizacija, **svi su pouzdani**)
* Prazna lista (**niko nije pouzdan**)
* Lista specifičnih **aplikacija**.

Takođe, unos može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju **teamid, apple,** i **cdhash.**

* Ako je naveden **teamid**, tada da bi se **pristupio vrednosti unosa** bez **upozorenja**, korišćena aplikacija mora imati **isti teamid**.
* Ako je naveden **apple**, tada aplikacija mora biti **potpisana** od strane **Apple-a**.
* Ako je naveden **cdhash**, tada aplikacija mora imati specifičan **cdhash**.

### Kreiranje Unosa u Keychain-u

Kada se **novi** **unos** kreira koristeći **`Keychain Access.app`**, primenjuju se sledeća pravila:

* Sve aplikacije mogu šifrovati.
* **Nijedna aplikacija** ne može izvoziti/dešifrovati (bez upozorenja korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACL-ove.
* **PartitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira unos u keychain-u**, pravila su malo drugačija:

* Sve aplikacije mogu šifrovati.
* Samo **kreirajuća aplikacija** (ili bilo koje druge eksplicitno dodate aplikacije) mogu izvoziti/dešifrovati (bez upozorenja korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACL-ove.
* **PartitionID** je postavljen na **`teamid:[ovde_teamID]`**.

## Pristupanje Keychain-u

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
**Enumeracija i iskopavanje** tajni u **ključnom lancu** koje **neće generisati upit** mogu se obaviti pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lista i dobijanje **informacija** o svakom unosu u ključnom lancu:

* API **`SecItemCopyMatching`** daje informacije o svakom unosu i postoje neki atributi koje možete postaviti prilikom korišćenja:
* **`kSecReturnData`**: Ako je tačno, pokušaće da dešifruje podatke (postavite na lažno da biste izbegli potencijalne iskačuće prozore)
* **`kSecReturnRef`**: Dobijte i referencu na stavku u ključnom lancu (postavite na tačno u slučaju da kasnije vidite da možete dešifrovati bez iskačućeg prozora)
* **`kSecReturnAttributes`**: Dobijte metapodatke o unosima
* **`kSecMatchLimit`**: Koliko rezultata vratiti
* **`kSecClass`**: Kakav je unos u ključnom lancu

Dobijanje **ACL-ova** svakog unosa:

* Pomoću API-ja **`SecAccessCopyACLList`** možete dobiti **ACL za stavku u ključnom lancu**, i vratiće listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti) gde svaka lista ima:
* Opis
* **Lista pouzdanih aplikacija**. Ovo može biti:
* Aplikacija: /Applications/Slack.app
* Binarni fajl: /usr/libexec/airportd
* Grupa: group://AirPort

Izvoz podataka:

* API **`SecKeychainItemCopyContent`** dobija tekstualne podatke
* API **`SecItemExport`** izvozi ključeve i sertifikate ali možda morate postaviti lozinke da biste izvezli sadržaj šifrovan

I ovo su **zahtevi** da biste mogli **izvesti tajnu bez upita**:

* Ako je **1+ pouzdanih** aplikacija navedeno:
* Potrebne su odgovarajuće **autorizacije** (**`Nil`**, ili biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup tajnim informacijama)
* Potrebno je da se potpis koda poklapa sa **PartitionID**
* Potrebno je da se potpis koda poklapa sa potpisom jedne **pouzdane aplikacije** (ili biti član odgovarajuće KeychainAccessGroup)
* Ako su **sve aplikacije pouzdane**:
* Potrebne su odgovarajuće **autorizacije**
* Potrebno je da se potpis koda poklapa sa **PartitionID**
* Ako nema **PartitionID**, onda ovo nije potrebno

{% hint style="danger" %}
Stoga, ako je navedena **1 aplikacija**, potrebno je **ubaciti kod u tu aplikaciju**.

Ako je **apple** naznačen u **partitionID**, možete pristupiti tome pomoću **`osascript`** tako da sve što veruje svim aplikacijama sa apple u partitionID. **`Python`** takođe može biti korišćen za ovo.
{% endhint %}

### Dva dodatna atributa

* **Nevidljivo**: To je boolean zastava za **sakrivanje** unosa iz **UI** Keychain aplikacije
* **Opšte**: Služi za čuvanje **metapodataka** (tako da NIJE ŠIFROVANO)
* Microsoft je čuvao sve osvežene tokene za pristup osetljivim krajnjim tačkama u običnom tekstu.

## Reference

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač na **dark vebu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici bili **napadnuti** od strane **malvera koji krade podatke**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
