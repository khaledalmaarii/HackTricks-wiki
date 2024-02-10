# Zloupotreba macOS instalera

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije o Pkg-u

macOS **instalacioni paket** (poznat i kao `.pkg` fajl) je format fajla koji se koristi na macOS-u za **distribuciju softvera**. Ovi fajlovi su poput **kutije koja sadrži sve što je potrebno da se softver instalira i pokrene ispravno**.

Sam paket fajl je arhiva koja sadrži **hijerarhiju fajlova i direktorijuma koji će biti instalirani na ciljnom** računaru. Takođe može uključivati **skripte** koje obavljaju zadatke pre i posle instalacije, poput podešavanja konfiguracionih fajlova ili čišćenja starih verzija softvera.

### Hijerarhija

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Prilagođavanja (naslov, tekst dobrodošlice...) i skripte/provere instalacije
* **PackageInfo (xml)**: Informacije, zahtevi za instalaciju, lokacija instalacije, putanje do skripti koje se izvršavaju
* **Bill of materials (bom)**: Lista fajlova za instalaciju, ažuriranje ili uklanjanje sa dozvolama za fajlove
* **Payload (CPIO arhiva gzip kompresovana)**: Fajlovi za instalaciju na `install-location` iz PackageInfo
* **Skripte (CPIO arhiva gzip kompresovana)**: Pre i post instalacione skripte i dodatni resursi izdvojeni u privremeni direktorijum za izvršavanje.

### Dekompresija
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Osnovne informacije o DMG-u

DMG datoteke, ili Apple Disk Images, su format datoteka koji se koristi u Apple-ovom macOS-u za disk slike. DMG datoteka je suštinski **montabilna disk slika** (sadrži sopstveni fajl sistem) koja sadrži sirove blok podatke obično komprimirane i ponekad šifrovane. Kada otvorite DMG datoteku, macOS je **montira kao da je fizički disk**, omogućavajući vam pristup njenom sadržaju.

### Hijerarhija

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Hijerarhija DMG datoteke može biti različita u zavisnosti od sadržaja. Međutim, za DMG datoteke aplikacija, obično prati ovu strukturu:

* Gornji nivo: Ovo je koren disk slike. Često sadrži aplikaciju i eventualno link ka folderu Aplikacije.
* Aplikacija (.app): Ovo je stvarna aplikacija. U macOS-u, aplikacija je obično paket koji sadrži mnogo pojedinačnih fajlova i foldera koji čine aplikaciju.
* Link ka Aplikacijama: Ovo je prečica ka folderu Aplikacije u macOS-u. Svrha ovoga je da olakša instalaciju aplikacije. Možete prevući .app fajl na ovu prečicu da biste instalirali aplikaciju.

## Eskalacija privilegija putem zloupotrebe pkg-a

### Izvršavanje iz javnih direktorijuma

Ako se skripta za pre ili post instalaciju na primer izvršava iz **`/var/tmp/Installerutil`**, napadač može kontrolisati tu skriptu kako bi eskalirao privilegije kada god se izvrši. Ili drugi sličan primer:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Ovo je [javna funkcija](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) koju nekoliko instalera i ažuriranja poziva da **izvrši nešto kao root**. Ova funkcija prihvata **putanju** **fajla** koji treba **izvršiti** kao parametar, međutim, ako napadač može **izmeniti** ovaj fajl, moći će **zloupotrebiti** njegovo izvršavanje sa privilegijama root-a kako bi eskalirao privilegije.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Za više informacija pogledajte ovaj video: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Izvršavanje putem montiranja

Ako instalater piše u `/tmp/fixedname/bla/bla`, moguće je **kreirati montiranje** preko `/tmp/fixedname` bez vlasnika, tako da možete **izmeniti bilo koji fajl tokom instalacije** kako biste zloupotrebili proces instalacije.

Primer za ovo je **CVE-2021-26089** koji je uspeo da **prepiše periodični skript** kako bi se izvršio kao root. Za više informacija pogledajte video: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kao malver

### Prazan Payload

Moguće je samo generisati **`.pkg`** fajl sa **pre i post-install skriptama** bez ikakvog payloada.

### JS u Distribution xml

Moguće je dodati **`<script>`** tagove u **distribution xml** fajl paketa i taj kod će biti izvršen i može **izvršavati komande** koristeći **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Reference

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
