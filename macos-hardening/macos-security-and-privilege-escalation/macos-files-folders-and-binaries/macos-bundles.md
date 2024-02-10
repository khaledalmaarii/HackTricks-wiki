# macOS Paketi

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

Paketi u macOS-u služe kao kontejneri za različite resurse, uključujući aplikacije, biblioteke i druge neophodne datoteke, čime se prikazuju kao jedinstveni objekti u Finder-u, poput poznatih `*.app` datoteka. Najčešće korišćeni paket je `.app` paket, iako su takođe prisutni i drugi tipovi kao što su `.framework`, `.systemextension` i `.kext`.

### Osnovne komponente paketa

Unutar paketa, posebno unutar direktorijuma `<application>.app/Contents/`, smešteni su različiti važni resursi:

- **_CodeSignature**: Ovaj direktorijum čuva detalje potpisivanja koda koji su vitalni za proveru integriteta aplikacije. Možete pregledati informacije o potpisivanju koda koristeći komande poput:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Sadrži izvršnu binarnu datoteku aplikacije koja se pokreće prilikom interakcije korisnika.
- **Resources**: Repozitorijum za komponente korisničkog interfejsa aplikacije, uključujući slike, dokumente i opise interfejsa (nib/xib datoteke).
- **Info.plist**: Deluje kao glavna konfiguraciona datoteka aplikacije, ključna za sistem da prepozna i interaguje sa aplikacijom na odgovarajući način.

#### Važni ključevi u Info.plist

Datoteka `Info.plist` je osnova za konfiguraciju aplikacije i sadrži ključeve kao što su:

- **CFBundleExecutable**: Određuje ime glavne izvršne datoteke koja se nalazi u direktorijumu `Contents/MacOS`.
- **CFBundleIdentifier**: Pruža globalni identifikator za aplikaciju, koji se široko koristi u macOS-u za upravljanje aplikacijama.
- **LSMinimumSystemVersion**: Označava minimalnu verziju macOS-a potrebnu za pokretanje aplikacije.

### Istraživanje paketa

Da biste istražili sadržaj paketa, poput `Safari.app`, možete koristiti sledeću komandu:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Ovo istraživanje otkriva direktorijume poput `_CodeSignature`, `MacOS`, `Resources`, i datoteke poput `Info.plist`, pri čemu svaki ima jedinstvenu svrhu, od osiguravanja aplikacije do definisanja njenog korisničkog interfejsa i operativnih parametara.

#### Dodatni direktorijumi paketa

Pored uobičajenih direktorijuma, paketi mogu takođe sadržati:

- **Frameworks**: Sadrži uvezene framework-ove koje koristi aplikacija.
- **PlugIns**: Direktorijum za dodatke i ekstenzije koje poboljšavaju mogućnosti aplikacije.
- **XPCServices**: Sadrži XPC servise koje aplikacija koristi za komunikaciju van procesa.

Ova struktura osigurava da su svi neophodni komponenti smeštene unutar paketa, olakšavajući modularno i sigurno okruženje aplikacije.

Za detaljnije informacije o ključevima u `Info.plist` datoteci i njihovom značenju, dokumentacija Apple razvojnog tima pruža obimne resurse: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
