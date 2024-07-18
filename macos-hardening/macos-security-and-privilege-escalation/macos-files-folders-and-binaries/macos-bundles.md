# macOS Paketi

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Osnovne Informacije

Paketi u macOS-u služe kao kontejneri za različite resurse uključujući aplikacije, biblioteke i druge neophodne fajlove, čineći ih jedinstvenim objektima u Finder-u, poput poznatih `*.app` fajlova. Najčešće korišćeni paket je `.app` paket, mada su prisutni i drugi tipovi poput `.framework`, `.systemextension` i `.kext`.

### Osnovne Komponente Paketa

Unutar paketa, posebno unutar direktorijuma `<aplikacija>.app/Contents/`, smešteni su različiti važni resursi:

* **\_CodeSignature**: Ovaj direktorijum čuva detalje potpisivanja koda važne za proveru integriteta aplikacije. Možete pregledati informacije o potpisivanju koda koristeći komande poput: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Sadrži izvršni binarni fajl aplikacije koji se pokreće prilikom interakcije korisnika.
* **Resources**: Repozitorijum za komponente korisničkog interfejsa aplikacije uključujući slike, dokumente i opise interfejsa (nib/xib fajlovi).
* **Info.plist**: Deluje kao glavni konfiguracioni fajl aplikacije, od suštinskog značaja za sistem da prepozna i interaguje sa aplikacijom na odgovarajući način.

#### Važni Ključevi u Info.plist

Fajl `Info.plist` je osnova za konfiguraciju aplikacije, sadrži ključeve poput:

* **CFBundleExecutable**: Specificira ime glavnog izvršnog fajla smeštenog u direktorijumu `Contents/MacOS`.
* **CFBundleIdentifier**: Pruža globalni identifikator za aplikaciju, široko korišćen od strane macOS-a za upravljanje aplikacijama.
* **LSMinimumSystemVersion**: Označava minimalnu verziju macOS-a potrebnu za pokretanje aplikacije.

### Istraživanje Paketa

Da biste istražili sadržaj paketa, poput `Safari.app`, možete koristiti sledeću komandu: `bash ls -lR /Applications/Safari.app/Contents`

Ovo istraživanje otkriva direktorijume poput `_CodeSignature`, `MacOS`, `Resources`, i fajlove poput `Info.plist`, svaki sa jedinstvenom svrhom od osiguravanja aplikacije do definisanja njenog korisničkog interfejsa i operativnih parametara.

#### Dodatni Direktorijumi Paketa

Pored uobičajenih direktorijuma, paketi mogu takođe sadržati:

* **Frameworks**: Sadrži uvezene okvire korišćene od strane aplikacije. Okviri su poput dylibs sa dodatnim resursima.
* **PlugIns**: Direktorijum za dodatke i ekstenzije koje poboljšavaju mogućnosti aplikacije.
* **XPCServices**: Drži XPC servise korišćene od strane aplikacije za komunikaciju van procesa.

Ova struktura osigurava da su svi neophodni komponenti zatvoreni unutar paketa, olakšavajući modularno i sigurno okruženje aplikacije.

Za detaljnije informacije o ključevima `Info.plist` i njihovim značenjima, Apple-ova dokumentacija za developere pruža obimne resurse: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
