# macOS Aplikacije za obradu ekstenzija datoteka i URL šema

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Baza podataka LaunchServices

Ovo je baza podataka svih instaliranih aplikacija u macOS-u koja se može upitati kako bi se dobile informacije o svakoj instaliranoj aplikaciji, kao što su URL šeme koje podržava i MIME tipovi.

Moguće je izbaciti ovu bazu podataka sa:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

Ili korišćenjem alata [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** je mozak baze podataka. Pruža **nekoliko XPC usluga** poput `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, i više. Ali takođe **zahteva određene privilegije** aplikacijama da bi mogle koristiti izložene XPC funkcionalnosti, poput `.launchservices.changedefaulthandler` ili `.launchservices.changeurlschemehandler` za promenu podrazumevanih aplikacija za mime tipove ili URL šeme i drugo.

**`/System/Library/CoreServices/launchservicesd`** zahteva uslugu `com.apple.coreservices.launchservicesd` i može se ispitati radi dobijanja informacija o pokrenutim aplikacijama. Može se ispitati sistemskim alatom /**`usr/bin/lsappinfo`** ili sa [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Aplikacije za rukovanje ekstenzijama fajlova i URL šemama

Sledeća linija može biti korisna za pronalaženje aplikacija koje mogu otvoriti fajlove u zavisnosti od ekstenzije:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

Ili koristite nešto poput [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Možete takođe proveriti ekstenzije podržane od strane aplikacije koristeći:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks obuka AWS Red Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks obuka GCP Red Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
