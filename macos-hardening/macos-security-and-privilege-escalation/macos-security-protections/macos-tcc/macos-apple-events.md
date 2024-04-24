# macOS Apple Events

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

**Apple događaji** su funkcija u Apple-ovom macOS-u koja omogućava aplikacijama da komuniciraju međusobno. Oni su deo **Apple Event Manager-a**, koji je komponenta macOS operativnog sistema odgovorna za upravljanje međuprocesnom komunikacijom. Ovaj sistem omogućava jednoj aplikaciji da pošalje poruku drugoj aplikaciji kako bi zatražila da obavi određenu operaciju, poput otvaranja fajla, dobijanja podataka ili izvršavanja komande.

mina daemon je `/System/Library/CoreServices/appleeventsd` koji registruje servis `com.apple.coreservices.appleevents`.

Svaka aplikacija koja može primati događaje će proveriti sa ovim demonom pružajući svoj Apple Event Mach Port. I kada aplikacija želi da pošalje događaj ka njemu, aplikacija će zatražiti ovaj port od demona.

Aplikacije u pesku zahtevaju privilegije poput `allow appleevent-send` i `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` kako bi mogle slati događaje. Imajte na umu da entitlements poput `com.apple.security.temporary-exception.apple-events` mogu ograničiti ko ima pristup slanju događaja što će zahtevati entitlements poput `com.apple.private.appleevents`.

{% hint style="success" %}
Moguće je koristiti env promenljivu **`AEDebugSends`** kako bi se zabeležile informacije o poslatoj poruci:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
