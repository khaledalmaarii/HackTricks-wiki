# macOS Apple Events

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

## Basic Information

**Apple Events** su funkcija u Apple-ovom macOS-u koja omogućava aplikacijama da komuniciraju jedna s drugom. One su deo **Apple Event Manager-a**, koji je komponenta macOS operativnog sistema odgovorna za upravljanje međuprocesnom komunikacijom. Ovaj sistem omogućava jednoj aplikaciji da pošalje poruku drugoj aplikaciji da zatraži da izvrši određenu operaciju, kao što je otvaranje datoteke, preuzimanje podataka ili izvršavanje komande.

Mina daemon je `/System/Library/CoreServices/appleeventsd` koji registruje servis `com.apple.coreservices.appleevents`.

Svaka aplikacija koja može primati događaje će se proveravati sa ovim daemon-om pružajući svoj Apple Event Mach Port. A kada aplikacija želi da pošalje događaj, aplikacija će zatražiti ovaj port od daemona.

Sandboxed aplikacije zahtevaju privilegije kao što su `allow appleevent-send` i `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` kako bi mogle slati događaje. Napomena da entitlements kao što su `com.apple.security.temporary-exception.apple-events` mogu ograničiti ko ima pristup slanju događaja, što će zahtevati entitlements kao što su `com.apple.private.appleevents`.

{% hint style="success" %}
It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
