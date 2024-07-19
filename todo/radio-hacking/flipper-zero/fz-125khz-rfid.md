# FZ - 125kHz RFID

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

Für weitere Informationen darüber, wie 125kHz-Tags funktionieren, siehe:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Aktionen

Für weitere Informationen über diese Arten von Tags [**lies diese Einführung**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lesen

Versucht, die **Karteninformationen zu lesen**. Dann kann sie **emuliert** werden.

{% hint style="warning" %}
Beachte, dass einige Gegensprechanlagen versuchen, sich vor Schlüsselduplikationen zu schützen, indem sie einen Schreibbefehl vor dem Lesen senden. Wenn das Schreiben erfolgreich ist, wird dieses Tag als gefälscht betrachtet. Wenn Flipper RFID emuliert, gibt es keine Möglichkeit für den Leser, es von dem Original zu unterscheiden, sodass keine solchen Probleme auftreten.
{% endhint %}

### Manuell hinzufügen

Du kannst **gefälschte Karten im Flipper Zero erstellen, indem du die Daten** manuell angibst und sie dann emulierst.

#### IDs auf Karten

Manchmal, wenn du eine Karte erhältst, findest du die ID (oder einen Teil davon) auf der Karte sichtbar geschrieben.

* **EM Marin**

Zum Beispiel ist es bei dieser EM-Marin-Karte möglich, die **letzten 3 von 5 Bytes im Klartext zu lesen**.\
Die anderen 2 können brute-forced werden, wenn du sie nicht von der Karte lesen kannst.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Das gleiche passiert bei dieser HID-Karte, wo nur 2 von 3 Bytes auf der Karte gedruckt gefunden werden können.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulieren/Schreiben

Nach dem **Kopieren** einer Karte oder dem **manuellen Eingeben** der ID ist es möglich, sie mit Flipper Zero zu **emulieren** oder sie auf eine echte Karte zu **schreiben**.

## Referenzen

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
