# FZ - NFC

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

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Für Informationen über RFID und NFC siehe die folgende Seite:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Unterstützte NFC-Karten <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Neben NFC-Karten unterstützt Flipper Zero **andere Arten von Hochfrequenzkarten**, wie mehrere **Mifare** Classic und Ultralight sowie **NTAG**.
{% endhint %}

Neue Arten von NFC-Karten werden zur Liste der unterstützten Karten hinzugefügt. Flipper Zero unterstützt die folgenden **NFC-Karten Typ A** (ISO 14443A):

* ﻿**Bankkarten (EMV)** — nur UID, SAK und ATQA lesen, ohne zu speichern.
* ﻿**Unbekannte Karten** — (UID, SAK, ATQA) lesen und eine UID emulieren.

Für **NFC-Karten Typ B, Typ F und Typ V** kann Flipper Zero eine UID lesen, ohne sie zu speichern.

### NFC-Karten Typ A <a href="#uvusf" id="uvusf"></a>

#### Bankkarte (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kann nur eine UID, SAK, ATQA und gespeicherte Daten auf Bankkarten **ohne Speicherung** lesen.

Bankkarten-LesebildFür Bankkarten kann Flipper Zero Daten **ohne Speicherung und Emulation** lesen.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Unbekannte Karten <a href="#id-37eo8" id="id-37eo8"></a>

Wenn Flipper Zero **nicht in der Lage ist, den Typ der NFC-Karte zu bestimmen**, können nur eine **UID, SAK und ATQA** **gelesen und gespeichert** werden.

Unbekannte Karten-LesebildFür unbekannte NFC-Karten kann Flipper Zero nur eine UID emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC-Karten Typen B, F und V <a href="#wyg51" id="wyg51"></a>

Für **NFC-Karten Typen B, F und V** kann Flipper Zero nur **eine UID lesen und anzeigen**, ohne sie zu speichern.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Aktionen

Für eine Einführung in NFC [**lies diese Seite**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lesen

Flipper Zero kann **NFC-Karten lesen**, versteht jedoch **nicht alle Protokolle**, die auf ISO 14443 basieren. Da **UID ein Low-Level-Attribut ist**, kann es vorkommen, dass **die UID bereits gelesen wurde, das High-Level-Datenübertragungsprotokoll jedoch noch unbekannt ist**. Du kannst UID mit Flipper für primitive Leser lesen, emulieren und manuell eingeben, die UID zur Autorisierung verwenden.

#### UID lesen VS Daten im Inneren lesen <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Im Flipper kann das Lesen von 13,56 MHz-Tags in zwei Teile unterteilt werden:

* **Low-Level-Lesen** — liest nur die UID, SAK und ATQA. Flipper versucht, das High-Level-Protokoll basierend auf diesen Daten, die von der Karte gelesen wurden, zu erraten. Du kannst dir dabei nicht 100% sicher sein, da es nur eine Annahme basierend auf bestimmten Faktoren ist.
* **High-Level-Lesen** — liest die Daten aus dem Speicher der Karte unter Verwendung eines spezifischen High-Level-Protokolls. Das wäre das Lesen der Daten auf einem Mifare Ultralight, das Lesen der Sektoren von einem Mifare Classic oder das Lesen der Attribute der Karte von PayPass/Apple Pay.

### Spezifisch lesen

Falls Flipper Zero nicht in der Lage ist, den Typ der Karte aus den Low-Level-Daten zu finden, kannst du in `Extra Actions` `Spezifischen Kartentyp lesen` auswählen und **manuell** **den Typ der Karte angeben, die du lesen möchtest**.

#### EMV Bankkarten (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Neben dem einfachen Lesen der UID kannst du viel mehr Daten von einer Bankkarte extrahieren. Es ist möglich, **die vollständige Kartennummer** (die 16 Ziffern auf der Vorderseite der Karte), **Gültigkeitsdatum** und in einigen Fällen sogar den **Namen des Besitzers** zusammen mit einer Liste der **neueste Transaktionen** zu erhalten.\
Allerdings kannst du **den CVV auf diese Weise nicht lesen** (die 3 Ziffern auf der Rückseite der Karte). Außerdem **sind Bankkarten vor Replay-Angriffen geschützt**, sodass das Kopieren mit Flipper und der anschließende Versuch, sie zu emulieren, um für etwas zu bezahlen, nicht funktionieren wird.

## Referenzen

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

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
