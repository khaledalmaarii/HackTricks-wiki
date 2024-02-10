# FZ - NFC

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologieinfrastruktur, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Einführung <a href="#9wrzi" id="9wrzi"></a>

Für Informationen über RFID und NFC besuchen Sie die folgende Seite:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Unterstützte NFC-Karten <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Neben NFC-Karten unterstützt Flipper Zero auch **andere Arten von Hochfrequenzkarten** wie mehrere **Mifare** Classic und Ultralight und **NTAG**.
{% endhint %}

Neue Arten von NFC-Karten werden zur Liste der unterstützten Karten hinzugefügt. Flipper Zero unterstützt die folgenden **NFC-Karten des Typs A** (ISO 14443A):

* ﻿**Bankkarten (EMV)** - nur UID, SAK und ATQA lesen, ohne zu speichern.
* ﻿**Unbekannte Karten** - UID, SAK und ATQA lesen und eine UID emulieren.

Für **NFC-Karten des Typs B, Typ F und Typ V** kann Flipper Zero eine UID lesen, ohne sie zu speichern.

### NFC-Karten des Typs A <a href="#uvusf" id="uvusf"></a>

#### Bankkarte (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kann nur eine UID, SAK, ATQA und gespeicherte Daten auf Bankkarten **ohne Speicherung** lesen.

Bildschirm zur BankkartenerkennungFür Bankkarten kann Flipper Zero nur Daten lesen, **ohne sie zu speichern und zu emulieren**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Unbekannte Karten <a href="#37eo8" id="37eo8"></a>

Wenn Flipper Zero den Kartentyp nicht erkennen kann, können nur eine **UID, SAK und ATQA** gelesen und gespeichert werden.

Bildschirm zur Erkennung unbekannter KartenFür unbekannte NFC-Karten kann Flipper Zero nur eine UID emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC-Karten der Typen B, F und V <a href="#wyg51" id="wyg51"></a>

Für **NFC-Karten der Typen B, F und V** kann Flipper Zero nur eine UID lesen und anzeigen, ohne sie zu speichern.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Aktionen

Für eine Einführung in NFC [**lesen Sie diese Seite**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lesen

Flipper Zero kann **NFC-Karten lesen**, versteht jedoch nicht alle Protokolle, die auf ISO 14443 basieren. Da die **UID jedoch ein Attribut auf niedriger Ebene** ist, kann es vorkommen, dass die UID bereits gelesen wurde, aber das Datenübertragungsprotokoll auf hoher Ebene noch unbekannt ist. Sie können die UID mit Flipper für primitive Lesegeräte lesen, die die UID zur Autorisierung verwenden.

#### Lesen der UID vs. Lesen der Daten im Inneren <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Beim Flipper kann das Lesen von 13,56 MHz-Tags in zwei Teile unterteilt werden:

* **Niedrigstufiges Lesen** - liest nur die UID, SAK und ATQA. Flipper versucht, das Protokoll auf hoher Ebene basierend auf diesen Daten zu erraten, die von der Karte gelesen wurden. Sie können sich jedoch nicht zu 100% sicher sein, da es sich nur um eine Annahme basierend auf bestimmten Faktoren handelt.
* **Hochstufiges Lesen** - liest die Daten aus dem Speicher der Karte mit einem bestimmten Protokoll auf hoher Ebene. Dies könnte das Lesen der Daten auf einem Mifare Ultralight, das Lesen der Sektoren auf einem Mifare Classic oder das Lesen der Attribute der Karte von PayPass/Apple Pay sein.

### Spezifisches Lesen

Falls Flipper Zero nicht in der Lage ist, den Kartentyp anhand der Daten auf niedriger Ebene zu erkennen, können Sie in `Zusätzliche Aktionen` die Option `Spezifischen Kartentyp lesen` auswählen und **manuell den gewünschten Kartentyp angeben**, den Sie lesen möchten.
#### EMV Bankkarten (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Neben dem einfachen Lesen der UID können Sie viele weitere Daten von einer Bankkarte extrahieren. Es ist möglich, **die vollständige Kartennummer** (die 16 Ziffern auf der Vorderseite der Karte), das **Gültigkeitsdatum** und in einigen Fällen sogar den **Namen des Eigentümers** zusammen mit einer Liste der **neuesten Transaktionen** zu erhalten.\
Jedoch können Sie auf diese Weise **nicht den CVV-Code lesen** (die 3 Ziffern auf der Rückseite der Karte). Außerdem sind **Bankkarten vor Replay-Angriffen geschützt**, sodass das Kopieren mit Flipper und anschließendes Versuchen, sie zum Bezahlen zu emulieren, nicht funktioniert.

## Referenzen

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF-Download** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
