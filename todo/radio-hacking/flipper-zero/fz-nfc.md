# FZ - NFC

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>

## Einführung <a href="#id-9wrzi" id="id-9wrzi"></a>

Für Informationen zu RFID und NFC besuchen Sie die folgende Seite:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Unterstützte NFC-Karten <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Neben NFC-Karten unterstützt Flipper Zero auch **andere Arten von Hochfrequenzkarten** wie verschiedene **Mifare** Classic und Ultralight und **NTAG**.
{% endhint %}

Neue Arten von NFC-Karten werden zur Liste der unterstützten Karten hinzugefügt. Flipper Zero unterstützt die folgenden **NFC-Karten Typ A** (ISO 14443A):

* **Bankkarten (EMV)** — nur UID, SAK und ATQA lesen, ohne zu speichern.
* **Unbekannte Karten** — lesen (UID, SAK, ATQA) und emulieren eine UID.

Für **NFC-Karten Typ B, Typ F und Typ V** kann Flipper Zero eine UID lesen, ohne sie zu speichern.

### NFC-Karten Typ A <a href="#uvusf" id="uvusf"></a>

#### Bankkarte (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero kann nur eine UID, SAK, ATQA und gespeicherte Daten auf Bankkarten **ohne Speicherung** lesen.

Bildschirm zur BankkartenerfassungFür Bankkarten kann Flipper Zero nur Daten lesen **ohne sie zu speichern und zu emulieren**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Unbekannte Karten <a href="#id-37eo8" id="id-37eo8"></a>

Wenn Flipper Zero den **Kartentyp der NFC-Karte nicht bestimmen kann**, können nur eine **UID, SAK und ATQA** gelesen und gespeichert werden.

Bildschirm zur Erfassung unbekannter KartenFür unbekannte NFC-Karten kann Flipper Zero nur eine UID emulieren.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC-Karten Typen B, F und V <a href="#wyg51" id="wyg51"></a>

Für **NFC-Karten der Typen B, F und V** kann Flipper Zero nur eine **UID lesen und anzeigen**, ohne sie zu speichern.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Aktionen

Für eine Einführung in NFC [**lesen Sie diese Seite**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Lesen

Flipper Zero kann **NFC-Karten lesen**, versteht jedoch **nicht alle Protokolle**, die auf ISO 14443 basieren. Da jedoch die **UID ein Attribut auf niedriger Ebene** ist, könnten Sie in einer Situation sein, in der die **UID bereits gelesen wurde, das Hochgeschwindigkeitsdatenübertragungsprotokoll jedoch noch unbekannt ist**. Sie können die UID mit Flipper für primitive Lesegeräte lesen, emulieren und manuell eingeben, die die UID zur Autorisierung verwenden.

#### Lesen der UID VS Lesen der Daten im Inneren <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Beim Lesen von 13,56 MHz-Tags in Flipper kann in zwei Teile unterteilt werden:

* **Niedrigpegel-Lesen** — liest nur die UID, SAK und ATQA. Flipper versucht, das Hochgeschwindigkeitsprotokoll basierend auf diesen Daten zu erraten, die von der Karte gelesen wurden. Sie können sich nicht zu 100 % sicher sein, da es nur eine Annahme aufgrund bestimmter Faktoren ist.
* **Hochpegel-Lesen** — liest die Daten aus dem Speicher der Karte mit einem spezifischen Hochgeschwindigkeitsprotokoll. Das wäre das Lesen der Daten auf einem Mifare Ultralight, das Lesen der Sektoren eines Mifare Classic oder das Lesen der Kartenattribute von PayPass/Apple Pay.

### Spezifisches Lesen

Falls Flipper Zero nicht in der Lage ist, den Kartentyp aus den Daten auf niedriger Ebene zu ermitteln, können Sie in `Zusätzliche Aktionen` die Option `Spezifischen Kartentyp lesen` auswählen und **manuell** **den Kartentyp angeben, den Sie lesen möchten**.

#### EMV-Bankkarten (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Neben dem einfachen Lesen der UID können Sie viele weitere Daten von einer Bankkarte extrahieren. Es ist möglich, die **vollständige Kartennummer** (die 16 Ziffern auf der Vorderseite der Karte), das **Ablaufdatum** und in einigen Fällen sogar den **Namen des Besitzers** zusammen mit einer Liste der **letzten Transaktionen** zu erhalten.\
Sie **können jedoch nicht auf diese Weise den CVV lesen** (die 3 Ziffern auf der Rückseite der Karte). Außerdem sind **Bankkarten vor Wiederholungsangriffen geschützt**, sodass das Kopieren mit Flipper und anschließende Versuch, sie zu emulieren, um etwas zu bezahlen, nicht funktionieren wird.
## Referenzen

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
