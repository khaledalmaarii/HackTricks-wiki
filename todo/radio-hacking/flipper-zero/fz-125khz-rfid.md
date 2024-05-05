# FZ - 125kHz RFID

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Einführung

Für weitere Informationen darüber, wie 125kHz-Tags funktionieren, siehe:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Aktionen

Für weitere Informationen zu diesen Arten von Tags [**lesen Sie diese Einführung**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Lesen

Versucht, die Karteninformationen **zu lesen**. Dann kann sie **emuliert** werden.

{% hint style="warning" %}
Beachten Sie, dass einige Gegensprechanlagen versuchen, sich vor der Schlüsselreplikation zu schützen, indem sie einen Schreibbefehl vor dem Lesen senden. Wenn das Schreiben erfolgreich ist, wird diese Karte als gefälscht betrachtet. Wenn Flipper RFID emuliert, gibt es für den Leser keine Möglichkeit, es vom Original zu unterscheiden, daher treten solche Probleme nicht auf.
{% endhint %}

### Manuell hinzufügen

Sie können **gefälschte Karten in Flipper Zero erstellen, indem Sie die Daten** manuell angeben und sie dann emulieren.

#### IDs auf Karten

Manchmal, wenn Sie eine Karte erhalten, finden Sie die ID (oder einen Teil davon) auf der Karte sichtbar geschrieben.

* **EM Marin**

Zum Beispiel ist es bei dieser EM-Marin-Karte auf der physischen Karte möglich, **die letzten 3 von 5 Bytes im Klartext zu lesen**.\
Die anderen 2 können durch Brute-Force ermittelt werden, wenn sie nicht von der Karte gelesen werden können.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Das Gleiche passiert bei dieser HID-Karte, bei der nur 2 von 3 Bytes auf der Karte gedruckt zu finden sind

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulieren/Schreiben

Nachdem eine Karte **kopiert** oder die ID **manuell eingegeben** wurde, ist es möglich, sie mit Flipper Zero **zu emulieren** oder sie in eine echte Karte **zu schreiben**.

## Referenzen

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
