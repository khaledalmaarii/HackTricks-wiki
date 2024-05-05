# Infrarot

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Funktionsweise des Infrarots <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge liegt zwischen **0,7 und 1000 Mikrometern**. Haushaltsfernbedienungen verwenden ein IR-Signal für die Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometern. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer spezifischen Frequenz blinken, wodurch das digitale Signal in ein IR-Signal umgewandelt wird.

Zur Empfang von IR-Signalen wird ein **Fotoreceiver** verwendet. Er **wandelt IR-Licht in Spannungsimpulse um**, die bereits **digitale Signale** sind. Normalerweise gibt es einen **Dunkellichtfilter im Empfänger**, der **nur die gewünschte Wellenlänge durchlässt** und Störungen herausfiltert.

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:

* Bit-Codierung
* Datenstruktur
* Trägerfrequenz — oft im Bereich von 36..38 kHz

#### Arten der Bit-Codierung <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsabstandscodierung**

Bits werden codiert, indem die Dauer des Abstands zwischen den Impulsen moduliert wird. Die Breite des Impulses selbst ist konstant.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreitencodierung**

Bits werden durch Modulation der Pulsbreite codiert. Die Breite des Abstands nach dem Impulsstoß ist konstant.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phasencodierung**

Es ist auch als Manchester-Codierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Impulsstoß und Abstand definiert. "Abstand zu Impulsstoß" bedeutet logisch "0", "Impulsstoß zu Abstand" bedeutet logisch "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen und anderer Exoten**

{% hint style="info" %}
Es gibt IR-Protokolle, die **versuchen, universell** für mehrere Arten von Geräten zu werden. Die bekanntesten sind RC5 und NEC. Leider bedeutet der bekannteste **nicht unbedingt der häufigste**. In meiner Umgebung habe ich nur zwei NEC-Fernbedienungen und keine RC5-Fernbedienungen getroffen.

Hersteller verwenden gerne ihre eigenen einzigartigen IR-Protokolle, selbst innerhalb desselben Gerätebereichs (zum Beispiel TV-Boxen). Daher können Fernbedienungen verschiedener Unternehmen und manchmal verschiedener Modelle desselben Unternehmens nicht mit anderen Geräten desselben Typs arbeiten.
{% endhint %}

### Erkunden eines IR-Signals

Der zuverlässigste Weg, um zu sehen, wie das IR-Signal der Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, sondern zeigt es "wie es ist" an. Dies ist nützlich für Tests und Debugging. Ich werde das erwartete Signal am Beispiel des NEC-IR-Protokolls zeigen.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Normalerweise gibt es am Anfang eines codierten Pakets eine Präambel. Dies ermöglicht es dem Empfänger, den Verstärkungspegel und den Hintergrund zu bestimmen. Es gibt auch Protokolle ohne Präambel, zum Beispiel Sharp.

Dann werden Daten übertragen. Die Struktur, die Präambel und die Bit-Codierungsmethode werden durch das spezifische Protokoll bestimmt.

Das **NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholungscode, der gesendet wird, während die Taste gedrückt wird. Sowohl der Befehl als auch der Wiederholungscode haben am Anfang dieselbe Präambel.

Der **Befehl** von NEC besteht neben der Präambel aus einem Adressbyte und einem Befehlsnummernbyte, anhand dessen das Gerät versteht, was ausgeführt werden muss. Adress- und Befehlsnummernbytes werden mit inversen Werten dupliziert, um die Integrität der Übertragung zu überprüfen. Am Ende des Befehls gibt es ein zusätzliches Stoppbit.

Der **Wiederholungscode** hat nach der Präambel eine "1", die ein Stoppbit ist.

Für **Logik "0" und "1"** verwendet NEC die Pulsabstandscodierung: Zuerst wird ein Impulsstoß übertragen, nach dem eine Pause folgt, deren Länge den Wert des Bits festlegt.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen **übertragen Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen auch alle Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass die **Klimaanlage und die Fernbedienung synchronisiert sind**.\
Dadurch wird vermieden, dass eine Maschine, die auf 20ºC eingestellt ist, mit einer Fernbedienung auf 21ºC erhöht wird und dann, wenn eine andere Fernbedienung, die die Temperatur noch auf 20ºC hat, verwendet wird, um die Temperatur weiter zu erhöhen, sie auf 21ºC "erhöht" (und nicht auf 22ºC, weil sie denkt, dass sie sich bereits auf 21ºC befindet).

### Angriffe

Sie können Infrarot mit Flipper Zero angreifen:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/) 

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
