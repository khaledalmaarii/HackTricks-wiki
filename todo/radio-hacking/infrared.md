# Infrarot

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Wie das Infrarot funktioniert <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarotlicht ist für Menschen unsichtbar**. Die IR-Wellenlänge reicht von **0,7 bis 1000 Mikrometer**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometer. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken, wodurch das digitale Signal in ein IR-Signal umgewandelt wird.

Um IR-Signale zu empfangen, wird ein **Fotoreceiver** verwendet. Er **wandelt IR-Licht in Spannungspulse um**, die bereits **digitale Signale** sind. In der Regel gibt es einen **Dunkellichtfilter im Empfänger**, der **nur die gewünschte Wellenlänge durchlässt** und Rauschen herausfiltert.

### Vielfalt der IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:

* Bitkodierung
* Datenstruktur
* Trägerfrequenz — oft im Bereich von 36..38 kHz

#### Bitkodierungsarten <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsabstandskodierung**

Bits werden kodiert, indem die Dauer des Abstands zwischen den Pulsen moduliert wird. Die Breite des Pulses selbst ist konstant.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreitenkodierung**

Bits werden durch Modulation der Pulsbreite kodiert. Die Breite des Abstands nach dem Pulsstoß ist konstant.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phasenkodierung**

Es ist auch als Manchester-Kodierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Pulsstoß und Raum definiert. "Raum zu Pulsstoß" bezeichnet Logik "0", "Pulsstoß zu Raum" bezeichnet Logik "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombination der vorherigen und anderer Exoten**

{% hint style="info" %}
Es gibt IR-Protokolle, die **versuchen, universell** für mehrere Gerätetypen zu werden. Die bekanntesten sind RC5 und NEC. Leider bedeutet das bekannteste **nicht das häufigste**. In meiner Umgebung habe ich nur zwei NEC-Fernbedienungen und keine RC5 gesehen.

Hersteller verwenden gerne ihre eigenen einzigartigen IR-Protokolle, selbst innerhalb derselben Geräteserie (zum Beispiel TV-Boxen). Daher können Fernbedienungen von verschiedenen Unternehmen und manchmal von verschiedenen Modellen desselben Unternehmens nicht mit anderen Geräten desselben Typs arbeiten.
{% endhint %}

### Erforschung eines IR-Signals

Der zuverlässigste Weg, um zu sehen, wie das IR-Signal der Fernbedienung aussieht, ist die Verwendung eines Oszilloskops. Es demoduliert oder invertiert das empfangene Signal nicht, es wird einfach "so wie es ist" angezeigt. Dies ist nützlich für Tests und Debugging. Ich werde das erwartete Signal am Beispiel des NEC-IR-Protokolls zeigen.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

In der Regel gibt es ein Preamble zu Beginn eines kodierten Pakets. Dies ermöglicht es dem Empfänger, den Verstärkungsgrad und den Hintergrund zu bestimmen. Es gibt auch Protokolle ohne Preamble, zum Beispiel Sharp.

Dann werden die Daten übertragen. Die Struktur, das Preamble und die Bitkodierungsmethode werden durch das spezifische Protokoll bestimmt.

**NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholcode, der gesendet wird, solange die Taste gedrückt wird. Sowohl der Befehl als auch der Wiederholcode haben am Anfang dasselbe Preamble.

Der **Befehl** von NEC besteht neben dem Preamble aus einem Adressbyte und einem Befehlsnummernbyte, durch das das Gerät versteht, was ausgeführt werden muss. Adress- und Befehlsnummernbytes werden mit inversen Werten dupliziert, um die Integrität der Übertragung zu überprüfen. Am Ende des Befehls gibt es ein zusätzliches Stoppbit.

Der **Wiederholcode** hat eine "1" nach dem Preamble, was ein Stoppbit ist.

Für **Logik "0" und "1"** verwendet NEC die Pulsabstandskodierung: Zuerst wird ein Pulsstoß übertragen, nach dem eine Pause folgt, deren Länge den Wert des Bits festlegt.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen **übertragen Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie **übertragen auch alle Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass die **Klimaanlage und die Fernbedienung synchronisiert sind**.\
Dies verhindert, dass eine auf 20ºC eingestellte Maschine mit einer Fernbedienung auf 21ºC erhöht wird und dann, wenn eine andere Fernbedienung, die die Temperatur immer noch auf 20ºC hat, verwendet wird, die Temperatur weiter erhöht wird, sie auf 21ºC "erhöht" (und nicht auf 22ºC, weil sie denkt, dass sie auf 21ºC ist).

### Angriffe

Sie können Infrarot mit Flipper Zero angreifen:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
