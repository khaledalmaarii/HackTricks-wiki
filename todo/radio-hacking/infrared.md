# Infrarot

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Wie Infrarot funktioniert <a href="#wie-der-infrarot-port-funktioniert" id="wie-der-infrarot-port-funktioniert"></a>

**Infrarotes Licht ist für Menschen unsichtbar**. Die IR-Wellenlänge liegt zwischen **0,7 und 1000 Mikrometern**. Haushaltsfernbedienungen verwenden ein IR-Signal zur Datenübertragung und arbeiten im Wellenlängenbereich von 0,75..1,4 Mikrometern. Ein Mikrocontroller in der Fernbedienung lässt eine Infrarot-LED mit einer bestimmten Frequenz blinken und wandelt das digitale Signal in ein IR-Signal um.

Zur Empfang von IR-Signalen wird ein **Fotoreceiver** verwendet. Er **wandelt das IR-Licht in Spannungsimpulse um**, die bereits **digitale Signale** sind. In der Regel befindet sich ein **Dunkellichtfilter im Empfänger**, der nur die gewünschte Wellenlänge durchlässt und Störungen herausfiltert.

### Verschiedene IR-Protokolle <a href="#verschiedene-ir-protokolle" id="verschiedene-ir-protokolle"></a>

IR-Protokolle unterscheiden sich in 3 Faktoren:

* Bit-Codierung
* Datenstruktur
* Trägerfrequenz - oft im Bereich von 36..38 kHz

#### Arten der Bit-Codierung <a href="#arten-der-bit-codierung" id="arten-der-bit-codierung"></a>

**1. Pulsabstandscodierung**

Bits werden durch Modulation der Dauer des Abstands zwischen den Impulsen codiert. Die Breite des Impulses selbst ist konstant.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreitencodierung**

Bits werden durch Modulation der Impulsbreite codiert. Die Breite des Abstands nach dem Impulsburst ist konstant.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Phasencodierung**

Es ist auch als Manchester-Codierung bekannt. Der logische Wert wird durch die Polarität des Übergangs zwischen Impulsburst und Abstand definiert. "Abstand zu Impulsburst" bedeutet logisch "0", "Impulsburst zu Abstand" bedeutet logisch "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Kombination aus den vorherigen und anderen Exoten**

{% hint style="info" %}
Es gibt IR-Protokolle, die **versuchen, universell** für mehrere Arten von Geräten zu sein. Die bekanntesten sind RC5 und NEC. Leider bedeutet "am bekanntesten" nicht unbedingt "am häufigsten". In meiner Umgebung habe ich nur zwei NEC-Fernbedienungen und keine RC5-Fernbedienungen gesehen.

Hersteller verwenden gerne ihre eigenen einzigartigen IR-Protokolle, selbst innerhalb derselben Gerätekategorie (z. B. TV-Boxen). Daher können Fernbedienungen von verschiedenen Unternehmen und manchmal von verschiedenen Modellen desselben Unternehmens nicht mit anderen Geräten derselben Art zusammenarbeiten.
{% endhint %}

### Untersuchung eines IR-Signals

Der zuverlässigste Weg, um zu sehen, wie das IR-Signal der Fernbedienung aussieht, besteht darin, ein Oszilloskop zu verwenden. Es demoduliert oder invertiert das empfangene Signal nicht, sondern zeigt es einfach "wie es ist" an. Dies ist nützlich für Tests und Debugging. Ich werde das erwartete Signal am Beispiel des NEC-IR-Protokolls zeigen.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Normalerweise gibt es am Anfang eines codierten Pakets eine Präambel. Dadurch kann der Empfänger den Verstärkungspegel und den Hintergrund bestimmen. Es gibt auch Protokolle ohne Präambel, zum Beispiel Sharp.

Dann werden Daten übertragen. Die Struktur, die Präambel und die Art der Bit-Codierung werden durch das spezifische Protokoll bestimmt.

Das **NEC-IR-Protokoll** enthält einen kurzen Befehl und einen Wiederholungscode, der gesendet wird, während die Taste gedrückt wird. Sowohl der Befehl als auch der Wiederholungscode haben dieselbe Präambel am Anfang.

Der **Befehl** von NEC besteht neben der Präambel aus einem Adressbyte und einem Befehlsnummernbyte, anhand dessen das Gerät versteht, was ausgeführt werden soll. Adress- und Befehlsnummernbytes werden mit inversen Werten dupliziert, um die Integrität der Übertragung zu überprüfen. Am Ende des Befehls befindet sich ein zusätzliches Stoppbit.

Der **Wiederholungscode** hat nach der Präambel eine "1", die ein Stoppbit ist.

Für die Logik "0" und "1" verwendet NEC die Pulsabstandscodierung: Zuerst wird ein Impulsburst übertragen, danach folgt eine Pause, deren Länge den Wert des Bits festlegt.

### Klimaanlagen

Im Gegensatz zu anderen Fernbedienungen übertragen **Klimaanlagen nicht nur den Code der gedrückten Taste**. Sie übertragen auch **alle Informationen**, wenn eine Taste gedrückt wird, um sicherzustellen, dass die **Klimaanlage und die Fernbedienung synchronisiert** sind.\
Dadurch wird vermieden, dass eine Maschine, die auf 20ºC eingestellt ist, mit einer Fernbedienung auf 21ºC erhöht wird und dann, wenn eine andere Fernbedienung verwendet wird, die die Temperatur noch auf 20ºC hat, die Temperatur weiter erhöht wird und auf 21ºC "erhöht" wird (und nicht auf 22ºC, weil sie denkt, dass sie sich bereits auf 21ºC befindet).

### Angriffe

Sie können Infrarot mit Flipper Zero angreifen:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder
