# Sub-GHz RF

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks in PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Garagentore

Garagentoröffner arbeiten typischerweise im Frequenzbereich von 300-190 MHz, wobei die häufigsten Frequenzen 300 MHz, 310 MHz, 315 MHz und 390 MHz sind. Dieser Frequenzbereich wird häufig für Garagentoröffner verwendet, da er weniger überfüllt ist als andere Frequenzbänder und weniger wahrscheinlich von anderen Geräten gestört wird.

## Autotüren

Die meisten Autoschlüssel-Fernbedienungen arbeiten entweder mit **315 MHz oder 433 MHz**. Dies sind beide Funkfrequenzen, die in verschiedenen Anwendungen verwendet werden. Der Hauptunterschied zwischen den beiden Frequenzen ist, dass 433 MHz eine größere Reichweite als 315 MHz hat. Dies bedeutet, dass 433 MHz besser für Anwendungen geeignet ist, die eine größere Reichweite erfordern, wie z.B. die Fernbedienung ohne Schlüssel.\
In Europa wird häufig 433,92 MHz verwendet, in den USA und Japan sind es 315 MHz.

## **Brute-Force-Angriff**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Wenn anstelle des Sendens jedes Codes 5 Mal (so gesendet, um sicherzustellen, dass der Empfänger ihn erhält) nur einmal gesendet wird, wird die Zeit auf 6 Minuten reduziert:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

und wenn Sie **die 2 ms Wartezeit** zwischen den Signalen **entfernen**, können Sie die Zeit auf **3 Minuten reduzieren**.

Darüber hinaus wird durch die Verwendung der De-Bruijn-Sequenz (eine Möglichkeit, die Anzahl der benötigten Bits zur Übermittlung aller potenziellen binären Zahlen zur Brute-Force-Attacke zu reduzieren) diese **Zeit auf nur 8 Sekunden reduziert**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Ein Beispiel für diesen Angriff wurde in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) implementiert.

Das **Erfordern eines Präambels verhindert die De-Bruijn-Sequenz**-Optimierung und **Rolling Codes verhindern diesen Angriff** (vorausgesetzt, der Code ist lang genug, um nicht durch Brute-Force entschlüsselt zu werden).

## Sub-GHz-Angriff

Um diese Signale mit dem Flipper Zero anzugreifen, überprüfen Sie:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolling-Code-Schutz

Automatische Garagentoröffner verwenden typischerweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Funksignal (RF)** an den Garagentoröffner, der den Motor aktiviert, um das Tor zu öffnen oder zu schließen.

Es ist möglich, dass jemand ein Gerät namens Code-Grabber verwendet, um das RF-Signal abzufangen und für später aufzuzeichnen. Dies wird als **Replay-Angriff** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **Rolling-Code**-System bekannt ist.

Das **RF-Signal wird normalerweise mit einem Rolling-Code** übertragen, was bedeutet, dass der Code bei jeder Verwendung geändert wird. Dies macht es **schwierig** für jemanden, das Signal abzufangen und es zu verwenden, um **unbefugten Zugriff** auf die Garage zu erhalten.

In einem Rolling-Code-System haben die Fernbedienung und der Garagentoröffner einen **gemeinsamen Algorithmus**, der jedes Mal, wenn die Fernbedienung verwendet wird, einen **neuen Code generiert**. Der Garagentoröffner reagiert nur auf den **richtigen Code**, was es viel schwieriger macht, dass jemand durch Erfassen eines Codes unbefugten Zugriff auf die Garage erhält.

### **Missing Link-Angriff**

Im Wesentlichen hören Sie auf den Knopf und **fangen das Signal auf, während die Fernbedienung außerhalb der Reichweite** des Geräts ist (sagen wir das Auto oder die Garage). Dann bewegen Sie sich zum Gerät und **verwenden den aufgezeichneten Code, um es zu öffnen**.

### Vollständiger Link-Jamming-Angriff

Ein Angreifer könnte das Signal in der Nähe des Fahrzeugs oder des Empfängers **stören**, sodass der **Empfänger den Code tatsächlich nicht 'hören' kann**, und sobald dies geschieht, können Sie einfach den Code **aufzeichnen und wiederholen**, wenn Sie mit dem Stören aufgehört haben.

Das Opfer wird irgendwann die **Schlüssel verwenden, um das Auto zu verriegeln**, aber dann wird der Angriff genügend "Tür schließen"-Codes aufgezeichnet haben, die hoffentlich erneut gesendet werden könnten, um die Tür zu öffnen (eine **Änderung der Frequenz könnte erforderlich sein**, da es Autos gibt, die die gleichen Codes zum Öffnen und Schließen verwenden, aber auf verschiedene Befehle in verschiedenen Frequenzen hören).

{% hint style="warning" %}
**Jamming funktioniert**, aber es fällt auf, wenn die **Person, die das Auto verriegelt, einfach die Türen testet**, um sicherzustellen, dass sie verriegelt sind, würde sie bemerken, dass das Auto nicht verriegelt ist. Darüber hinaus könnten sie, wenn sie sich solcher Angriffe bewusst wären, sogar darauf achten, dass die Türen nie das Schlossgeräusch gemacht haben oder die Autoslichter nie geblinkt haben, als sie die 'Verriegeln'-Taste gedrückt haben.
{% endhint %}

### **Code-Grabbing-Angriff (auch 'RollJam' genannt)**

Dies ist eine raffiniertere Jamming-Technik. Der Angreifer wird das Signal stören, sodass, wenn das Opfer versucht, die Tür zu verriegeln, es nicht funktioniert, aber der Angreifer wird diesen Code **aufzeichnen**. Dann wird das Opfer versuchen, das Auto erneut zu verriegeln, indem es die Taste drückt, und das Auto wird diesen zweiten Code **aufzeichnen**.\
Unmittelbar danach kann der **Angreifer den ersten Code senden** und das **Auto wird verriegeln** (das Opfer wird denken, dass der zweite Druck es geschlossen hat). Dann wird der Angreifer in der Lage sein, den zweiten gestohlenen Code zu senden, um das Auto zu öffnen (vorausgesetzt, dass ein **"Auto schließen"-Code auch zum Öffnen verwendet werden kann**). Eine Änderung der Frequenz könnte erforderlich sein (da es Autos gibt, die die gleichen Codes zum Öffnen und Schließen verwenden, aber auf verschiedene Befehle in verschiedenen Frequenzen hören).

Der Angreifer kann **den Empfänger des Autos stören und nicht seinen eigenen Empfänger**, denn wenn der Empfänger des Autos beispielsweise in einem 1-MHz-Breitband lauscht, wird der Angreifer nicht **die genaue Frequenz stören, die vom Fernbedienung verwendet wird, sondern eine nahe in diesem Spektrum**, während der **Empfänger des Angreifers in einem kleineren Bereich lauscht**, in dem er das Fernbedienungssignal **ohne das Störsignal** hören kann.

{% hint style="warning" %}
Andere in Spezifikationen gesehene Implementierungen zeigen, dass der **Rolling-Code ein Teil** des gesendeten Gesamtcodes ist. D.h. der gesendete Code ist ein **24-Bit-Schlüssel**, bei dem die ersten **12 den Rolling-Code**, die **zweiten 8 den Befehl** (wie verriegeln oder entriegeln) und die letzten 4 den **Prüfcode** darstellen. Fahrzeuge, die diesen Typ implementieren, sind ebenfalls anfällig, da der Angreifer lediglich den Rolling-Code-Segment ersetzen muss, um in der Lage zu sein, **jeden Rolling-Code auf beiden Frequenzen zu verwenden**.
{% endhint %}

{% hint style="danger" %}
Beachten Sie, dass, wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten sendet, der erste und zweite Code ungültig werden.
### Alarm auslösen Jamming-Angriff

Beim Testen gegen ein Nachrüst-Rolling-Code-System, das in einem Auto installiert ist, **das Senden des gleichen Codes zweimal** sofort **aktivierte den Alarm** und die Wegfahrsperre und bot eine einzigartige **Denial-of-Service**-Möglichkeit. Ironischerweise war das Mittel, um den Alarm und die Wegfahrsperre zu **deaktivieren**, das **Drücken** der **Fernbedienung**, was einem Angreifer die Möglichkeit gab, **kontinuierlich DoS-Angriffe durchzuführen**. Oder kombinieren Sie diesen Angriff mit dem **vorherigen**, um mehr Codes zu erhalten, da das Opfer den Angriff so schnell wie möglich stoppen möchte.

## Referenzen

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
