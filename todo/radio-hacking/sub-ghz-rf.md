# Sub-GHz RF

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null auf Heldenniveau mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Garagentore

Garagentoröffner arbeiten in der Regel im Frequenzbereich von 300-190 MHz, wobei die häufigsten Frequenzen 300 MHz, 310 MHz, 315 MHz und 390 MHz sind. Dieser Frequenzbereich wird häufig für Garagentoröffner verwendet, da er weniger überfüllt ist als andere Frequenzbänder und weniger wahrscheinlich von anderen Geräten gestört wird.

## Autotüren

Die meisten Autoschlüssel-Fernbedienungen arbeiten entweder mit **315 MHz oder 433 MHz**. Dies sind beide Funkfrequenzen und werden in verschiedenen Anwendungen verwendet. Der Hauptunterschied zwischen den beiden Frequenzen besteht darin, dass 433 MHz eine größere Reichweite als 315 MHz hat. Dies bedeutet, dass 433 MHz besser für Anwendungen geeignet ist, die eine größere Reichweite erfordern, wie z.B. die Fernbedienung für schlüsselloses Öffnen.\
In Europa wird häufig 433,92 MHz verwendet, während es in den USA und Japan 315 MHz ist.

## **Brute-Force-Angriff**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Wenn Sie anstelle des Sendens jedes Codes 5 Mal (um sicherzustellen, dass der Empfänger ihn erhält) ihn nur einmal senden, wird die Zeit auf 6 Minuten reduziert:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Und wenn Sie **die 2 ms Wartezeit** zwischen den Signalen entfernen, können Sie die Zeit auf 3 Minuten reduzieren.

Darüber hinaus wird durch die Verwendung der De-Bruijn-Sequenz (eine Möglichkeit, die Anzahl der benötigten Bits zum Senden aller potenziellen Binärzahlen für den Brute-Force-Angriff zu reduzieren) diese **Zeit auf nur 8 Sekunden reduziert**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Ein Beispiel für diesen Angriff wurde in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) implementiert.

Das **Verwenden einer Präambel verhindert die De-Bruijn-Sequenz**-Optimierung und **Rolling Codes verhindern diesen Angriff** (vorausgesetzt, der Code ist lang genug, um nicht durch Brute-Force geknackt zu werden).

## Sub-GHz-Angriff

Um diese Signale mit Flipper Zero anzugreifen, überprüfen Sie:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolling-Code-Schutz

Automatische Garagentoröffner verwenden in der Regel eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Funksignal (RF-Signal)** an den Garagentoröffner, der den Motor aktiviert, um das Tor zu öffnen oder zu schließen.

Es ist möglich, dass jemand ein Gerät namens Codegrabber verwendet, um das RF-Signal abzufangen und für späteren Gebrauch aufzuzeichnen. Dies wird als **Replay-Angriff** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **Rolling-Code-System** bekannt ist.

Das **RF-Signal wird in der Regel mit einem Rolling-Code übertragen**, was bedeutet, dass der Code bei jeder Verwendung geändert wird. Dies macht es **schwierig** für jemanden, das Signal abzufangen und es zu verwenden, um **unbefugten Zugriff** auf die Garage zu erlangen.

In einem Rolling-Code-System haben die Fernbedienung und der Garagentoröffner einen **gemeinsamen Algorithmus**, der jedes Mal, wenn die Fernbedienung verwendet wird, einen neuen Code generiert. Der Garagentoröffner reagiert nur auf den **richtigen Code**, was es viel schwieriger macht, durch Erfassen eines Codes unbefugten Zugriff auf die Garage zu erlangen.

### **Missing Link-Angriff**

Im Wesentlichen hören Sie auf den Knopf und **zeichnen das Signal auf, während die Fernbedienung außerhalb der Reichweite** des Geräts ist (z.B. das Auto oder die Garage). Dann gehen Sie zum Gerät und **verwenden den aufgezeichneten Code, um es zu öffnen**.

### Full Link Jamming-Angriff

Ein Angreifer könnte das Signal in der Nähe des Fahrzeugs oder des Empfängers **stören**, sodass der **Empfänger den Code nicht tatsächlich "hört"**, und sobald dies geschieht, können Sie einfach den Code **aufzeichnen und wiederholen**, wenn Sie aufgehört haben zu stören.

Das Opfer wird irgendwann die **Tasten verwenden, um das Auto zu verriegeln**, aber dann wird der Angriff genügend "Tür schließen"-Codes aufgezeichnet haben, die hoffentlich erneut gesendet werden können, um die Tür zu öffnen (eine **Änderung der Frequenz könnte erforderlich sein**, da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf verschiedene Befehle in unterschiedlichen Frequenzen hören).

{% hint style="warning" %}
**Jamming funktioniert**, aber es fällt auf, da wenn die **Person, die das Auto verriegelt, einfach die Türen testet**, um sicherzustellen, dass sie verriegelt sind, würde sie bemerken, dass das Auto nicht verriegelt ist. Außerdem könnten sie, wenn sie sich solcher Angriffe bewusst wären, sogar darauf achten, dass die Türen keinen Verriegelungs-**Klang** erzeugen oder die **Lichter** des Autos nicht aufleuchten, wenn sie die "Verriegeln"-Taste drücken.
{% endhint %}

### **Codegrabbing-Angriff (auch "RollJam" genannt)**

Dies ist eine raffiniertere Jamming-Technik. Der Angreifer stört das Signal, sodass das Opfer versucht, die Tür zu verriegeln, aber es nicht funktioniert, aber der Angreifer wird diesen Code **aufzeichnen**. Dann wird das Opfer versuchen, das Auto erneut zu verriegeln, indem es die Taste drückt, und das Auto wird diesen zweiten Code **aufzeichnen**.\
Sofort danach kann der Angreifer den ersten Code **senden** und das Auto wird sich **verriegeln** (das Opfer wird denken, dass der zweite Druck es geschlossen hat). Dann wird der Angreifer in der Lage sein, den zweiten gestohlenen Code zu **senden**, um das Auto zu öffnen (vorausgesetzt, dass ein **"Auto schließen"-Code auch zum Öffnen verwendet werden kann**). Eine Änderung der Frequenz könnte erforderlich sein (da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf verschiedene Befehle in unterschiedlichen Frequenzen hören).

Der Angreifer kann den Empfänger des Autos stören und nicht seinen eigenen Empfänger, da der Empfänger des Autos beispielsweise in einem 1 MHz breiten Frequenzbereich lauscht. Der Angre
### Alarm auslösende Jamming-Attacke

Bei einem Test gegen ein Nachrüst-Rolling-Code-System, das in einem Auto installiert war, wurde festgestellt, dass das **gleiche Code zweimal senden** sofort den Alarm und die Wegfahrsperre **aktiviert** und somit eine einzigartige **Denial-of-Service**-Möglichkeit bietet. Ironischerweise war es möglich, den Alarm und die Wegfahrsperre zu **deaktivieren**, indem man die **Fernbedienung drückt**, was einem Angreifer die Möglichkeit gibt, **kontinuierlich DoS-Angriffe** durchzuführen. Oder man kann diesen Angriff mit dem **vorherigen kombinieren, um mehr Codes zu erhalten**, da das Opfer den Angriff so schnell wie möglich stoppen möchte.

## Referenzen

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
