# Sub-GHz RF

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

## Garage Doors

Garagentoröffner arbeiten typischerweise im Frequenzbereich von 300-190 MHz, wobei die häufigsten Frequenzen 300 MHz, 310 MHz, 315 MHz und 390 MHz sind. Dieser Frequenzbereich wird häufig für Garagentoröffner verwendet, da er weniger überfüllt ist als andere Frequenzbänder und weniger wahrscheinlich von anderen Geräten gestört wird.

## Car Doors

Die meisten Autoschlüssel-Fobs arbeiten entweder auf **315 MHz oder 433 MHz**. Dies sind beides Funkfrequenzen, die in einer Vielzahl von Anwendungen verwendet werden. Der Hauptunterschied zwischen den beiden Frequenzen besteht darin, dass 433 MHz eine größere Reichweite hat als 315 MHz. Das bedeutet, dass 433 MHz besser für Anwendungen geeignet ist, die eine größere Reichweite erfordern, wie z.B. die Fernbedienung ohne Schlüssel.\
In Europa wird häufig 433,92 MHz verwendet, in den USA und Japan ist es 315 MHz.

## **Brute-force Attack**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Wenn man anstelle von fünfmaligem Senden jedes Codes (so gesendet, um sicherzustellen, dass der Empfänger ihn erhält) nur einmal sendet, wird die Zeit auf 6 Minuten reduziert:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

und wenn du die **2 ms Wartezeit** zwischen den Signalen **entfernst**, kannst du die Zeit auf **3 Minuten reduzieren.**

Darüber hinaus wird durch die Verwendung der De Bruijn-Sequenz (eine Methode zur Reduzierung der Anzahl der benötigten Bits, um alle potenziellen binären Zahlen zu brute-forcen) diese **Zeit auf nur 8 Sekunden reduziert**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Ein Beispiel für diesen Angriff wurde in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) implementiert.

Das Erfordernis eines **Preambels wird die De Bruijn-Sequenz**-Optimierung vermeiden und **rollende Codes werden diesen Angriff verhindern** (vorausgesetzt, der Code ist lang genug, um nicht brute-forcable zu sein).

## Sub-GHz Attack

Um diese Signale mit Flipper Zero anzugreifen, überprüfe:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolling Codes Protection

Automatische Garagentoröffner verwenden typischerweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Funksignal (RF)** an den Garagentoröffner, der den Motor aktiviert, um das Tor zu öffnen oder zu schließen.

Es ist möglich, dass jemand ein Gerät namens Code Grabber verwendet, um das RF-Signal abzufangen und für später zu speichern. Dies wird als **Replay-Angriff** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **rollendes Code**-System bekannt ist.

Das **RF-Signal wird typischerweise mit einem rollenden Code übertragen**, was bedeutet, dass sich der Code bei jeder Verwendung ändert. Dies macht es **schwierig**, dass jemand das Signal **abfängt** und es **verwendet**, um **unbefugten** Zugang zur Garage zu erhalten.

In einem rollenden Code-System haben die Fernbedienung und der Garagentoröffner einen **gemeinsamen Algorithmus**, der **bei jeder Verwendung einen neuen Code generiert**. Der Garagentoröffner reagiert nur auf den **richtigen Code**, was es viel schwieriger macht, unbefugten Zugang zur Garage zu erhalten, nur indem man einen Code abfängt.

### **Missing Link Attack**

Im Grunde hörst du auf den Knopf und **fängst das Signal ab, während die Fernbedienung außerhalb der Reichweite** des Geräts (zum Beispiel des Autos oder der Garage) ist. Dann gehst du zu dem Gerät und **verwendest den abgefangenen Code, um es zu öffnen**.

### Full Link Jamming Attack

Ein Angreifer könnte das Signal in der Nähe des Fahrzeugs oder des Empfängers **stören**, sodass der **Empfänger den Code nicht tatsächlich „hören“ kann**, und sobald das passiert, kannst du einfach den Code **abfangen und wieder abspielen**, wenn du das Stören gestoppt hast.

Das Opfer wird irgendwann die **Schlüssel verwenden, um das Auto abzuschließen**, aber dann wird der Angriff **genug „Tür schließen“-Codes** aufgezeichnet haben, die hoffentlich erneut gesendet werden können, um die Tür zu öffnen (eine **Änderung der Frequenz könnte erforderlich sein**, da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf beide Befehle in unterschiedlichen Frequenzen hören).

{% hint style="warning" %}
**Stören funktioniert**, aber es ist auffällig, denn wenn die **Person, die das Auto abschließt, einfach die Türen testet**, um sicherzustellen, dass sie abgeschlossen sind, würde sie bemerken, dass das Auto nicht abgeschlossen ist. Außerdem, wenn sie sich solcher Angriffe bewusst sind, könnten sie sogar hören, dass die Türen nie das **Geräusch** des Schlosses gemacht haben oder die **Lichter** des Autos nie geflackert haben, als sie den „Schließen“-Knopf drückten.
{% endhint %}

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dies ist eine **stealth Jamming-Technik**. Der Angreifer wird das Signal stören, sodass, wenn das Opfer versucht, die Tür abzuschließen, es nicht funktioniert, aber der Angreifer wird **diesen Code aufzeichnen**. Dann wird das Opfer **versuchen, das Auto erneut abzuschließen**, indem es den Knopf drückt, und das Auto wird **diesen zweiten Code aufzeichnen**.\
Sofort danach kann der **Angreifer den ersten Code senden** und das **Auto wird sich abschließen** (das Opfer wird denken, dass der zweite Druck es geschlossen hat). Dann wird der Angreifer in der Lage sein, den **zweiten gestohlenen Code zu senden, um** das Auto zu öffnen (vorausgesetzt, dass ein **„Auto schließen“-Code auch verwendet werden kann, um es zu öffnen**). Eine Änderung der Frequenz könnte erforderlich sein (da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf beide Befehle in unterschiedlichen Frequenzen hören).

Der Angreifer kann **den Empfänger des Autos stören und nicht seinen eigenen Empfänger**, denn wenn der Empfänger des Autos beispielsweise in einem 1 MHz-Breitband lauscht, wird der Angreifer nicht die genaue Frequenz stören, die von der Fernbedienung verwendet wird, sondern **eine nahe Frequenz in diesem Spektrum**, während der **Empfänger des Angreifers in einem kleineren Bereich lauscht**, wo er das Signal der Fernbedienung **ohne das Störsignal** hören kann.

{% hint style="warning" %}
Andere Implementierungen, die in Spezifikationen gesehen wurden, zeigen, dass der **rollende Code ein Teil** des gesamten gesendeten Codes ist. Das heißt, der gesendete Code ist ein **24-Bit-Schlüssel**, wobei die ersten **12 der rollende Code** sind, die **zweiten 8 der Befehl** (wie abschließen oder öffnen) und die letzten 4 die **Prüfziffer** sind. Fahrzeuge, die diesen Typ implementieren, sind auch natürlich anfällig, da der Angreifer lediglich das Segment des rollenden Codes ersetzen muss, um **jeden rollenden Code auf beiden Frequenzen verwenden zu können**.
{% endhint %}

{% hint style="danger" %}
Beachte, dass, wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten sendet, der erste und der zweite Code ungültig werden.
{% endhint %}

### Alarm Sounding Jamming Attack

Tests gegen ein nachgerüstetes rollendes Codesystem, das in einem Auto installiert ist, **aktivierten das Alarmsystem** und die Wegfahrsperre sofort, als **der gleiche Code zweimal gesendet wurde**, was eine einzigartige **Denial-of-Service**-Möglichkeit bot. Ironischerweise war das Mittel zur **Deaktivierung des Alarms** und der Wegfahrsperre, **die Fernbedienung zu drücken**, was einem Angreifer die Möglichkeit gab, **fortlaufend DoS-Angriffe durchzuführen**. Oder kombiniere diesen Angriff mit dem **vorherigen, um mehr Codes zu erhalten**, da das Opfer den Angriff so schnell wie möglich stoppen möchte.

## References

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

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
