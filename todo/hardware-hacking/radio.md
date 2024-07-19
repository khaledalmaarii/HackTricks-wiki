# Radio

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

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ist ein kostenloser digitaler Signalanalysator für GNU/Linux und macOS, der entwickelt wurde, um Informationen aus unbekannten Funksignalen zu extrahieren. Er unterstützt eine Vielzahl von SDR-Geräten über SoapySDR und ermöglicht eine anpassbare Demodulation von FSK-, PSK- und ASK-Signalen, dekodiert analoges Video, analysiert burstige Signale und hört analoge Sprachkanäle (alles in Echtzeit).

### Grundkonfiguration

Nach der Installation gibt es einige Dinge, die du in Betracht ziehen könntest zu konfigurieren.\
In den Einstellungen (der zweite Tab-Button) kannst du das **SDR-Gerät** auswählen oder **eine Datei** zum Lesen auswählen und die Frequenz, auf die du syntonisieren möchtest, sowie die Abtastrate (empfohlen bis zu 2,56 Msps, wenn dein PC dies unterstützt)\\

![](<../../.gitbook/assets/image (245).png>)

Im GUI-Verhalten wird empfohlen, einige Dinge zu aktivieren, wenn dein PC dies unterstützt:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
Wenn du feststellst, dass dein PC keine Signale erfasst, versuche, OpenGL zu deaktivieren und die Abtastrate zu senken.
{% endhint %}

### Anwendungen

* Um **einige Zeit eines Signals zu erfassen und zu analysieren**, halte einfach die Taste "Push to capture" so lange gedrückt, wie du benötigst.

![](<../../.gitbook/assets/image (960).png>)

* Der **Tuner** von SigDigger hilft, **bessere Signale zu erfassen** (aber er kann sie auch verschlechtern). Idealerweise starte mit 0 und mache **es größer, bis** du feststellst, dass das **Rauschen**, das eingeführt wird, **größer** ist als die **Verbesserung des Signals**, die du benötigst.

![](<../../.gitbook/assets/image (1099).png>)

### Synchronisieren mit dem Funkkanal

Mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger) synchronisiere dich mit dem Kanal, den du hören möchtest, konfiguriere die Option "Baseband audio preview", konfiguriere die Bandbreite, um alle gesendeten Informationen zu erhalten, und stelle dann den Tuner auf das Niveau ein, bevor das Rauschen wirklich zu steigen beginnt:

![](<../../.gitbook/assets/image (585).png>)

## Interessante Tricks

* Wenn ein Gerät Informationsbursts sendet, ist normalerweise der **erste Teil ein Präambel**, sodass du dir **keine Sorgen machen musst**, wenn du **keine Informationen** darin **findest oder wenn es einige Fehler** gibt.
* In Informationsrahmen solltest du normalerweise **verschiedene Rahmen gut ausgerichtet zueinander finden**:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Nachdem du die Bits wiederhergestellt hast, musst du sie möglicherweise irgendwie verarbeiten**. Zum Beispiel bedeutet in der Manchester-Codierung ein up+down eine 1 oder 0 und ein down+up wird das andere sein. Paare von 1s und 0s (ups und downs) werden eine echte 1 oder eine echte 0 sein.
* Selbst wenn ein Signal die Manchester-Codierung verwendet (es ist unmöglich, mehr als zwei 0s oder 1s hintereinander zu finden), könntest du **mehrere 1s oder 0s zusammen in der Präambel finden**!

### Aufdecken des Modulationstyps mit IQ

Es gibt 3 Möglichkeiten, Informationen in Signalen zu speichern: Modulation der **Amplitude**, **Frequenz** oder **Phase**.\
Wenn du ein Signal überprüfst, gibt es verschiedene Möglichkeiten, um herauszufinden, was verwendet wird, um Informationen zu speichern (finde mehr Möglichkeiten unten), aber eine gute Möglichkeit ist, das IQ-Diagramm zu überprüfen.

![](<../../.gitbook/assets/image (788).png>)

* **AM erkennen**: Wenn im IQ-Diagramm beispielsweise **2 Kreise** erscheinen (wahrscheinlich einer bei 0 und der andere bei einer anderen Amplitude), könnte das bedeuten, dass es sich um ein AM-Signal handelt. Dies liegt daran, dass im IQ-Diagramm der Abstand zwischen 0 und dem Kreis die Amplitude des Signals ist, sodass es einfach ist, verschiedene Amplituden zu visualisieren.
* **PM erkennen**: Wie im vorherigen Bild, wenn du kleine Kreise findest, die nicht miteinander verbunden sind, bedeutet das wahrscheinlich, dass eine Phasenmodulation verwendet wird. Dies liegt daran, dass im IQ-Diagramm der Winkel zwischen dem Punkt und dem 0,0 die Phase des Signals ist, was bedeutet, dass 4 verschiedene Phasen verwendet werden.
* Beachte, dass, wenn die Informationen im Faktum verborgen sind, dass eine Phase geändert wird und nicht in der Phase selbst, du keine klar differenzierten Phasen sehen wirst.
* **FM erkennen**: IQ hat kein Feld zur Identifizierung von Frequenzen (Abstand zum Zentrum ist Amplitude und Winkel ist Phase).\
Daher solltest du zur Identifizierung von FM **grundsätzlich nur einen Kreis** in diesem Diagramm sehen.\
Darüber hinaus wird eine andere Frequenz im IQ-Diagramm durch eine **Geschwindigkeitsbeschleunigung über den Kreis** "repräsentiert" (wenn du in SysDigger das Signal auswählst, wird das IQ-Diagramm gefüllt; wenn du eine Beschleunigung oder Richtungsänderung im erzeugten Kreis findest, könnte das bedeuten, dass es sich um FM handelt):

## AM-Beispiel

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Aufdecken von AM

#### Überprüfen der Hüllkurve

Überprüfe AM-Informationen mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger) und schaue dir einfach die **Hüllkurve** an, du kannst verschiedene klare Amplitudenlevel sehen. Das verwendete Signal sendet Pulse mit Informationen in AM, so sieht ein Puls aus:

![](<../../.gitbook/assets/image (590).png>)

Und so sieht ein Teil des Symbols mit der Wellenform aus:

![](<../../.gitbook/assets/image (734).png>)

#### Überprüfen des Histogramms

Du kannst **das gesamte Signal auswählen**, wo Informationen vorhanden sind, den **Amplitude**-Modus und **Auswahl** auswählen und auf **Histogramm** klicken. Du kannst beobachten, dass nur 2 klare Level gefunden werden

![](<../../.gitbook/assets/image (264).png>)

Wenn du beispielsweise Frequenz anstelle von Amplitude in diesem AM-Signal auswählst, findest du nur 1 Frequenz (keine Möglichkeit, dass Informationen, die in Frequenz moduliert sind, nur 1 Frequenz verwenden).

![](<../../.gitbook/assets/image (732).png>)

Wenn du viele Frequenzen findest, wird es wahrscheinlich kein FM sein; wahrscheinlich wurde die Frequenz des Signals nur aufgrund des Kanals modifiziert.

#### Mit IQ

In diesem Beispiel kannst du sehen, wie es einen **großen Kreis** gibt, aber auch **viele Punkte im Zentrum.**

![](<../../.gitbook/assets/image (222).png>)

### Symbolrate erhalten

#### Mit einem Symbol

Wähle das kleinste Symbol, das du finden kannst (damit du sicher bist, dass es nur 1 ist), und überprüfe die "Auswahlfrequenz". In diesem Fall wäre es 1,013 kHz (also 1 kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Mit einer Gruppe von Symbolen

Du kannst auch die Anzahl der Symbole angeben, die du auswählen möchtest, und SigDigger wird die Frequenz von 1 Symbol berechnen (je mehr ausgewählte Symbole, desto besser wahrscheinlich). In diesem Szenario habe ich 10 Symbole ausgewählt und die "Auswahlfrequenz" beträgt 1,004 kHz:

![](<../../.gitbook/assets/image (1008).png>)

### Bits erhalten

Nachdem du festgestellt hast, dass es sich um ein **AM-moduliertes** Signal handelt und die **Symbolrate** (und weißt, dass in diesem Fall etwas up eine 1 und etwas down eine 0 bedeutet), ist es sehr einfach, die **Bits** zu **erhalten**, die im Signal kodiert sind. Wähle also das Signal mit Informationen aus und konfiguriere die Abtastung und Entscheidung und drücke auf Abtasten (stelle sicher, dass **Amplitude** ausgewählt ist, die entdeckte **Symbolrate** konfiguriert ist und die **Gadner-Taktwiederherstellung** ausgewählt ist):

![](<../../.gitbook/assets/image (965).png>)

* **Sync zu Auswahlintervallen** bedeutet, dass, wenn du zuvor Intervalle ausgewählt hast, um die Symbolrate zu finden, diese Symbolrate verwendet wird.
* **Manuell** bedeutet, dass die angegebene Symbolrate verwendet wird.
* In **Festintervallauswahl** gibst du die Anzahl der Intervalle an, die ausgewählt werden sollen, und es berechnet die Symbolrate daraus.
* **Gadner-Taktwiederherstellung** ist normalerweise die beste Option, aber du musst immer noch eine ungefähre Symbolrate angeben.

Wenn du auf Abtasten drückst, erscheint dies:

![](<../../.gitbook/assets/image (644).png>)

Jetzt, um SigDigger zu verstehen, **wo der Bereich** des Niveaus, das Informationen trägt, ist, musst du auf das **niedrigere Niveau** klicken und gedrückt halten, bis das größte Niveau erreicht ist:

![](<../../.gitbook/assets/image (439).png>)

Wenn es beispielsweise **4 verschiedene Amplitudenlevel** gegeben hätte, müsstest du die **Bits pro Symbol auf 2** konfigurieren und von der kleinsten zur größten auswählen.

Schließlich **erhöhen** des **Zooms** und **Ändern der Zeilenhöhe** kannst du die Bits sehen (und du kannst alles auswählen und kopieren, um alle Bits zu erhalten):

![](<../../.gitbook/assets/image (276).png>)

Wenn das Signal mehr als 1 Bit pro Symbol hat (zum Beispiel 2), hat SigDigger **keine Möglichkeit zu wissen, welches Symbol 00, 01, 10, 11 ist**, also wird es verschiedene **Graustufen** verwenden, um jedes darzustellen (und wenn du die Bits kopierst, wird es **Zahlen von 0 bis 3** verwenden, die du behandeln musst).

Verwende auch **Codierungen** wie **Manchester**, und **up+down** kann **1 oder 0** sein und ein down+up kann eine 1 oder 0 sein. In diesen Fällen musst du die erhaltenen ups (1) und downs (0) behandeln, um die Paare von 01 oder 10 als 0s oder 1s zu ersetzen.

## FM-Beispiel

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Aufdecken von FM

#### Überprüfen der Frequenzen und Wellenform

Signalbeispiel, das Informationen moduliert in FM sendet:

![](<../../.gitbook/assets/image (725).png>)

Im vorherigen Bild kannst du ziemlich gut beobachten, dass **2 Frequenzen verwendet werden**, aber wenn du die **Wellenform** beobachtest, kannst du möglicherweise **die 2 verschiedenen Frequenzen nicht korrekt identifizieren**:

![](<../../.gitbook/assets/image (717).png>)

Das liegt daran, dass ich das Signal in beiden Frequenzen erfasst habe, daher ist eine ungefähr die andere in negativ:

![](<../../.gitbook/assets/image (942).png>)

Wenn die synchronisierte Frequenz **näher an einer Frequenz als an der anderen** ist, kannst du die 2 verschiedenen Frequenzen leicht sehen:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Überprüfen des Histogramms

Wenn du das Frequenzhistogramm des Signals mit Informationen überprüfst, kannst du leicht 2 verschiedene Signale sehen:

![](<../../.gitbook/assets/image (871).png>)

In diesem Fall, wenn du das **Amplitude-Histogramm** überprüfst, wirst du **nur eine Amplitude** finden, also **kann es kein AM sein** (wenn du viele Amplituden findest, könnte es daran liegen, dass das Signal entlang des Kanals an Leistung verloren hat):

![](<../../.gitbook/assets/image (817).png>)

Und dies wäre das Phasenhistogramm (was sehr klar macht, dass das Signal nicht in Phase moduliert ist):

![](<../../.gitbook/assets/image (996).png>)

#### Mit IQ

IQ hat kein Feld zur Identifizierung von Frequenzen (Abstand zum Zentrum ist Amplitude und Winkel ist Phase).\
Daher solltest du zur Identifizierung von FM **grundsätzlich nur einen Kreis** in diesem Diagramm sehen.\
Darüber hinaus wird eine andere Frequenz im IQ-Diagramm durch eine **Geschwindigkeitsbeschleunigung über den Kreis** "repräsentiert" (wenn du in SysDigger das Signal auswählst, wird das IQ-Diagramm gefüllt; wenn du eine Beschleunigung oder Richtungsänderung im erzeugten Kreis findest, könnte das bedeuten, dass es sich um FM handelt):

![](<../../.gitbook/assets/image (81).png>)

### Symbolrate erhalten

Du kannst die **gleiche Technik wie im AM-Beispiel verwenden**, um die Symbolrate zu erhalten, sobald du die Frequenzen gefunden hast, die Symbole tragen.

### Bits erhalten

Du kannst die **gleiche Technik wie im AM-Beispiel verwenden**, um die Bits zu erhalten, sobald du **festgestellt hast, dass das Signal in Frequenz moduliert ist** und die **Symbolrate**.
