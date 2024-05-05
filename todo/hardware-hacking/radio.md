# Radio

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ist ein kostenloser digitaler Signalanalysator für GNU/Linux und macOS, der entwickelt wurde, um Informationen unbekannter Funksignale zu extrahieren. Es unterstützt eine Vielzahl von SDR-Geräten über SoapySDR und ermöglicht die einstellbare Demodulation von FSK-, PSK- und ASK-Signalen, die Decodierung von Analogvideos, die Analyse von Burst-Signalen und das Abhören von analogen Sprachkanälen (alles in Echtzeit).

### Grundkonfiguration

Nach der Installation gibt es einige Dinge, die Sie in Betracht ziehen könnten zu konfigurieren.\
In den Einstellungen (die zweite Registerkarte) können Sie das **SDR-Gerät** auswählen oder eine Datei zum Lesen auswählen und die Frequenz zum Syntonisieren sowie die Abtastrate (empfohlen bis zu 2,56 Msps, wenn Ihr PC dies unterstützt)\\

![](<../../.gitbook/assets/image (245).png>)

In der GUI-Verhaltensweise wird empfohlen, einige Dinge zu aktivieren, wenn Ihr PC dies unterstützt:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
Wenn Sie feststellen, dass Ihr PC keine Signale erfasst, versuchen Sie, OpenGL zu deaktivieren und die Abtastrate zu verringern.
{% endhint %}

### Verwendungen

* Um einfach **eine Signalzeit zu erfassen und zu analysieren**, halten Sie einfach die Schaltfläche "Zum Erfassen drücken" so lange gedrückt, wie Sie benötigen.

![](<../../.gitbook/assets/image (960).png>)

* Der **Tuner** von SigDigger hilft dabei, **bessere Signale zu erfassen** (kann sie aber auch verschlechtern). Beginnen Sie idealerweise mit 0 und machen Sie ihn **größer, bis** Sie feststellen, dass das **Rauschen** größer ist als die **Verbesserung des Signals**, die Sie benötigen).

![](<../../.gitbook/assets/image (1099).png>)

### Synchronisieren mit dem Radiokanal

Mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger) synchronisieren Sie mit dem Kanal, den Sie hören möchten, konfigurieren die Option "Baseband-Audiopreview", konfigurieren die Bandbreite, um alle gesendeten Informationen zu erhalten, und stellen dann den Tuner auf das Niveau ein, bevor das Rauschen wirklich zu zunehmen beginnt:

![](<../../.gitbook/assets/image (585).png>)

## Interessante Tricks

* Wenn ein Gerät Bursts von Informationen sendet, ist der **erste Teil in der Regel ein Präambel**, sodass Sie sich keine Sorgen machen müssen, wenn Sie dort keine Informationen finden oder wenn Fehler auftreten.
* In Informationsrahmen sollten Sie normalerweise **verschiedene gut ausgerichtete Rahmen zwischen ihnen finden**:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Nachdem Sie die Bits wiederhergestellt haben, müssen Sie sie möglicherweise auf irgendeine Weise verarbeiten**. Zum Beispiel wird bei der Manchester-Codierung ein Auf+Ab ein 1 oder 0 sein und ein Ab+Auf wird der andere sein. Paare von 1en und 0en (Aufs und Abs) werden also eine echte 1 oder eine echte 0 sein.
* Selbst wenn ein Signal die Manchester-Codierung verwendet (es ist unmöglich, mehr als zwei 0en oder 1en hintereinander zu finden), könnten Sie **mehrere 1en oder 0en hintereinander in der Präambel finden**!

### Modulationstyp mit IQ aufdecken

Es gibt 3 Möglichkeiten, Informationen in Signalen zu speichern: Modulation der **Amplitude**, **Frequenz** oder **Phase**.\
Wenn Sie ein Signal überprüfen, gibt es verschiedene Möglichkeiten, um herauszufinden, welche Methode zur Speicherung von Informationen verwendet wird (weitere Möglichkeiten finden Sie unten), aber eine gute Methode besteht darin, das IQ-Diagramm zu überprüfen.

![](<../../.gitbook/assets/image (788).png>)

* **AM erkennen**: Wenn im IQ-Diagramm beispielsweise **2 Kreise** erscheinen (wahrscheinlich einer bei 0 und der andere bei einer anderen Amplitude), könnte dies bedeuten, dass es sich um ein AM-Signal handelt. Dies liegt daran, dass im IQ-Diagramm der Abstand zwischen der 0 und dem Kreis die Amplitude des Signals ist, sodass verschiedene Amplituden leicht visualisiert werden können.
* **PM erkennen**: Wie im vorherigen Bild, wenn Sie kleine Kreise finden, die nicht miteinander zusammenhängen, bedeutet dies wahrscheinlich, dass eine Phasenmodulation verwendet wird. Dies liegt daran, dass im IQ-Diagramm der Winkel zwischen dem Punkt und der 0,0 die Phase des Signals ist, was bedeutet, dass 4 verschiedene Phasen verwendet werden.
* Beachten Sie, dass, wenn die Information darin besteht, dass eine Phase geändert wird und nicht in der Phase selbst, Sie verschiedene Phasen nicht klar differenzieren werden.
* **FM erkennen**: IQ hat kein Feld, um Frequenzen zu identifizieren (Abstand zum Zentrum ist Amplitude und der Winkel ist Phase).\
Um FM zu identifizieren, sollten Sie in diesem Diagramm **im Wesentlichen nur einen Kreis** sehen.\
Darüber hinaus wird eine andere Frequenz im IQ-Diagramm durch eine **Beschleunigung über den Kreis hinweg "dargestellt"** (also in SysDigger, wenn Sie das Signal auswählen, wird das IQ-Diagramm ausgefüllt, wenn Sie eine Beschleunigung oder eine Richtungsänderung im erstellten Kreis finden, könnte dies bedeuten, dass es sich um FM handelt):

## AM-Beispiel

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM aufdecken

#### Überprüfen der Hülle

Überprüfen Sie AM-Informationen mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger)und betrachten Sie einfach die **Hülle**, um verschiedene klare Amplitudenstufen zu sehen. Das verwendete Signal sendet Impulse mit Informationen in AM, so sieht ein Impuls aus:

![](<../../.gitbook/assets/image (590).png>)

Und so sieht ein Teil des Symbols mit der Wellenform aus:

![](<../../.gitbook/assets/image (734).png>)

#### Überprüfen des Histogramms

Sie können das **gesamte Signal** dort auswählen, wo sich die Informationen befinden, den **Amplituden**-Modus auswählen und **Auswahl** und auf **Histogramm** klicken. Sie können feststellen, dass nur 2 klare Pegel gefunden werden

![](<../../.gitbook/assets/image (264).png>)

Wenn Sie beispielsweise anstelle von Amplitude in diesem AM-Signal die Frequenz auswählen, finden Sie nur 1 Frequenz (keine Möglichkeit, dass Informationen in der Frequenz moduliert werden, wenn nur 1 Frequenz verwendet wird).

![](<../../.gitbook/assets/image (732).png>)

Wenn Sie viele Frequenzen finden, handelt es sich wahrscheinlich nicht um FM, wahrscheinlich wurde die Signal-Frequenz nur aufgrund des Kanals geändert.
#### Mit IQ

In diesem Beispiel können Sie sehen, wie es einen **großen Kreis** gibt, aber auch **viele Punkte im Zentrum**.

![](<../../.gitbook/assets/image (222).png>)

### Symbolrate erhalten

#### Mit einem Symbol

Wählen Sie das kleinste Symbol aus, das Sie finden können (damit Sie sicher sind, dass es nur 1 ist) und überprüfen Sie die "Auswahl-Frequenz". In diesem Fall wäre es 1,013 kHz (also 1 kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Mit einer Gruppe von Symbolen

Sie können auch die Anzahl der Symbole angeben, die Sie auswählen werden, und SigDigger wird die Frequenz von 1 Symbol berechnen (je mehr Symbole ausgewählt werden, desto besser wahrscheinlich). In diesem Szenario habe ich 10 Symbole ausgewählt und die "Auswahl-Frequenz" beträgt 1,004 kHz:

![](<../../.gitbook/assets/image (1008).png>)

### Bits erhalten

Nachdem Sie festgestellt haben, dass es sich um ein **AM-moduliertes** Signal handelt und die **Symbolrate** gefunden haben (und wissen, dass in diesem Fall etwas nach oben bedeutet 1 und etwas nach unten bedeutet 0), ist es sehr einfach, die in dem Signal codierten **Bits zu erhalten**. Wählen Sie also das Signal mit Informationen aus, konfigurieren Sie die Abtastung und Entscheidung und drücken Sie auf "Abtasten" (überprüfen Sie, dass **Amplitude** ausgewählt ist, die entdeckte **Symbolrate** konfiguriert ist und die **Gardner-Taktwiederherstellung** ausgewählt ist):

![](<../../.gitbook/assets/image (965).png>)

* **Synchronisieren mit Auswahlintervallen** bedeutet, dass, wenn Sie zuvor Intervalle ausgewählt haben, um die Symbolrate zu finden, diese Symbolrate verwendet wird.
* **Manuell** bedeutet, dass die angegebene Symbolrate verwendet wird.
* Bei der **Festen Intervallaufteilung** geben Sie die Anzahl der Intervalle an, die ausgewählt werden sollen, und es berechnet die Symbolrate daraus.
* **Gardner-Taktwiederherstellung** ist normalerweise die beste Option, aber Sie müssen trotzdem eine ungefähre Symbolrate angeben.

Nach dem Drücken von "Abtasten" erscheint Folgendes:

![](<../../.gitbook/assets/image (644).png>)

Um SigDigger zu verstehen, **wo sich der Bereich** der Informationen befindet, die übertragen werden, müssen Sie auf das **untere Niveau** klicken und gedrückt halten, bis zum größten Niveau:

![](<../../.gitbook/assets/image (439).png>)

Wenn es zum Beispiel **4 verschiedene Pegel der Amplitude** gegeben hätte, hätten Sie die **Bits pro Symbol auf 2 konfigurieren** müssen und von kleinster bis größter Auswahl treffen müssen.

Schließlich, durch **Erhöhen** des **Zooms** und **Ändern der Zeilenhöhe**, können Sie die Bits sehen (und alle auswählen und kopieren, um alle Bits zu erhalten):

![](<../../.gitbook/assets/image (276).png>)

Wenn das Signal mehr als 1 Bit pro Symbol hat (zum Beispiel 2), hat SigDigger **keine Möglichkeit zu wissen, welches Symbol** 00, 01, 10, 11 ist, daher verwendet es verschiedene **Graustufen**, um jedes zu repräsentieren (und wenn Sie die Bits kopieren, werden **Zahlen von 0 bis 3** verwendet, die Sie behandeln müssen).

Verwenden Sie auch **Codierungen** wie **Manchester**, und **up+down** kann **1 oder 0** sein und ein down+up kann eine 1 oder 0 sein. In diesen Fällen müssen Sie die erhaltenen ups (1) und downs (0) behandeln, um die Paare von 01 oder 10 als 0s oder 1s zu ersetzen.

## FM Beispiel

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM aufdecken

#### Überprüfen der Frequenzen und des Wellenforms

Signalbeispiel, das Informationen in FM moduliert sendet:

![](<../../.gitbook/assets/image (725).png>)

In dem vorherigen Bild können Sie gut erkennen, dass **2 Frequenzen verwendet werden**, aber wenn Sie die **Wellenform beobachten**, könnten Sie **die 2 verschiedenen Frequenzen möglicherweise nicht korrekt identifizieren**:

![](<../../.gitbook/assets/image (717).png>)

Dies liegt daran, dass ich das Signal in beiden Frequenzen erfasse, daher ist eine ungefähr die andere in negativer Form:

![](<../../.gitbook/assets/image (942).png>)

Wenn die synchronisierte Frequenz **einer Frequenz näher liegt als der anderen**, können Sie die 2 verschiedenen Frequenzen leicht erkennen:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Überprüfen des Histogramms

Durch Überprüfen des Frequenzhistogramms des Signals mit Informationen können Sie leicht 2 verschiedene Signale erkennen:

![](<../../.gitbook/assets/image (871).png>)

In diesem Fall, wenn Sie das **Amplitudenhistogramm** überprüfen, werden Sie **nur eine Amplitude** finden, daher **kann es keine AM sein** (wenn Sie viele Amplituden finden, könnte es daran liegen, dass das Signal entlang des Kanals an Leistung verloren hat):

![](<../../.gitbook/assets/image (817).png>)

Und dies wäre das Phasenhistogramm (was sehr deutlich macht, dass das Signal nicht in der Phase moduliert ist):

![](<../../.gitbook/assets/image (996).png>)

#### Mit IQ

IQ hat kein Feld zur Identifizierung von Frequenzen (die Entfernung zum Zentrum ist die Amplitude und der Winkel ist die Phase).\
Daher sollten Sie, um FM zu identifizieren, in diesem Diagramm **im Wesentlichen nur einen Kreis** sehen.\
Darüber hinaus wird eine andere Frequenz im IQ-Diagramm durch eine **Beschleunigung über den Kreis** dargestellt (daher wird im SysDigger durch Auswahl des Signals das IQ-Diagramm erstellt; wenn Sie eine Beschleunigung oder Richtungsänderung im erstellten Kreis feststellen, könnte dies bedeuten, dass es sich um FM handelt):

![](<../../.gitbook/assets/image (81).png>)

### Symbolrate erhalten

Sie können die **gleiche Technik wie die im AM-Beispiel verwendete** verwenden, um die Symbolrate zu erhalten, sobald Sie die Frequenzen gefunden haben, die Symbole tragen.

### Bits erhalten

Sie können die **gleiche Technik wie die im AM-Beispiel verwendete** verwenden, um die Bits zu erhalten, sobald Sie festgestellt haben, dass das Signal in der Frequenz moduliert ist und die **Symbolrate** kennen.
