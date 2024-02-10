# Radio

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ist ein kostenloser digitaler Signalanalysator für GNU/Linux und macOS, der entwickelt wurde, um Informationen über unbekannte Funksignale zu extrahieren. Es unterstützt eine Vielzahl von SDR-Geräten über SoapySDR und ermöglicht die einstellbare Demodulation von FSK-, PSK- und ASK-Signalen, die Decodierung von analogem Video, die Analyse von Burst-Signalen und das Abhören von analogen Sprachkanälen (alles in Echtzeit).

### Grundkonfiguration

Nach der Installation gibt es einige Dinge, die Sie konfigurieren können.\
In den Einstellungen (der zweite Tab-Button) können Sie das **SDR-Gerät auswählen** oder eine **Datei auswählen**, um zu lesen, und die Frequenz zum Syntonisieren und die Abtastrate (empfohlen bis zu 2,56 Msps, wenn Ihr PC dies unterstützt)\\

![](<../../.gitbook/assets/image (655) (1).png>)

In der GUI-Verhaltensweise wird empfohlen, einige Dinge zu aktivieren, wenn Ihr PC dies unterstützt:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Wenn Sie feststellen, dass Ihr PC nichts erfasst, versuchen Sie, OpenGL zu deaktivieren und die Abtastrate zu verringern.
{% endhint %}

### Verwendung

* Um einfach **ein Signal aufzunehmen und zu analysieren**, halten Sie einfach den Button "Push to capture" gedrückt, solange Sie es benötigen.

![](<../../.gitbook/assets/image (631).png>)

* Der **Tuner** von SigDigger hilft dabei, **bessere Signale aufzunehmen** (kann sie aber auch verschlechtern). Idealerweise beginnen Sie mit 0 und erhöhen es, bis das **Rauschen** größer ist als die **Verbesserung des Signals**, das Sie benötigen.

![](<../../.gitbook/assets/image (658).png>)

### Synchronisieren mit dem Radiokanal

Mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger)können Sie sich mit dem Kanal synchronisieren, den Sie hören möchten. Konfigurieren Sie die Option "Baseband-Audiovorschau", stellen Sie die Bandbreite ein, um alle gesendeten Informationen zu erhalten, und stellen Sie dann den Tuner auf das Niveau ein, bevor das Rauschen wirklich zu zunehmen beginnt:

![](<../../.gitbook/assets/image (389).png>)

## Interessante Tricks

* Wenn ein Gerät Bursts von Informationen sendet, ist normalerweise der **erste Teil eine Präambel**, sodass Sie sich keine Sorgen machen müssen, wenn Sie dort keine Informationen finden oder wenn Fehler auftreten.
* In Informationsrahmen sollten Sie normalerweise **verschiedene gut ausgerichtete Rahmen finden**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Nachdem Sie die Bits wiederhergestellt haben, müssen Sie sie möglicherweise auf irgendeine Weise verarbeiten**. Zum Beispiel wird bei der Manchester-Codierung ein Auf+Ab ein 1 oder 0 sein und ein Ab+Auf das andere. Paare von 1en und 0en (Aufs und Abs) werden also eine echte 1 oder eine echte 0 sein.
* Selbst wenn ein Signal die Manchester-Codierung verwendet (es ist unmöglich, mehr als zwei 0en oder 1en hintereinander zu finden), können Sie **mehrere 1en oder 0en zusammen in der Präambel finden**!

### Entdecken des Modulationstyps mit IQ

Es gibt 3 Möglichkeiten, Informationen in Signalen zu speichern: Modulation der **Amplitude**, **Frequenz** oder **Phase**.\
Wenn Sie ein Signal überprüfen, gibt es verschiedene Möglichkeiten, um herauszufinden, welche Methode zur Speicherung von Informationen verwendet wird (weitere Möglichkeiten finden Sie unten), aber eine gute Methode besteht darin, das IQ-Diagramm zu überprüfen.

![](<../../.gitbook/assets/image (630).png>)

* **AM erkennen**: Wenn im IQ-Diagramm zum Beispiel **2 Kreise** erscheinen (wahrscheinlich einer bei 0 und einer bei einer anderen Amplitude), könnte dies bedeuten, dass es sich um ein AM-Signal handelt. Dies liegt daran, dass im IQ-Diagramm der Abstand zwischen 0 und dem Kreis die Amplitude des Signals ist, sodass verschiedene Amplituden leicht visualisiert werden können.
* **PM erkennen**: Wie im vorherigen Bild, wenn Sie kleine Kreise finden, die nicht miteinander zusammenhängen, bedeutet dies wahrscheinlich, dass eine Phasenmodulation verwendet wird. Dies liegt daran, dass im IQ-Diagramm der Winkel zwischen dem Punkt und 0,0 die Phase des Signals ist, was bedeutet, dass 4 verschiedene Phasen verwendet werden.
* Beachten Sie, dass Sie, wenn die Information darin besteht, dass sich eine Phase ändert und nicht in der Phase selbst, keine deutlich unterschiedlichen Phasen sehen werden.
* **FM erkennen**: IQ hat kein Feld, um Frequenzen zu identifizieren (Abstand zum Zentrum ist Amplitude und Winkel ist Phase).\
Daher sollten Sie, um FM zu identifizieren, in diesem Diagramm **nur einen Kreis** sehen.

Darüber hinaus wird eine andere Frequenz durch das IQ-Diagramm durch eine **Beschleunigung der Geschwindigkeit über den Kreis hinweg "repräsentiert"** (so dass im SysDigger, wenn das Signal ausgewählt ist, das IQ-Diagramm erstellt wird, wenn Sie eine Beschleunigung oder eine Richtungsänderung im erstellten Kreis feststellen, könnte dies bedeuten, dass es sich um FM handelt):

## AM-Beispiel

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM aufdecken

#### Überprüfen der Hüllkurve

Überprüfen Sie AM-Informationen mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger)und betrachten Sie einfach die **Hüllkurve**, um verschiedene klare Amplitudenstufen zu sehen. Das verwendete Signal sendet Impulse mit Informationen in AM, so sieht ein Impuls aus:

![](<../../.gitbook/assets/image (636).png>)

Und so sieht ein Teil des Symbols mit der Wellenform aus:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Überprüfen des Histogramms

Sie können das **gesamte Signal** auswählen, in dem sich die Informationen befinden, den Modus **Amplitude** auswählen und **Auswahl** und auf **Histogramm** klicken. Sie können feststellen, dass nur 2 klare Pegel gefunden werden

![](<../../.gitbook/assets/image (647) (1) (1).png>)

Wenn Sie beispielsweise in diesem AM-Signal anstelle von Amplitude die Frequenz auswählen, finden Sie nur 1 Frequenz (keine Möglichkeit, dass Informationen in der Frequenz moduliert werden, wenn nur 1 Frequenz verwendet wird).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

Wenn Sie viele Frequenzen finden, handelt es sich wahrscheinlich nicht um FM, wahrscheinlich wurde die Signal-Frequenz aufgrund des Kanals einfach geändert.
#### Mit IQ

In diesem Beispiel können Sie sehen, dass es einen **großen Kreis** gibt, aber auch **viele Punkte im Zentrum**.

![](<../../.gitbook/assets/image (640).png>)

### Symbolrate erhalten

#### Mit einem Symbol

Wählen Sie das kleinste Symbol aus, das Sie finden können (damit Sie sicher sein können, dass es nur 1 ist) und überprüfen Sie die "Auswahl-Frequenz". In diesem Fall wäre es 1,013 kHz (also 1 kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Mit einer Gruppe von Symbolen

Sie können auch die Anzahl der Symbole angeben, die Sie auswählen möchten, und SigDigger berechnet die Frequenz eines Symbols (je mehr Symbole ausgewählt werden, desto besser wahrscheinlich). In diesem Szenario habe ich 10 Symbole ausgewählt und die "Auswahl-Frequenz" beträgt 1,004 kHz:

![](<../../.gitbook/assets/image (635).png>)

### Bits erhalten

Nachdem Sie festgestellt haben, dass es sich um ein **AM-moduliertes** Signal handelt und die **Symbolrate** gefunden haben (und wissen, dass in diesem Fall etwas nach oben bedeutet 1 und etwas nach unten bedeutet 0), ist es sehr einfach, die in dem Signal codierten Bits zu **erhalten**. Wählen Sie also das Signal mit Informationen aus und konfigurieren Sie die Abtastung und Entscheidung und drücken Sie auf "Sample" (stellen Sie sicher, dass **Amplitude** ausgewählt ist, die entdeckte **Symbolrate** konfiguriert ist und die **Gardner Clock Recovery** ausgewählt ist):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals** bedeutet, dass, wenn Sie zuvor Intervalle ausgewählt haben, um die Symbolrate zu finden, diese Symbolrate verwendet wird.
* **Manual** bedeutet, dass die angegebene Symbolrate verwendet wird.
* Bei **Fixed interval selection** geben Sie die Anzahl der auszuwählenden Intervalle an und es berechnet die Symbolrate daraus.
* **Gardner Clock Recovery** ist normalerweise die beste Option, aber Sie müssen trotzdem eine ungefähre Symbolrate angeben.

Nach dem Drücken von "Sample" erscheint Folgendes:

![](<../../.gitbook/assets/image (659).png>)

Um SigDigger zu verstehen, **wo sich der Bereich** der Informationen befindet, müssen Sie auf das **niedrigste Niveau** klicken und gedrückt halten, bis zum größten Niveau:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Wenn es zum Beispiel **4 verschiedene Amplituden-Niveaus** gegeben hätte, hätten Sie die **Bits pro Symbol auf 2** konfigurieren und vom kleinsten zum größten auswählen müssen.

Schließlich können Sie durch **Erhöhen** des **Zooms** und **Ändern der Zeilenhöhe** die Bits sehen (und Sie können alles auswählen und kopieren, um alle Bits zu erhalten):

![](<../../.gitbook/assets/image (649) (1).png>)

Wenn das Signal mehr als 1 Bit pro Symbol (zum Beispiel 2) hat, hat SigDigger **keine Möglichkeit zu wissen, welches Symbol** 00, 01, 10, 11 ist, daher verwendet es verschiedene **Graustufen**, um jedes Symbol darzustellen (und wenn Sie die Bits kopieren, verwendet es **Zahlen von 0 bis 3**, die Sie behandeln müssen).

Verwenden Sie auch **Codierungen** wie **Manchester**, und **up+down** kann **1 oder 0** sein und down+up kann **1 oder 0** sein. In diesen Fällen müssen Sie die erhaltenen "up" (1) und "down" (0) behandeln, um die Paare 01 oder 10 als 0 oder 1 zu ersetzen.

## FM-Beispiel

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM aufdecken

#### Überprüfen der Frequenzen und der Wellenform

Beispiel für ein Signal, das Informationen in FM moduliert sendet:

![](<../../.gitbook/assets/image (661) (1).png>)

In dem vorherigen Bild können Sie gut erkennen, dass **2 Frequenzen verwendet werden**, aber wenn Sie die **Wellenform beobachten**, können Sie die **2 verschiedenen Frequenzen möglicherweise nicht korrekt identifizieren**:

![](<../../.gitbook/assets/image (653).png>)

Dies liegt daran, dass ich das Signal in beiden Frequenzen aufgenommen habe, daher ist eine ungefähr die andere in negativer Form:

![](<../../.gitbook/assets/image (656).png>)

Wenn die synchronisierte Frequenz **einer Frequenz näher ist als der anderen**, können Sie die 2 verschiedenen Frequenzen leicht erkennen:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Überprüfen des Histogramms

Wenn Sie das Frequenzhistogramm des Signals mit Informationen überprüfen, können Sie leicht 2 verschiedene Signale erkennen:

![](<../../.gitbook/assets/image (657).png>)

In diesem Fall finden Sie im **Amplitudenhistogramm** nur eine Amplitude, daher kann es sich nicht um AM handeln (wenn Sie viele Amplituden finden, kann es sein, dass das Signal entlang des Kanals an Leistung verloren hat):

![](<../../.gitbook/assets/image (646).png>)

Und dies wäre das Phasenhistogramm (das sehr deutlich macht, dass das Signal nicht in der Phase moduliert ist):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Mit IQ

IQ hat kein Feld, um Frequenzen zu identifizieren (die Entfernung zum Zentrum ist die Amplitude und der Winkel ist die Phase).\
Daher sollten Sie, um FM zu identifizieren, in diesem Diagramm **im Wesentlichen nur einen Kreis** sehen.\
Darüber hinaus wird eine andere Frequenz im IQ-Diagramm durch eine **Beschleunigung der Geschwindigkeit über den Kreis** "dargestellt" (wenn Sie das Signal in SysDigger auswählen, wird das IQ-Diagramm erstellt, und wenn Sie eine Beschleunigung oder eine Richtungsänderung im erstellten Kreis feststellen, könnte dies bedeuten, dass es sich um FM handelt):

![](<../../.gitbook/assets/image (643) (1).png>)

### Symbolrate erhalten

Sie können die **gleiche Technik wie im AM-Beispiel** verwenden, um die Symbolrate zu erhalten, sobald Sie die Frequenzen gefunden haben, die Symbole tragen.

### Bits erhalten

Sie können die **gleiche Technik wie im AM-Beispiel** verwenden, um die Bits zu erhalten, sobald Sie festgestellt haben, dass das Signal in der Frequenz moduliert ist und die Symbolrate kennen.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden**.

</details>
