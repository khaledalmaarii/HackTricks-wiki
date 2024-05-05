# Cheat Engine

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben** sehen möchten oder **HackTricks in PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind und sie zu ändern.\
Wenn Sie es herunterladen und ausführen, erhalten Sie eine **Anleitung** zur Verwendung des Tools. Es wird dringend empfohlen, diese abzuschließen, wenn Sie lernen möchten, wie man das Tool verwendet.

## Was suchen Sie?

![](<../../.gitbook/assets/image (762).png>)

Dieses Tool ist sehr nützlich, um herauszufinden, **wo ein bestimmter Wert** (normalerweise eine Zahl) **im Speicher eines Programms gespeichert ist**.\
**Normalerweise werden Zahlen** in **4-Byte-Form** gespeichert, aber Sie könnten sie auch in **Double-** oder **Float-Formaten** finden, oder Sie möchten nach etwas **anderem als einer Zahl** suchen. Aus diesem Grund müssen Sie sicherstellen, dass Sie auswählen, wonach Sie suchen möchten:

![](<../../.gitbook/assets/image (324).png>)

Sie können auch **verschiedene Arten von Suchen** angeben:

![](<../../.gitbook/assets/image (311).png>)

Sie können auch das Kästchen ankreuzen, um das Spiel anzuhalten, während der Speicher gescannt wird:

![](<../../.gitbook/assets/image (1052).png>)

### Tastenkombinationen

Unter _**Bearbeiten --> Einstellungen --> Tastenkombinationen**_ können Sie verschiedene **Tastenkombinationen** für verschiedene Zwecke festlegen, wie z.B. das **Anhalten** des **Spiels** (was sehr nützlich ist, wenn Sie zu einem bestimmten Zeitpunkt den Speicher scannen möchten). Weitere Optionen stehen zur Verfügung:

![](<../../.gitbook/assets/image (864).png>)

## Wert ändern

Sobald Sie herausgefunden haben, wo sich der **Wert** befindet, den Sie **suchen** (mehr dazu in den folgenden Schritten), können Sie ihn ändern, indem Sie darauf doppelklicken und dann den Wert doppelklicken:

![](<../../.gitbook/assets/image (563).png>)

Und schließlich das Kästchen ankreuzen, um die Änderung im Speicher vorzunehmen:

![](<../../.gitbook/assets/image (385).png>)

Die **Änderung** im Speicher wird sofort **angewendet** (beachten Sie, dass der Wert im Spiel **nicht aktualisiert wird**, bis das Spiel diesen Wert erneut verwendet).

## Wert suchen

Angenommen, es gibt einen wichtigen Wert (wie das Leben Ihres Benutzers), den Sie verbessern möchten, und Sie suchen nach diesem Wert im Speicher)

### Durch eine bekannte Änderung

Angenommen, Sie suchen nach dem Wert 100, Sie **führen einen Scan** durch, um nach diesem Wert zu suchen, und Sie finden viele Übereinstimmungen:

![](<../../.gitbook/assets/image (108).png>)

Dann tun Sie etwas, damit sich der **Wert ändert**, und Sie **halten** das Spiel an und **führen** einen **weiteren Scan** durch:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine wird nach den **Werten suchen, die von 100 auf den neuen Wert übergegangen sind**. Herzlichen Glückwunsch, Sie haben die **Adresse** des gesuchten Werts gefunden, den Sie jetzt ändern können.\
_Wenn Sie immer noch mehrere Werte haben, tun Sie etwas, um diesen Wert erneut zu ändern, und führen Sie einen weiteren "weiteren Scan" durch, um die Adressen zu filtern._

### Unbekannter Wert, bekannte Änderung

In dem Szenario, in dem Sie den Wert **nicht kennen**, aber wissen, **wie Sie ihn ändern können** (und sogar den Wert der Änderung kennen), können Sie nach Ihrer Zahl suchen.

Beginnen Sie also mit einem Scan des Typs "**Unbekannter Anfangswert**":

![](<../../.gitbook/assets/image (890).png>)

Dann ändern Sie den Wert, geben Sie an, **wie** sich der **Wert geändert hat** (in meinem Fall wurde er um 1 verringert) und führen Sie einen **weiteren Scan** durch:

![](<../../.gitbook/assets/image (371).png>)

Es werden Ihnen **alle Werte präsentiert, die auf die ausgewählte Weise geändert wurden**:

![](<../../.gitbook/assets/image (569).png>)

Sobald Sie Ihren Wert gefunden haben, können Sie ihn ändern.

Beachten Sie, dass es **viele mögliche Änderungen** gibt und Sie diese **Schritte so oft wie gewünscht** wiederholen können, um die Ergebnisse zu filtern:

![](<../../.gitbook/assets/image (574).png>)

### Zufällige Speicheradresse - Das Code finden

Bis jetzt haben wir gelernt, wie man eine Adresse findet, die einen Wert speichert, aber es ist sehr wahrscheinlich, dass in **unterschiedlichen Ausführungen des Spiels diese Adresse an verschiedenen Speicherorten liegt**. Finden wir also heraus, wie wir diese Adresse immer finden können.

Verwenden Sie einige der genannten Tricks, um die Adresse zu finden, an der Ihr aktuelles Spiel den wichtigen Wert speichert. Dann (halten Sie das Spiel an, wenn Sie möchten) klicken Sie mit der rechten Maustaste auf die gefundene **Adresse** und wählen Sie "**Herausfinden, was auf diese Adresse zugreift**" oder "**Herausfinden, was auf diese Adresse schreibt**":

![](<../../.gitbook/assets/image (1067).png>)

Die **erste Option** ist nützlich, um zu wissen, welche **Teile** des **Codes** diese **Adresse verwenden** (was für weitere Dinge wie **wissen, wo Sie den Code des Spiels ändern können** nützlich ist).\
Die **zweite Option** ist spezifischer und wird in diesem Fall hilfreicher sein, da wir daran interessiert sind, **zu wissen, von wo aus dieser Wert geschrieben wird**.

Sobald Sie eine dieser Optionen ausgewählt haben, wird der **Debugger** an das Programm angehängt und ein neues **leeres Fenster** wird angezeigt. Spielen Sie nun das Spiel und **ändern** Sie diesen **Wert** (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen gefüllt sein, die den Wert ändern**:

![](<../../.gitbook/assets/image (91).png>)

Nun, da Sie die Adresse gefunden haben, die den Wert ändert, können Sie den Code nach Belieben ändern (Cheat Engine ermöglicht es Ihnen, ihn schnell in NOPs zu ändern):

![](<../../.gitbook/assets/image (1057).png>)

Sie können ihn also jetzt so ändern, dass der Code Ihre Zahl nicht beeinflusst oder immer positiv beeinflusst.
### Zufällige Speicheradresse - Auffinden des Zeigers

Folgen Sie den vorherigen Schritten, um herauszufinden, wo sich der Wert befindet, an dem Sie interessiert sind. Verwenden Sie dann "**Herausfinden, was an diese Adresse schreibt**", um herauszufinden, welche Adresse diesen Wert schreibt, und klicken Sie doppelt darauf, um die Disassembly-Ansicht zu erhalten:

![](<../../.gitbook/assets/image (1039).png>)

Führen Sie dann einen neuen Scan durch, **suchen Sie nach dem Hex-Wert zwischen "\[]"** (der Wert von $edx in diesem Fall):

![](<../../.gitbook/assets/image (994).png>)

(_Wenn mehrere erscheinen, benötigen Sie normalerweise den mit der kleinsten Adresse_)\
Jetzt haben wir **den Zeiger gefunden, der den Wert modifizieren wird, an dem wir interessiert sind**.

Klicken Sie auf "**Adresse manuell hinzufügen**":

![](<../../.gitbook/assets/image (990).png>)

Klicken Sie nun auf das Kontrollkästchen "Zeiger" und fügen Sie die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Beachten Sie, wie die erste "Adresse" automatisch aus der Zeigeradresse ausgefüllt wird, die Sie eingeben)

Klicken Sie auf OK und ein neuer Zeiger wird erstellt:

![](<../../.gitbook/assets/image (308).png>)

Jedes Mal, wenn Sie diesen Wert ändern, **ändern Sie den wichtigen Wert, auch wenn die Speicheradresse, an der sich der Wert befindet, unterschiedlich ist**.

### Code-Injektion

Code-Injektion ist eine Technik, bei der Sie ein Stück Code in den Zielprozess einspeisen und dann die Ausführung des Codes umleiten, um durch Ihren eigenen geschriebenen Code zu gehen (zum Beispiel Punkte anstelle von Abzug).

Stellen Sie sich vor, Sie haben die Adresse gefunden, die 1 vom Leben Ihres Spielers abzieht:

![](<../../.gitbook/assets/image (203).png>)

Klicken Sie auf "Disassembler anzeigen", um den **Disassemble-Code** zu erhalten.\
Klicken Sie dann auf **STRG+a**, um das Fenster "Auto Assemble" aufzurufen, und wählen Sie _**Vorlage --> Code-Injektion**_

![](<../../.gitbook/assets/image (902).png>)

Füllen Sie die **Adresse der Anweisung, die Sie ändern möchten** aus (dies ist normalerweise vorausgefüllt):

![](<../../.gitbook/assets/image (744).png>)

Eine Vorlage wird generiert:

![](<../../.gitbook/assets/image (944).png>)

Fügen Sie Ihren neuen Assembler-Code in den Abschnitt "**newmem**" ein und entfernen Sie den Originalcode aus dem Abschnitt "**originalcode**", wenn Sie nicht möchten, dass er ausgeführt wird. In diesem Beispiel fügt der injizierte Code 2 Punkte hinzu, anstatt 1 abzuziehen:

![](<../../.gitbook/assets/image (521).png>)

**Klicken Sie auf Ausführen und so weiter, und Ihr Code sollte in das Programm injiziert werden, wodurch sich das Verhalten der Funktionalität ändert!**

## **Referenzen**

* **Cheat Engine Tutorial, um zu lernen, wie man mit Cheat Engine beginnt**

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
