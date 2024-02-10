<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind und sie zu ändern.\
Wenn Sie es herunterladen und ausführen, erhalten Sie eine **Anleitung**, wie Sie das Tool verwenden. Wenn Sie lernen möchten, wie Sie das Tool verwenden, wird empfohlen, es vollständig durchzugehen.

# Was suchen Sie?

![](<../../.gitbook/assets/image (580).png>)

Dieses Tool ist sehr nützlich, um herauszufinden, **wo ein bestimmter Wert** (normalerweise eine Zahl) **im Speicher** eines Programms gespeichert ist.\
**Normalerweise werden Zahlen** in **4-Byte-Form** gespeichert, aber Sie können sie auch in **Double-** oder **Float-Formaten** finden oder nach etwas suchen, **das keine Zahl ist**. Aus diesem Grund müssen Sie sicherstellen, dass Sie auswählen, wonach Sie suchen möchten:

![](<../../.gitbook/assets/image (581).png>)

Sie können auch **verschiedene Arten von Suchen** angeben:

![](<../../.gitbook/assets/image (582).png>)

Sie können auch das Kästchen aktivieren, um das Spiel anzuhalten, während der Speicher gescannt wird:

![](<../../.gitbook/assets/image (584).png>)

## Tastenkombinationen

In _**Bearbeiten --> Einstellungen --> Tastenkombinationen**_ können Sie verschiedene **Tastenkombinationen** für verschiedene Zwecke festlegen, z.B. zum **Anhalten** des **Spiels** (was sehr nützlich ist, wenn Sie zu einem bestimmten Zeitpunkt den Speicher scannen möchten). Weitere Optionen stehen zur Verfügung:

![](<../../.gitbook/assets/image (583).png>)

# Wert ändern

Sobald Sie herausgefunden haben, wo sich der **gesuchte Wert** befindet (mehr dazu in den folgenden Schritten), können Sie ihn ändern, indem Sie ihn doppelklicken und dann den Wert doppelklicken:

![](<../../.gitbook/assets/image (585).png>)

Und schließlich das Kästchen markieren, um die Änderung im Speicher vorzunehmen:

![](<../../.gitbook/assets/image (586).png>)

Die **Änderung** im **Speicher** wird sofort **angewendet** (beachten Sie, dass der Wert im Spiel **nicht aktualisiert wird**, bis das Spiel diesen Wert erneut verwendet).

# Wert suchen

Angenommen, Sie suchen nach einem wichtigen Wert (wie dem Leben Ihres Benutzers), den Sie verbessern möchten, und Sie suchen nach diesem Wert im Speicher)

## Durch eine bekannte Änderung

Angenommen, Sie suchen nach dem Wert 100, führen Sie eine Suche nach diesem Wert durch und finden Sie viele Übereinstimmungen:

![](<../../.gitbook/assets/image (587).png>)

Dann tun Sie etwas, damit sich der **Wert ändert**, und Sie **halten** das Spiel an und führen eine **nächste Suche** durch:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine sucht nach den **Werten**, die von 100 auf den neuen Wert **gegangen** sind. Herzlichen Glückwunsch, Sie haben die **Adresse** des gesuchten Werts gefunden und können ihn jetzt ändern.\
_Wenn Sie immer noch mehrere Werte haben, tun Sie etwas, um diesen Wert erneut zu ändern, und führen Sie eine weitere "nächste Suche" durch, um die Adressen zu filtern._

## Unbekannter Wert, bekannte Änderung

In dem Szenario, in dem Sie den **Wert nicht kennen**, aber wissen, **wie er sich ändern lässt** (und sogar den Wert der Änderung kennen), können Sie nach Ihrer Zahl suchen.

Beginnen Sie also mit einer Suche vom Typ "**Unbekannter Anfangswert**":

![](<../../.gitbook/assets/image (589).png>)

Dann ändern Sie den Wert, geben Sie an, **wie** sich der **Wert geändert** hat (in meinem Fall wurde er um 1 verringert) und führen Sie eine **nächste Suche** durch:

![](<../../.gitbook/assets/image (590).png>)

Es werden Ihnen **alle Werte angezeigt, die auf die ausgewählte Weise geändert wurden**:

![](<../../.gitbook/assets/image (591).png>)

Sobald Sie Ihren Wert gefunden haben, können Sie ihn ändern.

Beachten Sie, dass es **viele mögliche Änderungen** gibt und Sie diese **Schritte so oft wie gewünscht** wiederholen können, um die Ergebnisse zu filtern:

![](<../../.gitbook/assets/image (592).png>)

## Zufällige Speicheradresse - Code finden

Bis jetzt haben wir gelernt, wie man eine Adresse findet, die einen Wert speichert, aber es ist sehr wahrscheinlich, dass diese Adresse in **unterschiedlichen Ausführungen des Spiels an unterschiedlichen Speicherorten** liegt. Finden wir also heraus, wie wir diese Adresse immer finden können.

Verwenden Sie einige der genannten Tricks, um die Adresse zu finden, an der Ihr aktuelles Spiel den wichtigen Wert speichert. Klicken Sie dann mit der rechten Maustaste auf die gefundene **Adresse** und wählen Sie "**Herausfinden, was auf diese Adresse zugreift**" oder "**Herausfinden, was in diese Adresse schreibt**":

![](<../../.gitbook/assets/image (593).png>)

Die **erste Option** ist nützlich, um zu wissen, welche **Teile** des **Codes** diese **Adresse verwenden** (was für weitere Dinge nützlich ist, wie z.B. **wissen, wo Sie den Code des Spiels ändern können**).\
Die **zweite Option** ist spezifischer und wird in diesem Fall hilfreicher sein, da wir daran interessiert sind, **von wo aus dieser Wert geschrieben wird**.

Sobald Sie eine dieser Optionen ausgewählt haben, wird der **Debugger** an das Programm **angehängt** und ein neues **leeres Fenster** wird angezeigt. Spielen Sie nun das Spiel und ändern Sie diesen Wert (ohne das Spiel neu zu starten). Das **Fenster** sollte mit den **Adressen gefüllt sein**, die den **Wert ändern**:

![](<../../.gitbook/assets/image (594).png>)

Jetzt, da Sie die Adresse gefunden haben, an der der Wert geändert wird, können Sie den Code nach Belieben ändern (Cheat Engine ermöglicht es Ihnen, ihn schnell in NOPs zu ändern):

![](<../../.gitbook/assets/image (595).png>)

Sie können ihn also jetzt so ändern, dass der Code Ihre Zahl nicht beeinflusst oder immer positiv beeinflusst.
## Zufällige Speicheradresse - Finden des Zeigers

Folgen Sie den vorherigen Schritten, um herauszufinden, wo sich der Wert befindet, an dem Sie interessiert sind. Verwenden Sie dann "**Finden Sie heraus, was an diese Adresse schreibt**", um herauszufinden, welche Adresse diesen Wert schreibt, und doppelklicken Sie darauf, um die Disassembly-Ansicht zu erhalten:

![](<../../.gitbook/assets/image (596).png>)

Führen Sie dann eine neue Suche durch, indem Sie nach dem Hex-Wert zwischen "\[]" suchen (der Wert von $edx in diesem Fall):

![](<../../.gitbook/assets/image (597).png>)

(Wenn mehrere erscheinen, benötigen Sie normalerweise die Adresse mit der kleinsten Adresse)\
Jetzt haben wir den **Zeiger gefunden, der den Wert, an dem wir interessiert sind, ändern wird**.

Klicken Sie auf "**Adresse manuell hinzufügen**":

![](<../../.gitbook/assets/image (598).png>)

Klicken Sie nun auf das Kontrollkästchen "Zeiger" und fügen Sie die gefundene Adresse in das Textfeld ein (in diesem Szenario war die gefundene Adresse im vorherigen Bild "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Beachten Sie, wie die erste "Adresse" automatisch aus der eingegebenen Zeigeradresse ausgefüllt wird)

Klicken Sie auf OK und es wird ein neuer Zeiger erstellt:

![](<../../.gitbook/assets/image (600).png>)

Jetzt, jedes Mal, wenn Sie diesen Wert ändern, **ändern Sie den wichtigen Wert, auch wenn die Speicheradresse, an der sich der Wert befindet, unterschiedlich ist.**

## Code-Injektion

Code-Injektion ist eine Technik, bei der Sie einen Code in den Zielprozess injizieren und dann die Ausführung des Codes umleiten, um Ihren eigenen Code auszuführen (z. B. Punkte anstelle von Punktabzug zu geben).

Stellen Sie sich also vor, Sie haben die Adresse gefunden, die 1 vom Leben Ihres Spielers abzieht:

![](<../../.gitbook/assets/image (601).png>)

Klicken Sie auf "Disassembler anzeigen", um den **Disassemble-Code** zu erhalten.\
Klicken Sie dann auf **STRG+a**, um das Fenster "Auto Assemble" aufzurufen, und wählen Sie _**Vorlage --> Code-Injektion**_

![](<../../.gitbook/assets/image (602).png>)

Geben Sie die **Adresse der Anweisung ein, die Sie ändern möchten** (dies ist normalerweise vorausgefüllt):

![](<../../.gitbook/assets/image (603).png>)

Eine Vorlage wird generiert:

![](<../../.gitbook/assets/image (604).png>)

Fügen Sie also Ihren neuen Assembly-Code in den Abschnitt "**newmem**" ein und entfernen Sie den ursprünglichen Code aus dem Abschnitt "**originalcode**", wenn Sie nicht möchten, dass er ausgeführt wird. In diesem Beispiel fügt der injizierte Code 2 Punkte hinzu, anstatt 1 abzuziehen:

![](<../../.gitbook/assets/image (605).png>)

**Klicken Sie auf Ausführen und so weiter, und Ihr Code sollte in das Programm injiziert werden und das Verhalten der Funktion ändern!**

# **Referenzen**

* **Cheat Engine-Tutorial, um zu lernen, wie man mit Cheat Engine beginnt**



<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
