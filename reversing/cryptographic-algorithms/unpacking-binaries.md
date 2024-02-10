<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Identifizierung gepackter Binärdateien

* **Fehlende Zeichenketten**: Es ist üblich, dass gepackte Binärdateien kaum Zeichenketten enthalten.
* Viele **unbenutzte Zeichenketten**: Wenn Malware eine Art kommerziellen Packer verwendet, ist es üblich, viele Zeichenketten ohne Querverweise zu finden. Auch wenn diese Zeichenketten existieren, bedeutet das nicht, dass die Binärdatei nicht gepackt ist.
* Sie können auch einige Tools verwenden, um herauszufinden, welcher Packer zum Packen einer Binärdatei verwendet wurde:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Grundlegende Empfehlungen

* **Beginnen** Sie die Analyse der gepackten Binärdatei **von unten in IDA und arbeiten Sie sich nach oben** vor. Entpacker beenden sich, sobald der entpackte Code beendet ist, daher ist es unwahrscheinlich, dass der Entpacker die Ausführung an den entpackten Code am Anfang übergibt.
* Suchen Sie nach **JMP's** oder **CALLs** zu **Registern** oder **Speicherbereichen**. Suchen Sie auch nach **Funktionen, die Argumente und eine Adressrichtung pushen und dann `retn` aufrufen**, da der Rückgabewert der Funktion in diesem Fall die zuvor auf den Stack geschobene Adresse aufrufen kann.
* Setzen Sie einen **Breakpoint** auf `VirtualAlloc`, da dies Speicherplatz im Speicher alloziert, in den das Programm entpackten Code schreiben kann. Führen Sie "Run to user code" aus oder verwenden Sie F8, um **den Wert in EAX** nach Ausführung der Funktion zu erhalten, und "**folgen Sie dieser Adresse im Dump**". Sie wissen nie, ob dies der Bereich ist, in dem der entpackte Code gespeichert wird.
* **`VirtualAlloc`** mit dem Wert "**40**" als Argument bedeutet Lesen+Schreiben+Ausführen (hier wird Code kopiert, der ausgeführt werden muss).
* Beim Entpacken von Code ist es normal, **mehrere Aufrufe** zu **arithmetischen Operationen** und Funktionen wie **`memcopy`** oder **`Virtual`**`Alloc` zu finden. Wenn Sie sich in einer Funktion befinden, die anscheinend nur arithmetische Operationen durchführt und möglicherweise einige `memcopy` enthält, empfiehlt es sich, **das Ende der Funktion** (möglicherweise ein JMP oder Aufruf an ein Register) **oder zumindest den Aufruf der letzten Funktion** zu suchen und dann dorthin zu springen, da der Code nicht interessant ist.
* Beim Entpacken von Code **beachten** Sie immer, wenn Sie den **Speicherbereich ändern**, da eine Änderung des Speicherbereichs auf den **Beginn des Entpackungscodes** hinweisen kann. Sie können einen Speicherbereich einfach mit Process Hacker (Prozess --> Eigenschaften --> Speicher) dumpen.
* Beim Versuch, Code zu entpacken, ist eine gute Möglichkeit zu **erkennen, ob Sie bereits mit dem entpackten Code arbeiten** (damit Sie ihn einfach dumpen können), das Überprüfen der Zeichenketten der Binärdatei. Wenn Sie an einem bestimmten Punkt einen Sprung ausführen (möglicherweise durch Ändern des Speicherbereichs) und feststellen, dass **viele weitere Zeichenketten hinzugefügt wurden**, können Sie wissen, dass **Sie mit dem entpackten Code arbeiten**.\
Wenn der Packer jedoch bereits viele Zeichenketten enthält, können Sie überprüfen, wie viele Zeichenketten das Wort "http" enthalten und ob diese Anzahl zunimmt.
* Wenn Sie eine ausführbare Datei aus einem Speicherbereich dumpen, können Sie einige Header mit [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) reparieren.


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
