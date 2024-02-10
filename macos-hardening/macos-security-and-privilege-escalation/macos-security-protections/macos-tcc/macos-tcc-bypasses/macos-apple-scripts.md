# macOS Apple Scripts

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Apple Scripts

Es handelt sich um eine Skriptsprache, die zur Automatisierung von Aufgaben verwendet wird und **mit Remote-Prozessen interagiert**. Es ist sehr einfach, **andere Prozesse aufzufordern, bestimmte Aktionen auszuführen**. **Malware** kann diese Funktionen missbrauchen, um Funktionen von anderen Prozessen zu missbrauchen.\
Beispielsweise könnte eine Malware beliebigen JS-Code in geöffneten Browserseiten **einschleusen** oder **automatisch auf** einige vom Benutzer angeforderte Berechtigungen klicken.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier sind einige Beispiele: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Weitere Informationen über Malware, die AppleScripts verwendet, finden Sie [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple-Scripts können leicht "**kompiliert**" werden. Diese Versionen können mit `osadecompile` leicht "**dekompiliert**" werden.

Diese Skripte können jedoch auch als "Schreibgeschützt" exportiert werden (über die Option "Exportieren..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Und in diesem Fall kann der Inhalt selbst mit `osadecompile` nicht dekompiliert werden.

Es gibt jedoch immer noch einige Tools, die verwendet werden können, um diese Art von ausführbaren Dateien zu verstehen. [**Lesen Sie diese Forschung für weitere Informationen**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Das Tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) mit [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) wird sehr nützlich sein, um zu verstehen, wie das Skript funktioniert.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
