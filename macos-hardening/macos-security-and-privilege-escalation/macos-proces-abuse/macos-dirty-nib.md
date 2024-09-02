# macOS Dirty NIB

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

**Für weitere Details zur Technik siehe den Originalbeitrag von:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) und den folgenden Beitrag von [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Hier ist eine Zusammenfassung:

### Was sind Nib-Dateien

Nib (kurz für NeXT Interface Builder) Dateien, Teil von Apples Entwicklungsökosystem, sind dazu gedacht, **UI-Elemente** und deren Interaktionen in Anwendungen zu definieren. Sie umfassen serialisierte Objekte wie Fenster und Schaltflächen und werden zur Laufzeit geladen. Trotz ihrer fortwährenden Nutzung empfiehlt Apple jetzt Storyboards für eine umfassendere Visualisierung des UI-Flusses.

Die Haupt-Nib-Datei wird im Wert **`NSMainNibFile`** innerhalb der `Info.plist`-Datei der Anwendung referenziert und wird durch die Funktion **`NSApplicationMain`** geladen, die in der `main`-Funktion der Anwendung ausgeführt wird.

### Dirty Nib Injection Prozess

#### Erstellen und Einrichten einer NIB-Datei

1. **Erste Einrichtung**:
* Erstelle eine neue NIB-Datei mit XCode.
* Füge ein Objekt zur Benutzeroberfläche hinzu und setze seine Klasse auf `NSAppleScript`.
* Konfiguriere die anfängliche `source`-Eigenschaft über benutzerdefinierte Laufzeitattribute.
2. **Codeausführungs-Gadget**:
* Die Einrichtung ermöglicht das Ausführen von AppleScript auf Abruf.
* Integriere eine Schaltfläche, um das `Apple Script`-Objekt zu aktivieren, das speziell den Selektor `executeAndReturnError:` auslöst.
3. **Testen**:
*   Ein einfaches Apple Script zu Testzwecken:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```
* Teste, indem du im XCode-Debugger ausführst und auf die Schaltfläche klickst.

#### Zielanwendung anvisieren (Beispiel: Pages)

1. **Vorbereitung**:
* Kopiere die Zielanwendung (z. B. Pages) in ein separates Verzeichnis (z. B. `/tmp/`).
* Starte die Anwendung, um Gatekeeper-Probleme zu umgehen und sie zu cachen.
2. **Überschreiben der NIB-Datei**:
* Ersetze eine vorhandene NIB-Datei (z. B. About Panel NIB) durch die erstellte DirtyNIB-Datei.
3. **Ausführung**:
* Trigger die Ausführung, indem du mit der Anwendung interagierst (z. B. das Menüelement `Über` auswählst).

#### Proof of Concept: Zugriff auf Benutzerdaten

* Modifiziere das AppleScript, um auf Benutzerdaten zuzugreifen und diese zu extrahieren, wie z. B. Fotos, ohne die Zustimmung des Benutzers.

### Codebeispiel: Bösartige .xib-Datei

* Greife auf und überprüfe eine [**Beispiel einer bösartigen .xib-Datei**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4), die das Ausführen beliebigen Codes demonstriert.

### Anderes Beispiel

Im Beitrag [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) findest du ein Tutorial, wie man einen Dirty Nib erstellt.&#x20;

### Umgang mit Startbeschränkungen

* Startbeschränkungen hindern die Ausführung von Apps aus unerwarteten Orten (z. B. `/tmp`).
* Es ist möglich, Apps zu identifizieren, die nicht durch Startbeschränkungen geschützt sind, und sie für die NIB-Datei-Injektion anzuvisieren.

### Zusätzliche macOS-Schutzmaßnahmen

Seit macOS Sonoma sind Änderungen innerhalb von App-Bundles eingeschränkt. Frühere Methoden umfassten:

1. Kopieren der App an einen anderen Ort (z. B. `/tmp/`).
2. Umbenennen von Verzeichnissen innerhalb des App-Bundles, um anfängliche Schutzmaßnahmen zu umgehen.
3. Nach dem Ausführen der App, um sich bei Gatekeeper zu registrieren, das App-Bundle zu modifizieren (z. B. Ersetzen von MainMenu.nib durch Dirty.nib).
4. Umbenennen der Verzeichnisse zurück und erneutes Ausführen der App, um die injizierte NIB-Datei auszuführen.

**Hinweis**: Neuere macOS-Updates haben diesen Exploit gemildert, indem sie Dateiänderungen innerhalb von App-Bundles nach dem Caching durch Gatekeeper verhindern, wodurch der Exploit unwirksam wird.

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
