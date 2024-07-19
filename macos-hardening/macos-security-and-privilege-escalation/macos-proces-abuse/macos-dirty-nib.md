# macOS Dirty NIB

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

**Für weitere Details zur Technik siehe den Originalbeitrag von: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Hier ist eine Zusammenfassung:

NIB-Dateien, Teil von Apples Entwicklungsökosystem, sind dazu gedacht, **UI-Elemente** und deren Interaktionen in Anwendungen zu definieren. Sie umfassen serialisierte Objekte wie Fenster und Schaltflächen und werden zur Laufzeit geladen. Trotz ihrer fortwährenden Nutzung empfiehlt Apple jetzt Storyboards für eine umfassendere Visualisierung des UI-Flusses.

### Sicherheitsbedenken bei NIB-Dateien
Es ist wichtig zu beachten, dass **NIB-Dateien ein Sicherheitsrisiko darstellen können**. Sie haben das Potenzial, **willkürliche Befehle auszuführen**, und Änderungen an NIB-Dateien innerhalb einer App hindern Gatekeeper nicht daran, die App auszuführen, was eine erhebliche Bedrohung darstellt.

### Dirty NIB Injektionsprozess
#### Erstellen und Einrichten einer NIB-Datei
1. **Erste Einrichtung**:
- Erstelle eine neue NIB-Datei mit XCode.
- Füge ein Objekt zur Benutzeroberfläche hinzu und setze seine Klasse auf `NSAppleScript`.
- Konfiguriere die anfängliche `source`-Eigenschaft über benutzerdefinierte Laufzeitattribute.

2. **Codeausführungs-Gadget**:
- Die Einrichtung ermöglicht das Ausführen von AppleScript auf Abruf.
- Integriere eine Schaltfläche, um das `Apple Script`-Objekt zu aktivieren, das speziell den Selektor `executeAndReturnError:` auslöst.

3. **Testen**:
- Ein einfaches Apple Script zu Testzwecken:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Teste, indem du im XCode-Debugger ausführst und auf die Schaltfläche klickst.

#### Zielanwendung anvisieren (Beispiel: Pages)
1. **Vorbereitung**:
- Kopiere die Ziel-App (z. B. Pages) in ein separates Verzeichnis (z. B. `/tmp/`).
- Starte die App, um Gatekeeper-Probleme zu umgehen und sie zu cachen.

2. **Überschreiben der NIB-Datei**:
- Ersetze eine vorhandene NIB-Datei (z. B. About Panel NIB) durch die erstellte DirtyNIB-Datei.

3. **Ausführung**:
- Trigger die Ausführung, indem du mit der App interagierst (z. B. das Menüelement `Über` auswählst).

#### Proof of Concept: Zugriff auf Benutzerdaten
- Ändere das AppleScript, um auf Benutzerdaten zuzugreifen und diese zu extrahieren, z. B. Fotos, ohne die Zustimmung des Benutzers.

### Codebeispiel: Bösartige .xib-Datei
- Greife auf eine [**Beispiel einer bösartigen .xib-Datei**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) zu, die das Ausführen willkürlichen Codes demonstriert.

### Umgang mit Startbeschränkungen
- Startbeschränkungen hindern die Ausführung von Apps aus unerwarteten Orten (z. B. `/tmp`).
- Es ist möglich, Apps zu identifizieren, die nicht durch Startbeschränkungen geschützt sind, und sie für die NIB-Datei-Injektion anzuvisieren.

### Zusätzliche macOS-Schutzmaßnahmen
Seit macOS Sonoma sind Änderungen innerhalb von App-Bundles eingeschränkt. Frühere Methoden umfassten:
1. Kopieren der App an einen anderen Ort (z. B. `/tmp/`).
2. Umbenennen von Verzeichnissen innerhalb des App-Bundles, um anfängliche Schutzmaßnahmen zu umgehen.
3. Nach dem Ausführen der App, um sich bei Gatekeeper zu registrieren, das App-Bundle ändern (z. B. Ersetzen von MainMenu.nib durch Dirty.nib).
4. Verzeichnisse zurückbenennen und die App erneut ausführen, um die injizierte NIB-Datei auszuführen.

**Hinweis**: Neuere macOS-Updates haben diesen Exploit gemildert, indem sie Dateiänderungen innerhalb von App-Bundles nach dem Caching durch Gatekeeper verhindern, wodurch der Exploit unwirksam wird.


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
