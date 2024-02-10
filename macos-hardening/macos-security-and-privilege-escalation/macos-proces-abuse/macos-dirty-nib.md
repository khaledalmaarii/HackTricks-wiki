# macOS Dirty NIB

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

**Für weitere Details zur Technik lesen Sie den Originalbeitrag unter: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** Hier ist eine Zusammenfassung:

NIB-Dateien, Teil des Apple-Entwicklungsumfelds, dienen zur Definition von **UI-Elementen** und deren Interaktionen in Anwendungen. Sie umfassen serialisierte Objekte wie Fenster und Schaltflächen und werden zur Laufzeit geladen. Obwohl sie weiterhin verwendet werden, empfiehlt Apple jetzt Storyboards für eine umfassendere Visualisierung des UI-Flusses.

### Sicherheitsbedenken bei NIB-Dateien
Es ist wichtig zu beachten, dass **NIB-Dateien ein Sicherheitsrisiko darstellen** können. Sie haben das Potenzial, **beliebige Befehle auszuführen**, und Änderungen an NIB-Dateien innerhalb einer App hindern Gatekeeper nicht daran, die App auszuführen, was eine erhebliche Bedrohung darstellt.

### Dirty NIB-Injektionsprozess
#### Erstellen und Einrichten einer NIB-Datei
1. **Erstmalige Einrichtung**:
- Erstellen Sie eine neue NIB-Datei mit XCode.
- Fügen Sie ein Objekt zur Oberfläche hinzu und setzen Sie seine Klasse auf `NSAppleScript`.
- Konfigurieren Sie das anfängliche `source`-Attribut über benutzerdefinierte Laufzeitattribute.

2. **Code-Ausführungsgadget**:
- Die Einrichtung ermöglicht das Ausführen von AppleScript auf Abruf.
- Integrieren Sie eine Schaltfläche, um das `Apple Script`-Objekt zu aktivieren und den `executeAndReturnError:`-Selektor spezifisch auszulösen.

3. **Testen**:
- Ein einfaches AppleScript zum Testen:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Testen Sie, indem Sie es im XCode-Debugger ausführen und auf die Schaltfläche klicken.

#### Ausrichtung auf eine Anwendung (Beispiel: Pages)
1. **Vorbereitung**:
- Kopieren Sie die Ziel-App (z. B. Pages) in ein separates Verzeichnis (z. B. `/tmp/`).
- Starten Sie die App, um Gatekeeper-Probleme zu umgehen und sie zu cachen.

2. **Überschreiben der NIB-Datei**:
- Ersetzen Sie eine vorhandene NIB-Datei (z. B. About Panel NIB) durch die erstellte DirtyNIB-Datei.

3. **Ausführung**:
- Starten Sie die Ausführung, indem Sie mit der App interagieren (z. B. das Menüelement `About` auswählen).

#### Proof of Concept: Zugriff auf Benutzerdaten
- Ändern Sie das AppleScript, um auf Benutzerdaten zuzugreifen und sie ohne Zustimmung des Benutzers zu extrahieren, z. B. Fotos.

### Codebeispiel: Bösartige .xib-Datei
- Greifen Sie auf eine [**Beispiel einer bösartigen .xib-Datei**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) zu, die die Ausführung beliebigen Codes demonstriert.

### Umgang mit Startbeschränkungen
- Startbeschränkungen verhindern die Ausführung von Apps an unerwarteten Orten (z. B. `/tmp`).
- Es ist möglich, Apps zu identifizieren, die nicht durch Startbeschränkungen geschützt sind, und sie für die Injektion von NIB-Dateien anzugreifen.

### Weitere macOS-Schutzmaßnahmen
Ab macOS Sonoma sind Änderungen innerhalb von App-Bundles eingeschränkt. Frühere Methoden umfassten jedoch:
1. Kopieren der App an einen anderen Ort (z. B. `/tmp/`).
2. Umbenennen von Verzeichnissen innerhalb des App-Bundles, um anfängliche Schutzmaßnahmen zu umgehen.
3. Nach dem Ausführen der App zur Registrierung bei Gatekeeper das App-Bundle ändern (z. B. MainMenu.nib durch Dirty.nib ersetzen).
4. Umbenennen der Verzeichnisse zurück und erneutes Ausführen der App zur Ausführung der injizierten NIB-Datei.

**Hinweis**: Aktuelle macOS-Updates haben diesen Exploit durch die Verhinderung von Dateiänderungen innerhalb von App-Bundles nach dem Gatekeeper-Caching abgeschwächt, wodurch der Exploit unwirksam wird.


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
