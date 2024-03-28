# macOS-Bundles

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandising**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

## Grundlegende Informationen

Bundles in macOS dienen als Container für verschiedene Ressourcen, einschließlich Anwendungen, Bibliotheken und anderen erforderlichen Dateien, die sie im Finder als einzelne Objekte erscheinen lassen, wie die vertrauten `*.app`-Dateien. Das am häufigsten verwendete Bundle ist das `.app`-Bundle, obwohl auch andere Typen wie `.framework`, `.systemextension` und `.kext` weit verbreitet sind.

### Wesentliche Komponenten eines Bundles

Innerhalb eines Bundles, insbesondere innerhalb des `<Anwendung>.app/Contents/`-Verzeichnisses, sind verschiedene wichtige Ressourcen untergebracht:

* **\_CodeSignature**: Dieses Verzeichnis speichert wichtige Code-Signaturdetails zur Überprüfung der Integrität der Anwendung. Sie können die Code-Signaturinformationen mit Befehlen wie überprüfen: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Enthält das ausführbare Binär der Anwendung, das bei Benutzerinteraktion ausgeführt wird.
* **Ressourcen**: Ein Repository für die Benutzeroberflächenkomponenten der Anwendung, einschließlich Bilder, Dokumente und Schnittstellenbeschreibungen (nib/xib-Dateien).
* **Info.plist**: Dient als Hauptkonfigurationsdatei der Anwendung, die für das System entscheidend ist, um die Anwendung angemessen zu erkennen und mit ihr zu interagieren.

#### Wichtige Schlüssel in Info.plist

Die Datei `Info.plist` ist ein Eckpfeiler für die Anwendungskonfiguration und enthält Schlüssel wie:

* **CFBundleExecutable**: Gibt den Namen der Hauptausführungsdatei im Verzeichnis `Contents/MacOS` an.
* **CFBundleIdentifier**: Bietet einen globalen Bezeichner für die Anwendung, der von macOS umfangreich für die Anwendungsverwaltung verwendet wird.
* **LSMinimumSystemVersion**: Gibt die minimale macOS-Version an, die für das Ausführen der Anwendung erforderlich ist.

### Erkunden von Bundles

Um den Inhalt eines Bundles wie `Safari.app` zu erkunden, kann der folgende Befehl verwendet werden: `bash ls -lR /Applications/Safari.app/Contents`

Diese Erkundung zeigt Verzeichnisse wie `_CodeSignature`, `MacOS`, `Ressourcen` und Dateien wie `Info.plist`, die jeweils einen einzigartigen Zweck von der Sicherung der Anwendung bis zur Definition ihrer Benutzeroberfläche und Betriebsparameter erfüllen.

#### Zusätzliche Bundle-Verzeichnisse

Über die üblichen Verzeichnisse hinaus können Bundles auch enthalten:

* **Frameworks**: Enthält gebündelte Frameworks, die von der Anwendung verwendet werden. Frameworks sind wie dylibs mit zusätzlichen Ressourcen.
* **PlugIns**: Ein Verzeichnis für Plug-Ins und Erweiterungen, die die Fähigkeiten der Anwendung erweitern.
* **XPCServices**: Enthält XPC-Dienste, die von der Anwendung für die Kommunikation außerhalb des Prozesses verwendet werden.

Diese Struktur gewährleistet, dass alle erforderlichen Komponenten innerhalb des Bundles eingeschlossen sind und eine modulare und sichere Anwendungsumgebung ermöglichen.

Für weitere detaillierte Informationen zu `Info.plist`-Schlüsseln und deren Bedeutung bietet die Apple-Entwicklerdokumentation umfangreiche Ressourcen: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandising**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>
