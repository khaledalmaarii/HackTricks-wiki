# macOS-Bundles

{% hint style="success" %}
Lernen & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Grundlegende Informationen

Bundles in macOS dienen als Container für verschiedene Ressourcen, einschließlich Anwendungen, Bibliotheken und anderen erforderlichen Dateien, die sie im Finder als einzelne Objekte erscheinen lassen, wie die vertrauten `*.app`-Dateien. Das am häufigsten verwendete Bundle ist das `.app`-Bundle, obwohl auch andere Typen wie `.framework`, `.systemextension` und `.kext` verbreitet sind.

### Wesentliche Komponenten eines Bundles

Innerhalb eines Bundles, insbesondere innerhalb des `<Anwendung>.app/Contents/`-Verzeichnisses, sind verschiedene wichtige Ressourcen untergebracht:

* **\_CodeSignature**: Dieses Verzeichnis speichert wichtige Code-Signaturdetails zur Überprüfung der Integrität der Anwendung. Sie können die Code-Signaturinformationen mit Befehlen wie überprüfen: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Enthält das ausführbare Binär der Anwendung, das bei Benutzerinteraktion ausgeführt wird.
* **Ressourcen**: Ein Repository für die Benutzeroberflächenkomponenten der Anwendung, einschließlich Bilder, Dokumente und Schnittstellenbeschreibungen (nib/xib-Dateien).
* **Info.plist**: Dient als Hauptkonfigurationsdatei der Anwendung, die für das System entscheidend ist, um die Anwendung angemessen zu erkennen und mit ihr zu interagieren.

#### Wichtige Schlüssel in Info.plist

Die Datei `Info.plist` ist ein Eckpfeiler für die Anwendungskonfiguration und enthält Schlüssel wie:

* **CFBundleExecutable**: Gibt den Namen der Hauptausführungsdatei an, die sich im Verzeichnis `Contents/MacOS` befindet.
* **CFBundleIdentifier**: Bietet einen globalen Bezeichner für die Anwendung, der von macOS umfangreich für die Anwendungsverwaltung verwendet wird.
* **LSMinimumSystemVersion**: Gibt die minimale macOS-Version an, die für das Ausführen der Anwendung erforderlich ist.

### Erkunden von Bundles

Um den Inhalt eines Bundles wie `Safari.app` zu erkunden, kann der folgende Befehl verwendet werden: `bash ls -lR /Applications/Safari.app/Contents`

Diese Erkundung zeigt Verzeichnisse wie `_CodeSignature`, `MacOS`, `Ressourcen` und Dateien wie `Info.plist`, die jeweils einen einzigartigen Zweck von der Sicherung der Anwendung bis zur Definition ihrer Benutzeroberfläche und Betriebsparameter erfüllen.

#### Zusätzliche Bundle-Verzeichnisse

Über die üblichen Verzeichnisse hinaus können Bundles auch enthalten:

* **Frameworks**: Enthält gebündelte Frameworks, die von der Anwendung verwendet werden. Frameworks sind wie dylibs mit zusätzlichen Ressourcen.
* **PlugIns**: Ein Verzeichnis für Plug-Ins und Erweiterungen, die die Fähigkeiten der Anwendung verbessern.
* **XPCServices**: Enthält XPC-Dienste, die von der Anwendung für die Kommunikation außerhalb des Prozesses verwendet werden.

Diese Struktur gewährleistet, dass alle erforderlichen Komponenten im Bundle eingeschlossen sind und eine modulare und sichere Anwendungsumgebung ermöglichen.

Für weitere detaillierte Informationen zu `Info.plist`-Schlüsseln und deren Bedeutung bietet die Apple-Entwicklerdokumentation umfangreiche Ressourcen: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Lernen & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}
