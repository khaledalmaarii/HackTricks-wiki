# macOS Installationsmissbrauch

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den HackTricks- und HackTricks Cloud-GitHub-Repositories einreichen.

</details>

## Grundlegende Informationen zu Pkg

Ein macOS-Installationspaket (auch als `.pkg`-Datei bekannt) ist ein Dateiformat, das von macOS verwendet wird, um Software zu verteilen. Diese Dateien sind wie eine Box, die alles enthält, was eine Software zum Installieren und Ausführen benötigt.

Die Paketdatei selbst ist ein Archiv, das eine Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden sollen. Es kann auch Skripte enthalten, um Aufgaben vor und nach der Installation auszuführen, wie z.B. das Einrichten von Konfigurationsdateien oder das Bereinigen alter Versionen der Software.

### Hierarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Anpassungen (Titel, Willkommenstext...) und Skript/Installationsprüfungen
- **PackageInfo (xml)**: Informationen, Installationsanforderungen, Installationsort, Pfade zu auszuführenden Skripten
- **Bill of materials (bom)**: Liste der zu installierenden, zu aktualisierenden oder zu entfernenden Dateien mit Dateiberechtigungen
- **Payload (CPIO-Archiv gzip-komprimiert)**: Dateien, die im `install-location` aus PackageInfo installiert werden sollen
- **Skripte (CPIO-Archiv gzip-komprimiert)**: Vor- und Nachinstallations-Skripte und weitere Ressourcen, die zum Ausführen in ein temporäres Verzeichnis extrahiert werden.

### Dekomprimieren
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## DMG Grundlegende Informationen

DMG-Dateien oder Apple Disk Images sind ein Dateiformat, das von Apples macOS für Disk-Images verwendet wird. Eine DMG-Datei ist im Wesentlichen ein **einbindbares Disk-Image** (es enthält sein eigenes Dateisystem), das in der Regel komprimierte und manchmal verschlüsselte Rohblockdaten enthält. Wenn Sie eine DMG-Datei öffnen, mountet macOS sie wie eine physische Festplatte und ermöglicht Ihnen den Zugriff auf deren Inhalte.

### Hierarchie

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Die Hierarchie einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Bei Anwendungs-DMGs folgt sie jedoch in der Regel dieser Struktur:

* Top-Level: Dies ist die Wurzel des Disk-Images. Es enthält oft die Anwendung und möglicherweise einen Link zum Ordner "Programme".
* Anwendung (.app): Dies ist die eigentliche Anwendung. In macOS ist eine Anwendung in der Regel ein Paket, das viele einzelne Dateien und Ordner enthält, die die Anwendung ausmachen.
* Anwendungslink: Dies ist eine Verknüpfung zum Ordner "Programme" in macOS. Der Zweck besteht darin, die Installation der Anwendung zu erleichtern. Sie können die .app-Datei zu dieser Verknüpfung ziehen, um die App zu installieren.

## Privilege Escalation durch Missbrauch von pkg

### Ausführung aus öffentlichen Verzeichnissen

Wenn beispielsweise ein Vor- oder Nachinstallations-Skript aus **`/var/tmp/Installerutil`** ausgeführt wird und ein Angreifer dieses Skript kontrollieren kann, kann er Berechtigungen eskalieren, wann immer es ausgeführt wird. Oder ein ähnliches Beispiel:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [öffentliche Funktion](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die von mehreren Installationsprogrammen und Updatern aufgerufen wird, um etwas als Root auszuführen. Diese Funktion akzeptiert den **Pfad** der **Datei**, die als Parameter **ausgeführt** werden soll. Wenn ein Angreifer jedoch diese Datei **ändern** kann, kann er ihre Ausführung mit Root-Rechten **missbrauchen**, um Berechtigungen zu eskalieren.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Für weitere Informationen schauen Sie sich diesen Vortrag an: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Ausführung durch Mounting

Wenn ein Installer in `/tmp/fixedname/bla/bla` schreibt, ist es möglich, einen **Mount** über `/tmp/fixedname` ohne Besitzer zu erstellen, sodass Sie während der Installation **beliebige Dateien ändern** können, um den Installationsprozess zu missbrauchen.

Ein Beispiel dafür ist **CVE-2021-26089**, bei dem es gelungen ist, ein periodisches Skript zu überschreiben, um als Root ausgeführt zu werden. Für weitere Informationen werfen Sie einen Blick auf den Vortrag: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg als Malware

### Leerer Payload

Es ist möglich, eine **`.pkg`**-Datei nur mit **vor- und nachinstallierten Skripten** ohne Payload zu generieren.

### JS in Distribution xml

Es ist möglich, **`<script>`**-Tags in der **Distribution-XML**-Datei des Pakets hinzuzufügen, und dieser Code wird ausgeführt und kann Befehle mit **`system.run`** ausführen:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referenzen

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
