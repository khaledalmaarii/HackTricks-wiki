# macOS Installers Missbrauch

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Pkg Grundlegende Informationen

Ein macOS **Installationspaket** (auch bekannt als `.pkg`-Datei) ist ein Dateiformat, das von macOS verwendet wird, um **Software zu verteilen**. Diese Dateien sind wie eine **Box, die alles enthält, was eine Software** benötigt, um korrekt installiert und ausgeführt zu werden.

Die Paketdatei selbst ist ein Archiv, das eine **Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden sollen**. Es kann auch **Skripte** enthalten, um Aufgaben vor und nach der Installation auszuführen, wie z. B. Konfigurationsdateien einzurichten oder alte Versionen der Software zu bereinigen.

### Hierarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Anpassungen (Titel, Willkommens-Text...) und Skript/Installationsprüfungen
* **PackageInfo (xml)**: Informationen, Installationsanforderungen, Installationsort, Pfade zu auszuführenden Skripten
* **Materialliste (bom)**: Liste der Dateien, die installiert, aktualisiert oder entfernt werden sollen, mit Dateiberechtigungen
* **Payload (CPIO-Archiv gzip-komprimiert)**: Dateien, die im `install-location` aus PackageInfo installiert werden sollen
* **Skripte (CPIO-Archiv gzip-komprimiert)**: Vor- und Nachinstallations-Skripte und weitere Ressourcen, die in ein temporäres Verzeichnis extrahiert werden, um ausgeführt zu werden.

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
Um den Inhalt des Installers ohne manuelles Entpacken zu visualisieren, können Sie auch das kostenlose Tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) verwenden.

## DMG Grundinformationen

DMG-Dateien oder Apple Disk Images sind ein Dateiformat, das von Apples macOS für Festplattenabbilder verwendet wird. Eine DMG-Datei ist im Wesentlichen ein **einbindbares Festplattenabbild** (es enthält sein eigenes Dateisystem), das rohe Blockdaten enthält, die typischerweise komprimiert und manchmal verschlüsselt sind. Wenn Sie eine DMG-Datei öffnen, **bindet macOS sie ein, als ob es sich um eine physische Festplatte handeln würde**, und ermöglicht Ihnen den Zugriff auf deren Inhalt.

{% hint style="danger" %}
Beachten Sie, dass **`.dmg`**-Installer **so viele Formate** unterstützen, dass in der Vergangenheit einige von ihnen mit Schwachstellen missbraucht wurden, um **Kernelcodeausführung** zu erlangen.
{% endhint %}

### Hierarchie

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Die Hierarchie einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Für Anwendungs-DMGs folgt sie jedoch in der Regel dieser Struktur:

* Top-Level: Dies ist die Wurzel des Festplattenabbilds. Es enthält oft die Anwendung und möglicherweise einen Link zum Ordner "Programme".
* Anwendung (.app): Dies ist die tatsächliche Anwendung. In macOS ist eine Anwendung in der Regel ein Paket, das viele einzelne Dateien und Ordner enthält, die die Anwendung ausmachen.
* Anwendungslink: Dies ist eine Verknüpfung zum Ordner "Programme" in macOS. Der Zweck besteht darin, es Ihnen zu erleichtern, die Anwendung zu installieren. Sie können die .app-Datei zu dieser Verknüpfung ziehen, um die App zu installieren.

## Privilege Escalation durch pkg-Missbrauch

### Ausführung aus öffentlichen Verzeichnissen

Wenn beispielsweise ein Vor- oder Nachinstallations-Skript aus **`/var/tmp/Installerutil`** ausgeführt wird und ein Angreifer dieses Skript kontrollieren könnte, könnte er Berechtigungen eskalieren, wann immer es ausgeführt wird. Oder ein ähnliches Beispiel:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [öffentliche Funktion](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die von mehreren Installationsprogrammen und Updatern aufgerufen wird, um **etwas als Root auszuführen**. Diese Funktion akzeptiert den **Pfad** der **Datei**, die als Parameter **ausgeführt** werden soll. Wenn ein Angreifer jedoch diese Datei **ändern** könnte, könnte er deren Ausführung mit Root-Rechten **missbrauchen**, um Berechtigungen zu **eskaliere**n.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Ausführung durch Einhängen

Wenn ein Installer nach `/tmp/fixedname/bla/bla` schreibt, ist es möglich, **ein Mount über** `/tmp/fixedname` ohne Besitzer zu erstellen, sodass Sie **während der Installation jede Datei ändern** können, um den Installationsprozess zu missbrauchen.

Ein Beispiel hierfür ist **CVE-2021-26089**, bei dem es gelungen ist, **ein periodisches Skript zu überschreiben**, um die Ausführung als Root zu erhalten. Für weitere Informationen schauen Sie sich den Vortrag an: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg als Malware

### Leerer Payload

Es ist möglich, einfach eine **`.pkg`**-Datei mit **Vor- und Nachinstallations-Skripten** ohne Payload zu generieren.

### JS in Distribution-XML

Es ist möglich, **`<script>`**-Tags in der **Distribution-XML**-Datei des Pakets hinzuzufügen, und dieser Code wird ausgeführt, um Befehle mit **`system.run`** auszuführen:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Referenzen

* [**DEF CON 27 - Entpacken von Pkgs Ein Blick in macOS-Installationspakete und häufige Sicherheitslücken**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Die wilde Welt der macOS-Installer" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Entpacken von Pkgs Ein Blick in macOS-Installationspakete**](https://www.youtube.com/watch?v=kCXhIYtODBg)
