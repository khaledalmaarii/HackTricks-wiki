# macOS Sandbox

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## Grundlegende Informationen

Der macOS Sandbox (ursprünglich Seatbelt genannt) **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die in dem Sandbox-Profil festgelegten zulässigen Aktionen. Dadurch wird sichergestellt, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.

Jede App mit der **Berechtigung** **`com.apple.security.app-sandbox`** wird innerhalb der Sandbox ausgeführt. **Apple-Binärdateien** werden normalerweise innerhalb einer Sandbox ausgeführt und um sie im **App Store** zu veröffentlichen, ist diese Berechtigung **obligatorisch**. Daher werden die meisten Anwendungen innerhalb der Sandbox ausgeführt.

Um zu kontrollieren, was ein Prozess tun kann oder nicht, hat die Sandbox **Hooks** in allen **Syscalls** im Kernel. **Abhängig** von den **Berechtigungen** der App erlaubt die Sandbox bestimmte Aktionen.

Einige wichtige Komponenten der Sandbox sind:

* Die **Kernel-Erweiterung** `/System/Library/Extensions/Sandbox.kext`
* Das **private Framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Ein **Daemon**, der in Userland läuft `/usr/libexec/sandboxd`
* Die **Container** `~/Library/Containers`

Im Ordner "Containers" finden Sie **einen Ordner für jede in der Sandbox ausgeführte App** mit dem Namen der Bundle-ID:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
In jedem Bundle-ID-Ordner finden Sie die **plist** und das **Datenverzeichnis** der App:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Beachten Sie, dass selbst wenn die symbolischen Links vorhanden sind, um aus dem Sandbox auszubrechen und auf andere Ordner zuzugreifen, die App immer noch **Berechtigungen haben muss**, um auf sie zuzugreifen. Diese Berechtigungen befinden sich in der **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Alles, was von einer Sandbox-Anwendung erstellt/geändert wird, erhält das **Quarantäneattribut**. Dadurch wird verhindert, dass eine Sandbox-Umgebung ausgelöst wird, wenn die Sandbox-App versucht, etwas mit **`open`** auszuführen.
{% endhint %}

### Sandbox-Profile

Die Sandbox-Profile sind Konfigurationsdateien, die angeben, was in dieser **Sandbox** **erlaubt/verboten** ist. Es verwendet die **Sandbox Profile Language (SBPL)**, die die [**Scheme**](https://de.wikipedia.org/wiki/Scheme)-Programmiersprache verwendet.

Hier finden Sie ein Beispiel:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Überprüfen Sie diese [**Forschung**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **um weitere Aktionen zu überprüfen, die erlaubt oder verweigert werden könnten.**
{% endhint %}

Wichtige **Systemdienste** laufen auch in ihrer eigenen benutzerdefinierten **Sandbox**, wie z.B. der Dienst `mdnsresponder`. Sie können diese benutzerdefinierten **Sandbox-Profile** anzeigen unter:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Weitere Sandbox-Profile können unter [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) überprüft werden.

**App Store**-Apps verwenden das Profil **`/System/Library/Sandbox/Profiles/application.sb`**. In diesem Profil können Sie überprüfen, wie Berechtigungen wie **`com.apple.security.network.server`** einem Prozess die Nutzung des Netzwerks ermöglichen.

SIP ist ein Sandbox-Profil namens platform\_profile in /System/Library/Sandbox/rootless.conf

### Beispiele für Sandbox-Profile

Um eine Anwendung mit einem **spezifischen Sandbox-Profil** zu starten, können Sie verwenden:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))
```

Dieses Sandbox-Profil erlaubt das Lesen und Schreiben von Metadaten und Daten für die Datei "/path/to/file". Alle anderen Aktionen sind standardmäßig verboten.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Beachten Sie, dass die von Apple entwickelte Software, die auf Windows läuft, keine zusätzlichen Sicherheitsvorkehrungen wie Anwendungssandboxing hat.
{% endhint %}

Beispiel für Umgehungen:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sie können Dateien außerhalb der Sandbox schreiben, deren Name mit `~$` beginnt).

### MacOS Sandbox-Profile

macOS speichert System-Sandbox-Profile an zwei Orten: **/usr/share/sandbox/** und **/System/Library/Sandbox/Profiles**.

Und wenn eine Drittanbieteranwendung die Berechtigung _**com.apple.security.app-sandbox**_ hat, wendet das System das Profil **/System/Library/Sandbox/Profiles/application.sb** auf diesen Prozess an.

### **iOS Sandbox-Profil**

Das Standardprofil heißt **container** und wir haben keine textuelle Darstellung des SBPL. Im Speicher wird diese Sandbox als Allow/Deny-Baum für jede Berechtigung aus der Sandbox dargestellt.

### Debuggen und Umgehen der Sandbox

Auf macOS, im Gegensatz zu iOS, wo Prozesse von Anfang an vom Kernel in einer Sandbox ausgeführt werden, **müssen Prozesse sich selbst für die Sandbox entscheiden**. Das bedeutet, dass auf macOS ein Prozess nicht durch die Sandbox eingeschränkt ist, bis er aktiv beschließt, in sie einzutreten.

Prozesse werden automatisch in der Benutzerland-Sandbox ausgeführt, wenn sie die Berechtigung `com.apple.security.app-sandbox` haben. Für eine ausführliche Erklärung dieses Prozesses siehe:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Überprüfen der PID-Berechtigungen**

[**Gemäß diesem**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s) Video kann **`sandbox_check`** (es handelt sich um einen `__mac_syscall`) überprüfen, ob eine Operation in einer bestimmten PID von der Sandbox erlaubt ist oder nicht.

Das [**Tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) kann überprüfen, ob eine PID eine bestimmte Aktion ausführen kann:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Benutzerdefinierte SBPL in App Store Apps

Es könnte für Unternehmen möglich sein, ihre Apps mit benutzerdefinierten Sandbox-Profilen (anstatt mit dem Standardprofil) auszuführen. Sie müssen die Berechtigung **`com.apple.security.temporary-exception.sbpl`** verwenden, die von Apple autorisiert werden muss.

Es ist möglich, die Definition dieser Berechtigung in **`/System/Library/Sandbox/Profiles/application.sb:`** zu überprüfen.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Dies wird den String nach dieser Berechtigung als Sandbox-Profil **auswerten**.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
