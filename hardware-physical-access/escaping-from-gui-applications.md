<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Engine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

# Überprüfen möglicher Aktionen innerhalb der GUI-Anwendung

**Gängige Dialogfelder** sind Optionen zum **Speichern einer Datei**, **Öffnen einer Datei**, Auswahl einer Schriftart, einer Farbe... Die meisten von ihnen bieten eine vollständige Explorer-Funktionalität. Dies bedeutet, dass Sie auf Explorer-Funktionalitäten zugreifen können, wenn Sie auf diese Optionen zugreifen können:

* Schließen/Schließen als
* Öffnen/Öffnen mit
* Drucken
* Exportieren/Importieren
* Suchen
* Scannen

Sie sollten überprüfen, ob Sie können:

* Dateien ändern oder neue erstellen
* Symbolische Links erstellen
* Zugriff auf eingeschränkte Bereiche erhalten
* Andere Apps ausführen

## Befehlsausführung

Vielleicht können Sie **über die Option `Öffnen mit`** eine Art Shell öffnen/ausführen.

### Windows

Zum Beispiel _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ finden Sie weitere Binärdateien, die zur Ausführung von Befehlen (und zur Durchführung unerwarteter Aktionen) verwendet werden können, hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Mehr hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Umgehen von Pfadbeschränkungen

* **Umgebungsvariablen**: Es gibt viele Umgebungsvariablen, die auf einen bestimmten Pfad verweisen
* **Andere Protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Symbolische Links**
* **Verknüpfungen**: STRG+N (neue Sitzung öffnen), STRG+R (Befehle ausführen), STRG+UMSCHALT+ESC (Task-Manager),  Windows+E (Explorer öffnen), STRG-B, STRG-I (Favoriten), STRG-H (Verlauf), STRG-L, STRG-O (Datei/Öffnen-Dialog), STRG-P (Druckdialog), STRG-S (Speichern unter)
* Verstecktes Administrationsmenü: STRG-ALT-F8, STRG-ESC-F9
* **Shell-URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC-Pfade**: Pfade zum Verbinden mit freigegebenen Ordnern. Sie sollten versuchen, sich mit dem C$ des lokalen Computers zu verbinden ("\\\127.0.0.1\c$\Windows\System32")
* **Weitere UNC-Pfade:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Laden Sie Ihre Binärdateien herunter

Konsole: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registrierungseditor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Dateisystemzugriff über den Browser

| PFAD                | PFAD              | PFAD               | PFAD                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Verknüpfungen

* Sticky Keys – SHIFT 5 Mal drücken
* Mouse Keys – SHIFT+ALT+NUMLOCK
* Hoher Kontrast – SHIFT+ALT+PRINTSCN
* Umschalttasten – NUMLOCK 5 Sekunden gedrückt halten
* Filtertasten – Rechte UMSCHALT 12 Sekunden gedrückt halten
* WINDOWS+F1 – Windows-Suche
* WINDOWS+D – Desktop anzeigen
* WINDOWS+E – Windows Explorer starten
* WINDOWS+R – Ausführen
* WINDOWS+U – Center für Erleichterte Bedienung
* WINDOWS+F – Suche
* SHIFT+F10 – Kontextmenü
* STRG+UMSCHALT+ESC – Task-Manager
* STRG+ALT+ENTF – Startbildschirm bei neueren Windows-Versionen
* F1 – Hilfe F3 – Suche
* F6 – Adressleiste
* F11 – Vollbildmodus innerhalb des Internet Explorers
* STRG+H – Internet Explorer-Verlauf
* STRG+T – Internet Explorer – Neuer Tab
* STRG+N – Internet Explorer – Neue Seite
* STRG+O – Datei öffnen
* STRG+S – Speichern STRG+N – Neuer RDP / Citrix
## Wischgesten

* Wischen Sie von der linken Seite nach rechts, um alle geöffneten Fenster zu sehen, minimieren Sie die KIOSK-App und greifen Sie direkt auf das gesamte Betriebssystem zu;
* Wischen Sie von der rechten Seite nach links, um das Aktionscenter zu öffnen, minimieren Sie die KIOSK-App und greifen Sie direkt auf das gesamte Betriebssystem zu;
* Wischen Sie vom oberen Rand, um die Titelleiste für eine App im Vollbildmodus sichtbar zu machen;
* Wischen Sie von unten nach oben, um die Taskleiste in einer App im Vollbildmodus anzuzeigen.

## Internet Explorer Tricks

### 'Bildsymbolleiste'

Es handelt sich um eine Symbolleiste, die oben links auf dem Bild erscheint, wenn darauf geklickt wird. Sie können Speichern, Drucken, Mailen, "Meine Bilder" im Explorer öffnen. Der Kiosk muss Internet Explorer verwenden.

### Shell-Protokoll

Geben Sie diese URLs ein, um eine Explorer-Ansicht zu erhalten:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Systemsteuerung
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mein Computer
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Meine Netzwerkumgebung
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Dateierweiterungen anzeigen

Überprüfen Sie diese Seite für weitere Informationen: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Browser-Tricks

Backup iKat-Versionen:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Erstellen Sie einen gemeinsamen Dialog mit JavaScript und greifen Sie auf den Datei-Explorer zu: `document.write('<input/type=file>')`
Quelle: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gesten und Tasten

* Wischen Sie mit vier (oder fünf) Fingern nach oben / Doppelklicken Sie auf die Home-Taste: Um die Multitasking-Ansicht anzuzeigen und die App zu wechseln

* Wischen Sie mit vier oder fünf Fingern in eine Richtung: Um zur nächsten/vorherigen App zu wechseln

* Zoomen Sie mit fünf Fingern auf den Bildschirm / Berühren Sie die Home-Taste / Wischen Sie mit einem Finger von unten schnell nach oben auf dem Bildschirm: Um auf den Startbildschirm zuzugreifen

* Wischen Sie mit einem Finger langsam 1-2 Zoll von unten nach oben auf dem Bildschirm: Das Dock wird angezeigt

* Wischen Sie mit einem Finger von oben auf dem Display nach unten: Um Ihre Benachrichtigungen anzuzeigen

* Wischen Sie mit einem Finger von der oberen rechten Ecke des Bildschirms nach unten: Um das Steuerzentrum des iPad Pro anzuzeigen

* Wischen Sie mit einem Finger 1-2 Zoll von links auf dem Bildschirm: Um die Ansicht für heute anzuzeigen

* Wischen Sie schnell mit einem Finger von der Mitte des Bildschirms nach rechts oder links: Um zur nächsten/vorherigen App zu wechseln

* Drücken und halten Sie die Ein/**Aus**/Standby-Taste in der oberen rechten Ecke des **iPad +** Bewegen Sie den Schieberegler zum **Ausschalten** ganz nach rechts: Zum Ausschalten

* Drücken Sie die Ein/**Aus**/Standby-Taste in der oberen rechten Ecke des **iPad und die Home-Taste für einige Sekunden**: Zum erzwingen eines harten Ausschaltens

* Drücken Sie die Ein/**Aus**/Standby-Taste in der oberen rechten Ecke des **iPad und die Home-Taste schnell**: Um einen Screenshot zu machen, der unten links auf dem Display erscheint. Drücken Sie beide Tasten gleichzeitig sehr kurz, als ob Sie sie einige Sekunden lang gedrückt halten würden, wird ein erzwungenes Ausschalten durchgeführt.

## Verknüpfungen

Sie sollten eine iPad-Tastatur oder einen USB-Tastaturadapter haben. Es werden nur Verknüpfungen angezeigt, die beim Verlassen der Anwendung helfen könnten.

| Taste | Name         |
| --- | ------------ |
| ⌘   | Befehl      |
| ⌥   | Option (Alt) |
| ⇧   | Umschalt        |
| ↩   | Eingabe       |
| ⇥   | Tabulatortaste          |
| ^   | Steuerung      |
| ←   | Linke Pfeiltaste   |
| →   | Rechte Pfeiltaste  |
| ↑   | Obere Pfeiltaste     |
| ↓   | Untere Pfeiltaste   |

### Systemverknüpfungen

Diese Verknüpfungen sind für die visuellen Einstellungen und Soundeinstellungen, abhängig von der Verwendung des iPads.

| Verknüpfung | Aktion                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Bildschirm verdunkeln                                                                    |
| F2       | Bildschirm erhellen                                                                |
| F7       | Zurück zum vorherigen Song                                                                  |
| F8       | Wiedergabe/Pause                                                                     |
| F9       | Nächster Song                                                                      |
| F10      | Stummschalten                                                                           |
| F11      | Lautstärke verringern                                                                |
| F12      | Lautstärke erhöhen                                                                |
| ⌘ Leertaste  | Eine Liste der verfügbaren Sprachen anzeigen; um eine auszuwählen, tippen Sie erneut auf die Leertaste. |

### iPad-Navigation

| Verknüpfung                                           | Aktion                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Zum Startbildschirm gehen                                              |
| ⌘⇧H (Befehl-Umschalt-H)                              | Zum Startbildschirm gehen                                              |
| ⌘ (Leertaste)                                          | Spotlight öffnen                                          |
| ⌘⇥ (Befehl-Tabulatortaste)                                   | Liste der zuletzt verwendeten Apps anzeigen                                 |
| ⌘\~                                                | Zur letzten App gehen                                       |
| ⌘⇧3 (Befehl-Umschalt-3)                              | Screenshot (erscheint unten links zum Speichern oder Bearbeiten) |
| ⌘⇧4                                                | Screenshot machen und im Editor öffnen                    |
| ⌘ gedrückt halten                                   | Liste der für die App verfügbaren Verknüpfungen                 |
| ⌘⌥D (Befehl-Option/Alt-D)                         | Das Dock aufrufen                                      |
| ^⌥H (Steuerung-Option-H)                             | Home-Taste                                             |
| ^⌥H H (Steuerung-Option-H-H)                         | Multitasking-Leiste anzeigen                                      |
| ^⌥I (Steuerung-Option-i)                             | Elementauswahl                                            |
| Escape                                             | Zurück-Taste                                             |
| → (Rechte Pfeiltaste)                                    | Nächstes Element                                               |
| ← (Linke Pfeiltaste)                                     | Vorheriges Element                                           |
| ↑↓ (Obere Pfeiltaste, Untere Pfeiltaste)                          | Gleichzeitig auf das ausgewählte Element tippen                        |
| ⌥ ↓ (Option-Untere Pfeiltaste)                            | Nach unten scrollen                                             |
| ⌥↑ (Option-Obere Pfeiltaste)                               | Nach oben scrollen                                               |
| ⌥← oder ⌥→ (Option-Linke Pfeiltaste oder Option-Rechte Pfeiltaste) | Nach links oder rechts scrollen                                    |
| ^⌥S (Steuerung-Option-S)                             | Sprachausgabe von VoiceOver ein- oder ausschalten                         |
| ⌘⇧⇥ (Befehl-Umschalt-Tabulatortaste)                            | Zur vorherigen App wechseln                              |
| ⌘⇥ (Befehl-Tabulatortaste)                                   | Zur ursprünglichen App zurückwechseln                         |
| ←+→, dann Option + ← oder Option+→                   | Durch das Dock navigieren                                   |
### Safari-Verknüpfungen

| Verknüpfung              | Aktion                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Befehl-L)           | Ort öffnen                                       |
| ⌘T                      | Neuen Tab öffnen                                 |
| ⌘W                      | Aktuellen Tab schließen                          |
| ⌘R                      | Aktuellen Tab aktualisieren                      |
| ⌘.                      | Laden des aktuellen Tabs stoppen                 |
| ^⇥                      | Zum nächsten Tab wechseln                        |
| ^⇧⇥ (Strg-Umschalt-Tab) | Zum vorherigen Tab wechseln                      |
| ⌘L                      | Texteingabe/URL-Feld auswählen, um es zu ändern  |
| ⌘⇧T (Befehl-Umschalt-T) | Zuletzt geschlossenen Tab öffnen (kann mehrmals verwendet werden) |
| ⌘\[                     | Geht eine Seite zurück in deinem Browserverlauf |
| ⌘]                      | Geht eine Seite vorwärts in deinem Browserverlauf |
| ⌘⇧R                    | Leseansicht aktivieren                            |

### Mail-Verknüpfungen

| Verknüpfung                   | Aktion                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Ort öffnen                   |
| ⌘T                         | Neuen Tab öffnen             |
| ⌘W                         | Aktuellen Tab schließen      |
| ⌘R                         | Aktuellen Tab aktualisieren  |
| ⌘.                         | Laden des aktuellen Tabs stoppen |
| ⌘⌥F (Befehl-Option/Alt-F) | In deinem Postfach suchen    |

# Referenzen

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Du kannst ihre Website besuchen und ihre Suchmaschine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Lerne AWS-Hacking von Null zum Profi mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn du dein **Unternehmen in HackTricks beworben sehen möchtest** oder **HackTricks als PDF herunterladen möchtest**, sieh dir die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Hol dir das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecke [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Trete der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teile deine Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichst.

</details>
