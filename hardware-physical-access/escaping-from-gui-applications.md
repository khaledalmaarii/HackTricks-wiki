# Escaping from KIOSKs

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}



---

## Überprüfen des physischen Geräts

|   Komponente   | Aktion                                                               |
| -------------- | -------------------------------------------------------------------- |
| Netzschalter   | Das Gerät aus- und wieder einschalten kann den Startbildschirm anzeigen |
| Netzkabel      | Überprüfen, ob das Gerät neu startet, wenn die Stromversorgung kurz unterbrochen wird |
| USB-Ports      | Physikalische Tastatur mit mehr Tastenkombinationen anschließen       |
| Ethernet       | Netzwerk-Scan oder Sniffing kann weitere Ausnutzung ermöglichen       |


## Überprüfen möglicher Aktionen innerhalb der GUI-Anwendung

**Gemeinsame Dialoge** sind Optionen wie **Datei speichern**, **Datei öffnen**, Schriftart auswählen, Farbe... Die meisten von ihnen bieten **vollständige Explorer-Funktionalität**. Das bedeutet, dass du auf Explorer-Funktionalitäten zugreifen kannst, wenn du auf diese Optionen zugreifen kannst:

* Schließen/Als schließen
* Öffnen/Öffnen mit
* Drucken
* Exportieren/Importieren
* Suchen
* Scannen

Du solltest überprüfen, ob du:

* Dateien ändern oder neue erstellen kannst
* Symbolische Links erstellen kannst
* Zugriff auf eingeschränkte Bereiche erhalten kannst
* Andere Apps ausführen kannst

### Befehlsausführung

Vielleicht kannst du **mit einer `Öffnen mit`** Option\*\* eine Art Shell öffnen/ausführen.

#### Windows

Zum Beispiel _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ finde mehr Binärdateien, die verwendet werden können, um Befehle auszuführen (und unerwartete Aktionen durchzuführen) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Mehr hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Umgehung von Pfadbeschränkungen

* **Umgebungsvariablen**: Es gibt viele Umgebungsvariablen, die auf einen bestimmten Pfad zeigen
* **Andere Protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Symbolische Links**
* **Verknüpfungen**: CTRL+N (neue Sitzung öffnen), CTRL+R (Befehle ausführen), CTRL+SHIFT+ESC (Task-Manager), Windows+E (Explorer öffnen), CTRL-B, CTRL-I (Favoriten), CTRL-H (Verlauf), CTRL-L, CTRL-O (Datei/Öffnen Dialog), CTRL-P (Drucken Dialog), CTRL-S (Speichern unter)
* Verstecktes Administrationsmenü: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell-URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC-Pfade**: Pfade, um sich mit freigegebenen Ordnern zu verbinden. Du solltest versuchen, dich mit dem C$ des lokalen Geräts zu verbinden ("\\\127.0.0.1\c$\Windows\System32")
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

### Lade deine Binärdateien herunter

Konsole: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registrierungseditor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Zugriff auf das Dateisystem über den Browser

| PFAD                | PFAD              | PFAD               | PFAD                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Tastenkombinationen

* Sticky Keys – Drücke SHIFT 5 Mal
* Mouse Keys – SHIFT+ALT+NUMLOCK
* Hoher Kontrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Halte NUMLOCK 5 Sekunden lang gedrückt
* Filter Keys – Halte die rechte SHIFT-Taste 12 Sekunden lang gedrückt
* WINDOWS+F1 – Windows-Suche
* WINDOWS+D – Desktop anzeigen
* WINDOWS+E – Windows Explorer starten
* WINDOWS+R – Ausführen
* WINDOWS+U – Eingabehilfen-Center
* WINDOWS+F – Suchen
* SHIFT+F10 – Kontextmenü
* CTRL+SHIFT+ESC – Task-Manager
* CTRL+ALT+DEL – Splashscreen in neueren Windows-Versionen
* F1 – Hilfe F3 – Suchen
* F6 – Adressleiste
* F11 – Vollbildmodus in Internet Explorer umschalten
* CTRL+H – Internet Explorer Verlauf
* CTRL+T – Internet Explorer – Neuer Tab
* CTRL+N – Internet Explorer – Neue Seite
* CTRL+O – Datei öffnen
* CTRL+S – Speichern CTRL+N – Neues RDP / Citrix

### Wischgesten

* Wische von der linken Seite nach rechts, um alle offenen Fenster zu sehen, die KIOSK-App zu minimieren und direkt auf das gesamte Betriebssystem zuzugreifen;
* Wische von der rechten Seite nach links, um das Aktionscenter zu öffnen, die KIOSK-App zu minimieren und direkt auf das gesamte Betriebssystem zuzugreifen;
* Wische von der oberen Kante, um die Titelleiste für eine im Vollbildmodus geöffnete App sichtbar zu machen;
* Wische von unten nach oben, um die Taskleiste in einer Vollbild-App anzuzeigen.

### Internet Explorer Tricks

#### 'Bildwerkzeugleiste'

Es ist eine Werkzeugleiste, die oben links im Bild erscheint, wenn es angeklickt wird. Du kannst Speichern, Drucken, Mailto, "Meine Bilder" im Explorer öffnen. Der Kiosk muss Internet Explorer verwenden.

#### Shell-Protokoll

Gib diese URLs ein, um eine Explorer-Ansicht zu erhalten:

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
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Meine Netzwerkplätze
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Dateiendungen anzeigen

Überprüfe diese Seite für weitere Informationen: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browser-Tricks

Backup iKat-Versionen:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Erstelle einen gemeinsamen Dialog mit JavaScript und greife auf den Datei-Explorer zu: `document.write('<input/type=file>')`\
Quelle: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesten und Tasten

* Wische mit vier (oder fünf) Fingern nach oben / Doppeltippe auf die Home-Taste: Um die Multitasking-Ansicht anzuzeigen und die App zu wechseln
* Wische in eine Richtung mit vier oder fünf Fingern: Um zur nächsten/vorherigen App zu wechseln
* Kneife den Bildschirm mit fünf Fingern / Berühre die Home-Taste / Wische schnell mit 1 Finger von unten nach oben: Um auf die Startseite zuzugreifen
* Wische mit 1 Finger von unten am Bildschirm nur 1-2 Zoll (langsam): Das Dock wird angezeigt
* Wische mit 1 Finger von oben auf dem Display: Um deine Benachrichtigungen anzuzeigen
* Wische mit 1 Finger in die obere rechte Ecke des Bildschirms: Um das Kontrollzentrum des iPad Pro zu sehen
* Wische mit 1 Finger von der linken Seite des Bildschirms 1-2 Zoll: Um die Heute-Ansicht zu sehen
* Wische schnell mit 1 Finger von der Mitte des Bildschirms nach rechts oder links: Um zur nächsten/vorherigen App zu wechseln
* Drücke und halte die Ein-/Aus-/Sleep-Taste in der oberen rechten Ecke des **iPad +** Bewege den Schieberegler **ausschalten** ganz nach rechts: Um auszuschalten
* Drücke die Ein-/Aus-/Sleep-Taste in der oberen rechten Ecke des **iPad und die Home-Taste für einige Sekunden**: Um einen harten Ausschaltvorgang zu erzwingen
* Drücke die Ein-/Aus-/Sleep-Taste in der oberen rechten Ecke des **iPad und die Home-Taste schnell**: Um einen Screenshot zu machen, der in der unteren linken Ecke des Displays angezeigt wird. Drücke beide Tasten gleichzeitig sehr kurz, da du sie einige Sekunden lang gedrückt hältst, wird ein harter Ausschaltvorgang durchgeführt.

### Tastenkombinationen

Du solltest eine iPad-Tastatur oder einen USB-Tastaturadapter haben. Nur Tastenkombinationen, die beim Verlassen der Anwendung helfen könnten, werden hier angezeigt.

| Taste | Name         |
| ----- | ------------ |
| ⌘   | Befehl      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Eingabe       |
| ⇥   | Tab          |
| ^   | Steuerung      |
| ←   | Linker Pfeil   |
| →   | Rechter Pfeil  |
| ↑   | Aufwärtspfeil     |
| ↓   | Abwärtspfeil     |

#### System-Tastenkombinationen

Diese Tastenkombinationen sind für die visuellen Einstellungen und Toneinstellungen, abhängig von der Nutzung des iPads.

| Tastenkombination | Aktion                                                                         |
| ----------------- | ------------------------------------------------------------------------------ |
| F1                | Bildschirm dimmen                                                                |
| F2                | Bildschirm aufhellen                                                            |
| F7                | Einen Song zurück                                                              |
| F8                | Abspielen/Pause                                                                 |
| F9                | Song überspringen                                                              |
| F10               | Stummschalten                                                                  |
| F11               | Lautstärke verringern                                                          |
| F12               | Lautstärke erhöhen                                                              |
| ⌘ Leertaste       | Eine Liste verfügbarer Sprachen anzeigen; um eine auszuwählen, drücke die Leertaste erneut. |

#### iPad-Navigation

| Tastenkombination                                   | Aktion                                                  |
| --------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gehe zur Startseite                                     |
| ⌘⇧H (Befehl-Shift-H)                              | Gehe zur Startseite                                     |
| ⌘ (Leertaste)                                      | Spotlight öffnen                                        |
| ⌘⇥ (Befehl-Tab)                                   | Liste der letzten zehn verwendeten Apps                 |
| ⌘\~                                                | Gehe zur letzten App                                    |
| ⌘⇧3 (Befehl-Shift-3)                              | Screenshot (schwebt unten links, um zu speichern oder zu handeln) |
| ⌘⇧4                                                | Screenshot und öffne ihn im Editor                     |
| Drücke und halte ⌘                                 | Liste der verfügbaren Tastenkombinationen für die App   |
| ⌘⌥D (Befehl-Option/Alt-D)                         | Dock anzeigen                                           |
| ^⌥H (Steuerung-Option-H)                           | Home-Taste                                             |
| ^⌥H H (Steuerung-Option-H-H)                       | Multitasking-Leiste anzeigen                            |
| ^⌥I (Steuerung-Option-i)                           | Elementauswahl                                         |
| Escape                                             | Zurück-Taste                                           |
| → (Rechter Pfeil)                                  | Nächstes Element                                       |
| ← (Linker Pfeil)                                   | Vorheriges Element                                     |
| ↑↓ (Aufwärtspfeil, Abwärtspfeil)                   | Ausgewähltes Element gleichzeitig antippen             |
| ⌥ ↓ (Option-Abwärtspfeil)                          | Nach unten scrollen                                    |
| ⌥↑ (Option-Aufwärtspfeil)                          | Nach oben scrollen                                     |
| ⌥← oder ⌥→ (Option-Linker Pfeil oder Option-Rechter Pfeil) | Nach links oder rechts scrollen                        |
| ^⌥S (Steuerung-Option-S)                           | VoiceOver-Sprachausgabe ein- oder ausschalten         |
| ⌘⇧⇥ (Befehl-Shift-Tab)                            | Zum vorherigen App wechseln                            |
| ⌘⇥ (Befehl-Tab)                                   | Zur ursprünglichen App zurückwechseln                  |
| ←+→, dann Option + ← oder Option+→                 | Durch das Dock navigieren                              |

#### Safari-Tastenkombinationen

| Tastenkombination          | Aktion                                           |
| -------------------------- | ------------------------------------------------ |
| ⌘L (Befehl-L)              | Standort öffnen                                  |
| ⌘T                        | Neuen Tab öffnen                                 |
| ⌘W                        | Den aktuellen Tab schließen                      |
| ⌘R                        | Den aktuellen Tab aktualisieren                  |
| ⌘.                        | Das Laden des aktuellen Tabs stoppen             |
| ^⇥                        | Zum nächsten Tab wechseln                        |
| ^⇧⇥ (Steuerung-Shift-Tab) | Zum vorherigen Tab wechseln                      |
| ⌘L                        | Textfeld/URL-Feld auswählen, um es zu ändern     |
| ⌘⇧T (Befehl-Shift-T)      | Letzten geschlossenen Tab öffnen (kann mehrmals verwendet werden) |
| ⌘\[                       | Gehe eine Seite in deinem Browserverlauf zurück |
| ⌘]                        | Gehe eine Seite in deinem Browserverlauf vorwärts |
| ⌘⇧R                       | Reader-Modus aktivieren                          |

#### Mail-Tastenkombinationen

| Tastenkombination                   | Aktion                       |
| ----------------------------------- | ---------------------------- |
| ⌘L                                 | Standort öffnen              |
| ⌘T                                 | Neuen Tab öffnen             |
| ⌘W                                 | Den aktuellen Tab schließen   |
| ⌘R                                 | Den aktuellen Tab aktualisieren |
| ⌘.                                 | Das Laden des aktuellen Tabs stoppen |
| ⌘⌥F (Befehl-Option/Alt-F)         | In deinem Postfach suchen    |

## Referenzen

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)



{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
