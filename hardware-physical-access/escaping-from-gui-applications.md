<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


# Kyk vir moontlike aksies binne die GUI-toepassing

**Gewone dialoë** is daardie opsies soos **'n lêer stoor', 'n lêer oopmaak', 'n lettertipe kies', 'n kleur kies'... Die meeste van hulle sal 'n volledige Verkenner-funksionaliteit bied. Dit beteken dat jy Verkenner-funksies kan gebruik as jy toegang het tot hierdie opsies:

* Sluit/Sluit as
* Maak oop/Maak oop met
* Druk
* Uitvoer/Invoer
* Soek
* Skandeer

Jy moet kyk of jy kan:

* Lêers wysig of nuwe lêers skep
* Simboliese skakels skep
* Toegang kry tot beperkte areas
* Ander programme uitvoer

## Opdraguitvoering

Miskien kan jy **deur die gebruik van 'n `Maak oop met`-opsie** 'n sekere soort skel uitvoer/maak oop.

### Windows

Byvoorbeeld _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ vind meer binnerwerke wat gebruik kan word om opdragte uit te voer (en onverwagte aksies uit te voer) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Meer hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Om padbeperkings te omseil

* **Omgewingsveranderlikes**: Daar is baie omgewingsveranderlikes wat na 'n sekere pad wys
* **Ander protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Simboliese skakels**
* **Kortpaaie**: CTRL+N (maak nuwe sessie oop), CTRL+R (Voer opdragte uit), CTRL+SHIFT+ESC (Taakbestuurder),  Windows+E (maak Verkenner oop), CTRL-B, CTRL-I (Gunstelinge), CTRL-H (Geskiedenis), CTRL-L, CTRL-O (Lêer/Oopmaak-dialoog), CTRL-P (Druk-dialoog), CTRL-S (Stoor as)
* Versteekte Administratiewe kieslys: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell-URI's**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC-paaie**: Paaie om aan gedeelde lêers te koppel. Jy moet probeer om aan die C$ van die plaaslike masjien te koppel ("\\\127.0.0.1\c$\Windows\System32")
* **Meer UNC-paaie:**

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

## Laai jou binnerwerke af

Konsol: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Verkenner: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registreerredigeerder: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Toegang tot lêersisteem vanuit die blaaier

| PAD                | PAD              | PAD               | PAD                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Kortpaaie

* Plakkerige Sleutels – Druk SHIFT 5 keer
* Muis Sleutels – SHIFT+ALT+NUMLOCK
* Hoë Kontras – SHIFT+ALT+PRINTSCN
* Wissel Sleutels – Hou NUMLOCK vir 5 sekondes
* Filter Sleutels – Hou regter SHIFT vir 12 sekondes
* WINDOWS+F1 – Windows Soek
* WINDOWS+D – Wys Skermblad
* WINDOWS+E – Lanceer Windows Verkenner
* WINDOWS+R – Hardloop
* WINDOWS+U – Toeganklikheidsentrum
* WINDOWS+F – Soek
* SHIFT+F10 – Konteks Menu
* CTRL+SHIFT+ESC – Taakbestuurder
* CTRL+ALT+DEL – Skermblad op nuwer Windows-weergawes
* F1 – Hulp F3 – Soek
* F6 – Adresbalk
* F11 – Wissel volledige skerm binne Internet Explorer
* CTRL+H – Internet Explorer Geskiedenis
* CTRL+T – Internet Explorer – Nuwe Blad
* CTRL+N – Internet Explorer – Nuwe Bladsy
* CTRL+O – Maak Lêer Oop
* CTRL+S – Stoor CTRL+N – Nuwe RDP / Citrix
## Swaai

* Swaai van die linkerkant na die regterkant om alle oop vensters te sien, waardeur die KIOSK-toepassing geminimaliseer word en direkte toegang tot die hele bedryfstelsel verkry word;
* Swaai van die regterkant na die linkerkant om die Aksiesentrum oop te maak, waardeur die KIOSK-toepassing geminimaliseer word en direkte toegang tot die hele bedryfstelsel verkry word;
* Swaai in van die boonste rand om die titelbalk sigbaar te maak vir 'n toepassing wat in volledige skermmodus geopen is;
* Swaai op van die onderkant om die taakbalk in 'n volledige skermtoepassing te wys.

## Internet Explorer Truuks

### 'Beeldwerkset'

Dit is 'n werkbalk wat verskyn aan die bokant-links van 'n prent as dit geklik word. Jy sal in staat wees om dit te Stoor, Druk, Mailto, "My prente" in Verkenner oop te maak. Die Kiosk moet Internet Explorer gebruik.

### Skulpotokol

Tik hierdie URL's om 'n Verkenner-weergawe te verkry:

* `shell:Administratiewe Hulpmiddels`
* `shell:DokumenteBiblioteek`
* `shell:Libraries`
* `shell:Gebruikersprofiele`
* `shell:Persoonlik`
* `shell:SoekTuisblad`
* `shell:Netwerkplekke`
* `shell:StuurNa`
* `shell:Gebruikersprofiele`
* `shell:Gemeenskaplike Administratiewe Hulpmiddels`
* `shell:MyRekenaarVouer`
* `shell:InternetVouer`
* `Shell:Profiel`
* `Shell:Programlêers`
* `Shell:System`
* `Shell:BeheerpaneelVouer`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Beheerpaneel
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Rekenaar
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Netwerkplekke
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Wys Lêeruitbreidings

Kyk na hierdie bladsy vir meer inligting: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Blaaier truuks

Maak 'n rugsteun van iKat-weergawes:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Skep 'n gemeenskaplike dialoogvenster met behulp van JavaScript en kry toegang tot lêerverkenner: `document.write('<input/type=file>')`
Bron: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gebare en knoppies

* Swaai op met vier (of vyf) vingers / Dubbeltik op die Huis-knoppie: Om die multitask-weergawe te sien en App te verander

* Swaai een kant of die ander met vier of vyf vingers: Om na die volgende/vorige App te verander

* Knyp die skerm met vyf vingers / Raak die Huis-knoppie aan / Swaai op met 1 vinger van die onderkant van die skerm in 'n vinnige beweging na bo: Om by die Huis te kom

* Swaai een vinger van die onderkant van die skerm net 1-2 duim (stadig): Die dok sal verskyn

* Swaai af van die boonste gedeelte van die vertoning met 1 vinger: Om jou kennisgewings te sien

* Swaai af met 1 vinger die bokant-regterhoek van die skerm: Om die beheersentrum van die iPad Pro te sien

* Swaai 1 vinger van die linkerkant van die skerm 1-2 duim: Om die Vandaag-weergawe te sien

* Swaai vinnig 1 vinger van die middel van die skerm na regs of links: Om na die volgende/vorige App te verander

* Druk en hou die Aan/**Af**/Slaap-knoppie aan die bokant-regterhoek van die **iPad +** Skuif die "skakelaar vir aflaai" heeltemal na regs: Om af te skakel

* Druk die Aan/**Af**/Slaap-knoppie aan die bokant-regterhoek van die **iPad en die Huis-knoppie vir 'n paar sekondes**: Om 'n harde krag af te dwing

* Druk die Aan/**Af**/Slaap-knoppie aan die bokant-regterhoek van die **iPad en die Huis-knoppie vinnig**: Om 'n skermkiekie te neem wat in die onderste linkerkant van die vertoning sal verskyn. Druk beide knoppies terselfdertyd baie kort in, asof jy hulle 'n paar sekondes vashou, sal 'n harde krag afgedwing word.

## Kortpaaie

Jy moet 'n iPad-toetsbord of 'n USB-toetsbord-adapter hê. Slegs kortpaaie wat kan help om te ontsnap uit die toepassing, sal hier gewys word.

| Sleutel | Naam         |
| --- | ------------ |
| ⌘   | Bevel      |
| ⌥   | Opsie (Alt) |
| ⇧   | Skuif        |
| ↩   | Terugkeer       |
| ⇥   | Tab          |
| ^   | Beheer      |
| ←   | Linkerpyl   |
| →   | Regterpyl  |
| ↑   | Op-pyl     |
| ↓   | Af-pyl   |

### Stelselkortpaaie

Hierdie kortpaaie is vir die visuele instellings en klankinstellings, afhangende van die gebruik van die iPad.

| Kortpad | Aksie                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Verdonker skerm                                                                    |
| F2       | Verhelder skerm                                                                |
| F7       | Terug een liedjie                                                                  |
| F8       | Speel/pouseer                                                                     |
| F9       | Oorslaan liedjie                                                                      |
| F10      | Stil                                                                           |
| F11      | Verlaag volume                                                                |
| F12      | Verhoog volume                                                                |
| ⌘ Spasie  | Wys 'n lys van beskikbare tale; om een te kies, tik weer op die spasiebalk. |

### iPad navigasie

| Kortpad                                           | Aksie                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gaan na die Huis                                              |
| ⌘⇧H (Bevel-Shift-H)                              | Gaan na die Huis                                              |
| ⌘ (Spasie)                                          | Maak Spotlight oop                                          |
| ⌘⇥ (Bevel-Tab)                                   | Lys die laaste tien gebruikte programme                                 |
| ⌘\~                                                | Gaan na die laaste App                                       |
| ⌘⇧3 (Bevel-Shift-3)                              | Skermkiekie (swaai in die onderste linkerkant om dit te stoor of daarop te reageer) |
| ⌘⇧4                                                | Skermkiekie en maak dit oop in die redakteur                    |
| Druk en hou ⌘                                   | Lys van beskikbare kortpaaie vir die App                 |
| ⌘⌥D (Bevel-Opsie/Alt-D)                         | Bring die dok op                                      |
| ^⌥H (Beheer-Opsie-H)                             | Huis-knoppie                                             |
| ^⌥H H (Beheer-Opsie-H-H)                         | Wys multitask-balk                                      |
| ^⌥I (Beheer-Opsie-i)                             | Item-keuse                                              |
| Escape                                             | Terug-knoppie                                             |
| → (Regterpyl)                                    | Volgende item                                               |
| ← (Linkerpyl)                                     | Vorige item                                           |
| ↑↓ (Op-pyl, Af-pyl)                          | Gelyktydig tik op geselekteerde item                        |
| ⌥ ↓ (Opsie-Af-pyl)                            | Rol af                                             |
| ⌥↑ (Opsie-Op-pyl)                               | Rol op                                               |
| ⌥← of ⌥→ (Opsie-Linkerpyl of Opsie-Regterpyl) | Rol links of regs                                    |
| ^⌥S (Beheer-Opsie-S)                             | Skakel VoiceOver-spraak aan of af                         |
| ⌘⇧⇥ (Bevel-Shift-Tab)                            | Skakel na die vorige app                              |
| ⌘⇥ (Bevel-Tab)                                   | Skakel terug na die oorspronklike app                         |
| ←+→, dan Opsie + ←
### Safari snelkoppelinge

| Snelkoppeling            | Aksie                                            |
| ----------------------- | ------------------------------------------------- |
| ⌘L (Command-L)          | Maak Ligging Oop                                 |
| ⌘T                      | Maak 'n nuwe oortjie oop                          |
| ⌘W                      | Maak die huidige oortjie toe                       |
| ⌘R                      | Verfris die huidige oortjie                        |
| ⌘.                      | Stop die laai van die huidige oortjie              |
| ^⇥                      | Skakel na die volgende oortjie                     |
| ^⇧⇥ (Control-Shift-Tab) | Beweeg na die vorige oortjie                       |
| ⌘L                      | Kies die teksinvoer/URL-veld om dit te wysig       |
| ⌘⇧T (Command-Shift-T)   | Maak die laaste toegegooide oortjie oop (kan verskeie kere gebruik word) |
| ⌘\[                     | Gaan een bladsy terug in jou blaai-geskiedenis     |
| ⌘]                      | Gaan een bladsy vorentoe in jou blaai-geskiedenis  |
| ⌘⇧R                     | Aktiveer Leesermodus                              |

### Poskantoor snelkoppelinge

| Snelkoppeling                   | Aksie                          |
| ------------------------------ | ------------------------------- |
| ⌘L                              | Maak Ligging Oop                |
| ⌘T                              | Maak 'n nuwe oortjie oop         |
| ⌘W                              | Maak die huidige oortjie toe     |
| ⌘R                              | Verfris die huidige oortjie      |
| ⌘.                              | Stop die laai van die huidige oortjie |
| ⌘⌥F (Command-Option/Alt-F)      | Soek in jou posbus               |

# Verwysings

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
