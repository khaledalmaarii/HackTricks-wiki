# Ontsnapping uit KIOSKs

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kyk of 'n maatskappy of sy kliënte deur **steel-malware** **gekompromiteer** is.

Die primêre doel van WhiteIntel is om rekening-oorneeminge en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteel-malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

***

## Kyk vir moontlike aksies binne die GUI-toepassing

**Gewone Dialoë** is daardie opsies om 'n lêer te **stoor**, 'n lêer te **open**, 'n lettertipe te kies, 'n kleur te kies... Die meeste van hulle sal 'n volledige Verkenner-funksionaliteit **aanbied**. Dit beteken dat jy Verkenner-funksionaliteite kan gebruik as jy hierdie opsies kan gebruik:

* Sluit/Sluit as
* Open/Open met
* Druk
* Uitvoer/Invoer
* Soek
* Skandeer

Jy moet nagaan of jy kan:

* Wysig of nuwe lêers skep
* Simboliese skakels skep
* Toegang tot beperkte areas kry
* Ander programme uitvoer

### Opdraguitvoering

Miskien **deur 'n `Open met`**-opsie te gebruik\*\* kan jy 'n soort van skel uitvoer.

#### Windows

Byvoorbeeld _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ vind meer bineêre lêers wat gebruik kan word om opdragte uit te voer (en onverwagte aksies uit te voer) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Meer hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Om padbeperkings te omseil

* **Omgevingsveranderlikes**: Daar is baie omgevingsveranderlikes wat na 'n sekere pad wys
* **Ander protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Simboliese skakels**
* **Kortpaaie**: CTRL+N (open nuwe sessie), CTRL+R (Voer Opdragte uit), CTRL+SHIFT+ESC (Taakbestuurder), Windows+E (open verkenner), CTRL-B, CTRL-I (Gunstelinge), CTRL-H (Geskiedenis), CTRL-L, CTRL-O (Lêer/Open Dialoog), CTRL-P (Druk Dialoog), CTRL-S (Stoor As)
* Versteekte Administratiewe kieslys: CTRL-ALT-F8, CTRL-ESC-F9
* **Skel-URI's**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
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

### Laai Jou Bineêre lêers af

Konsol: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Verkenner: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registerredigeerder: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Toegang tot lêersisteem vanaf die blaaier

| PAD                | PAD              | PAD               | PAD                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Kortpaaie

* Plakkerige Sleutels – Druk SHIFT 5 keer
* Muis Sleutels – SHIFT+ALT+NUMLOCK
* Hoë Kontras – SHIFT+ALT+PRINTSCN
* Wissel Sleutels – Hou NUMLOCK vir 5 sekondes
* Filter Sleutels – Hou regter SHIFT vir 12 sekondes
* WINDOWS+F1 – Windows Soek
* WINDOWS+D – Wys Skerm
* WINDOWS+E – Lanceer Windows Verkenner
* WINDOWS+R – Hardloop
* WINDOWS+U – Toeganklikheidsentrum
* WINDOWS+F – Soek
* SHIFT+F10 – Konteksmenu
* CTRL+SHIFT+ESC – Taakbestuurder
* CTRL+ALT+DEL – Spatskerm op nuwer Windows-weergawes
* F1 – Hulp F3 – Soek
* F6 – Adresbalk
* F11 – Wissel volledige skerm binne Internet Explorer
* CTRL+H – Internet Explorer Geskiedenis
* CTRL+T – Internet Explorer – Nuwe Bladsy
* CTRL+N – Internet Explorer – Nuwe Bladsy
* CTRL+O – Maak Lêer Oop
* CTRL+S – Stoor CTRL+N – Nuwe RDP / Citrix
### Swipes

* Swaai van die linkerkant na die regterkant om al die oop Vensters te sien, wat die KIOSK-toepassing minimaliseer en direkte toegang tot die hele OS gee;
* Swaai van die regterkant na die linkerkant om die Aksiesentrum oop te maak, wat die KIOSK-toepassing minimaliseer en direkte toegang tot die hele OS gee;
* Swaai van die boonste kant in om die titelbalk sigbaar te maak vir 'n toepassing wat in volledige skermmodus oopgemaak is;
* Swaai van onder af op om die taakbalk in 'n volledige skermtoepassing te wys.

### Internet Explorer Truuks

#### 'Beeldwerkstafel'

Dit is 'n werkstafel wat op die boonste-linkerkant van die beeld verskyn as dit geklik word. Jy sal in staat wees om te Stoor, Druk, Mailto, "My Pictures" in Explorer oop te maak. Die Kiosk moet Internet Explorer gebruik.

#### Skulprotokol

Tik hierdie URL's om 'n Verkenner-aansig te verkry:

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
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Beheerpaneel
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Rekenaar
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Netwerkplekke
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Wys Lêeruitbreidings

Kyk op hierdie bladsy vir meer inligting: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Blaaiers truuks

Rugsteun iKat-weergawes:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Skep 'n gemeenskaplike dialoogvenster met behulp van JavaScript en kry toegang tot lêerontdekker: `document.write('<input/type=file>')`\
Bron: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gebare en knoppies

* Swaai op met vier (of vyf) vingers / Dubbelklik op die Huis-knoppie: Om die multitask-aansig te sien en Program te verander
* Swaai een kant of die ander met vier of vyf vingers: Om na die volgende/laaste Program te verander
* Knyp die skerm met vyf vingers / Raak die Huis-knoppie aan / Swaai op met 1 vinger van onder af na die bokant van die skerm in 'n vinnige beweging na die bokant: Om by die Huis te kom
* Swaai een vinger van onder af na die bokant van die skerm net 1-2 duim (stadig): Die dok sal verskyn
* Swaai af van die bokant van die vertoning met 1 vinger: Om jou kennisgewings te sien
* Swaai af met 1 vinger na die bokant-regterhoek van die skerm: Om die beheersentrum van die iPad Pro te sien
* Swaai 1 vinger van die linkerkant van die skerm 1-2 duim: Om die Vandag-aansig te sien
* Swaai vinnig 1 vinger van die middel van die skerm na regs of links: Om na die volgende/laaste Program te verander
* Druk en hou die Aan/**Af**/Slaap-knoppie aan die bokant-regterhoek van die **iPad +** Skuif die Skyf na **krag af** skyf heeltemal na regs: Om af te skakel
* Druk die Aan/**Af**/Slaap-knoppie aan die bokant-regterhoek van die **iPad en die Huis-knoppie vir 'n paar sekondes**: Om 'n krag af te dwing
* Druk die Aan/**Af**/Slaap-knoppie aan die bokant-regterhoek van die **iPad en die Huis-knoppie vinnig**: Om 'n skermkiekie te neem wat in die onderste linkerkant van die vertoning sal verskyn. Druk beide knoppies gelyktydig baie kort in, asof jy hulle vir 'n paar sekondes vas hou, sal 'n krag af gedwing word.

### Kortpaaie

Jy moet 'n iPad-sleutelbord of 'n USB-sleutelbord-adapter hê. Slegs kortpaaie wat kan help om te ontsnap uit die toepassing sal hier vertoon word.

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
| ↑   | Bo-pyl     |
| ↓   | Af-pyl   |

#### Stelsel kortpaaie

Hierdie kortpaaie is vir die visuele instellings en klankinstellings, afhangende van die gebruik van die iPad.

| Kortpad | Aksie                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Verduister skerm                                                                    |
| F2       | Verlig skerm                                                                |
| F7       | Terug een liedjie                                                                  |
| F8       | Speel/pouse                                                                     |
| F9       | Spring liedjie                                                                      |
| F10      | Stil                                                                           |
| F11      | Verminder volume                                                                |
| F12      | Verhoog volume                                                                |
| ⌘ Spasie  | Wys 'n lys van beskikbare tale; om een te kies, tik weer op die spasiebalk. |

#### iPad navigasie

| Kortpad                                           | Aksie                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gaan na die Huis                                              |
| ⌘⇧H (Bevel-Shift-H)                              | Gaan na die Huis                                              |
| ⌘ (Spasie)                                          | Maak Spotlight oop                                          |
| ⌘⇥ (Bevel-Tab)                                   | Lys van laaste tien gebruikte Programme                                 |
| ⌘\~                                                | Gaan na die laaste Program                                       |
| ⌘⇧3 (Bevel-Shift-3)                              | Skermkiekie (bly in die onderste linkerkant om dit te stoor of daarop te reageer) |
| ⌘⇧4                                                | Skermkiekie en maak dit oop in die redigeerder                    |
| Druk en hou ⌘                                   | Lys van beskikbare kortpaaie vir die Program                 |
| ⌘⌥D (Bevel-Opsie/Alt-D)                         | Bring die dok op                                      |
| ^⌥H (Beheer-Opsie-H)                             | Huis-knoppie                                             |
| ^⌥H H (Beheer-Opsie-H-H)                         | Wys multitask-balk                                      |
| ^⌥I (Beheer-Opsie-i)                             | Item-keuse                                            |
| Ontsnapping                                             | Terug-knoppie                                             |
| → (Regterpyl)                                    | Volgende item                                               |
| ← (Linkerpyl)                                     | Vorige item                                           |
| ↑↓ (Bo-pyl, Af-pyl)                          | Gelyktydig tik op die gekose item                        |
| ⌥ ↓ (Opsie-Af-pyl)                            | Rol af                                             |
| ⌥↑ (Opsie-Bo-pyl)                               | Rol op                                               |
| ⌥← of ⌥→ (Opsie-Links-pyl of Opsie-Regs-pyl) | Rol links of regs                                    |
| ^⌥S (Beheer-Opsie-S)                             | Skakel VoiceOver-spraak aan of af                         |
| ⌘⇧⇥ (Bevel-Shift-Tab)                            | Skakel na die vorige Program                              |
| ⌘⇥ (Bevel-Tab)                                   | Skakel terug na die oorspronklike Program                         |
| ←+→, dan Opsie + ← of Opsie+→                   | Navigeer deur die Dok                                   |
#### Safari snelkoppelinge

| Snelkoppeling           | Aksie                                            |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Maak Ligging Oop                                 |
| ⌘T                      | Maak 'n nuwe lappie oop                          |
| ⌘W                      | Sluit die huidige lappie                         |
| ⌘R                      | Verfris die huidige lappie                       |
| ⌘.                      | Stop met die laai van die huidige lappie         |
| ^⇥                      | Skakel na die volgende lappie                    |
| ^⇧⇥ (Control-Shift-Tab) | Beweeg na die vorige lappie                      |
| ⌘L                      | Kies die teks invoer/URL-veld om dit te wysig    |
| ⌘⇧T (Command-Shift-T)   | Maak laaste geslote lappie oop (kan verskeie kere gebruik word) |
| ⌘\[                     | Gaan een bladsy terug in jou blaai-geskiedenis  |
| ⌘]                      | Gaan een bladsy vorentoe in jou blaai-geskiedenis |
| ⌘⇧R                     | Aktiveer Leesermodus                             |

#### Poskantoor snelkoppelinge

| Snelkoppeling            | Aksie                       |
| ------------------------ | ---------------------------- |
| ⌘L                       | Maak Ligging Oop            |
| ⌘T                       | Maak 'n nuwe lappie oop      |
| ⌘W                       | Sluit die huidige lappie     |
| ⌘R                       | Verfris die huidige lappie   |
| ⌘.                       | Stop met die laai van die huidige lappie |
| ⌘⌥F (Command-Option/Alt-F) | Soek in jou posbus          |

## Verwysings

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is a **dark-web** fueled search engine that offers **free** functionalities to check if a company or its customers have been **compromised** by **stealer malwares**.

Their primary goal of WhiteIntel is to combat account takeovers and ransomware attacks resulting from information-stealing malware.

You can check their website and try their engine for **free** at:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
