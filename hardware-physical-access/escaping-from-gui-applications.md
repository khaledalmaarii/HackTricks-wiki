# Ontsnapping uit KIOSK

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}



---

## Kontroleer fisiese toestel

|   Komponent    | Aksie                                                               |
| -------------- | -------------------------------------------------------------------- |
| Kragknoppie    | Om die toestel af en weer aan te skakel kan die begin skerm blootstel  |
| Kragkabel      | Kontroleer of die toestel herbegin wanneer die krag kortliks afgesny word |
| USB-poorte     | Koppel fisiese sleutelbord met meer sneltoetsen                     |
| Ethernet       | Netwerk skandering of sniffing kan verdere uitbuiting moontlik maak   |


## Kontroleer vir moontlike aksies binne die GUI-toepassing

**Algemene Dialoë** is daardie opsies van **'n lêer stoor**, **'n lêer oopmaak**, 'n lettertipe kies, 'n kleur... Die meeste van hulle sal **'n volledige Explorer-funksionaliteit bied**. Dit beteken dat jy toegang tot Explorer-funksies sal hê as jy toegang tot hierdie opsies kan kry:

* Sluit/Sluit as
* Oop/Oop met
* Druk
* Eksporteer/Importeer
* Soek
* Skandeer

Jy moet kontroleer of jy kan:

* Lêers wysig of nuwe lêers skep
* Simboliese skakels skep
* Toegang tot beperkte areas kry
* Ander toepassings uitvoer

### Opdraguitvoering

Miskien **deur 'n `Open with`** opsie kan jy 'n tipe shell oopmaak/uitvoer.

#### Windows

Byvoorbeeld _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ vind meer binaries wat gebruik kan word om opdragte uit te voer (en onverwagte aksies uit te voer) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Meer hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Om padbeperkings te omseil

* **Omgewing veranderlikes**: Daar is baie omgewing veranderlikes wat na 'n sekere pad wys
* **Ander protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Simboliese skakels**
* **Sneltoetste**: CTRL+N (oop nuwe sessie), CTRL+R (Voer Opdragte uit), CTRL+SHIFT+ESC (Taakbestuurder), Windows+E (oop explorer), CTRL-B, CTRL-I (Gunstelinge), CTRL-H (Gesiedenis), CTRL-L, CTRL-O (Lêer/Oop Dialoog), CTRL-P (Druk Dialoog), CTRL-S (Stoor As)
* Versteekte Administratiewe menu: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administratiewe Gereedskap, shell:DokumenteBiblioteek, shell:Biblioteke, shell:Gebruikersprofiele, shell:Persoonlik, shell:SoekTuisGids, shell:Stelselshell:NetwerkPlekkeGids, shell:StuurNa, shell:GebruikersProfiele, shell:Gemeenskaplike Administratiewe Gereedskap, shell:MyRekenaarGids, shell:InternetGids_
* **UNC-pade**: Pade om aan gedeelde vouers te koppel. Jy moet probeer om aan die C$ van die plaaslike masjien te koppel ("\\\127.0.0.1\c$\Windows\System32")
* **Meer UNC-pade:**

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

### Laai jou binaries af

Konsol: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registrie redigeerder: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Toegang tot lêerstelsel vanaf die blaaier

| PAD                 | PAD               | PAD                | PAD                 |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Sneltoetste

* Plakkerige Sleutels – Druk SHIFT 5 keer
* Muis Sleutels – SHIFT+ALT+NUMLOCK
* Hoë Kontras – SHIFT+ALT+PRINTSCN
* Wissel Sleutels – Hou NUMLOCK vir 5 sekondes
* Filter Sleutels – Hou regter SHIFT vir 12 sekondes
* WINDOWS+F1 – Windows Soek
* WINDOWS+D – Wys Bureaublad
* WINDOWS+E – Begin Windows Explorer
* WINDOWS+R – Voer uit
* WINDOWS+U – Toeganklikheidsentrum
* WINDOWS+F – Soek
* SHIFT+F10 – Konteksmenu
* CTRL+SHIFT+ESC – Taakbestuurder
* CTRL+ALT+DEL – Splash skerm op nuwer Windows weergawes
* F1 – Hulp F3 – Soek
* F6 – Adresbalk
* F11 – Wissel volle skerm binne Internet Explorer
* CTRL+H – Internet Explorer Gesiedenis
* CTRL+T – Internet Explorer – Nuwe Tab
* CTRL+N – Internet Explorer – Nuwe Bladsy
* CTRL+O – Oop Lêer
* CTRL+S – Stoor CTRL+N – Nuwe RDP / Citrix

### Veeg

* Veeg van die linkerkant na die regterkant om al die oop Windows te sien, die KIOSK-toepassing te minimaliseer en direk toegang tot die hele OS te verkry;
* Veeg van die regterkant na die linkerkant om die Aksie Sentrum te open, die KIOSK-toepassing te minimaliseer en direk toegang tot die hele OS te verkry;
* Veeg in vanaf die boonste rand om die titelbalk sigbaar te maak vir 'n toepassing wat in volle skermmodus oopgemaak is;
* Veeg op vanaf die onderkant om die taakbalk in 'n volle skerm toepassing te wys.

### Internet Explorer Truuks

#### 'Beeld Toolbar'

Dit is 'n toolbar wat aan die boonste linkerkant van die beeld verskyn wanneer dit geklik word. Jy sal in staat wees om te Stoor, Druk, Mailto, "My Beelde" in Explorer oop te maak. Die Kiosk moet Internet Explorer gebruik.

#### Shell Protokol

Tik hierdie URL's in om 'n Explorer-weergave te verkry:

* `shell:Administratiewe Gereedskap`
* `shell:DokumenteBiblioteek`
* `shell:Biblioteke`
* `shell:Gebruikersprofiele`
* `shell:Persoonlik`
* `shell:SoekTuisGids`
* `shell:NetwerkPlekkeGids`
* `shell:StuurNa`
* `shell:GebruikersProfiele`
* `shell:Gemeenskaplike Administratiewe Gereedskap`
* `shell:MyRekenaarGids`
* `shell:InternetGids`
* `Shell:Profiel`
* `Shell:ProgramFiles`
* `Shell:Stelsel`
* `Shell:BeheerPaneelGids`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Beheer Paneel
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Rekenaar
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Netwerk Plekke
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Wys Lêer Uitbreidings

Kyk hierdie bladsy vir meer inligting: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Blaaiers truuks

Back-up iKat weergawes:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Skep 'n algemene dialoog met JavaScript en toegang lêer verkenner: `document.write('<input/type=file>')`\
Bron: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gebare en knoppies

* Veeg op met vier (of vyf) vingers / Dubbel-tik die Tuis knoppie: Om die multitaskweergave te sien en die Toepassing te verander
* Veeg een kant of die ander met vier of vyf vingers: Om na die volgende/laaste Toepassing te verander
* Knyp die skerm met vyf vingers / Raak die Tuis knoppie / Veeg op met 1 vinger vanaf die onderkant van die skerm in 'n vinnige beweging na bo: Om toegang tot Tuis te verkry
* Veeg een vinger vanaf die onderkant van die skerm net 1-2 duim (stadig): Die dok sal verskyn
* Veeg af vanaf die boonste deel van die skerm met 1 vinger: Om jou kennisgewings te sien
* Veeg af met 1 vinger in die boonste regterhoek van die skerm: Om die iPad Pro se kontrole sentrum te sien
* Veeg 1 vinger vanaf die linkerkant van die skerm 1-2 duim: Om die Vandag-weergave te sien
* Veeg vinnig 1 vinger vanaf die middel van die skerm na regs of links: Om na die volgende/laaste Toepassing te verander
* Druk en hou die Aan/**Af**/Slaap knoppie in die boonste regterhoek van die **iPad +** Beweeg die Gly om **af te skakel** skuif heeltemal na regs: Om af te skakel
* Druk die Aan/**Af**/Slaap knoppie in die boonste regterhoek van die **iPad en die Tuis knoppie vir 'n paar sekondes**: Om 'n harde afskakeling te dwing
* Druk die Aan/**Af**/Slaap knoppie in die boonste regterhoek van die **iPad en die Tuis knoppie vinnig**: Om 'n skermskoot te neem wat in die onderste linkerhoek van die skerm sal verskyn. Druk albei knoppies op dieselfde tyd baie kort asof jy hulle 'n paar sekondes hou, sal 'n harde afskakeling uitgevoer word.

### Sneltoets

Jy moet 'n iPad sleutelbord of 'n USB sleutelbord-adapter hê. Net sneltoets wat kan help om uit die toepassing te ontsnap sal hier getoon word.

| Sleutel | Naam         |
| ------- | ------------ |
| ⌘       | Opdrag      |
| ⌥       | Opsie (Alt) |
| ⇧       | Shift        |
| ↩       | Terug        |
| ⇥       | Tab          |
| ^       | Beheer       |
| ←       | Linker Pyl  |
| →       | Regter Pyl   |
| ↑       | Bo Pyl      |
| ↓       | Onder Pyl    |

#### Stelselsneltoets

Hierdie sneltoetse is vir die visuele instellings en klankinstellings, afhangende van die gebruik van die iPad.

| Sneltoets | Aksie                                                                         |
| --------- | ------------------------------------------------------------------------------ |
| F1        | Verlaag Skerm                                                                  |
| F2        | Verhoog skerm                                                                  |
| F7        | Terug een liedjie                                                              |
| F8        | Speel/pouse                                                                   |
| F9        | Skuif liedjie                                                                  |
| F10       | Stil                                                                           |
| F11       | Verminder volume                                                                |
| F12       | Verhoog volume                                                                  |
| ⌘ Space   | Wys 'n lys van beskikbare tale; om een te kies, tik weer die spasie sleutel. |

#### iPad navigasie

| Sneltoets                                           | Aksie                                                  |
| --------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gaan na Tuis                                           |
| ⌘⇧H (Opdrag-Shift-H)                               | Gaan na Tuis                                           |
| ⌘ (Space)                                         | Open Spotlight                                          |
| ⌘⇥ (Opdrag-Tab)                                   | Lys laaste tien gebruikte toepassings                   |
| ⌘\~                                                | Gaan na die laaste Toepassing                           |
| ⌘⇧3 (Opdrag-Shift-3)                              | Skermskoot (hang in onderste linkerhoek om te stoor of daarop te handel) |
| ⌘⇧4                                               | Skermskoot en open dit in die redigeerder              |
| Druk en hou ⌘                                   | Lys van sneltoetse beskikbaar vir die Toepassing       |
| ⌘⌥D (Opdrag-Optie/Alt-D)                         | Bring die dok op                                       |
| ^⌥H (Beheer-Optie-H)                             | Tuis knoppie                                           |
| ^⌥H H (Beheer-Optie-H-H)                         | Wys multitaskbalk                                      |
| ^⌥I (Beheer-Optie-i)                             | Item kieser                                            |
| Escape                                             | Terug knoppie                                          |
| → (Regter pyl)                                    | Volgende item                                          |
| ← (Linker pyl)                                     | Vorige item                                           |
| ↑↓ (Bo pyl, Onder pyl)                          | Gelijktijdig tik op die geselekte item                |
| ⌥ ↓ (Opsie-Onder pyl)                            | Rol af                                                |
| ⌥↑ (Opsie-Bo pyl)                               | Rol op                                                |
| ⌥← of ⌥→ (Opsie-Linker pyl of Opsie-Regter pyl) | Rol links of regs                                      |
| ^⌥S (Beheer-Optie-S)                             | Skakel VoiceOver spraak aan of af                      |
| ⌘⇧⇥ (Opdrag-Shift-Tab)                            | Wissel na die vorige toepassing                         |
| ⌘⇥ (Opdrag-Tab)                                   | Wissel terug na die oorspronklike toepassing           |
| ←+→, dan Opsie + ← of Opsie+→                   | Navigeer deur Dok                                      |

#### Safari sneltoetse

| Sneltoets                | Aksie                                           |
| ------------------------ | ------------------------------------------------ |
| ⌘L (Opdrag-L)           | Open Ligging                                    |
| ⌘T                      | Open 'n nuwe tab                               |
| ⌘W                      | Sluit die huidige tab                          |
| ⌘R                      | Vernuw die huidige tab                          |
| ⌘.                      | Stop laai van die huidige tab                   |
| ^⇥                      | Wissel na die volgende tab                       |
| ^⇧⇥ (Beheer-Shift-Tab) | Beweeg na die vorige tab                        |
| ⌘L                      | Kies die teksinvoer/URL veld om dit te wysig   |
| ⌘⇧T (Opdrag-Shift-T)   | Open laaste geslote tab (kan verskeie kere gebruik word) |
| ⌘\[                     | Gaan terug een bladsy in jou blaai geskiedenis  |
| ⌘]                      | Gaan vorentoe een bladsy in jou blaai geskiedenis |
| ⌘⇧R                     | Aktiveer Leser Modus                             |

#### Posvak sneltoetse

| Sneltoets                   | Aksie                       |
| --------------------------- | ---------------------------- |
| ⌘L                         | Open Ligging                |
| ⌘T                         | Open 'n nuwe tab            |
| ⌘W                         | Sluit die huidige tab        |
| ⌘R                         | Vernuw die huidige tab      |
| ⌘.                         | Stop laai van die huidige tab |
| ⌘⌥F (Opdrag-Optie/Alt-F) | Soek in jou posvak         |

## Verwysings

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)



{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
