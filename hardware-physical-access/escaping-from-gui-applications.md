<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je **dark-web** pretraživač koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu**.

Primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

# Provera mogućih akcija unutar GUI aplikacije

**Uobičajeni dijalozi** su opcije poput **čuvanja fajla**, **otvaranja fajla**, izbora fonta, boje... Većina njih će **ponuditi punu funkcionalnost Explorer-a**. To znači da ćete moći pristupiti funkcionalnostima Explorer-a ako možete pristupiti ovim opcijama:

* Zatvori/Zatvori kao
* Otvori/Otvori sa
* Štampaj
* Izvoz/Uvoz
* Pretraga
* Skeniranje

Treba da proverite da li možete:

* Modifikovati ili kreirati nove fajlove
* Kreirati simboličke veze
* Pristupiti ograničenim područjima
* Izvršiti druge aplikacije

## Izvršavanje komandi

Možda **korišćenjem opcije `Otvori sa`** možete otvoriti/izvršiti neku vrstu shell-a.

### Windows

Na primer _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pronađite više binarnih fajlova koji se mogu koristiti za izvršavanje komandi (i obavljanje neočekivanih akcija) ovde: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Više ovde: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Bypassiranje restrikcija putanje

* **Okružne promenljive**: Postoji mnogo okružnih promenljivih koje pokazuju na neku putanju
* **Drugi protokoli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Simboličke veze**
* **Prečice**: CTRL+N (otvori novu sesiju), CTRL+R (Izvrši komande), CTRL+SHIFT+ESC (Menadžer zadataka),  Windows+E (otvori explorer), CTRL-B, CTRL-I (Favoriti), CTRL-H (Istorija), CTRL-L, CTRL-O (Dijalog za otvaranje fajla), CTRL-P (Dijalog za štampanje), CTRL-S (Sačuvaj kao)
* Skriveni administrativni meni: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URI-ji**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC putanje**: Putanje za povezivanje sa deljenim fasciklama. Trebalo bi da pokušate da se povežete sa C$ lokalne mašine ("\\\127.0.0.1\c$\Windows\System32")
* **Još UNC putanja:**

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

## Preuzimanje vaših binarnih fajlova

Konzola: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor registra: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Pristupanje fajl sistemu iz pretraživača

| PUTANJA                | PUTANJA              | PUTANJA               | PUTANJA                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Prečice

* Ljepljive tipke – Pritisnite SHIFT 5 puta
* Mišje tipke – SHIFT+ALT+NUMLOCK
* Visoki kontrast – SHIFT+ALT+PRINTSCN
* Prekidači tipki – Držite NUMLOCK 5 sekundi
* Filter tipki – Držite desni SHIFT 12 sekundi
* WINDOWS+F1 – Windows Pretraga
* WINDOWS+D – Prikaz radne površine
* WINDOWS+E – Pokreni Windows Explorer
* WINDOWS+R – Pokreni
* WINDOWS+U – Centar za olakšavanje pristupa
* WINDOWS+F – Pretraga
* SHIFT+F10 – Kontekstualni meni
* CTRL+SHIFT+ESC – Menadžer zadataka
* CTRL+ALT+DEL – Početni ekran na novijim verzijama Windows-a
* F1 – Pomoć F3 – Pretraga
* F6 – Traka adrese
* F11 – Prekidač za celozaslonski prikaz u Internet Explorer-u
* CTRL+H – Istorija Internet Explorera
* CTRL+T – Internet Explorer – Novi tab
* CTRL+N – Internet Explorer – Nova stranica
* CTRL+O – Otvori fajl
* CTRL+S – Sačuvaj CTRL+N – Novi RDP / Citrix
## Potezi

* Povucite s leve strane na desnu da biste videli sve otvorene prozore, minimizirajući KIOSK aplikaciju i direktno pristupajući celom OS-u;
* Povucite s desne strane na levu da biste otvorili Akcioni centar, minimizirajući KIOSK aplikaciju i direktno pristupajući celom OS-u;
* Povucite odozgo da biste videli traku sa naslovom za aplikaciju otvorenu u režimu punog ekrana;
* Povucite odozdo nagore da biste prikazali traku sa zadacima u aplikaciji na punom ekranu.

## Trikovi za Internet Explorer

### 'Alat za slike'

To je traka sa alatima koja se pojavljuje u gornjem levom uglu slike kada se klikne na nju. Moći ćete da Sačuvate, Štampate, Pošaljete e-poštu, Otvorite "Moje slike" u Exploreru. Kiosk mora koristiti Internet Explorer.

### Shell protokol

Unesite ove URL-ove da biste dobili prikaz Explorer-a:

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
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Kontrolna tabla
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Moj računar
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Moj mrežni prostor
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Prikazivanje ekstenzija datoteka

Proverite ovu stranicu za više informacija: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Trikovi za pretraživače

Rezervne verzije iKat-a:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Kreirajte zajednički dijalog pomoću JavaScript-a i pristupite istraživaču datoteka: `document.write('<input/type=file>')`
Izvor: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Pokreti i dugmad

* Povucite nagore sa četiri (ili pet) prstiju / Dvaput dodirnite dugme Početna: Da biste videli prikaz višestrukih zadataka i promenili aplikaciju

* Povucite na jednu ili drugu stranu sa četiri ili pet prstiju: Da biste promenili na sledeću/prethodnu aplikaciju

* Štipnite ekran sa pet prstiju / Dodirnite dugme Početna / Povucite nagore jednim prstom sa dna ekrana u brzom pokretu nagore: Da biste pristupili Početnoj stranici

* Povucite jednim prstom sa dna ekrana samo 1-2 inča (sporo): Pojavljuje se dock

* Povucite nadole sa vrha ekrana jednim prstom: Da biste videli obaveštenja

* Povucite nadole jednim prstom u gornjem desnom uglu ekrana: Da biste videli kontrolni centar iPad Pro-a

* Povucite jednim prstom sa leve strane ekrana 1-2 inča: Da biste videli Prikaz današnjih događaja

* Brzo povucite jednim prstom sa centra ekrana udesno ili ulevo: Da biste promenili na sledeću/prethodnu aplikaciju

* Pritisnite i držite dugme Uključi/**Isključi**/Spavanje u gornjem desnom uglu **iPad-a +** Pomerite klizač za **isključivanje** sve do kraja udesno: Da biste isključili

* Pritisnite dugme Uključi/**Isključi**/Spavanje u gornjem desnom uglu **iPad-a i dugme Početna nekoliko sekundi**: Da biste prinudno isključili uređaj

* Pritisnite dugme Uključi/**Isključi**/Spavanje u gornjem desnom uglu **iPad-a i dugme Početna brzo**: Da biste napravili snimak ekrana koji će se pojaviti u donjem levom uglu ekrana. Pritisnite oba dugmeta istovremeno veoma kratko, jer ako ih držite nekoliko sekundi, izvršiće se prinudno isključivanje.

## Prečice

Treba da imate tastaturu za iPad ili adapter za USB tastaturu. Biće prikazane samo prečice koje mogu pomoći u izlasku iz aplikacije.

| Taster | Naziv         |
| --- | ------------ |
| ⌘   | Komanda      |
| ⌥   | Opcija (Alt) |
| ⇧   | Shift        |
| ↩   | Povratak       |
| ⇥   | Tab          |
| ^   | Kontrola      |
| ←   | Leva strelica   |
| →   | Desna strelica  |
| ↑   | Strelica nagore     |
| ↓   | Strelica nadole   |

### Sistemske prečice

Ove prečice su za vizuelna podešavanja i zvučna podešavanja, u zavisnosti od upotrebe iPada.

| Prečica | Radnja                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Zamrači ekran                                                                    |
| F2       | Osvetli ekran                                                                |
| F7       | Nazad jedna pesma                                                                  |
| F8       | Pusti/pauziraj                                                                     |
| F9       | Preskoči pesmu                                                                      |
| F10      | Isključi zvuk                                                                           |
| F11      | Smanji zvuk                                                                |
| F12      | Povećaj zvuk                                                                |
| ⌘ Space  | Prikazuje listu dostupnih jezika; da biste izabrali jedan, ponovo dodirnite razmaknicu. |

### Navigacija na iPad-u

| Prečica                                           | Radnja                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Idi na Početnu stranicu                                              |
| ⌘⇧H (Command-Shift-H)                              | Idi na Početnu stranicu                                              |
| ⌘ (Space)                                          | Otvori Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Lista poslednjih deset korišćenih aplikacija                                 |
| ⌘\~                                                | Idi na poslednju aplikaciju                                       |
| ⌘⇧3 (Command-Shift-3)                              | Snimak ekrana (pojavljuje se u donjem levom uglu za čuvanje ili radnju) |
| ⌘⇧4                                                | Snimak ekrana i otvori ga u uređivaču                    |
| Pritisnite i držite ⌘                                   | Lista dostupnih prečica za aplikaciju                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Prikazuje dock                                      |
| ^⌥H (Control-Option-H)                             | Dugme Početna                                             |
| ^⌥H H (Control-Option-H-H)                         | Prikazuje traku sa višestrukim zadacima                                      |
| ^⌥I (Control-Option-i)                             | Biranje stavki                                            |
| Escape                                             | Dugme Nazad                                             |
| → (Desna strelica)                                    | Sledeća stavka                                               |
| ← (Leva strelica)                                     | Prethodna stavka                                           |
| ↑↓ (Strelica nagore, Strelica nadole)                          | Istovremeno dodirnite izabranu stavku                        |
| ⌥ ↓ (Opcija-Strelica nadole)                            | Pomeri nadole                                             |
| ⌥↑ (Opcija-Strelica nagore)                               | Pomeri nagore                                               |
| ⌥← ili ⌥→ (Opcija-Leva strelica ili Opcija-Desna strelica) | Pomeri levo ili desno                                    |
| ^⌥S (Control-Option-S)                             | Uključi ili isključi govorni izlaz                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Prebaci se na prethodnu aplikaciju                              |
| ⌘⇥ (Command-Tab)                                   | Vrati se na originalnu aplikaciju                         |
| ←+→, zatim Opcija + ← ili Opcija+→                   | Navigacija kroz Dock                                   |
### Safari prečice

| Prečica                | Radnja                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Otvori lokaciju                                  |
| ⌘T                      | Otvori novi tab                                   |
| ⌘W                      | Zatvori trenutni tab                            |
| ⌘R                      | Osveži trenutni tab                          |
| ⌘.                      | Zaustavi učitavanje trenutnog taba                     |
| ^⇥                      | Prebaci se na sledeći tab                           |
| ^⇧⇥ (Control-Shift-Tab) | Prebaci se na prethodni tab                         |
| ⌘L                      | Izaberi tekstualni unos/URL polje da ga izmeniš     |
| ⌘⇧T (Command-Shift-T)   | Otvori poslednji zatvoreni tab (može se koristiti više puta) |
| ⌘\[                     | Vrati se jednu stranicu unazad u istoriji pretrage      |
| ⌘]                      | Idi napred jednu stranicu u istoriji pretrage   |
| ⌘⇧R                     | Aktiviraj režim čitača                             |

### Prečice za Mail

| Prečica                   | Radnja                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otvori lokaciju                |
| ⌘T                         | Otvori novi tab               |
| ⌘W                         | Zatvori trenutni tab        |
| ⌘R                         | Osveži trenutni tab      |
| ⌘.                         | Zaustavi učitavanje trenutnog taba |
| ⌘⌥F (Command-Option/Alt-F) | Pretraži svoj poštanski sandučić       |

# Reference

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-webom** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade podatke**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
