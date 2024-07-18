# Bekstvo iz KIOSK-ova

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **kradljivih malvera**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

## Provera fizičkog uređaja

|   Komponenta   | Radnja                                                               |
| ------------- | -------------------------------------------------------------------- |
| Dugme za napajanje  | Isključivanje i ponovno uključivanje uređaja može otkriti početni ekran      |
| Napojni kabl   | Proverite da li se uređaj ponovo pokreće kada se napajanje kratko isključi   |
| USB portovi     | Povežite fizičku tastaturu sa više prečica                        |
| Ethernet      | Skeniranje mreže ili špijuniranje može omogućiti daljnje iskorišćavanje             |


## Provera mogućih radnji unutar GUI aplikacije

**Uobičajeni dijalozi** su opcije poput **čuvanja datoteke**, **otvaranja datoteke**, izbora fonta, boje... Većina njih će **ponuditi punu funkcionalnost Explorer-a**. To znači da ćete moći pristupiti funkcionalnostima Explorer-a ako možete pristupiti ovim opcijama:

* Zatvori/Zatvori kao
* Otvori/Otvori sa
* Štampaj
* Izvoz/Uvoz
* Pretraga
* Skeniranje

Treba da proverite da li možete:

* Izmeniti ili kreirati nove datoteke
* Kreirati simboličke veze
* Pristupiti ograničenim područjima
* Izvršiti druge aplikacije

### Izvršavanje komandi

Možda **korišćenjem opcije `Otvori sa`** možete otvoriti/izvršiti neku vrstu ljuske.

#### Windows

Na primer _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pronađite više binarnih datoteka koje se mogu koristiti za izvršavanje komandi (i obavljanje neočekivanih radnji) ovde: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Više ovde: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassing ograničenja putanje

* **Okružne promenljive**: Postoji mnogo okružnih promenljivih koje pokazuju na neku putanju
* **Drugi protokoli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Simboličke veze**
* **Prečice**: CTRL+N (otvori novu sesiju), CTRL+R (Izvrši komande), CTRL+SHIFT+ESC (Upravitelj zadataka), Windows+E (otvori explorer), CTRL-B, CTRL-I (Favoriti), CTRL-H (Istorija), CTRL-L, CTRL-O (Dijalog za otvaranje datoteke), CTRL-P (Dijalog za štampanje), CTRL-S (Sačuvaj kao)
* Skriveni administrativni meni: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URI-ji**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC putanje**: Putanje za povezivanje sa deljenim fasciklama. Trebalo bi da pokušate da se povežete sa C$ lokalnog računara ("\\\127.0.0.1\c$\Windows\System32")
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

### Preuzimanje vaših binarnih datoteka

Konzola: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor registra: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Pristupanje fajl sistemu iz pretraživača

| PUTANJA                | PUTANJA              | PUTANJA               | PUTANJA                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |
### Prečice

* Ljepljive tipke - Pritisnite SHIFT 5 puta
* Miš tipke - SHIFT+ALT+NUMLOCK
* Visoki kontrast - SHIFT+ALT+PRINTSCN
* Prekidač tipki - Držite NUMLOCK 5 sekundi
* Filter tipki - Držite desni SHIFT 12 sekundi
* WINDOWS+F1 - Windows pretraga
* WINDOWS+D - Prikaz radne površine
* WINDOWS+E - Pokreni Windows Explorer
* WINDOWS+R - Pokreni
* WINDOWS+U - Centar za olakšavanje pristupa
* WINDOWS+F - Pretraga
* SHIFT+F10 - Kontekstualni meni
* CTRL+SHIFT+ESC - Upravitelj zadataka
* CTRL+ALT+DEL - Početni zaslon na novijim verzijama Windowsa
* F1 - Pomoć F3 - Pretraga
* F6 - Traka adrese
* F11 - Prebacivanje na puni ekran unutar Internet Explorera
* CTRL+H - Istorija Internet Explorera
* CTRL+T - Internet Explorer - Novi tab
* CTRL+N - Internet Explorer - Nova stranica
* CTRL+O - Otvori datoteku
* CTRL+S - Sačuvaj CTRL+N - Novi RDP / Citrix

### Potezi

* Povucite s lijeve strane prema desno da biste vidjeli sve otvorene prozore, minimizirajući KIOSK aplikaciju i pristupajući čitavom OS direktno;
* Povucite s desne strane prema lijevo da biste otvorili Centar za akciju, minimizirajući KIOSK aplikaciju i pristupajući čitavom OS direktno;
* Povucite s gornje ivice da biste vidjeli traku naslova za aplikaciju otvorenu u režimu punog ekrana;
* Povucite prema gore s dna da biste prikazali traku zadataka u aplikaciji na punom ekranu.

### Trikovi za Internet Explorer

#### 'Alatna traka slike'

To je traka s alatima koja se pojavljuje na gornjem lijevom dijelu slike kada se klikne na nju. Moći ćete Sačuvati, Štampati, Poslati putem e-pošte, Otvoriti "Moje slike" u Exploreru. Kiosk mora koristiti Internet Explorer.

#### Shell protokol

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

### Prikazivanje ekstenzija datoteka

Posetite ovu stranicu za više informacija: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Trikovi pregledača

Rezervne verzije iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Kreirajte zajednički dijalog pomoću JavaScript-a i pristupite Exploreru: `document.write('<input/type=file>')`\
Izvor: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Pokreti i dugmad

* Povucite prema gore s četiri (ili pet) prstiju / Dvaput dodirnite dugme Početna: Da biste videli prikaz višestrukih zadataka i promenili aplikaciju
* Povucite na jednu ili drugu stranu s četiri ili pet prstiju: Da biste promenili na sledeću/prethodnu aplikaciju
* Štipnite ekran s pet prstiju / Dodirnite dugme Početna / Povucite prema gore s jednim prstom s dna ekrana u brzom pokretu prema gore: Da biste pristupili Početnoj stranici
* Povucite jednim prstom s dna ekrana samo 1-2 inča (sporo): Pojavljuje se dock
* Povucite prema dole s vrha ekrana jednim prstom: Da biste videli obaveštenja
* Povucite prema dole s jednim prstom u gornjem desnom uglu ekrana: Da biste videli kontrolni centar iPad Pro-a
* Povucite jednim prstom s leve strane ekrana 1-2 inča: Da biste videli Prikaz dana
* Brzo povucite jednim prstom s centra ekrana udesno ili ulevo: Da biste promenili na sledeću/prethodnu aplikaciju
* Pritisnite i držite dugme za uključivanje/isključivanje na gornjem desnom uglu iPada + Pomerite klizač za isključivanje napajanja skroz udesno: Da biste isključili napajanje
* Pritisnite dugme za uključivanje/isključivanje na gornjem desnom uglu iPada i dugme Početna nekoliko sekundi: Da biste prinudno isključili napajanje
* Pritisnite dugme za uključivanje/isključivanje na gornjem desnom uglu iPada i dugme Početna brzo: Da biste napravili snimak ekrana koji će se pojaviti u donjem levom uglu ekrana. Pritisnite oba dugmeta istovremeno vrlo kratko kao da ih držite nekoliko sekundi, izvršiće se prinudno isključivanje napajanja

### Prečice

Treba da imate tastaturu za iPad ili adapter za USB tastaturu. Ovde će biti prikazane samo prečice koje mogu pomoći u izlasku iz aplikacije.

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
| ↑   | Gornja strelica     |
| ↓   | Donja strelica   |

#### Sistemske prečice

Ove prečice su za vizuelna podešavanja i zvučna podešavanja, u zavisnosti od korišćenja iPada.

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

#### Navigacija na iPadu

| Prečica                                           | Radnja                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Idi na Početnu stranicu                                              |
| ⌘⇧H (Command-Shift-H)                              | Idi na Početnu stranicu                                              |
| ⌘ (Space)                                          | Otvori Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Lista poslednjih deset korišćenih aplikacija                                 |
| ⌘\~                                                | Idi na poslednju aplikaciju                                       |
| ⌘⇧3 (Command-Shift-3)                              | Snimak ekrana (pojaviće se u donjem levom uglu da se sačuva ili deluje na njega) |
| ⌘⇧4                                                | Snimak ekrana i otvori ga u editoru                    |
| Pritisnite i držite ⌘                                   | Lista dostupnih prečica za aplikaciju                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Prikazuje dock                                      |
| ^⌥H (Control-Option-H)                             | Dugme Početna                                             |
| ^⌥H H (Control-Option-H-H)                         | Prikaz trake višestrukih zadataka                                      |
| ^⌥I (Control-Option-i)                             | Biranje stavke                                            |
| Escape                                             | Dugme Nazad                                             |
| → (Desna strelica)                                    | Sledeća stavka                                               |
| ← (Leva strelica)                                     | Prethodna stavka                                           |
| ↑↓ (Gornja strelica, Donja strelica)                          | Istovremeno dodirnite izabranu stavku                        |
| ⌥ ↓ (Opcija-Dole strelica)                            | Pomeri se nadole                                             |
| ⌥↑ (Opcija-Gore strelica)                               | Pomeri se nagore                                               |
| ⌥← ili ⌥→ (Opcija-Leva strelica ili Opcija-Desna strelica) | Pomeri se levo ili desno                                    |
| ^⌥S (Control-Option-S)                             | Uključi ili isključi govor VoiceOver                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Prebaci se na prethodnu aplikaciju                              |
| ⌘⇥ (Command-Tab)                                   | Vrati se na originalnu aplikaciju                         |
| ←+→, zatim Opcija + ← ili Opcija+→                   | Navigacija kroz Dock                                   |
#### Safari prečice

| Prečica                | Radnja                                           |
| ----------------------- | ------------------------------------------------- |
| ⌘L (Command-L)          | Otvori lokaciju                                   |
| ⌘T                      | Otvori novi tab                                   |
| ⌘W                      | Zatvori trenutni tab                              |
| ⌘R                      | Osveži trenutni tab                               |
| ⌘.                      | Zaustavi učitavanje trenutnog taba                |
| ^⇥                      | Prebaci se na sledeći tab                         |
| ^⇧⇥ (Control-Shift-Tab) | Prebaci se na prethodni tab                       |
| ⌘L                      | Izaberi tekstualni unos/URL polje za izmenu       |
| ⌘⇧T (Command-Shift-T)   | Otvori poslednji zatvoreni tab (može se koristiti više puta) |
| ⌘\[                     | Vrati se jednu stranicu unazad u istoriji pretrage |
| ⌘]                      | Idi jednu stranicu unapred u istoriji pretrage    |
| ⌘⇧R                     | Aktiviraj režim čitača                             |

#### Prečice za e-poštu

| Prečica                   | Radnja                        |
| -------------------------- | ----------------------------- |
| ⌘L                         | Otvori lokaciju               |
| ⌘T                         | Otvori novi tab               |
| ⌘W                         | Zatvori trenutni tab          |
| ⌘R                         | Osveži trenutni tab           |
| ⌘.                         | Zaustavi učitavanje trenutnog taba |
| ⌘⌥F (Command-Option/Alt-F) | Pretraži svoje sanduče        |

## Reference

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokrenut na **dark webu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji kradu informacije**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji kradu informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
