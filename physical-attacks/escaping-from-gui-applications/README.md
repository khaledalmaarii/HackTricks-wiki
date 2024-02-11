<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Angalia vitendo vinavyowezekana ndani ya programu ya GUI

**Dialogs za Kawaida** ni chaguo kama **kuhifadhi faili**, **kufungua faili**, kuchagua fonti, rangi... Zaidi yao itakupa **uwezo kamili wa Explorer** ikiwa unaweza kupata chaguo hizi:

* Funga/Funga kama
* Fungua/Fungua na
* Chapisha
* Eksporti/Ingiza
* Tafuta
* Skani

Unapaswa kuangalia ikiwa unaweza:

* Badilisha au tengeneza faili mpya
* Tengeneza viungo vya ishara
* Pata ufikiaji kwenye maeneo yaliyozuiwa
* Tekeleza programu nyingine

## Utekelezaji wa Amri

Labda **kwa kutumia chaguo la `Fungua na`** unaweza kufungua/utekeleza aina fulani ya kabati.

### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata zaidi ya faili za utekelezaji (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Kuepuka vizuizi vya njia

* **Mazingira ya mazingira**: Kuna mazingira mengi ya mazingira yanayoelekeza kwenye njia fulani
* **Itifaki zingine**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Viungo vya ishara**
* **Vidokezo**: CTRL+N (fungua kikao kipya), CTRL+R (Tekeleza Amri), CTRL+SHIFT+ESC (Meneja wa Kazi), Windows+E (fungua Explorer), CTRL-B, CTRL-I (Vipendwa), CTRL-H (Historia), CTRL-L, CTRL-O (Faili/Fungua Dialog), CTRL-P (Chapisha Dialog), CTRL-S (Hifadhi Kama)
* Menyu ya Utawala iliyofichwa: CTRL-ALT-F8, CTRL-ESC-F9
* **URI za Kabati**: _shell:Vyombo vya Utawala, shell:ThriftDocuments, shell:Thrifts, shell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Vyombo vya Utawala vya Kawaida, shell:KompyutaYangu, shell:InternetFolder_
* **Njia za UNC**: Njia za kuunganisha folda zilizoshirikiwa. Jaribu kuunganisha C$ ya mashine ya ndani ("\\\127.0.0.1\c$\Windows\System32")
* **Njia zaidi za UNC:**

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

## Pakua Programu zako

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Mhariri wa Usajili: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Kupata mfumo wa faili kutoka kwenye kivinjari

| NJIA                | NJIA              | NJIA               | NJIA                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Vidokezo

* Sticky Keys – Bonyeza SHIFT mara 5
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Shikilia NUMLOCK kwa sekunde 5
* Filter Keys – Shikilia SHIFT ya kulia kwa sekunde 12
* WINDOWS+F1 – Tafuta ya Windows
* WINDOWS+D – Onyesha Desktop
* WINDOWS+E – Anzisha Windows Explorer
* WINDOWS+R – Run
* WINDOWS+U – Kituo cha Upatikanaji Rahisi
* WINDOWS+F – Tafuta
* SHIFT+F10 – Menyu ya Muktadha
* CTRL+SHIFT+ESC – Meneja wa Kazi
* CTRL+ALT+DEL – Skrini ya kuanza kwenye toleo jipya la Windows
* F1 – Msaada F3 – Tafuta
* F6 – Kikoa cha Anwani
* F11 – Badilisha skrini kamili ndani ya Internet Explorer
* CTRL+H – Historia ya Internet Explorer
* CTRL+T – Internet Explorer – Tabo Mpya
* CTRL+N – Internet Explorer – Ukurasa Mpya
* CTRL+O – Fungua Faili
* CTRL+S – Hifadhi CTRL+N – RDP Mpya / Citrix
## Swipes

* Piga kwa upande wa kushoto kwenda kulia kuona madirisha yote yaliyofunguliwa, kupunguza programu ya KIOSK na kupata mfumo wa uendeshaji wote moja kwa moja;
* Piga kwa upande wa kulia kwenda kushoto kufungua Kituo cha Matendo, kupunguza programu ya KIOSK na kupata mfumo wa uendeshaji wote moja kwa moja;
* Piga kwa upande wa juu kutoka pembe ya juu kuifanya mstari wa kichwa uonekane kwa programu iliyofunguliwa kwenye hali ya skrini kamili;
* Piga kwa juu kutoka chini kuonyesha upau wa kazi katika programu ya skrini kamili.

## Mbinu za Internet Explorer

### 'Kishikizo cha Picha'

Ni kishikizo kinachoonekana juu-kushoto ya picha unapobonyeza. Utaweza Kuokoa, Kuchapisha, Kutuma Barua, Kufungua "Picha Zangu" kwenye Mtafutaji. Kiosk inahitaji kutumia Internet Explorer.

### Itifaki ya Shell

Andika URL hizi ili kupata mtazamo wa Mtafutaji:

* `shell:Vifaa vya Utawala`
* `shell:Thibitisho za Nyaraka`
* `shell:Vitabu vya Maktaba`
* `shell:Viprofaili vya Mtumiaji`
* `shell:Binafsi`
* `shell:Kabati la Nyumbani la Utafutaji`
* `shell:Kabati la Nafasi za Mtandao`
* `shell:Tuma Kwa`
* `shell:Viprofaili vya Mtumiaji`
* `shell:Vifaa vya Utawala vya Kawaida`
* `shell:Kabati la Kompyuta Yangu`
* `shell:Kabati la Mtandao`
* `Shell:Wasifu`
* `Shell:Faili za Programu`
* `Shell:Mfumo`
* `Shell:Kabati la Udhibiti`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Kituo cha Udhibiti
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Kompyuta Yangu
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Nafasi za Mtandao Yangu
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Onyesha Vipeperushi vya Faili

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Mbinu za Vivinjari

Hifadhi toleo za iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Unda sanduku la mazungumzo ya kawaida kwa kutumia JavaScript na ufikie mtafutaji wa faili: `document.write('<input/type=file>')`
Chanzo: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Mielekeo na vitufe

* Piga juu na vidole vinne (au vitano) / Bonyeza mara mbili kitufe cha Nyumbani: Kuona muonekano wa multitask na kubadilisha Programu

* Piga upande mmoja au mwingine na vidole vinne au vitano: Ili kubadilisha kwa Programu inayofuata/ya mwisho

* Kanda skrini na vidole vitano / Chagua kitufe cha Nyumbani / Piga juu na kidole 1 kutoka chini ya skrini kwa mwendo wa haraka kwenda juu: Kufikia Nyumbani

* Piga kidole kimoja kutoka chini ya skrini kwa umbali wa 1-2 inchi (polepole): Dock itaonekana

* Piga chini kutoka juu ya skrini na kidole 1: Kuona arifa zako

* Piga chini na kidole 1 pembe ya juu-kulia ya skrini: Kuona kituo cha udhibiti cha iPad Pro

* Piga kidole 1 kutoka kushoto ya skrini 1-2 inchi: Kuona muonekano wa Leo

* Piga kidole 1 kwa haraka kutoka katikati ya skrini kwenda kulia au kushoto: Kubadilisha kwa Programu inayofuata/ya mwisho

* Bonyeza na ushike kitufe cha On/**Off**/Sleep kwenye pembe ya juu-kulia ya **iPad +** Sogeza kisahani cha **kuzima** nguvu mpaka mwisho wa kulia: Kuzima

* Bonyeza kitufe cha On/**Off**/Sleep kwenye pembe ya juu-kulia ya **iPad na kitufe cha Nyumbani kwa sekunde chache**: Kuzima nguvu kwa nguvu

* Bonyeza kitufe cha On/**Off**/Sleep kwenye pembe ya juu-kulia ya **iPad na kitufe cha Nyumbani kwa haraka**: Kuchukua picha ya skrini ambayo itaonekana chini kushoto ya skrini. Bonyeza vifungo vyote kwa wakati mmoja kwa muda mfupi sana kama vile unawashika kwa sekunde chache kuzima nguvu kwa nguvu.

## Vipeperushi

Unapaswa kuwa na kibodi ya iPad au kibodi ya USB. Hapa tutaweka tu vipeperushi ambavyo vinaweza kusaidia kutoroka kutoka kwenye programu.

| Kitufe | Jina         |
| ------ | ------------ |
| ⌘      | Amri         |
| ⌥      | Chaguo (Alt) |
| ⇧      | Kugeuza      |
| ↩      | Kurudi       |
| ⇥      | Tab          |
| ^      | Udhibiti     |
| ←      | Mshale wa Kushoto   |
| →      | Mshale wa Kulia  |
| ↑      | Mshale wa Juu     |
| ↓      | Mshale wa Chini   |

### Vipeperushi vya Mfumo

Vipeperushi hivi ni kwa mipangilio ya kuonekana na sauti, kulingana na matumizi ya iPad.

| Kipeperushi | Hatua                                                                         |
| ---------- | ------------------------------------------------------------------------------ |
| F1         | Punguza Skrini                                                                    |
| F2         | Ongeza mwangaza                                                                |
| F7         | Rudi nyuma wimbo                                                                  |
| F8         | Cheza/Pauza                                                                     |
| F9         | Ruka wimbo                                                                      |
| F10        | Kimya                                                                           |
| F11        | Punguza sauti                                                                |
| F12        | Ongeza sauti                                                                |
| ⌘ Space    | Onyesha orodha ya lugha zinazopatikana; kuchagua moja, bonyeza tena nafasi ya nafasi. |

### Uvigeuzi wa iPad

| Kipeperushi                                           | Hatua                                                  |
| ---------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                   | Nenda Nyumbani                                         |
| ⌘⇧H (Amri-Geuza-H)                                   | Nenda Nyumbani                                         |
| ⌘ (Nafasi)                                           | Fungua Spotlight                                       |
| ⌘⇥ (Amri-Tab)                                        | Onyesha programu zilizotumiwa kwa mara kumi za mwisho    |
| ⌘\~                                                  | Nenda kwenye Programu ya Mwisho                         |
| ⌘⇧3 (Amri-Geuza-3)                                   | Picha ya skrini (inahamia chini kushoto kuokoa au kuitumia) |
| ⌘⇧4                                                  | Picha ya skrini na ifungue kwenye mhariri               |
| Bonyeza na ushike ⌘                                   | Orodha ya vipeperushi inapatikana kwa Programu           |
| ⌘⌥D (Amri-Chaguo/Alt-D)                              | Onyesha dock                                           |
| ^⌥H (Udhibiti-Chaguo-H)                              | Kitufe cha Nyumbani                                    |
| ^⌥H H (Udhibiti-Chaguo-H-H)                          | Onyesha upau wa multitask                               |
| ^⌥I (Udhibiti-Chaguo-i)                              | Chagua kipengee                                        |
| Escape                                               | Kitufe cha Nyuma                                       |
| → (Mshale wa Kulia)                                  | Kipengee kijacho                                       |
| ← (Mshale wa Kushoto)                                | Kipengee cha awali                                     |
| ↑↓ (Mshale wa Juu, Mshale wa Chini)                  | Bonyeza kwa wakati mmoja kipengee kilichochaguliwa       |
| ⌥ ↓ (Chaguo-Mshale wa Chini)                         | Geu
### Vielelezo vya Safari

| Vielelezo                | Hatua                                            |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Amri-L)             | Fungua Mahali                                    |
| ⌘T                      | Fungua kichupo kipya                             |
| ⌘W                      | Funga kichupo cha sasa                           |
| ⌘R                      | Sasisha kichupo cha sasa                         |
| ⌘.                      | Acha kupakia kichupo cha sasa                    |
| ^⇥                      | Badilisha kwenye kichupo kijacho                  |
| ^⇧⇥ (Kudhibiti-Shift-Tab) | Hamia kwenye kichupo kilichopita                 |
| ⌘L                      | Chagua kisanduku cha maandishi/eneo la URL ili kubadilisha |
| ⌘⇧T (Amri-Shift-T)     | Fungua kichupo kilichofungwa mwisho (inaweza kutumika mara kadhaa) |
| ⌘\[                     | Rudi kwenye ukurasa uliopita katika historia yako ya kuvinjari |
| ⌘]                      | Nenda mbele kwenye ukurasa mmoja katika historia yako ya kuvinjari |
| ⌘⇧R                     | Wezesha Mode ya Msomaji                           |

### Vielelezo vya Barua

| Vielelezo                   | Hatua                         |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Mahali                 |
| ⌘T                         | Fungua kichupo kipya          |
| ⌘W                         | Funga kichupo cha sasa        |
| ⌘R                         | Sasisha kichupo cha sasa      |
| ⌘.                         | Acha kupakia kichupo cha sasa |
| ⌘⌥F (Amri-Alt-F)           | Tafuta kwenye sanduku lako la barua pepe |

# Marejeo

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
