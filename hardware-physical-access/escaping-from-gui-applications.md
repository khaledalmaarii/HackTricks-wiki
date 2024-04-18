<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** hapa:

{% embed url="https://whiteintel.io" %}

---

# Angalia vitendo vinavyowezekana ndani ya programu ya GUI

**Vidirisha vya Kawaida** ni chaguo kama **kuokoa faili**, **kufungua faili**, kuchagua font, rangi... Zaidi yao itakupa **ufanisi kamili wa Explorer**. Hii inamaanisha kuwa utaweza kupata ufanisi wa Explorer ikiwa unaweza kupata chaguo hizi:

* Funga/Funga kama
* Fungua/Fungua na
* Chapisha
* Eksporti/Ingiza
* Tafuta
* Skani

Unapaswa kuangalia ikiwa unaweza:

* Badilisha au unda faili mpya
* Unda viungo vya ishara
* Pata ufikiaji wa maeneo yaliyozuiliwa
* Tekeleza programu zingine

## Utekelezaji wa Amri

Labda **ukitumia chaguo la `Fungua na`** unaweza kufungua/tekeleza aina fulani ya kabati.

### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata zaidi ya faili za binari zinazoweza kutumika kutekeleza amri (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Kupitisha vikwazo vya njia

* **Mazingira ya mazingira**: Kuna mazingira mengi ya mazingira yanayoelekeza kwenye njia fulani
* **Itifaki zingine**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Viungo vya ishara**
* **Vielekezi**: CTRL+N (fungua kikao kipya), CTRL+R (Tekeleza Amri), CTRL+SHIFT+ESC (Meneja wa Kazi),  Windows+E (fungua Explorer), CTRL-B, CTRL-I (Vipendwa), CTRL-H (Historia), CTRL-L, CTRL-O (Faili/Dirisha la Kufungua), CTRL-P (Dirisha la Kuchapisha), CTRL-S (Hifadhi Kama)
* Menyu ya Utawala iliyofichwa: CTRL-ALT-F8, CTRL-ESC-F9
* **URI za Kabati**: _kabati:Vyombo vya Utawala, kabati:ThesisLibrary, kabati:Vitabu vya Maktaba, kabati:Profaili za Mtumiaji, kabati:Binafsi, kabati:ThesisHomeFolder, kabati:Mfumo wa kabati:Vifaa vya Mtandao, kabati:SendTo, kabati:Profaili za Watumiaji, kabati:Vyombo vya Utawala vya Kawaida, kabati:KompyutaYangu, kabati:Intaneti_
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

## Pakua Binari Zako

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Mhariri wa Usajili: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Kupata mfumo wa faili kutoka kwenye kivinjari

| NJIA                | NJIA              | NJIA               | NJIA                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| Faili:/C:/windows    | Faili:/C:/windows/ | Faili:/C:/windows\\ | Faili:/C:\windows    |
| Faili:/C:\windows\\  | Faili:/C:\windows/ | Faili://C:/windows  | Faili://C:/windows/  |
| Faili://C:/windows\\ | Faili://C:\windows | Faili://C:\windows/ | Faili://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Vielekezi

* Vielekezi vya Kufunga – Bonyeza SHIFT mara 5
* Vielekezi vya Panya – SHIFT+ALT+NUMLOCK
* Mabadiliko ya Juu – SHIFT+ALT+PRINTSCN
* Vielekezi vya Toggle – Shikilia NUMLOCK kwa sekunde 5
* Vielekezi vya Kichujio – Shikilia SHIFT ya kulia kwa sekunde 12
* WINDOWS+F1 – Tafuta Windows
* WINDOWS+D – Onyesha Dakiika
* WINDOWS+E – Anzisha Windows Explorer
* WINDOWS+R – Tekeleza
* WINDOWS+U – Kituo cha Upatikanaji Rahisi
* WINDOWS+F – Tafuta
* SHIFT+F10 – Menyu ya Muktadha
* CTRL+SHIFT+ESC – Meneja wa Kazi
* CTRL+ALT+DEL – Skrini ya Kufurahisha kwenye toleo jipya la Windows
* F1 – Msaada F3 – Tafuta
* F6 – Mstari wa Anwani
* F11 – Badilisha skrini nzima ndani ya Internet Explorer
* CTRL+H – Historia ya Internet Explorer
* CTRL+T – Internet Explorer – Kichupo Kipya
* CTRL+N – Internet Explorer – Ukurasa Mpya
* CTRL+O – Fungua Faili
* CTRL+S – Hifadhi CTRL+N – RDP Mpya / Citrix
## Swipes

* Piga kwa upande wa kushoto kwenda kulia kuona Madirisha yote yaliyofunguliwa, kupunguza programu ya KIOSK na kupata mfumo wa uendeshaji moja kwa moja;
* Piga kwa upande wa kulia kwenda kushoto kufungua Kituo cha Matendo, kupunguza programu ya KIOSK na kupata mfumo wa uendeshaji moja kwa moja;
* Piga kwa ndani kutoka pembe ya juu kuifanya upau wa kichwa uonekane kwa programu iliyofunguliwa kwa mode kamili ya skrini;
* Piga juu kutoka chini kuonyesha upau wa kazi katika programu ya skrini kamili.

## Mbinu za Internet Explorer

### 'Mwambaa wa Picha'

Ni mwambaa unaotokea juu-kushoto wa picha unapobonyeza. Utaweza Kuokoa, Kuchapisha, Kutuma kwa Barua pepe, Kufungua "Picha Zangu" kwenye Explorer. Kiosk inahitaji kutumia Internet Explorer.

### Itifaki ya Shell

Andika URL hizi kupata mtazamo wa Explorer:

* `shell:Vifaa vya Utawala`
* `shell:Thibitisho za Nyaraka`
* `shell:Vifaa vya Maktaba`
* `shell:Profaili za Mtumiaji`
* `shell:Binafsi`
* `shell:Kutafuta Folda ya Nyumbani`
* `shell:Folda za Nafasi za Mtandao`
* `shell:Tuma Kwa`
* `shell:Profaili za Mtumiaji`
* `shell:Vifaa vya Utawala wa Kawaida`
* `shell:Funga Kompyuta Yangu`
* `shell:Funga Mtandao`
* `Shell:Profaili`
* `Shell:Faili za Programu`
* `Shell:Mfumo`
* `Shell:Folda ya Udhibiti wa Paneli`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Udhibiti wa Paneli
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Kompyuta Yangu
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Nafasi za Mtandao Yangu
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Onyesha Vifungu vya Faili

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Mbinu za Vivinjari

Backup toleo la iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Unda dialog ya kawaida kwa kutumia JavaScript na ufikie mtazamaji wa faili: `document.write('<input/type=file>')`
Chanzo: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Miguso na Vitufe

* Piga juu kwa vidole vinne (au vitano) / Bonyeza kitufe cha Nyumbani mara mbili: Kuona mtazamo wa kazi nyingi na kubadilisha Programu

* Piga upande mmoja au mwingine kwa vidole vinne au vitano: Ili kubadilisha kwa Programu inayofuata/ya mwisho

* Kanda skrini kwa vidole vitano / Gusa kitufe cha Nyumbani / Piga juu kutoka chini ya skrini kwa harakati ya haraka kwenda juu: Kupata Nyumbani

* Piga kidole kimoja kutoka chini ya skrini kwa umbali wa 1-2 inchi (polepole): Doki itaonekana

* Piga chini kutoka juu ya skrini kwa kidole kimoja: Kuona arifa zako

* Piga chini kwa kidole kimoja kona ya juu-kulia ya skrini: Kuona kituo cha udhibiti wa iPad Pro

* Piga kidole kimoja kutoka kushoto mwa skrini 1-2 inchi: Kuona mtazamo wa Leo

* Piga haraka kidole kimoja kutoka katikati mwa skrini kwenda kulia au kushoto: Kubadilisha kwa Programu inayofuata/ya mwisho

* Bonyeza na shikilia kitufe cha Kuwasha/Gafla/Gafla juu kulia mwa **iPad +** Hamisha Kielekezo cha **kuzima** kulia kabisa: Kuzima

* Bonyeza kitufe cha Kuwasha/Gafla/Gafla juu kulia mwa **iPad na kitufe cha Nyumbani kwa sekunde chache**: Kufanya kuzima ngumu

* Bonyeza kitufe cha Kuwasha/Gafla/Gafla juu kulia mwa **iPad na kitufe cha Nyumbani haraka**: Kupiga picha ya skrini itakayotokea chini kushoto ya skrini. Bonyeza vifungo vyote kwa wakati mmoja kwa muda mfupi kana kwamba unawashikilia sekunde chache kuzima ngumu itafanyika.

## Vielekezo vya Haraka

Unapaswa kuwa na kibodi ya iPad au kigeuzi cha kibodi cha USB. Vielekezo pekee vitakavyosaidia kutoroka kutoka kwa programu yataonyeshwa hapa.

| Kitufe | Jina         |
| --- | ------------ |
| ⌘   | Amri      |
| ⌥   | Chaguo (Alt) |
| ⇧   | Badilisha        |
| ↩   | Rudi       |
| ⇥   | Tab          |
| ^   | Udhibiti      |
| ←   | Mshale wa Kushoto   |
| →   | Mshale wa Kulia  |
| ↑   | Mshale wa Juu     |
| ↓   | Mshale wa Chini   |

### Vielekezo vya Mfumo

Vielekezo hivi ni kwa mipangilio ya kuonekana na sauti, kulingana na matumizi ya iPad.

| Vielekezo | Hatua                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Punguza Skrini                                                                    |
| F2       | Ongeza mwangaza wa skrini                                                                |
| F7       | Rudi nyimbo moja                                                                  |
| F8       | Cheza/Acha                                                                     |
| F9       | Ruka nyimbo                                                                      |
| F10      | Lemaza                                                                           |
| F11      | Punguza sauti                                                                |
| F12      | Ongeza sauti                                                                |
| ⌘ Space  | Onyesha orodha ya lugha zilizopo; kuchagua moja, bonyeza tena kitufe cha nafasi. |

### Uvigezo wa iPad

| Vielekezo                                           | Hatua                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Nenda kwa Nyumbani                                              |
| ⌘⇧H (Amri-Shift-H)                              | Nenda kwa Nyumbani                                              |
| ⌘ (Space)                                          | Fungua Spotlight                                          |
| ⌘⇥ (Amri-Tab)                                   | Orodhesha programu kumi zilizotumiwa mwisho                                 |
| ⌘\~                                                | Nenda kwa Programu iliyopita                                       |
| ⌘⇧3 (Amri-Shift-3)                              | Piga picha ya skrini (inahamia chini kushoto kuhifadhi au kuchukua hatua) |
| ⌘⇧4                                                | Piga picha ya skrini na ifungue kwenye mhariri                    |
| Bonyeza na shikilia ⌘                                   | Orodha ya vielekezo inapatikana kwa Programu                 |
| ⌘⌥D (Amri-Chaguo/Alt-D)                         | Lete doki                                      |
| ^⌥H (Udhibiti-Chaguo-H)                             | Kitufe cha Nyumbani                                             |
| ^⌥H H (Udhibiti-Chaguo-H-H)                         | Onyesha upau wa kazi nyingi                                      |
| ^⌥I (Udhibiti-Chaguo-i)                             | Chagua kipengee                                            |
| Kutoroka                                             | Kitufe cha nyuma                                             |
| → (Mshale wa Kulia)                                    | Kipengee kifuatacho                                               |
| ← (Mshale wa Kushoto)                                     | Kipengee kilichopita                                           |
| ↑↓ (Mshale wa Juu, Mshale wa Chini)                          | Bonyeza kwa wakati mmoja kipengee kilichochaguliwa                        |
| ⌥ ↓ (Chaguo-Mshale wa Chini)                            | Endesha chini                                             |
| ⌥↑ (Chaguo-Mshale wa Juu)                               | Endesha juu                                               |
| ⌥← or ⌥→ (Chaguo-Mshale wa Kushoto au Chaguo-Mshale wa Kulia) | Endesha kushoto au kulia                                    |
| ^⌥S (Udhibiti-Chaguo-S)                             | Wezesha au Lemaza Sauti ya VoiceOver                         |
| ⌘⇧⇥ (Amri-Shift-Tab)                            | Badilisha kwa programu iliyopita                              |
| ⌘⇥ (Amri-Tab)                                   | Badilisha kurudi kwa programu ya awali                         |
| ←+→, kisha Chaguo + ← au Chaguo+→                   | Endesha kupitia Doki                                   |
### Vielelezo vya Safari

| Vielelezo                | Hatua                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Amri-L)          | Fungua Mahali                                    |
| ⌘T                      | Fungua kichupo kipya                                   |
| ⌘W                      | Funga kichupo cha sasa                            |
| ⌘R                      | Sasisha kichupo cha sasa                          |
| ⌘.                      | Acha kupakia kichupo cha sasa                     |
| ^⇥                      | Badilisha kwenye kichupo kijacho                           |
| ^⇧⇥ (Kudhibiti-Shift-Tab) | Hamia kwenye kichupo kilichopita                         |
| ⌘L                      | Chagua kisanduku cha maandishi/eneo la URL ili ulibadilishe     |
| ⌘⇧T (Amri-Shift-T)   | Fungua kichupo kilichofungwa mwisho (inaweza kutumika mara kadhaa) |
| ⌘\[                     | Rudi nyuma ukurasa mmoja katika historia yako ya kutembelea      |
| ⌘]                      | Nenda mbele ukurasa mmoja katika historia yako ya kutembelea   |
| ⌘⇧R                     | Wezesha Mode ya Msomaji                             |

### Vielelezo vya Barua pepe

| Vielelezo                   | Hatua                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Mahali                |
| ⌘T                         | Fungua kichupo kipya               |
| ⌘W                         | Funga kichupo cha sasa        |
| ⌘R                         | Sasisha kichupo cha sasa      |
| ⌘.                         | Acha kupakia kichupo cha sasa |
| ⌘⌥F (Amri-Option/Alt-F) | Tafuta kwenye sanduku lako la barua pepe       |

# Marejeo

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji iliyochangiwa na **dark-web** inayotoa huduma za **bure** kuchunguza ikiwa kampuni au wateja wake wameathiriwa na **malwares za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao kwa **bure** kwa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
