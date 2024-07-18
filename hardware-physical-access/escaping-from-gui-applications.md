# Kutoroka kwenye KIOSKs

{% hint style="success" %}
Jifunze & zoezi AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa utendaji wa **bure** kuchunguza ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** hapa:

{% embed url="https://whiteintel.io" %}

---

## Angalia kifaa cha kimwili

|   Sehemu   | Hatua                                                               |
| ---------- | ------------------------------------------------------------------- |
| Kitufe cha nguvu  | Kuzima kifaa na kukiwasha tena kunaweza kufunua skrini ya kuanza      |
| Kifaa cha umeme   | Angalia ikiwa kifaa kinazimika wakati umeme unakatwa kwa muda mfupi   |
| Bandari za USB     | Unganisha kibodi ya kimwili yenye makato zaidi                        |
| Ethernet      | Uchunguzi wa mtandao au kunusa unaweza kuwezesha unyonyaji zaidi             |


## Angalia vitendo vinavyowezekana ndani ya programu ya GUI

**Vidirisha vya Kawaida** ni chaguo kama **kuokoa faili**, **kufungua faili**, kuchagua fonti, rangi... Vingi vitatoa **utendaji kamili wa Explorer**. Hii inamaanisha kuwa utaweza kufikia utendaji wa Explorer ikiwa unaweza kufikia chaguo hizi:

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

### Utekelezaji wa Amri

Labda **kwa kutumia chaguo la `Fungua na`** unaweza kufungua/tekeleza aina fulani ya kabibi.

#### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata zaidi ya binari zinazoweza kutumika kutekeleza amri (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Kupitisha vizuizi vya njia

* **Mazingira ya mazingira**: Kuna mazingira mengi ya mazingira yanayoelekeza kwenye njia fulani
* **Itifaki nyingine**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Viungo vya ishara**
* **Vidakuzi**: CTRL+N (fungua kikao kipya), CTRL+R (Tekeleza Amri), CTRL+SHIFT+ESC (Meneja wa Kazi), Windows+E (fungua explorer), CTRL-B, CTRL-I (Vipendwa), CTRL-H (Historia), CTRL-L, CTRL-O (Faili/Fungua Dirisha), CTRL-P (Dirisha la Kuchapisha), CTRL-S (Hifadhi Kama)
* Menyu ya Utawala iliyofichwa: CTRL-ALT-F8, CTRL-ESC-F9
* **URI za Kabibi**: _shell:Vyombo vya Utawala, shell:Thibitisho za Nyaraka, shell:Vifaa vya Maktaba, shell:Profaili za Mtumiaji, shell:Binafsi, shell:Dirisha la Nyumbani la Utafutaji, shell:Mfumo wa Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Yangu, shell:Kabrasha la Mtandao, shell:Tuma Kwa, shell:Profaili za Watumiaji, shell:Vyombo vya Utawala vya Kawaida, shell:Kompyuta Y
### Vitufe

* Sticky Keys – Bonyeza SHIFT mara 5
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Shikilia NUMLOCK kwa sekunde 5
* Filter Keys – Shikilia SHIFT ya kulia kwa sekunde 12
* WINDOWS+F1 – Tafuta Windows
* WINDOWS+D – Onyesha Eneo la Kazi
* WINDOWS+E – Anzisha Mtafutaji wa Windows
* WINDOWS+R – Tekeleza
* WINDOWS+U – Kituo cha Upatikanaji Rahisi
* WINDOWS+F – Tafuta
* SHIFT+F10 – Menyu ya Muktadha
* CTRL+SHIFT+ESC – Meneja wa Kazi
* CTRL+ALT+DEL – Skrini ya kuingia kwenye toleo jipya la Windows
* F1 – Msaada F3 – Tafuta
* F6 – Mstari wa Anwani
* F11 – Badilisha skrini nzima ndani ya Internet Explorer
* CTRL+H – Historia ya Internet Explorer
* CTRL+T – Internet Explorer – Kichupo Kipya
* CTRL+N – Internet Explorer – Ukurasa Mpya
* CTRL+O – Fungua Faili
* CTRL+S – Hifadhi CTRL+N – RDP / Citrix Mpya

### Swaipu

* Swaipu kutoka upande wa kushoto kwenda kulia kuona Madirisha yote yaliyofunguliwa, kupunguza programu ya KIOSK na kupata OS nzima moja kwa moja;
* Swaipu kutoka upande wa kulia kwenda kushoto kufungua Kituo cha Matendo, kupunguza programu ya KIOSK na kupata OS nzima moja kwa moja;
* Swaipu kutoka juu kufanya upau wa kichwa uonekane kwa programu iliyofunguliwa kwa modi ya skrini kamili;
* Swaipu kutoka chini kuonyesha upau wa kazi katika programu ya skrini kamili.

### Hila za Internet Explorer

#### 'Mwambaa wa Picha'

Ni mwambaa wa zana unaotokea juu-kushoto mwa picha unapobonyeza. Utaweza Hifadhi, Chapa, Tuma kwa Barua, Fungua "Picha Zangu" kwenye Mtafutaji. Kiosk inahitaji kutumia Internet Explorer.

#### Itifaki ya Shell

Andika URL hizi kupata mtazamo wa Mtafutaji:

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
* `shell:Kompyuta Yangu`
* `shell:Intaneti`
* `Shell:Profaili`
* `Shell:Faili za Programu`
* `Shell:Mfumo`
* `Shell:Kisanduku cha Udhibiti`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Kisanduku cha Udhibiti
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Kompyuta Yangu
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Nafasi Zangu za Mtandao
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Onyesha Vificho vya Faili

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Hila za Vivinjari

Backup toleo la iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Unda sanduku la mazungumzo ya kawaida kwa kutumia JavaScript na ufikie mtafutaji wa faili: `document.write('<input/type=file>')`\
Chanzo: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Miguso na Vitufe

* Swaipu juu na vidole vinne (au vitano) / Bonyeza mara mbili kitufe cha Nyumbani: Kuona muonekano wa kazi nyingi na kubadilisha Programu
* Swaipu upande mmoja au mwingine na vidole vinne au vitano: Ili kubadilisha kwenye Programu inayofuata/ya mwisho
* Kanda skrini na vidole vitano / Gusa kitufe cha Nyumbani / Swaipu juu na kidole 1 kutoka chini ya skrini kwa harakati ya haraka kwenda juu: Kufikia Nyumbani
* Swaipu kidole 1 kutoka chini ya skrini kwa umbali wa 1-2 inchi (polepole): Doki itaonekana
* Swaipu chini kutoka juu ya skrini na kidole 1: Kuona arifa zako
* Swaipu chini na kidole 1 kona ya juu-kulia ya skrini: Kuona kituo cha udhibiti cha iPad Pro
* Swaipu kidole 1 kutoka kushoto mwa skrini 1-2 inchi: Kuona muonekano wa Leo
* Swaipu haraka kidole 1 kutoka katikati mwa skrini kwenda kulia au kushoto: Kubadilisha kwenye Programu inayofuata/ya mwisho
* Bonyeza na shikilia kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad +** Slide kwa **kuzima** kwa kusogeza mpaka mwisho: Kuzima
* Bonyeza kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad na kitufe cha Nyumbani kwa sekunde chache**: Kufanya kuzima ngumu
* Bonyeza kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad na kitufe cha Nyumbani haraka**: Kuchukua picha ya skrini itakayotokea chini kushoto ya skrini. Bonyeza vifungo vyote kwa wakati mmoja kwa muda mfupi kama vile unavyowashikilia sekunde chache kuzima ngumu itafanyika.

### Vitufe vya Haraka

Unapaswa kuwa na kibodi ya iPad au kigeuzi cha kibodi cha USB. Vitufe pekee ambavyo vinaweza kusaidia kutoroka kutoka kwenye programu vitafunuliwa hapa.

| Kitufe | Jina         |
| --- | ------------ |
| ⌘   | Amri      |
| ⌥   | Chaguo (Alt) |
| ⇧   | Badilisha        |
| ↩   | Kurudi       |
| ⇥   | Kichupo          |
| ^   | Udhibiti      |
| ←   | Mshale wa Kushoto   |
| →   | Mshale wa Kulia  |
| ↑   | Mshale wa Juu     |
| ↓   | Mshale wa Chini   |

#### Vitufe vya Mfumo

Vitufe hivi ni kwa mipangilio ya kuonekana na sauti, kulingana na matumizi ya iPad.

| Kitufe | Hatua                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Punguza Skrini                                                                    |
| F2       | Ongeza mwangaza wa skrini                                                                |
| F7       | Rudi nyuma wimbo mmoja                                                                  |
| F8       | Cheza/acheza                                                                     |
| F9       | Ruka wimbo                                                                      |
| F10      | Kimya                                                                           |
| F11      | Punguza sauti                                                                |
| F12      | Ongeza sauti                                                                |
| ⌘ Space  | Onyesha orodha ya lugha zilizopo; kuchagua moja, bonyeza tena kitufe cha nafasi. |

#### Uvigezo wa iPad

| Kitufe                                           | Hatua                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Nenda kwa Nyumbani                                              |
| ⌘⇧H (Amri-Shift-H)                              | Nenda kwa Nyumbani                                              |
| ⌘ (Space)                                          | Fungua Spotlight                                          |
| ⌘⇥ (Amri-Tab)                                   | Onyesha programu kumi zilizotumiwa mwisho                                 |
| ⌘\~                                                | Nenda kwa Programu iliyopita                                       |
| ⌘⇧3 (Amri-Shift-3)                              | Piga picha ya skrini (inahamia chini kushoto kuihifadhi au kuitumia) |
| ⌘⇧4                                                | Piga picha ya skrini na ifungue kwenye mhariri                    |
| Bonyeza na shikilia ⌘                                   | Orodha ya vitufe inayopatikana kwa Programu                 |
| ⌘⌥D (Amri-Chaguo/Alt-D)                         | Lete doki                                      |
| ^⌥H (Udhibiti-Chaguo-H)                             | Kitufe cha Nyumbani                                             |
| ^⌥H H (Udhibiti-Chaguo-H-H)                         | Onyesha upau wa kazi                                      |
| ^⌥I (Udhibiti-Chaguo-i)                             | Chagua Kipengee                                            |
| Kutoroka                                             | Kitufe cha Nyuma                                             |
| → (Mshale wa Kulia)                                    | Kipengee kifuatacho                                               |
| ← (Mshale wa Kushoto)                                     | Kipengee kilichopita                                           |
| ↑↓ (Mshale wa Juu, Mshale wa Chini)                          | Bonyeza mara moja kwa wakati mmoja kwenye kipengee kilichochaguliwa                        |
| ⌥ ↓ (Chaguo-Mshale wa Chini)                            | Endesha chini                                             |
| ⌥↑ (Chaguo-Mshale wa Juu)                               | Endesha juu                                               |
| ⌥← or ⌥→ (Chaguo-Mshale wa Kushoto au Chaguo-Mshale wa Kulia) | Endesha kushoto au kulia                                    |
| ^⌥S (Udhibiti-Chaguo-S)                             | Wezesha au Lemaza Hotuba ya VoiceOver                         |
| ⌘⇧⇥ (Amri-Shift-Tab)                            | Badilisha kwenye programu iliyopita                              |
| ⌘⇥ (Amri-Tab)                                   | Badilisha kurudi kwenye programu ya awali                         |
| ←+→, kisha Chaguo + ← au Chaguo+→                   | Endesha kupitia Doki                                   |
#### Vielelezo vya Safari

| Shortcut                | Hatua                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Amri-L)             | Fungua Mahali                                   |
| ⌘T                      | Fungua kichupo kipya                            |
| ⌘W                      | Funga kichupo cha sasa                          |
| ⌘R                      | Sasisha kichupo cha sasa                        |
| ⌘.                      | Acha kupakia kichupo cha sasa                   |
| ^⇥                      | Badilisha kwenye kichupo kijacho                 |
| ^⇧⇥ (Kudhibiti-Shift-Tab) | Hamia kwenye kichupo kilichopita                |
| ⌘L                      | Chagua sanduku la maandishi/eneo la URL kwa ajili ya kuhariri |
| ⌘⇧T (Amri-Shift-T)      | Fungua kichupo kilichofungwa mwisho (inaweza kutumika mara kadhaa) |
| ⌘\[                     | Nenda nyuma ukurasa mmoja katika historia yako ya kutembelea |
| ⌘]                      | Nenda mbele ukurasa mmoja katika historia yako ya kutembelea |
| ⌘⇧R                    | Wezesha Mode ya Msomaji                         |

#### Vielelezo vya Barua pepe

| Shortcut                   | Hatua                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Mahali               |
| ⌘T                         | Fungua kichupo kipya        |
| ⌘W                         | Funga kichupo cha sasa      |
| ⌘R                         | Sasisha kichupo cha sasa    |
| ⌘.                         | Acha kupakia kichupo cha sasa |
| ⌘⌥F (Amri-Option/Alt-F)    | Tafuta kwenye sanduku lako la barua pepe |

## Marejeo

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba taarifa.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Jifunze & jifanye mazoezi ya Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & jifanye mazoezi ya Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
