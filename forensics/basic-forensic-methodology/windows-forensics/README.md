# Windows Vitu

## Windows Vitu

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Vitu vya Kawaida vya Windows

### Arifa za Windows 10

Katika njia `\Users\<jina_la_mtumiaji>\AppData\Local\Microsoft\Windows\Notifications` unaweza kupata database `appdb.dat` (kabla ya Windows anniversary) au `wpndatabase.db` (baada ya Windows Anniversary).

Ndani ya database hii ya SQLite, unaweza kupata meza ya `Notification` na arifa zote (katika muundo wa XML) ambazo zinaweza kuwa na data muhimu.

### Timeline

Timeline ni sifa ya Windows ambayo hutoa **historia ya mfululizo** ya kurasa za wavuti zilizotembelewa, hati zilizohaririwa, na programu zilizotekelezwa.

Database iko katika njia `\Users\<jina_la_mtumiaji>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Database hii inaweza kufunguliwa na chombo cha SQLite au na chombo [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **ambacho huzalisha faili 2 ambazo zinaweza kufunguliwa na chombo** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Faili zilizopakuliwa zinaweza kuwa na **ADS Zone.Identifier** inayoonyesha **jinsi** ilivyopakuliwa kutoka kwenye mtandao wa ndani, mtandao, nk. Programu fulani (kama vivinjari) kawaida huweka **habari zaidi** kama vile **URL** ambapo faili ilipakuliwa kutoka.

## **Nakala za Faili**

### Recycle Bin

Katika Vista/Win7/Win8/Win10 **Recycle Bin** inaweza kupatikana kwenye saraka **`$Recycle.bin`** kwenye mizizi ya diski (`C:\$Recycle.bin`).\
Wakati faili inafutwa kwenye saraka hii, faili 2 maalum zinaundwa:

* `$I{id}`: Taarifa za faili (tarehe ya kufutwa}
* `$R{id}`: Yaliyomo ya faili

![](<../../../.gitbook/assets/image (486).png>)

Ukiwa na faili hizi, unaweza kutumia chombo [**Rifiuti**](https://github.com/abelcheung/rifiuti2) kupata anwani halisi ya faili zilizofutwa na tarehe ambayo ilifutwa (tumia `rifiuti-vista.exe` kwa Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Nakala za Kivuli za Kiasi

Kivuli cha Kiasi ni teknolojia iliyojumuishwa katika Microsoft Windows ambayo inaweza kuunda nakala za **hifadhi** au picha za faili au kiasi cha kompyuta, hata wakati zinatumika.

Nakala hizo za hifadhi kawaida zipo katika `\System Volume Information` kutoka kwenye mizizi ya mfumo wa faili na jina linajumuisha **UIDs** zilizoonyeshwa katika picha ifuatayo:

![](<../../../.gitbook/assets/image (520).png>)

Kwa kufunga picha ya uchunguzi na **ArsenalImageMounter**, zana ya [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) inaweza kutumika kuangalia nakala ya kivuli na hata **kuchambua faili** kutoka kwenye nakala za hifadhi ya kivuli.

![](<../../../.gitbook/assets/image (521).png>)

Kuingia kwenye usajili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` kuna faili na funguo **ambazo hazitahifadhiwa**:

![](<../../../.gitbook/assets/image (522).png>)

Usajili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` pia una habari ya usanidi kuhusu `Nakala za Kivuli za Kiasi`.

### Faili za Kiotomatiki za Ofisi

Unaweza kupata faili za kiotomatiki za ofisi katika: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Vitu vya Shell

Kipengele cha shell ni kipengele ambacho kina habari juu ya jinsi ya kupata faili nyingine.

### Nyaraka za Hivi Karibuni (LNK)

Windows **kwa moja kwa moja** **huunda** viungo hivi vya **njia za mkato** wakati mtumiaji **anapofungua, kutumia au kuunda faili** katika:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Ofisi: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Unapounda saraka, kiungo kwa saraka hiyo, kwa saraka ya mzazi, na kwa saraka ya babu pia huundwa.

Faili za kiungo zilizoundwa kiotomatiki hizi **zina habari kuhusu asili** kama ikiwa ni **faili** **au** saraka, **nyakati za MAC** za faili hiyo, **habari ya kiasi** ambapo faili imehifadhiwa, na **saraka ya faili ya lengo**. Habari hii inaweza kuwa na manufaa katika kurejesha faili hizo ikiwa zimeondolewa.

Pia, **tarehe ya kuundwa ya faili ya kiungo** ni wakati wa kwanza faili ya asili ilipotumiwa **kwa mara ya kwanza** na **tarehe** **iliyobadilishwa** ya faili ya kiungo ni **wakati wa mwisho** faili ya asili iliyotumiwa.

Kuangalia faili hizi, unaweza kutumia [**LinkParser**](http://4discovery.com/our-tools/).

Katika zana hii utapata **seti 2** za alama za wakati:

* **Seti ya Kwanza:**
1. Tarehe ya Kubadilishwa ya Faili
2. Tarehe ya Kufikia Faili
3. Tarehe ya Kuunda Faili
* **Seti ya Pili:**
1. Tarehe ya Kubadilishwa ya Kiungo
2. Tarehe ya Kufikia Kiungo
3. Tarehe ya Kuunda Kiungo.

Seti ya kwanza ya alama za wakati inahusiana na **alama za wakati za faili yenyewe**. Seti ya pili inahusiana na **alama za wakati za faili iliyolinkishwa**.

Unaweza kupata habari sawa kwa kutumia zana ya Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Katika kesi hii, habari itahifadhiwa ndani ya faili ya CSV.

### Jumplists

Hizi ni faili za hivi karibuni ambazo zinaonyeshwa kwa kila programu. Ni orodha ya **faili za hivi karibuni zilizotumiwa na programu** ambayo unaweza kufikia kwenye kila programu. Zinaweza kuundwa **kiotomatiki au kuwa desturi**.

Jumplists zilizoundwa kiotomatiki zimehifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists zina majina yanayofuata muundo `{id}.autmaticDestinations-ms` ambapo ID ya awali ni ID ya programu.

Jumplists desturi zimehifadhiwa katika `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` na zinaundwa na programu kawaida kwa sababu kitu **muhimu** kimefanyika na faili (labda imepewa alama kama pendwa).

Muda wa **kuundwa** kwa jumplist yoyote unaonyesha **wakati wa kwanza faili ilipofikiwa** na muda wa **kubadilishwa mara ya mwisho**.

Unaweza kuangalia jumplists kwa kutumia [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Tafadhali kumbuka kuwa alama za wakati zinazotolewa na JumplistExplorer zinahusiana na faili ya jumplist yenyewe_)

### Shellbags

[**Fuata kiungo hiki kujifunza ni nini shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Matumizi ya USB za Windows

Inawezekana kutambua kuwa kifaa cha USB kilitumiwa kutokana na uundaji wa:

* Folda ya Hivi Karibuni ya Windows
* Folda ya Hivi Karibuni ya Microsoft Office
* Jumplists

Tafadhali kumbuka kuwa baadhi ya faili za LNK badala ya kuonyesha njia ya asili, zinaelekeza kwenye folda ya WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

Faili katika folda ya WPDNSE ni nakala ya faili za asili, kwa hivyo hazitadumu baada ya kuanza upya kwa PC na GUID inachukuliwa kutoka kwa shellbag.

### Taarifa za Usajili

[Angalia ukurasa huu ili kujifunza](interesting-windows-registry-keys.md#usb-information) ni funguo gani za usajili zina habari muhimu kuhusu vifaa vilivyounganishwa kupitia USB.

### setupapi

Angalia faili `C:\Windows\inf\setupapi.dev.log` ili kupata alama za wakati kuhusu wakati uhusiano wa USB ulifanyika (tafuta `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) inaweza kutumika kupata habari kuhusu vifaa vya USB vilivyowahi kuunganishwa kwenye picha.

![](<../../../.gitbook/assets/image (483).png>)

### Usafi wa Plug and Play

Kazi iliyopangwa inayojulikana kama 'Usafi wa Plug and Play' imeundwa kwa kusafisha toleo zilizopitwa na wakati za madereva. Kinyume na madhumuni yake ya kuhifadhi toleo la hivi karibuni la mfuko wa dereva, vyanzo vya mtandaoni vinapendekeza pia inalenga madereva ambayo hayajatumika kwa siku 30. Kwa hivyo, madereva kwa vifaa vinavyoweza kuondolewa ambavyo havijaunganishwa katika siku 30 zinaweza kufutwa.

Kazi hiyo iko katika njia ifuatayo:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Picha inayoonyesha maudhui ya kazi inapatikana:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Vipengele muhimu na Mipangilio ya Kazi:**
- **pnpclean.dll**: DLL hii inahusika na mchakato halisi wa usafi.
- **UseUnifiedSchedulingEngine**: Imewekwa kuwa `TRUE`, ikionyesha matumizi ya injini ya jumla ya ratiba ya kazi.
- **MaintenanceSettings**:
- **Kipindi ('P1M')**: Inaelekeza Meneja wa Kazi kuanzisha kazi ya usafi kila mwezi wakati wa matengenezo ya kiotomatiki ya kawaida.
- **Mwisho wa Muda ('P2M')**: Inaagiza Meneja wa Kazi, ikiwa kazi inashindwa kwa miezi miwili mfululizo, kutekeleza kazi wakati wa matengenezo ya dharura ya kiotomatiki.

Usanidi huu unahakikisha matengenezo na usafi wa kawaida wa madereva, na utoaji wa kujaribu tena kazi ikiwa kuna kushindwa mfululizo.

**Kwa habari zaidi angalia:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Barua pepe

Barua pepe zina sehemu **2 za kuvutia: Vichwa na maudhui** ya barua pepe. Katika **vichwa** unaweza kupata habari kama:

* **Nani** alituma barua pepe (anwani ya barua pepe, IP, seva za barua pepe ambazo zimeelekeza barua pepe)
* **Lini** barua pepe iliyotumwa

Pia, ndani ya vichwa vya `References` na `In-Reply-To` unaweza kupata kitambulisho cha ujumbe:

![](<../../../.gitbook/assets/image (484).png>)

### Programu ya Barua pepe ya Windows

Programu hii inahifadhi barua pepe katika HTML au maandishi. Unaweza kupata barua pepe ndani ya folda za ndani za `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Barua pepe zimehifadhiwa na kipengee cha `.dat`.

**Metadata** ya barua pepe na **mawasiliano** yanaweza kupatikana ndani ya **database ya EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Badilisha kipengee** cha faili kutoka `.vol` hadi `.edb` na unaweza kutumia zana [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) kuifungua. Ndani ya meza ya `Message` unaweza kuona barua pepe.

### Microsoft Outlook

Wakati seva za Exchange au wateja wa Outlook wanapotumika, kutakuwa na vichwa vya MAPI:

* `Mapi-Client-Submit-Time`: Wakati wa mfumo wakati barua pepe iliyotumwa
* `Mapi-Conversation-Index`: Idadi ya ujumbe wa watoto wa mazungumzo na alama ya wakati ya kila ujumbe wa mazungumzo
* `Mapi-Entry-ID`: Kitambulisho cha ujumbe.
* `Mappi-Message-Flags` na `Pr_last_Verb-Executed`: Habari kuhusu mteja wa MAPI (ujumbe umesomwa? haujasomwa? umesasishwa? umeelekezwa? nje ya ofisi?)

Katika mteja wa Microsoft Outlook, ujumbe wote uliotumwa/ulipopokelewa, data ya mawasiliano, na data ya kalenda zimehifadhiwa katika faili ya PST katika:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Njia ya usajili `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT
### Faili za Microsoft Outlook OST

Faili ya **OST** inazalishwa na Microsoft Outlook wakati inapowekwa na **IMAP** au seva ya **Exchange**, ikihifadhi habari sawa na faili ya PST. Faili hii inasawazishwa na seva, ikihifadhi data kwa **miezi 12 iliyopita** hadi **ukubwa wa juu wa 50GB**, na iko katika saraka ile ile na faili ya PST. Ili kuona faili ya OST, [**Mtazamaji wa OST wa Kernel**](https://www.nucleustechnologies.com/ost-viewer.html) inaweza kutumika.

### Kupata Viambatisho

Viambatisho vilivyopotea vinaweza kupatikana kutoka:

- Kwa **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Kwa **IE11 na zaidi**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Faili za Thunderbird MBOX

**Thunderbird** hutumia faili za **MBOX** kuhifadhi data, zilizoko katika `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Vielelezo vya Picha

- **Windows XP na 8-8.1**: Kufikia saraka na vielelezo huzalisha faili ya `thumbs.db` inayohifadhi hakikisho za picha, hata baada ya kufutwa.
- **Windows 7/10**: `thumbs.db` inaundwa wakati inafikiwa kupitia mtandao kupitia njia ya UNC.
- **Windows Vista na toleo jipya**: Hakikisho za vielelezo vimehifadhiwa katika `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` na faili zinaitwa **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) na [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) ni zana za kuona faili hizi.

### Habari za Usajili wa Windows

Usajili wa Windows, ukihifadhi data kubwa ya shughuli za mfumo na mtumiaji, inapatikana katika faili zifuatazo:

- `%windir%\System32\Config` kwa funguo za chini za `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` kwa `HKEY_CURRENT_USER`.
- Windows Vista na toleo jipya hufanya nakala rudufu ya faili za usajili za `HKEY_LOCAL_MACHINE` katika `%Windir%\System32\Config\RegBack\`.
- Kwa kuongezea, habari za utekelezaji wa programu zimehifadhiwa katika `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` kuanzia Windows Vista na Windows 2008 Server.

### Zana

Baadhi ya zana ni muhimu kuchambua faili za usajili:

* **Mhariri wa Usajili**: Imewekwa katika Windows. Ni kiolesura cha GUI cha kupitia usajili wa Windows wa kikao cha sasa.
* [**Mchunguzi wa Usajili**](https://ericzimmerman.github.io/#!index.md): Inakuwezesha kupakia faili ya usajili na kuzunguka kupitia hiyo kwa kutumia GUI. Pia ina Vialamisho vinavyobainisha funguo zenye habari muhimu.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Tena, ina GUI inayoruhusu kuzunguka kupitia usajili uliopakiwa na pia ina programu-jalizi ambazo zinaonyesha habari muhimu ndani ya usajili uliopakiwa.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Programu nyingine ya GUI inayoweza kuchambua habari muhimu kutoka kwa usajili uliopakiwa.

### Kurejesha Kipengele Kilichofutwa

Wakati funguo inafutwa, inaashiria hivyo, lakini mpaka nafasi inayochukuliwa inahitajika, haitaondolewa. Kwa hivyo, kwa kutumia zana kama **Mchunguzi wa Usajili**, ni inawezekana kurejesha funguo hizi zilizofutwa.

### Wakati wa Kuandika Mwisho

Kila Funguo-Kitu kina **muda** unaonyesha wakati uliopita ulibadilishwa.

### SAM

Faili/hive ya **SAM** ina **watumiaji, vikundi na nywila za watumiaji** za mfumo.

Katika `SAM\Domains\Account\Users` unaweza kupata jina la mtumiaji, RID, kuingia mwisho, kuingia kushindwa mwisho, hesabu ya kuingia, sera ya nywila na wakati akaunti iliumbwa. Ili kupata **nywila** unahitaji pia faili/hive ya **SYSTEM**.

### Vitambulisho Vinavyovutia katika Usajili wa Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programu Zilizotekelezwa

### Mchakato wa Msingi wa Windows

Katika [chapisho hili](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) unaweza kujifunza kuhusu michakato ya kawaida ya Windows ili kugundua tabia za shaka.

### Programu Zilizotekelezwa Hivi Karibuni za Windows

Ndani ya usajili wa `NTUSER.DAT` katika njia `Software\Microsoft\Current Version\Search\RecentApps` unaweza kupata funguo za ziada na habari kuhusu **programu iliyotekelezwa**, **wakati wa mwisho** iliyotekelezwa, na **idadi ya mara** iliyozinduliwa.

### BAM (Background Activity Moderator)

Unaweza kufungua faili ya `SYSTEM` na mhariri wa usajili na ndani ya njia `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` unaweza kupata habari kuhusu **programu zilizotekelezwa na kila mtumiaji** (zingatia `{SID}` katika njia) na **wakati gani** zilitekelezwa (wakati uko ndani ya thamani ya Data ya usajili).

### Windows Prefetch

Prefetching ni mbinu inayoruhusu kompyuta kupata kimya-kimya **rasilimali zinazohitajika ili kuonyesha yaliyomo** ambayo mtumiaji **anaweza kufikia hivi karibuni** ili rasilimali ziweze kupatikana haraka.

Windows prefetch inajumuisha kuunda **hifadhi za programu zilizotekelezwa** ili ziweze kupakia haraka. Hifadhi hizi zinaundwa kama faili za `.pf` katika njia: `C:\Windows\Prefetch`. Kuna kikomo cha faili 128 katika XP/VISTA/WIN7 na faili 1024 katika Win8/Win10.

Jina la faili linaundwa kama `{jina_la_programu}-{hash}.pf` (hash inategemea njia na hoja za kutekelezwa). Katika W10 faili hizi zimefupishwa. Tafadhali kumbuka kuwa uwepo wa faili pekee unaonyesha kwamba **programu ilitekelezwa** wakati fulani.

Faili ya `C:\Windows\Prefetch\Layout.ini` ina **majina ya saraka za faili zilizopakuliwa mapema**. Faili hii ina **habari kuhusu idadi ya utekelezaji**, **tarehe** za utekelezaji, na **faili** **zilizofunguliwa** na programu.

Kutazama faili hizi unaweza kutumia zana [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** ina lengo kama prefetch, **kuwezesha programu kufunguka haraka** kwa kutabiri ni programu gani itakayofunguliwa baadaye. Hata hivyo, haitoi huduma ya prefetch.\
Huduma hii itazalisha faili za database katika `C:\Windows\Prefetch\Ag*.db`.

Katika hizi database unaweza kupata **jina** la **programu**, **idadi** ya **utekelezaji**, **faili** **zilizofunguliwa**, **kiasi** **cha ufikivu**, **njia kamili**, **muda** na **muda wa alama**.

Unaweza kupata habari hii kwa kutumia zana [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **inachunguza** **rasilimali** **zilizotumiwa** **na mchakato**. Ilianza katika W8 na hifadhi data katika database ya ESE iliyo katika `C:\Windows\System32\sru\SRUDB.dat`.

Inatoa habari ifuatayo:

* AppID na Njia
* Mtumiaji aliyetekeleza mchakato
* Herufi zilizotumwa
* Herufi zilizopokelewa
* Kiolesura cha Mtandao
* Muda wa uhusiano
* Muda wa mchakato

Habari hii inasasishwa kila baada ya dakika 60.

Unaweza kupata data kutoka kwenye faili hii kwa kutumia zana [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, inayojulikana pia kama **ShimCache**, ni sehemu ya **Application Compatibility Database** iliyoendelezwa na **Microsoft** kushughulikia matatizo ya utangamano wa programu. Sehemu hii ya mfumo inarekodi vipande mbalimbali vya metadata ya faili, ambavyo ni pamoja na:

- Njia kamili ya faili
- Ukubwa wa faili
- Wakati wa Mwisho wa Kubadilishwa chini ya **$Standard\_Information** (SI)
- Wakati wa Mwisho wa Kuboreshwa wa ShimCache
- Bendera ya Utekelezaji wa Mchakato

Data kama hiyo imehifadhiwa ndani ya usajili katika maeneo maalum kulingana na toleo la mfumo wa uendeshaji:

- Kwa XP, data imehifadhiwa chini ya `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` na uwezo wa kuingiza vitu 96.
- Kwa Server 2003, pamoja na toleo la Windows 2008, 2012, 2016, 7, 8, na 10, njia ya uhifadhi ni `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, ikiruhusu vitu 512 na 1024 mtawaliwa.

Ili kuchambua habari iliyohifadhiwa, inapendekezwa kutumia zana ya [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Faili ya **Amcache.hve** ni msingi wa usajili ambao unaorodhesha maelezo kuhusu programu ambazo zimefanywa kwenye mfumo. Kawaida inapatikana kwenye `C:\Windows\AppCompat\Programas\Amcache.hve`.

Faili hii inajulikana kwa kuhifadhi rekodi za michakato iliyotekelezwa hivi karibuni, ikiwa ni pamoja na njia za faili za kutekelezwa na hashi zao za SHA1. Habari hii ni muhimu kwa kufuatilia shughuli za programu kwenye mfumo.

Ili kuchambua na kuchanganua data kutoka kwenye faili ya **Amcache.hve**, unaweza kutumia zana ya [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Amri ifuatayo ni mfano wa jinsi ya kutumia AmcacheParser kuchambua maudhui ya faili ya **Amcache.hve** na kutoa matokeo katika muundo wa CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Miongoni mwa faili za CSV zilizozalishwa, `Amcache_Unassociated file entries` ni muhimu sana kwa sababu inatoa habari kamili kuhusu faili zisizohusishwa.

Faili ya CVS yenye kuvutia zaidi ni `Amcache_Unassociated file entries`.

### RecentFileCache

Kipengele hiki kinaweza kupatikana tu katika W7 kwenye `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` na ina habari kuhusu utekelezaji wa hivi karibuni wa baadhi ya programu.

Unaweza kutumia zana [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) kuipasua faili.

### Kazi zilizopangwa

Unaweza kuzitoa kutoka `C:\Windows\Tasks` au `C:\Windows\System32\Tasks` na kuzisoma kama XML.

### Huduma

Unaweza kuzipata katika usajili chini ya `SYSTEM\ControlSet001\Services`. Unaweza kuona ni nini kitatekelezwa na lini.

### **Duka la Windows**

Programu zilizosakinishwa zinaweza kupatikana katika `\ProgramData\Microsoft\Windows\AppRepository\`\
Hifadhidata hii ina **logi** na **kila programu iliyosakinishwa** kwenye mfumo ndani ya hifadhidata **`StateRepository-Machine.srd`**.

Ndani ya jedwali la Programu katika hifadhidata hii, ni sawa kupata safu: "Kitambulisho cha Programu", "Nambari ya Pakiti", na "Jina la Kuonyesha". Safu hizi zina habari kuhusu programu zilizosakinishwa na zinaweza kupatikana ikiwa programu fulani zilifutwa kwa sababu vitambulisho vya programu zilizosakinishwa vinapaswa kuwa vya mfululizo.

Pia ni sawa kupata **programu iliyosakinishwa** ndani ya njia ya usajili: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Na **programu zilizofutwa** katika: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Matukio ya Windows

Habari zinazoonekana ndani ya matukio ya Windows ni:

* Kilichotokea
* Muda (UTC + 0)
* Watumiaji waliohusika
* Wenyewe waliohusika (jina la mwenyeji, IP)
* Mali zilizofikiwa (faili, folda, printer, huduma)

Magogo yapo katika `C:\Windows\System32\config` kabla ya Windows Vista na katika `C:\Windows\System32\winevt\Logs` baada ya Windows Vista. Kabla ya Windows Vista, magogo ya matukio yalikuwa katika muundo wa binary na baada yake, yako katika muundo wa **XML** na hutumia kifaa cha **.evtx**.

Mahali pa faili za matukio yanaweza kupatikana katika usajili wa SYSTEM katika **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Yaweza kuonekana kutoka kwenye Tazama Matukio ya Windows (**`eventvwr.msc`**) au kwa kutumia zana nyingine kama [**Event Log Explorer**](https://eventlogxp.com) **au** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Kuelewa Kumbukumbu za Matukio ya Usalama ya Windows

Matukio ya ufikiaji hurekodiwa katika faili ya usanidi wa usalama iliyoko kwenye `C:\Windows\System32\winevt\Security.evtx`. Ukubwa wa faili hii unaweza kubadilishwa, na unapofikia uwezo wake, matukio ya zamani hufutwa. Matukio yaliyorekodiwa ni pamoja na kuingia na kutoka kwa watumiaji, hatua za watumiaji, na mabadiliko ya mipangilio ya usalama, pamoja na ufikiaji wa faili, folda, na mali zilizoshirikiwa.

### Vitambulisho vya Matukio Muhimu kwa Uthibitishaji wa Mtumiaji:

- **Tukio la Kitambulisho 4624**: Inaonyesha mtumiaji aliyethibitishwa kwa mafanikio.
- **Tukio la Kitambulisho 4625**: Inaonyesha kushindwa kwa uthibitishaji.
- **Vitambulisho vya Matukio 4634/4647**: Inawakilisha matukio ya kuingia na kutoka kwa mtumiaji.
- **Tukio la Kitambulisho 4672**: Inaonyesha kuingia kwa mtumiaji na mamlaka ya usimamizi.

#### Aina za ziada ndani ya Tukio la Kitambulisho 4634/4647:

- **Mwingiliano (2)**: Kuingia moja kwa moja ya mtumiaji.
- **Mtandao (3)**: Kufikia folda zilizoshirikiwa.
- **Kundi (4)**: Utekelezaji wa michakato ya kundi.
- **Huduma (5)**: Kuzindua huduma.
- **Mandaraka (6)**: Uthibitishaji wa mandaraka.
- **Kufungua (7)**: Kufungua skrini kwa kutumia nenosiri.
- **Mtandao wa Wazi (8)**: Uhamisho wa nenosiri wazi, mara nyingi kutoka kwa IIS.
- **Vyeti Vipya (9)**: Matumizi ya vitambulisho tofauti kwa ufikiaji.
- **Mwingiliano wa Mbali (10)**: Kuingia kwa mbali kwenye desktop au huduma za terminal.
- **Mwingiliano wa Akiba (11)**: Kuingia na vitambulisho vya akiba bila mawasiliano na kudhibiti kikoa.
- **Mwingiliano wa Mbali wa Akiba (12)**: Kuingia kwa mbali na vitambulisho vya akiba.
- **Kufungua kwa Akiba (13)**: Kufungua kwa kutumia vitambulisho vya akiba.

#### Vyeti vya Hali na Hali za Ziada kwa Tukio la Kitambulisho 4625:

- **0xC0000064**: Jina la mtumiaji halipo - Inaweza kuashiria shambulio la uchunguzi wa majina ya watumiaji.
- **0xC000006A**: Jina sahihi la mtumiaji lakini nenosiri sio sahihi - Inaweza kuwa jaribio la kuhesabu au kuvunja nenosiri.
- **0xC0000234**: Akaunti ya mtumiaji imefungwa - Inaweza kufuata shambulio la kuhesabu kwa kuingia mara nyingi kwa kushindwa.
- **0xC0000072**: Akaunti imelemazwa - Jaribio lisiloruhusiwa la kufikia akaunti zilizolemazwa.
- **0xC000006F**: Kuingia nje ya muda ulioruhusiwa - Inaonyesha jaribio la kufikia nje ya masaa ya kuingia yaliyowekwa, inaweza kuwa ishara ya ufikiaji usioruhusiwa.
- **0xC0000070**: Ukiukaji wa vikwazo vya kituo cha kazi - Inaweza kuwa jaribio la kuingia kutoka eneo lisiloruhusiwa.
- **0xC0000193**: Akaunti imeisha muda wake - Jaribio la kufikia akaunti za watumiaji zilizopita muda wake.
- **0xC0000071**: Nenosiri limeisha muda wake - Jaribio la kuingia na nywila zilizopitwa na wakati.
- **0xC0000133**: Matatizo ya usawazishaji wa muda - Tofauti kubwa ya muda kati ya mteja na seva inaweza kuwa ishara ya mashambulizi ya hali ya juu kama vile pass-the-ticket.
- **0xC0000224**: Inahitajika mabadiliko ya lazima ya nenosiri - Mabadiliko ya mara kwa mara ya lazima yanaweza kuashiria jaribio la kudhoofisha usalama wa akaunti.
- **0xC0000225**: Inaonyesha hitilafu ya mfumo badala ya shida ya usalama.
- **0xC000015b**: Amezuiliwa aina ya kuingia - Jaribio la kufikia na aina ya kuingia isiyoruhusiwa, kama mtumiaji anayejaribu kutekeleza kuingia kwa huduma.

#### Tukio la Kitambulisho 4616:
- **Mabadiliko ya Muda**: Kubadilisha muda wa mfumo, inaweza kuficha mfululizo wa
#### Matukio ya Nguvu ya Mfumo

Tukio la ID ya 6005 linaashiria kuanza kwa mfumo, wakati Tukio la ID ya 6006 linamaanisha kuzima.

#### Kufuta Kumbukumbu

Tukio la Usalama la ID ya 1102 linasema kufutwa kwa kumbukumbu, tukio muhimu kwa uchambuzi wa kisayansi. 


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
