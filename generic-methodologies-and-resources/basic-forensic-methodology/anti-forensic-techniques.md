# Mbinu za Kuzuia Uchunguzi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Vielelezo vya Wakati

Mshambuliaji anaweza kuwa na nia ya **kubadilisha vielelezo vya wakati wa faili** ili kuepuka kugunduliwa.\
Inawezekana kupata vielelezo vya wakati ndani ya MFT katika sifa `$STANDARD_INFORMATION` na `$FILE_NAME`.

Sifa zote zina vielelezo 4 vya wakati: **Mabadiliko**, **upatikanaji**, **umbaji**, na **ubadilishaji wa usajili wa MFT** (MACE au MACB).

**Windows explorer** na zana nyingine huonyesha habari kutoka kwa **`$STANDARD_INFORMATION`**.

### TimeStomp - Zana ya Kuzuia Uchunguzi

Zana hii **inabadilisha** habari ya vielelezo vya wakati ndani ya **`$STANDARD_INFORMATION`** **lakini** **sio** habari ndani ya **`$FILE_NAME`**. Kwa hivyo, inawezekana **kutambua** **shughuli za shaka**.

### Usnjrnl

**Usn Journal** (Jarida la Nambari ya Mfululizo wa Sasisho) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko kwenye kiasi. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu uchunguzi wa mabadiliko haya.

![](<../../.gitbook/assets/image (798).png>)

Picha iliyotangulia ni **matokeo** yanayoonyeshwa na **zana** ambapo inaweza kuonekana kwamba baadhi ya **mabadiliko yalifanywa** kwenye faili.

### $LogFile

**Mabadiliko yote ya metadata kwenye mfumo wa faili yanalogwa** katika mchakato unaojulikana kama [kuandika kabla ya kuingia](https://en.wikipedia.org/wiki/Write-ahead\_logging). Metadata iliyologwa inahifadhiwa kwenye faili inayoitwa `**$LogFile**`, iliyoko kwenye saraka ya msingi ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) inaweza kutumika kuchambua faili hii na kutambua mabadiliko.

![](<../../.gitbook/assets/image (134).png>)

Tena, kwenye matokeo ya zana inawezekana kuona kwamba **baadhi ya mabadiliko yalifanywa**.

Kwa kutumia zana hiyo hiyo inawezekana kutambua **wakati vielelezo vya wakati vilibadilishwa**:

![](<../../.gitbook/assets/image (1086).png>)

* CTIME: Wakati wa umbaji wa faili
* ATIME: Wakati wa mabadiliko ya faili
* MTIME: Ubunifu wa usajili wa MFT wa faili
* RTIME: Wakati wa upatikanaji wa faili

### Linganisha `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua faili zilizobadilishwa kwa shaka ni kulinganisha wakati kwenye sifa zote mbili kutafuta **tofauti**.

### Nanosekunde

Vielelezo vya wakati vya **NTFS** vina **usahihi** wa **nanosekunde 100**. Kwa hivyo, kupata faili zenye vielelezo vya wakati kama 2010-10-10 10:10:**00.000:0000 ni shaka sana**.

### SetMace - Zana ya Kuzuia Uchunguzi

Zana hii inaweza kubadilisha sifa zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Walakini, kuanzia Windows Vista, ni muhimu kuwa na OS hai kubadilisha habari hii.

## Kuficha Data

NFTS hutumia kikundi na ukubwa wa habari wa chini. Hii inamaanisha kwamba ikiwa faili inatumia kikundi na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili ifutwe. Kwa hivyo, inawezekana **kuficha data katika nafasi hii ya ziada**.

Kuna zana kama slacker inaruhusu kuficha data katika nafasi hii "iliyofichwa". Walakini, uchambuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kwamba data fulani iliongezwa:

![](<../../.gitbook/assets/image (1057).png>)

Kwa hivyo, inawezekana kupata nafasi ya ziada kwa kutumia zana kama FTK Imager. Tafadhali kumbuka kwamba aina hii ya zana inaweza kuokoa yaliyomo yaliyofichwa au hata yaliyofichwa.

## UsbKill

Hii ni zana ambayo ita**zima kompyuta ikiwa mabadiliko yoyote kwenye bandari za USB** yatagunduliwa.\
Njia ya kugundua hii itakuwa kuchunguza michakato inayoendelea na **kupitia kila script ya python inayoendesha**.

## Usambazaji wa Linux wa Moja kwa Moja

Distros hizi zinaendeshwa ndani ya **kumbukumbu ya RAM**. Njia pekee ya kugundua ni **ikiwa mfumo wa faili wa NTFS unafungwa na ruhusa za kuandika**. Ikiwa inafungwa tu na ruhusa za kusoma haitawezekana kugundua uvamizi.

## Kufuta Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Usanidi wa Windows

Inawezekana kulemaza njia kadhaa za kuingiza data za Windows ili kufanya uchunguzi wa kiforensiki kuwa mgumu zaidi.

### Lemaza Vielelezo vya Wakati - UserAssist

Hii ni funguo ya usajili inayohifadhi tarehe na saa wakati kila programu iliyotekelezwa na mtumiaji.

Kulemaza UserAssist kunahitaji hatua mbili:

1. Weka funguo mbili za usajili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote kuwa sifuri ili kuonyesha kwamba tunataka UserAssist iwelemazwe.
2. Futa matawi yako ya usajili yanayoonekana kama `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Lemaza Vielelezo vya Wakati - Prefetch

Hii itahifadhi habari kuhusu programu zilizotekelezwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Walakini, hii pia inaweza kuwa muhimu kwa mazoezi ya kiforensiki.

* Tekeleza `regedit`
* Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Bonyeza kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
* Chagua Badilisha kwa kila moja kubadilisha thamani kutoka 1 (au 3) hadi 0
* Anza tena

### Lemaza Vielelezo vya Wakati - Wakati wa Mwisho wa Upatikanaji

Kila wakati saraka inafunguliwa kutoka kwenye kiasi cha NTFS kwenye seva ya Windows NT, mfumo unachukua muda wa **kuboresha uga wa vielelezo wa wakati kwenye kila saraka iliyoorodheshwa**, unaitwa wakati wa mwisho wa upatikanaji. Kwenye kiasi cha NTFS kinachotumiwa sana, hii inaweza kuathiri utendaji.

1. Fungua Mhariri wa Usajili (Regedit.exe).
2. Nenda kwa `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na weka thamani yake kuwa 1, ambayo italemaza mchakato.
4. Funga Mhariri wa Usajili, na zima upya seva.
### Futa Historia ya USB

**Mingine** ya **Vifaa vya USB** huhifadhiwa kwenye Usajili wa Windows Chini ya funguo la Usajili la **USBSTOR** ambalo lina funguo za chini zinazoundwa unapoweka Kifaa cha USB kwenye PC au Laptop yako. Unaweza kupata funguo hili hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kufuta hili** kutafuta futa historia ya USB.\
Unaweza pia kutumia zana [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) kuhakikisha umewafuta (na kuwafuta).

Faili nyingine inayohifadhi habari kuhusu USB ni faili `setupapi.dev.log` ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

### Lemaza Nakala za Kivuli

**Panga** nakala za kivuli kwa `vssadmin list shadowstorage`\
**Zifute** kwa kukimbia `vssadmin delete shadow`

Unaweza pia kuzifuta kupitia GUI kwa kufuata hatua zilizopendekezwa katika [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Kulemaza nakala za kivuli [hatua kutoka hapa](https://support.waters.com/KB\_Inf/Other/WKB15560\_How\_to\_disable\_Volume\_Shadow\_Copy\_Service\_VSS\_in\_Windows):

1. Fungua programu ya Huduma kwa kuingiza "huduma" kwenye sanduku la utaftaji wa maandishi baada ya kubofya kitufe cha kuanza cha Windows.
2. Kutoka kwenye orodha, pata "Nakala ya Kivuli", ichague, kisha ufikie Vipengele kwa kubofya kulia.
3. Chagua Lemaza kutoka kwenye menyu ya kunjuzi ya "Aina ya Kuanza", kisha thibitisha mabadiliko kwa kubofya Tumia na Sawa.

Pia niwezekanavyo kurekebisha usanidi wa ni faili zipi zitakazokuwa zinakopiwa katika nakala ya kivuli kwenye usajili `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Futa faili zilizofutwa

* Unaweza kutumia **Zana ya Windows**: `cipher /w:C` Hii itaagiza cipher kuondoa data yoyote kutoka nafasi ya diski isiyotumiwa inapatikana ndani ya diski ya C.
* Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

### Futa magogo ya matukio ya Windows

* Windows + R --> eventvwr.msc --> Panua "Vipologo vya Windows" --> Bofya kulia kwenye kila jamii na chagua "Futa Logi"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Lemaza magogo ya matukio ya Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Ndani ya sehemu ya huduma, lemesha huduma "Logi ya Matukio ya Windows"
* `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

### Lemaza $UsnJrnl

* `fsutil usn deletejournal /d c:`
