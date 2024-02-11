<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Vipindi vya Wakati

Mshambuliaji anaweza kuwa na nia ya **kubadilisha vipindi vya wakati wa faili** ili kuepuka kugundulika.\
Inawezekana kupata vipindi vya wakati ndani ya MFT kwenye sifa `$STANDARD_INFORMATION` __ na __ `$FILE_NAME`.

Sifa zote zina vipindi vya wakati 4: **Mabadiliko**, **upatikanaji**, **umbaji**, na **ubadilishaji wa usajili wa MFT** (MACE au MACB).

**Windows explorer** na zana zingine huonyesha habari kutoka kwa **`$STANDARD_INFORMATION`**.

## TimeStomp - Zana ya Kuzuia Uchunguzi

Zana hii **inabadilisha** habari ya vipindi vya wakati ndani ya **`$STANDARD_INFORMATION`** **lakini** **sio** habari ndani ya **`$FILE_NAME`**. Kwa hivyo, inawezekana **kutambua** **shughuli** **tuhuma**.

## Usnjrnl

**USN Journal** (Kumbukumbu ya Nambari ya Mfululizo ya Sasisho) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) ambacho kinafuatilia mabadiliko kwenye kiasi. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu uchunguzi wa mabadiliko haya.

![](<../../.gitbook/assets/image (449).png>)

Picha iliyotangulia ni **matokeo** yanayoonyeshwa na **zana** ambapo inaweza kuonekana kuwa **mabadiliko fulani yalifanywa** kwenye faili.

## $LogFile

**Mabadiliko yote ya metadata kwenye mfumo wa faili yanalindwa** katika mchakato unaojulikana kama [kuandika kabla ya kuingiza](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyorekodiwa inahifadhiwa kwenye faili iliyoitwa `**$LogFile**`, iliyoko kwenye saraka ya msingi ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) inaweza kutumika kuchambua faili hii na kutambua mabadiliko.

![](<../../.gitbook/assets/image (450).png>)

Tena, kwenye matokeo ya zana inawezekana kuona kuwa **mabadiliko fulani yalifanywa**.

Kwa kutumia zana hiyo hiyo inawezekana kutambua **vipindi vya wakati vilivyobadilishwa**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Wakati wa umbaji wa faili
* ATIME: Wakati wa kubadilisha faili
* MTIME: Ubunifu wa usajili wa MFT wa faili
* RTIME: Wakati wa kupata faili

## Linganisha `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua faili zilizobadilishwa kwa tuhuma ni kulinganisha wakati kwenye sifa zote mbili kutafuta **tofauti**.

## Nanodetano

Vipindi vya wakati vya **NTFS** vina **usahihi** wa **nanodetano 100**. Kwa hivyo, kupata faili na vipindi vya wakati kama 2010-10-10 10:10:**00.000:0000 ni tuhuma sana**.

## SetMace - Zana ya Kuzuia Uchunguzi

Zana hii inaweza kubadilisha sifa zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Walakini, kuanzia Windows Vista, ni lazima kuwa na OS hai ili kubadilisha habari hii.

# Kujificha Data

NFTS hutumia kikundi na ukubwa wa habari wa chini. Hii inamaanisha kuwa ikiwa faili inatumia kikundi na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili ifutwe. Kwa hivyo, inawezekana **kujificha data katika nafasi hii ya siri**.

Kuna zana kama slacker ambayo inaruhusu kujificha data katika nafasi hii "iliyofichwa". Walakini, uchambuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kuwa data fulani iliongezwa:

![](<../../.gitbook/assets/image (452).png>)

Kwa hivyo, inawezekana kupata nafasi ya siri kwa kutumia zana kama FTK Imager. Kumbuka kuwa aina hii ya zana inaweza kuokoa yaliyomo yaliyofichwa au hata yaliyofichwa.

# UsbKill

Hii ni zana ambayo ita**zima kompyuta ikiwa kuna mabadiliko yoyote kwenye bandari za USB**.\
Njia ya kugundua hii ni kuchunguza michakato inayoendelea na **kuchunguza kila script ya python inayoendelea**.

# Usambazaji wa Linux wa Moja kwa Moja

Distros hizi za Linux zinaendeshwa ndani ya kumbukumbu ya RAM. Njia pekee ya kugundua ni **ikiwa mfumo wa faili wa NTFS umemalizika na ruhusa za kuandika**. Ikiwa imeunganishwa tu na ruhusa za kusoma, haitawezekana kugundua uvamizi.

# Kufuta Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Usanidi wa Windows

Inawezekana kulemaza njia kadhaa za kuingiza data za Windows ili kufanya uchunguzi wa kisayansi kuwa mgumu zaidi.

## Lemaza Vipindi vya Wakati - UserAssist

Hii ni ufunguo wa usajili ambao unahifadhi tarehe na saa wakati kila programu iliyotekelezwa na mtumiaji.

Kulemaza UserAssist kunahitaji hatua mbili:

1. Weka ufunguo wa usajili mbili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote kuwa sifuri ili kuonyesha kuwa tunataka UserAssist iwelemazwe.
2. Futa matawi yako ya usajili yanayofanana na `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Lemaza Vipindi vya Wakati - Prefetch

Hii itahifadhi habari juu ya programu zilizotekelezwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Walakini, hii pia inaweza kuwa muhimu kwa mazoezi ya kisayansi.

* Tekeleza `regedit`
* Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Bonyeza kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
* Chagua Bad
## Futa Historia ya USB

Maelezo yote ya **Vifaa vya USB** hifadhiwa katika Usajili wa Windows chini ya ufunguo wa Usajili wa **USBSTOR** ambao una funguo ndogo zinazoundwa unapoweka Kifaa cha USB kwenye PC au Laptop yako. Unaweza kupata ufunguo huu hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kwa kufuta** hii utafuta historia ya USB.\
Unaweza pia kutumia zana [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) ili kuhakikisha umewafuta (na kuwafuta).

Faili nyingine ambayo inahifadhi habari kuhusu USB ni faili `setupapi.dev.log` ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

## Lemaza Nakala za Kivuli

**Pata orodha** ya nakala za kivuli kwa kutumia `vssadmin list shadowstorage`\
**Zifute** kwa kuendesha `vssadmin delete shadow`

Unaweza pia kuzifuta kupitia GUI kwa kufuata hatua zilizopendekezwa katika [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Kulemaza nakala za kivuli [hatua kutoka hapa](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua programu ya Huduma kwa kuingiza "huduma" katika sanduku la utaftaji wa maandishi baada ya kubonyeza kitufe cha kuanza cha Windows.
2. Kutoka kwenye orodha, tafuta "Volume Shadow Copy", ichague, na kisha ufikie Vipengele kwa kubofya kulia.
3. Chagua Lemaza kutoka kwenye menyu ya kushuka ya "Aina ya Kuanza", kisha thibitisha mabadiliko kwa kubonyeza Tumia na Sawa.

Pia ni pia inawezekana kubadilisha usanidi wa ni faili zipi zitakazohifadhiwa katika nakala ya kivuli kwenye usajili `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Futa faili zilizofutwa

* Unaweza kutumia **zana ya Windows**: `cipher /w:C` Hii itaagiza cipher kuondoa data yoyote kutoka kwenye nafasi ya diski isiyotumiwa inayopatikana ndani ya diski C.
* Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

## Futa magogo ya tukio la Windows

* Windows + R --> eventvwr.msc --> Panua "Magogo ya Windows" --> Bonyeza kulia kwenye kila jamii na chagua "Futa Magogo"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Lemaza magogo ya tukio la Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Ndani ya sehemu ya huduma, lemesha huduma "Windows Event Log"
* `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

## Lemaza $UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
