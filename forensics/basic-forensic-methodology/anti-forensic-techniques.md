<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# Vipindi vya Muda

Mshambuliaji anaweza kuwa na nia ya **kubadilisha vipindi vya mafaili** ili kuepuka kugunduliwa.\
Inawezekana kupata vipindi vya mafaili ndani ya MFT katika sifa `$STANDARD_INFORMATION` __ na __ `$FILE_NAME`.

Sifa zote zina vipindi 4: **Mabadiliko**, **upatikanaji**, **umbaji**, na **ubadilishaji wa usajili wa MFT** (MACE au MACB).

**Windows explorer** na zana nyingine huonyesha habari kutoka kwa **`$STANDARD_INFORMATION`**.

## TimeStomp - Zana ya Kuzuia Upelelezi

Zana hii **inabadilisha** habari ya vipindi ndani ya **`$STANDARD_INFORMATION`** **lakini** **sio** habari ndani ya **`$FILE_NAME`**. Kwa hivyo, inawezekana **kutambua** **shughuli za shaka**.

## Usnjrnl

**USN Journal** (Update Sequence Number Journal) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko kwenye kiasi. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu uchunguzi wa mabadiliko haya.

![](<../../.gitbook/assets/image (449).png>)

Picha iliyotangulia ni **matokeo** yanayoonyeshwa na **zana** ambapo inaweza kuonekana kwamba baadhi ya **mabadiliko yalifanywa** kwenye faili.

## $LogFile

**Mabadiliko yote ya metadata kwenye mfumo wa faili yanalogwa** katika mchakato unaojulikana kama [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyologwa inahifadhiwa kwenye faili inayoitwa `**$LogFile**`, iliyoko kwenye saraka ya msingi ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) inaweza kutumika kuchambua faili hii na kutambua mabadiliko.

![](<../../.gitbook/assets/image (450).png>)

Tena, kwenye matokeo ya zana inawezekana kuona kwamba **baadhi ya mabadiliko yalifanywa**.

Kwa kutumia zana hiyo hiyo inawezekana kutambua **vipindi vilivyobadilishwa**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Wakati wa umbaji wa faili
* ATIME: Wakati wa kubadilisha faili
* MTIME: Mabadiliko ya usajili wa MFT wa faili
* RTIME: Wakati wa kupata faili

## Linganisha `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua mafaili yaliyobadilishwa kwa shaka ni kulinganisha wakati kwenye sifa zote mbili kutafuta **tofauti**.

## Nanosekunde

Vipindi vya **NTFS** vina **usahihi** wa **nanosekunde 100**. Kwa hivyo, kupata mafaili na vipindi kama 2010-10-10 10:10:**00.000:0000 ni shaka sana**.

## SetMace - Zana ya Kuzuia Upelelezi

Zana hii inaweza kubadilisha sifa zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Walakini, kuanzia Windows Vista, ni lazima kuwa na OS hai kubadilisha habari hii.

# Kuficha Data

NFTS hutumia kikundi na ukubwa wa habari wa chini. Hii inamaanisha kwamba ikiwa faili inatumia kikundi na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili ifutwe. Kwa hivyo, inawezekana **kuficha data katika nafasi hii ya ziada**.

Kuna zana kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyofichwa". Walakini, uchambuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kwamba data fulani iliongezwa:

![](<../../.gitbook/assets/image (452).png>)

Kwa hivyo, inawezekana kupata nafasi ya ziada kwa kutumia zana kama FTK Imager. Tafadhali kumbuka kwamba aina hii ya zana inaweza kuokoa yaliyomo yaliyofichwa au hata yaliyofichwa.

# UsbKill

Hii ni zana ambayo ita**zima kompyuta ikiwa mabadiliko yoyote kwenye bandari za USB** yatagunduliwa.\
Njia ya kugundua hii itakuwa kuchunguza michakato inayoendelea na **kupitia kila script ya python inayoendesha**.

# Usambazaji wa Linux wa Moja kwa Moja

Distros hizi zinaendeshwa ndani ya **kumbukumbu ya RAM**. Njia pekee ya kuzigundua ni **ikiwa mfumo wa faili wa NTFS unafungwa na ruhusa za kuandika**. Ikiwa inafungwa tu na ruhusa za kusoma haitawezekana kugundua uvamizi.

# Kufuta Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Usanidi wa Windows

Inawezekana kulemaza njia kadhaa za kuingiza data za Windows ili kufanya uchunguzi wa upelelezi kuwa mgumu zaidi.

## Lemaza Vipindi - UserAssist

Hii ni funguo ya usajili inayohifadhi tarehe na saa wakati kila programu iliyotekelezwa na mtumiaji.

Kulemaza UserAssist kunahitaji hatua mbili:

1. Weka funguo mbili za usajili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote mbili kuwa sifuri ili kuonyesha kwamba tunataka UserAssist iwezeshwe.
2. Futa matawi yako ya usajili yanayoonekana kama `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Lemaza Vipindi - Prefetch

Hii itahifadhi habari kuhusu programu zilizotekelezwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Walakini, hii pia inaweza kuwa muhimu kwa mazoezi ya upelelezi.

* Tekeleza `regedit`
* Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Bonyeza kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
* Chagua Badilisha kwa kila moja kubadilisha thamani kutoka 1 (au 3) hadi 0
* Anza tena

## Lemaza Vipindi - Wakati wa Mwisho wa Upatikanaji

Kila wakati saraka inafunguliwa kutoka kwenye kiasi cha NTFS kwenye seva ya Windows NT, mfumo huchukua muda wa **kuboresha uga wa vipindi kwenye kila saraka iliyoorodheshwa**, inaitwa wakati wa mwisho wa upatikanaji. Kwenye kiasi cha NTFS kinachotumiwa sana, hii inaweza kuathiri utendaji.

1. Fungua Mhariri wa Usajili (Regedit.exe).
2. Nenda kwa `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na weka thamani yake kuwa 1, ambayo italemaza mchakato.
4. Funga Mhariri wa Usajili, na anza upya seva.
## Futa Historia ya USB

**Mingine** ya **Vifaa vya USB** huhifadhiwa katika Usajili wa Windows Chini ya funguo la Usajili la **USBSTOR** ambalo lina vichwa vidogo vilivyo umbwa unapoweka Kifaa cha USB kwenye PC au Laptop yako. Unaweza kupata funguo hili hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kufuta hili** kutafuta historia ya USB.\
Unaweza pia kutumia zana [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) kuhakikisha umewafuta (na kuwafuta).

Faili nyingine inayohifadhi habari kuhusu USB ni faili `setupapi.dev.log` ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

## Lemaza Nakala za Kivuli

**Pata** nakala za kivuli kwa `vssadmin list shadowstorage`\
**Zifute** kwa kuendesha `vssadmin delete shadow`

Unaweza pia kuzifuta kupitia GUI kwa kufuata hatua zilizopendekezwa katika [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Kulemaza nakala za kivuli [hatua kutoka hapa](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua programu ya Huduma kwa kubonyeza "huduma" kwenye sanduku la utaftaji wa maandishi baada ya kubonyeza kitufe cha kuanza cha Windows.
2. Kutoka kwenye orodha, pata "Nakala ya Kivuli ya Kiasi", ichague, kisha ufikie Vipengele kwa kubonyeza kulia.
3. Chagua Lemaza kutoka kwenye menyu ya kunjua "Aina ya Kuanza", kisha thibitisha mabadiliko kwa kubonyeza Tumia na Sawa.

Pia niwezekane kurekebisha usanidi wa ni faili zipi zitakazokuwa zimekopwa katika nakala ya kivuli kwenye usajili `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Futa Faili Zilizofutwa

* Unaweza kutumia **Zana ya Windows**: `cipher /w:C` Hii itaagiza cipher kuondoa data yoyote kutoka nafasi ya diski isiyotumiwa inapatikana ndani ya diski ya C.
* Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

## Futa Magogo ya Matukio ya Windows

* Windows + R --> eventvwr.msc --> Panua "Vipande vya Windows" --> Bonyeza kulia kwa kila jamii na chagua "Futa Logi"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Lemaza Magogo ya Matukio ya Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Ndani ya sehemu ya huduma, lemesha huduma "Logi ya Matukio ya Windows"
* `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

## Lemaza $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
