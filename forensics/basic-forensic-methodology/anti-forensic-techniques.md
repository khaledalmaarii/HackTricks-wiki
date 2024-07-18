{% hint style="success" %}
Jifunze na zoezi AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# Muda wa Kumbukumbu

Mshambuliaji anaweza kuwa na nia ya **kubadilisha muda wa faili** ili kuepuka kugunduliwa.\
Inawezekana kupata muda wa kumbukumbu ndani ya MFT katika sifa `$STANDARD_INFORMATION` __ na __ `$FILE_NAME`.

Sifa zote zina vipindi 4 vya muda: **Mabadiliko**, **upatikanaji**, **umbizo**, na **ubadilishaji wa usajili wa MFT** (MACE au MACB).

**Windows explorer** na zana nyingine huonyesha habari kutoka kwa **`$STANDARD_INFORMATION`**.

## TimeStomp - Zana ya Kuzuia Udukuzi

Zana hii **inabadilisha** habari ya muda ndani ya **`$STANDARD_INFORMATION`** **lakini** **si** habari ndani ya **`$FILE_NAME`**. Hivyo, inawezekana **kutambua** **shughuli za shaka**.

## Usnjrnl

**USN Journal** (Jarida la Nambari ya Mfululizo wa Sasisho) ni kipengele cha NTFS (mfumo wa faili wa Windows NT) kinachofuatilia mabadiliko ya kiasi. Zana ya [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) inaruhusu uchunguzi wa mabadiliko haya.

![](<../../.gitbook/assets/image (449).png>)

Picha iliyotangulia ni **matokeo** yanayoonyeshwa na **zana** ambapo inaweza kuonekana kwamba **mabadiliko fulani yalifanywa** kwa faili.

## $LogFile

**Mabadiliko yote ya metadata kwenye mfumo wa faili yanalogwa** katika mchakato unaojulikana kama [kuandika kabla ya kuingia](https://en.wikipedia.org/wiki/Write-ahead_logging). Metadata iliyologwa inahifadhiwa katika faili inayoitwa `**$LogFile**`, iliyoko katika saraka ya msingi ya mfumo wa faili wa NTFS. Zana kama [LogFileParser](https://github.com/jschicht/LogFileParser) inaweza kutumika kuchambua faili hii na kutambua mabadiliko.

![](<../../.gitbook/assets/image (450).png>)

Tena, katika matokeo ya zana inawezekana kuona kwamba **mabadiliko fulani yalifanywa**.

Kwa kutumia zana hiyo hiyo inawezekana kutambua **muda ambao vipindi vya muda vilibadilishwa**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Muda wa uundaji wa faili
* ATIME: Muda wa kubadilisha faili
* MTIME: Muda wa ubadilishaji wa usajili wa MFT
* RTIME: Muda wa kupata faili

## Linganisha `$STANDARD_INFORMATION` na `$FILE_NAME`

Njia nyingine ya kutambua faili zilizobadilishwa kwa shaka ni kulinganisha muda kwenye sifa zote mbili kutafuta **tofauti**.

## Nanosekunde

Vipindi vya muda vya **NTFS** vina **usahihi** wa **nanosekunde 100**. Hivyo, kupata faili zenye vipindi vya muda kama 2010-10-10 10:10:**00.000:0000 ni shaka sana**.

## SetMace - Zana ya Kuzuia Udukuzi

Zana hii inaweza kubadilisha sifa zote mbili `$STARNDAR_INFORMATION` na `$FILE_NAME`. Hata hivyo, kuanzia Windows Vista, ni lazima kuwa na OS hai kubadilisha habari hii.

# Kuficha Data

NTFS hutumia kikundi na ukubwa wa habari wa chini. Hii inamaanisha kwamba ikiwa faili inatumia kikundi na nusu, **nusu iliyobaki haitatumika kamwe** hadi faili ifutwe. Hivyo, inawezekana **kuficha data katika nafasi hii ya ziada**.

Kuna zana kama slacker zinazoruhusu kuficha data katika nafasi hii "iliyofichwa". Hata hivyo, uchambuzi wa `$logfile` na `$usnjrnl` unaweza kuonyesha kwamba data fulani iliongezwa:

![](<../../.gitbook/assets/image (452).png>)

Hivyo, inawezekana kupata nafasi ya ziada kwa kutumia zana kama FTK Imager. Tafadhali kumbuka kwamba aina hii ya zana inaweza kuokoa maudhui yaliyofichwa au hata yaliyofichwa.

# UsbKill

Hii ni zana ambayo ita**zima kompyuta ikiwa mabadiliko yoyote kwenye bandari za USB** yatagunduliwa.\
Njia ya kugundua hii itakuwa kuchunguza michakato inayoendelea na **kupitia kila script ya python inayoendesha**.

# Usambazaji wa Linux wa Moja kwa Moja

Distros hizi zina**endeshwa ndani ya kumbukumbu ya RAM**. Njia pekee ya kugundua ni **ikiwa mfumo wa faili wa NTFS unafungwa na ruhusa za kuandika**. Ikiwa inafungwa tu na ruhusa za kusoma haitawezekana kugundua uvamizi.

# Kufuta Salama

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Usanidi wa Windows

Inawezekana kulemaza njia kadhaa za kuingiza data za Windows ili kufanya uchunguzi wa kumbukumbu kuwa mgumu zaidi.

## Lemaza Vipindi vya Muda - UserAssist

Hii ni funguo ya usajili inayohifadhi tarehe na saa wakati kila programu iliyotekelezwa na mtumiaji.

Kulemaza UserAssist kunahitaji hatua mbili:

1. Weka funguo mbili za usajili, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` na `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, zote kuwa sifuri ili kuonyesha kwamba tunataka UserAssist iwezeshwe.
2. Futa matawi yako ya usajili yanayoonekana kama `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Lemaza Vipindi vya Muda - Prefetch

Hii itahifadhi habari kuhusu programu zilizotekelezwa kwa lengo la kuboresha utendaji wa mfumo wa Windows. Hata hivyo, hii inaweza pia kuwa muhimu kwa mazoezi ya udukuzi.

* Tekeleza `regedit`
* Chagua njia ya faili `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Bonyeza kulia kwenye `EnablePrefetcher` na `EnableSuperfetch`
* Chagua Badilisha kwa kila moja kubadilisha thamani kutoka 1 (au 3) hadi 0
* Anza tena

## Lemaza Vipindi vya Muda - Muda wa Mwisho wa Upatikanaji

Kila wakati saraka inafunguliwa kutoka kwenye kiasi cha NTFS kwenye seva ya Windows NT, mfumo huchukua muda wa **kuboresha uga wa vipindi vya muda kwenye kila saraka iliyoorodheshwa**, unaitwa muda wa mwisho wa upatikanaji. Kwenye kiasi cha NTFS kinachotumiwa sana, hii inaweza kuathiri utendaji.

1. Fungua Mhariri wa Usajili (Regedit.exe).
2. Nenda kwa `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tafuta `NtfsDisableLastAccessUpdate`. Ikiwa haipo, ongeza DWORD hii na weka thamani yake kuwa 1, ambayo italemaza mchakato.
4. Funga Mhariri wa Usajili, na anza upya seva.
## Futa Historia ya USB

**Mingine** ya **Vifaa vya USB** huhifadhiwa kwenye Usajili wa Windows Chini ya funguo la Usajili la **USBSTOR** ambalo lina funguo za chini zinazoundwa kila unapoweka Kifaa cha USB kwenye PC au Laptop yako. Unaweza kupata funguo hili hapa H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Kufuta hili** kutafuta historia ya USB.\
Unaweza pia kutumia zana [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) kuhakikisha umewafuta (na kuwafuta).

Faili nyingine inayohifadhi habari kuhusu USB ni faili `setupapi.dev.log` ndani ya `C:\Windows\INF`. Hii pia inapaswa kufutwa.

## Lemaza Nakala za Kivuli

**Pata orodha** ya nakala za kivuli kwa `vssadmin list shadowstorage`\
**Zifute** kwa kukimbia `vssadmin delete shadow`

Unaweza pia kuzifuta kupitia GUI kwa kufuata hatua zilizopendekezwa katika [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Kulemaza nakala za kivuli [hatua kutoka hapa](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Fungua programu ya Huduma kwa kuingiza "huduma" kwenye sanduku la utaftaji wa maandishi baada ya kubofya kitufe cha kuanza cha Windows.
2. Kutoka kwenye orodha, pata "Nakala ya Kivuli ya Kiasi", ichague, kisha ufikie Mali kwa kubofya kulia.
3. Chagua Lemaza kutoka kwenye menyu ya kunjuzi ya "Aina ya Kuanza", kisha thibitisha mabadiliko kwa kubofya Tumia na Sawa.

Pia niwezekanavyo kurekebisha usanidi wa ni faili zipi zitakazokuwa zimekopwa katika nakala ya kivuli kwenye usajili `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Futa Faili Zilizofutwa

* Unaweza kutumia **Zana ya Windows**: `cipher /w:C` Hii itaagiza cipher kuondoa data yoyote kutoka kwenye nafasi ya diski isiyotumiwa inapatikana ndani ya diski ya C.
* Unaweza pia kutumia zana kama [**Eraser**](https://eraser.heidi.ie)

## Futa Kumbukumbu za Matukio ya Windows

* Windows + R --> eventvwr.msc --> Panua "Vichwa vya Windows" --> Bofya kulia kwa kila jamii na chagua "Futa Kumbukumbu"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Lemaza Kumbukumbu za Matukio ya Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Ndani ya sehemu ya huduma, lemesha huduma "Kumbukumbu ya Matukio ya Windows"
* `WEvtUtil.exec clear-log` au `WEvtUtil.exe cl`

## Lemaza $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
