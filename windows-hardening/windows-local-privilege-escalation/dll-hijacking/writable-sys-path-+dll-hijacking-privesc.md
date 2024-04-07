# Njia ya Kuongeza Mamlaka kwa Kutumia Dll Hijacking kwa Njia ya Kuandika kwenye Sys Path

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

Ikiwa umegundua kuwa unaweza **kuandika kwenye folda ya Njia ya Mfumo** (kumbuka hii haitafanya kazi ikiwa unaweza kuandika kwenye folda ya Njia ya Mtumiaji) inawezekana kwamba unaweza **kuongeza mamlaka** kwenye mfumo.

Kwa kufanya hivyo, unaweza kutumia **Dll Hijacking** ambapo uta**iba maktaba inayopakiwa** na huduma au mchakato na **mamlaka zaidi** kuliko zako, na kwa sababu huduma hiyo inapakia Dll ambayo labda hata haipo kwenye mfumo mzima, itajaribu kuipakia kutoka kwenye Njia ya Mfumo ambapo unaweza kuandika.

Kwa habari zaidi kuhusu **Dll Hijacking ni nini** angalia:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Kuongeza Mamlaka kwa Kutumia Dll Hijacking

### Kupata Dll Iliyokosekana

Jambo la kwanza unahitaji ni ** kutambua mchakato** unaofanya kazi na **mamlaka zaidi** kuliko zako ambao unajaribu **kupakia Dll kutoka kwenye Njia ya Mfumo** unayoweza kuandika.

Shida katika kesi hizi ni kwamba labda mchakato huo tayari unafanya kazi. Ili kujua ni Dll zipi zinakosekana kwenye huduma unahitaji kuzindua procmon haraka iwezekanavyo (kabla ya michakato kupakiwa). Kwa hivyo, ili kugundua .dll zilizokosekana fanya:

* **Unda** folda `C:\privesc_hijacking` na ongeza njia `C:\privesc_hijacking` kwenye **mazingira ya mfumo ya Njia**. Unaweza kufanya hivi **kwa mikono** au kwa kutumia **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Zindua **`procmon`** na nenda kwa **`Chaguo`** --> **`Wezesha kuingia kwenye mfumo`** na bonyeza **`Sawa`** kwenye ujumbe.
* Kisha, **zima**. Wakati kompyuta inapoanza tena **`procmon`** itaanza **kurekodi** matukio haraka iwezekanavyo.
* Mara tu **Windows** inapoanza **tekeleza `procmon`** tena, itakwambia kuwa imekuwa ikifanya kazi na itakuuliza ikiwa unataka **kuhifadhi** matukio kwenye faili. Sema **ndiyo** na **hifadhi matukio kwenye faili**.
* **Baada ya** faili **kuundwa**, **funga** dirisha lililofunguliwa la **`procmon`** na **fungua faili ya matukio**.
* Ongeza hizi **vichujio** na utapata Dlls zote ambazo baadhi ya **mchakato ulijaribu kuzipakia** kutoka kwenye folda ya Njia ya Mfumo inayoweza kuandikwa:

<figure><img src="../../../.gitbook/assets/image (942).png" alt=""><figcaption></figcaption></figure>

### Dlls Zilizokosekana

Nikiendesha hii kwenye **mashine ya Windows 11 ya bure ya virtual (vmware)** nilipata matokeo haya:

<figure><img src="../../../.gitbook/assets/image (604).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii .exe ni bure hivyo waepuke, Dlls zilizokosekana zilikuwa kutoka:

| Huduma                         | Dll                | Mstari wa Amri                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Meneja wa Kazi (Mipangilio)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Huduma ya Sera ya Uchunguzi (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Baada ya kupata hii, nilipata chapisho la blogu lenye kuvutia ambalo pia linaelezea jinsi ya [**kutumia WptsExtensions.dll kwa privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Ambayo ndio **tutakayofanya sasa**.

### Utekaji Nyara

Kwa hivyo, ili **kupandisha vyeo** tutateka nyara maktaba ya **WptsExtensions.dll**. Tukiwa na **njia** na **jina** tunahitaji tu **kuunda dll mbaya**.

Unaweza [**jaribu kutumia mifano yoyote hii**](./#kuunda-na-kukusanya-dlls). Unaweza kutekeleza mizigo kama: pata ganda la rev, ongeza mtumiaji, tekeleza taa...

{% hint style="warning" %}
Tafadhali kumbuka kwamba **huduma zote hazitekelezwi** na **`NT AUTHORITY\SYSTEM`** baadhi pia zinatekelezwa na **`NT AUTHORITY\LOCAL SERVICE`** ambayo ina **mamlaka kidogo** na huenda **usitaweze kuunda mtumiaji mpya** kutumia ruhusa zake.\
Walakini, mtumiaji huyo ana **ruhusa ya seImpersonate**, kwa hivyo unaweza kutumia [**potato suite kupandisha vyeo**](../roguepotato-and-printspoofer.md). Kwa hivyo, katika kesi hii ganda la rev ni chaguo bora kuliko kujaribu kuunda mtumiaji.
{% endhint %}

Wakati wa kuandika **Huduma ya Meneja wa Kazi** inatekelezwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **kuunda Dll mbaya** (_katika kesi yangu nilitumia ganda la rev x64 na nilipata ganda lakini msalama alikikata kwa sababu ilikuwa kutoka msfvenom_), iihifadhi kwenye Njia ya Mfumo inayoweza kuandikwa kwa jina **WptsExtensions.dll** na **zima** kompyuta (au zima huduma au fanya chochote kinachohitajika kurudisha huduma/programu iliyoguswa).

Huduma ikianza tena, **dll inapaswa kupakia na kutekelezwa** (unaweza **kutumia tena** mbinu ya **procmon** kuangalia ikiwa **maktaba ilipakia kama ilivyotarajiwa**).
