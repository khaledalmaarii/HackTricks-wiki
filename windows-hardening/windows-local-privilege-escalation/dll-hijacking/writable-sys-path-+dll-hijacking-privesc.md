# Writable Sys Path +Dll Hijacking Privesc

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

Ikiwa umegundua kuwa unaweza **kuandika kwenye folda ya Njia ya Mfumo** (kumbuka kuwa hii haitafanya kazi ikiwa unaweza kuandika kwenye folda ya Njia ya Mtumiaji), inawezekana kuwa unaweza **kuongeza mamlaka** kwenye mfumo.

Ili kufanya hivyo, unaweza kutumia **Dll Hijacking** ambapo utaiba maktaba inayopakiwa na huduma au mchakato na **mamlaka zaidi** kuliko zako, na kwa sababu huduma hiyo inapakia Dll ambayo labda haipo kabisa kwenye mfumo mzima, itajaribu kuipakia kutoka kwenye Njia ya Mfumo ambapo unaweza kuandika.

Kwa habari zaidi kuhusu **Dll Hijacking ni nini**, angalia:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Kuongeza Mamlaka kwa Kutumia Dll Hijacking

### Kupata Dll Inayokosekana

Jambo la kwanza unahitaji kufanya ni **kutambua mchakato** unaoendesha na **mamlaka zaidi** kuliko wewe ambao unajaribu **kupakia Dll kutoka kwenye Njia ya Mfumo** ambayo unaweza kuandika.

Shida katika kesi hizi ni kwamba labda mchakato huo tayari unaendelea. Ili kupata Dll zinazokosekana kwenye huduma unahitaji kuzindua procmon haraka iwezekanavyo (kabla ya michakato kupakiwa). Kwa hivyo, ili kupata .dlls zinazokosekana, fanya yafuatayo:

* **Tengeneza** folda `C:\privesc_hijacking` na ongeza njia `C:\privesc_hijacking` kwenye **mazingira ya Njia ya Mfumo**. Unaweza kufanya hivi **kwa mkono** au kwa kutumia **PS**:

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

* Zindua **`procmon`** na nenda kwa **`Chaguo`** --> **`Wezesha kuingia kwenye kumbukumbu`** na bonyeza **`Sawa`** kwenye ujumbe.
* Kisha, **zima**. Wakati kompyuta inapoanza tena, **procmon** itaanza **kurekodi** matukio mara moja.
* Mara baada ya **Windows** kuanza, tekeleza tena **procmon**, itakuambia kuwa imekuwa ikifanya kazi na itakuuliza ikiwa unataka kuhifadhi matukio kwenye faili. Sema **ndio** na **hifadhi matukio kwenye faili**.
* **Baada** ya **faili** kuwa **imeundwa**, **funga** dirisha la **procmon** lililofunguliwa na **fungua faili ya matukio**.
* Ongeza **vichujio** hivi na utapata Dll zote ambazo baadhi ya **mchakato ulijaribu kuzipakia** kutoka kwenye folda ya Njia ya Mfumo inayoweza kuandikwa:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Dll Zilizokosekana

Nikikimbia hii kwenye **mashine ya Windows 11 ya bure (vmware)** nilipata matokeo haya:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii, .exe hazina maana, hivyo waipuuze, Dll zilizokosekana zilikuwa kutoka:

| Huduma                          | Dll                | Mstari wa Amri                                                       |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Baada ya kupata hii, nilipata chapisho la blogu lenye kuvutia ambalo pia linaelezea jinsi ya [**kutumia WptsExtensions.dll kwa privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Hii ndio tunayotarajia **kufanya sasa**.

### Utekaji

Kwa hivyo, ili **kuongeza mamlaka**, tutateka maktaba ya **WptsExtensions.dll**. Tukiwa na **njia** na **jina**, tunahitaji tu **kuunda dll mbaya**.

Unaweza [**jaribu kutumia moja ya mifano hii**](./#creating-and-compiling-dlls). Unaweza kutekeleza malipo kama vile: kupata kabati la rev, kuongeza mtumiaji, kutekeleza beacon...

{% hint style="warning" %}
Tafadhali kumbuka kuwa **huduma zote hazitekelezwi** na **`NT AUTHORITY\SYSTEM`** baadhi pia zinatekelezwa na **`NT AUTHORITY\LOCAL SERVICE`** ambayo ina **mamlaka kidogo** na huwezi kuunda mtumiaji mpya kwa kutumia mamlaka yake.\
Hata hivyo, mtumiaji huyo ana **ruhusa ya seImpersonate**, kwa hivyo unaweza kutumia [**zana ya viazi kuongeza mamlaka**](../roguepotato-and-printspoofer.md). Kwa hivyo, katika kesi hii kabati la rev ni chaguo bora kuliko jaribio la kuunda mtumiaji.
{% endhint %}

Wakati wa kuandika huduma ya **Task Scheduler** inatekelezwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **kuunda Dll mbaya** (_katika kesi yangu nilitumia kabati la rev x64 na nilipata kabati lakini msalaba wa ulinzi uliua kwa sababu ilikuwa kutoka msfvenom_), iihifadhi kwenye Njia ya Mfumo inayoweza kuandikwa na jina la **WptsExtensions.dll** na **zima** kompyuta (au zima huduma au fanya chochote kinachohitajika kuanzisha tena huduma/programu iliyoharibiwa).

Huduma inapoanza tena, **dll inapaswa kupakiwa na kutekelezwa** (unaweza **kutumia tena** mbinu ya **procmon** kuangalia ikiwa **maktaba imepakia kama ilivyotarajiwa**).

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
