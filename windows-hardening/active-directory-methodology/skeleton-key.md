# Skeleton Key

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS wa HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Shambulio la Skeleton Key

Shambulio la **Skeleton Key** ni mbinu ya kisasa ambayo inaruhusu wadukuzi kukiuka **uthibitishaji wa Active Directory** kwa **kuingiza nenosiri kuu** kwenye kisimamizi cha kikoa. Hii inawezesha mshambuliaji kuwa **uthibitisho kama mtumiaji yeyote** bila nenosiri lao, kwa ufanisi **kuwapa ufikiaji usiozuiliwa** kwenye kikoa.

Inaweza kutekelezwa kwa kutumia [Mimikatz](https://github.com/gentilkiwi/mimikatz). Kutekeleza shambulio hili kunahitaji **haki za Msimamizi wa Kikoa**, na mshambuliaji lazima alenge kila kisimamizi cha kikoa ili kuhakikisha ukiukaji kamili. Walakini, athari ya shambulio ni ya muda, kwani **kuanzisha upya kwa kisimamizi cha kikoa kunasafisha programu hasidi**, na hivyo kuhitaji utekelezaji upya kwa ufikiaji endelevu.

**Kutekeleza shambulio** kunahitaji amri moja tu: `misc::skeleton`.

## Kupunguza Athari

Mbinu za kupunguza athari za shambulio kama hizi ni pamoja na kufuatilia nambari maalum za tukio ambazo zinaonyesha ufungaji wa huduma au matumizi ya mamlaka nyeti. Hasa, kutafuta Tukio la Mfumo ID 7045 au Tukio la Usalama ID 4673 kunaweza kufichua shughuli za shaka. Kwa kuongezea, kukimbia `lsass.exe` kama mchakato uliolindwa kunaweza kuzuia sana juhudi za wadukuzi, kwani hii inahitaji watumie dereva wa mode ya kernel, ikiongeza ugumu wa shambulio.

Hapa kuna amri za PowerShell za kuimarisha hatua za usalama:

- Ili kugundua ufungaji wa huduma za shaka, tumia: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Hasa, ili kugundua dereva wa Mimikatz, amri ifuatayo inaweza kutumika: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Ili kuimarisha `lsass.exe`, inashauriwa kuwezesha kama mchakato uliolindwa: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Uhakiki baada ya kuanzisha upya kwa mfumo ni muhimu ili kuhakikisha kuwa hatua za kinga zimefanikiwa kutumika. Hii inaweza kufanikiwa kupitia: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Marejeo
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS wa HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
