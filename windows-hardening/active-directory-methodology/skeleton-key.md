# Skeleton Key

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Skeleton Key Attack

**Shambulio la Skeleton Key** ni mbinu ya kisasa inayowezesha washambuliaji **kuzidi uthibitisho wa Active Directory** kwa **kuingiza nenosiri kuu** kwenye kidhibiti cha eneo. Hii inamwezesha mshambuliaji **kujiwasilisha kama mtumiaji yeyote** bila nenosiri lao, ikitoa **ufikiaji usio na kikomo** kwa eneo hilo.

Inaweza kufanywa kwa kutumia [Mimikatz](https://github.com/gentilkiwi/mimikatz). Ili kutekeleza shambulio hili, **haki za Domain Admin ni lazima**, na mshambuliaji lazima alenge kila kidhibiti cha eneo ili kuhakikisha uvunjaji wa kina. Hata hivyo, athari za shambulio ni za muda mfupi, kwani **kuanzisha upya kidhibiti cha eneo kunafuta malware**, na inahitaji upya wa utekelezaji kwa ufikiaji endelevu.

**Kutekeleza shambulio** kunahitaji amri moja: `misc::skeleton`.

## Mitigations

Mikakati ya kupunguza dhidi ya mashambulizi kama haya ni pamoja na kufuatilia vitambulisho maalum vya tukio vinavyoashiria usakinishaji wa huduma au matumizi ya mamlaka nyeti. Kwa haswa, kutafuta Kitambulisho cha Tukio la Mfumo 7045 au Kitambulisho cha Tukio la Usalama 4673 kunaweza kufichua shughuli za kushangaza. Zaidi ya hayo, kuendesha `lsass.exe` kama mchakato uliohifadhiwa kunaweza kuzuia kwa kiasi kikubwa juhudi za washambuliaji, kwani hii inawahitaji kutumia dereva wa hali ya kernel, ikiongeza ugumu wa shambulio.

Hapa kuna amri za PowerShell za kuboresha hatua za usalama:

- Ili kugundua usakinishaji wa huduma za kushangaza, tumia: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Kwa haswa, kugundua dereva wa Mimikatz, amri ifuatayo inaweza kutumika: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Ili kuimarisha `lsass.exe`, inashauriwa kuifanya kuwa mchakato uliohifadhiwa: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Uthibitisho baada ya kuanzisha upya mfumo ni muhimu ili kuhakikisha kuwa hatua za ulinzi zimewekwa kwa mafanikio. Hii inaweza kufanywa kupitia: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
