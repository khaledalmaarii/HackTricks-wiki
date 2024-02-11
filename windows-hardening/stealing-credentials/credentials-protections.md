# Ulinzi wa Vitambulisho vya Windows

## Ulinzi wa Vitambulisho

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## WDigest

Itifaki ya [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), iliyoletwa na Windows XP, imeundwa kwa ajili ya uwakiki kupitia Itifaki ya HTTP na **imeamilishwa kwa chaguo-msingi kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mazingira haya ya chaguo-msingi husababisha **uhifadhi wa nywila za maandishi wazi kwenye LSASS** (Local Security Authority Subsystem Service). Mshambuliaji anaweza kutumia Mimikatz ku **chukua vitambulisho hivi** kwa kutekeleza:
```bash
sekurlsa::wdigest
```
Ili **kuzima au kuwasha kipengele hiki**, funguo za usajili za _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima ziwekwe kama "1". Ikiwa funguo hizi ziko **hazipo au zimewekwa kama "0"**, WDigest imelemazwa:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft iliboresha usalama wa LSA ili **kuzuia kusoma kumbukumbu au kuingiza nambari kwa njia isiyoidhinishwa na michakato isiyotegemewa**. Kuboresha hii inazuia utendaji wa kawaida wa amri kama vile `mimikatz.exe sekurlsa:logonpasswords`. Ili **kuwezesha ulinzi ulioboreshwa huu**, thamani ya _**RunAsPPL**_ katika _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ inapaswa kubadilishwa kuwa 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Kupita

Inawezekana kuvuka ulinzi huu kwa kutumia dereva wa Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Mlinzi wa Vitambulisho

**Mlinzi wa Vitambulisho**, kipengele pekee cha **Windows 10 (toleo la Enterprise na Education)**, huimarisha usalama wa vitambulisho vya mashine kwa kutumia **Hali Salama ya Kivinjari (VSM)** na **Usalama kwa Msingi wa Uwakilishi (VBS)**. Inatumia nyongeza za kivinjari za CPU kuweka michakato muhimu ndani ya nafasi salama ya kumbukumbu, mbali na kufikia mfumo wa uendeshaji kuu. Kizuizi hiki kuhakikisha hata kernel haiwezi kufikia kumbukumbu katika VSM, kwa hiyo kulinda vitambulisho kutokana na mashambulizi kama vile **pass-the-hash**. **Mamlaka ya Usalama wa Ndani (LSA)** inafanya kazi ndani ya mazingira salama kama trustlet, wakati mchakato wa **LSASS** katika mfumo wa uendeshaji kuu unafanya kazi tu kama mawasiliano na LSA ya VSM.

Kwa chaguo-msingi, **Mlinzi wa Vitambulisho** haipo na inahitaji kuwezeshwa kwa mikono ndani ya shirika. Ni muhimu kwa kuimarisha usalama dhidi ya zana kama **Mimikatz**, ambazo zinakwamishwa katika uwezo wao wa kuchukua vitambulisho. Hata hivyo, udhaifu unaweza bado kutumiwa kupitia kuongeza **Watoaji wa Usalama (SSP)** desturi ili kukamata vitambulisho wazi wakati wa jaribio la kuingia.

Kuwezesha hali ya uanzishaji wa **Mlinzi wa Vitambulisho**, unaweza kuchunguza ufunguo wa usajili **_LsaCfgFlags_** chini ya **_HKLM\System\CurrentControlSet\Control\LSA_**. Thamani ya "**1**" inaonyesha uanzishaji na **ufunguo wa UEFI**, "**2**" bila ufunguo, na "**0**" inaonyesha kuwa haiko kuwezeshwa. Uchunguzi huu wa usajili, ingawa ni ishara yenye nguvu, sio hatua pekee ya kuwezesha Mlinzi wa Vitambulisho. Miongozo ya kina na skripti ya PowerShell kwa kuwezesha kipengele hiki zinapatikana mtandaoni.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa ufahamu kamili na maelekezo juu ya kuwezesha **Credential Guard** katika Windows 10 na uanzishaji wake wa moja kwa moja katika mifumo inayolingana ya **Windows 11 Enterprise na Education (toleo 22H2)**, tembelea [nyaraka za Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Maelezo zaidi juu ya kutekeleza SSPs za desturi kwa ajili ya kukamata vitambulisho vya siri vimeelezewa katika [mwongozo huu](../active-directory-methodology/custom-ssp.md).


## Njia ya RDP RestrictedAdmin

**Windows 8.1 na Windows Server 2012 R2** ziliingiza vipengele vingi vipya vya usalama, ikiwa ni pamoja na **_Njia ya RDP Restricted Admin_**. Njia hii ililenga kuimarisha usalama kwa kupunguza hatari zinazohusiana na mashambulizi ya **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**.

Kawaida, unapounganisha kwenye kompyuta ya mbali kupitia RDP, vitambulisho vyako huhifadhiwa kwenye kompyuta ya lengo. Hii inaleta hatari kubwa ya usalama, hasa wakati unatumia akaunti zenye mamlaka ya juu. Hata hivyo, kwa kuanzishwa kwa **_Njia ya Restricted Admin_**, hatari hii inapunguzwa kwa kiasi kikubwa.

Unapoanzisha uunganisho wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, uwakiki kwenye kompyuta ya mbali hufanyika bila kuhifadhi vitambulisho vyako kwenye kompyuta hiyo. Hii inahakikisha kuwa, katika tukio la kuambukizwa na programu hasidi au ikiwa mtumiaji mwenye nia mbaya anapata ufikiaji wa seva ya mbali, vitambulisho vyako havitatiliwa hatarini, kwani havihifadhiwi kwenye seva.

Ni muhimu kutambua kuwa katika **Njia ya Restricted Admin**, jaribio la kupata rasilimali za mtandao kutoka kwenye kikao cha RDP halitatumia vitambulisho vyako binafsi; badala yake, utambulisho wa **kompyuta** unatumika.

Kipengele hiki kinawakilisha hatua muhimu katika kusimamia uunganisho wa desktop wa mbali na kulinda habari nyeti isifichuliwe katika kesi ya uvunjaji wa usalama.

![](../../.gitbook/assets/ram.png)

Kwa maelezo zaidi tembelea [rasilimali hii](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Vitambulisho Vilivyohifadhiwa

Windows inalinda **vitambulisho vya kikoa** kupitia **Mamlaka ya Usalama wa Ndani (LSA)**, ikisaidia mchakato wa kuingia kwa njia ya usalama kama vile **Kerberos** na **NTLM**. Moja ya vipengele muhimu vya Windows ni uwezo wake wa kuhifadhi **kuingia kwa kikoa cha mwisho kumi** ili kuhakikisha watumiaji wanaweza bado kupata kompyuta zao hata kama **kudhibitiwa kwa kikoa kunakosekana** - jambo zuri kwa watumiaji wa kompyuta za mkononi ambao mara nyingi hawako kwenye mtandao wa kampuni yao.

Idadi ya kuingia zilizohifadhiwa inaweza kubadilishwa kupitia **funguo maalum za usajili au sera za kikundi**. Ili kuona au kubadilisha mipangilio hii, amri ifuatayo hutumiwa:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Upatikanaji wa vitambulisho vilivyohifadhiwa hulindwa kwa nguvu, na akaunti ya **SYSTEM** pekee ina ruhusa muhimu ya kuviona. Wasimamizi wanaohitaji kupata habari hii lazima wafanye hivyo kwa mamlaka ya mtumiaji wa SYSTEM. Vitambulisho hivyo hifadhiwa kwenye: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** inaweza kutumika kuondoa vitambulisho vilivyohifadhiwa kwa kutumia amri `lsadump::cache`.

Kwa maelezo zaidi, chanzo cha asili [hapa](http://juggernaut.wikidot.com/cached-credentials) kinatoa habari kamili.

## Watumiaji Waliohifadhiwa

Uanachama katika kikundi cha **Watumiaji Waliohifadhiwa** huleta nyongeza kadhaa za usalama kwa watumiaji, ikihakikisha kiwango cha juu cha ulinzi dhidi ya wizi na matumizi mabaya ya vitambulisho:

- **Uhamishaji wa Vitambulisho (CredSSP)**: Hata ikiwa mipangilio ya Sera ya Kikundi kwa **Kuruhusu uhamishaji wa vitambulisho vya chaguo-msingi** imeamilishwa, vitambulisho vya wazi vya Watumiaji Waliohifadhiwa havitahifadhiwa.
- **Windows Digest**: Kuanzia **Windows 8.1 na Windows Server 2012 R2**, mfumo hautahifadhi vitambulisho vya wazi vya Watumiaji Waliohifadhiwa, bila kujali hali ya Windows Digest.
- **NTLM**: Mfumo hautahifadhi vitambulisho vya wazi vya Watumiaji Waliohifadhiwa au kazi za mwelekeo mmoja wa NT (NTOWF).
- **Kerberos**: Kwa Watumiaji Waliohifadhiwa, uwakilishi wa Kerberos hautazalisha funguo za **DES** au **RC4**, wala hautahifadhi vitambulisho vya wazi au funguo za muda mrefu zaidi ya upatikanaji wa Tiketi ya Kwanza ya Kutoa (TGT) ya awali.
- **Ingia Nje ya Mtandao**: Watumiaji Waliohifadhiwa hawatakuwa na uthibitisho uliohifadhiwa uliozalishwa wakati wa kuingia au kufungua, ikimaanisha kuwa ingia nje ya mtandao haikubaliki kwa akaunti hizi.

Ulinzi huu unaanza mara tu mtumiaji, ambaye ni mwanachama wa kikundi cha **Watumiaji Waliohifadhiwa**, anapoingia kwenye kifaa. Hii inahakikisha kuwa hatua muhimu za usalama zimechukuliwa ili kulinda dhidi ya njia mbalimbali za kuvunja vitambulisho.

Kwa habari zaidi, tafadhali rejea [hati rasmi](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Jedwali kutoka** [**hati**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
