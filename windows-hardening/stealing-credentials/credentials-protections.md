# Kinga za Kibali za Windows

## Kinga za Kibali

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## WDigest

Itifaki ya [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396), iliyoanzishwa na Windows XP, imeundwa kwa ajili ya uthibitisho kupitia Itifaki ya HTTP na **imezimwa kwa chaguo-msingi kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mipangilio ya msingi kama hii husababisha **uhifadhi wa nywila za maandishi wazi kwenye LSASS** (Local Security Authority Subsystem Service). Mshambuliaji anaweza kutumia Mimikatz kuchimba **kibali hizi** kwa kutekeleza:
```bash
sekurlsa::wdigest
```
Ili **kuamsha au kulemaza kipengele hiki**, funguo za usajili za _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima ziwekwe kuwa "1". Ikiwa funguo hizi ziko **hazipo au zimewekwa kuwa "0"**, WDigest **imelemazwa**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ulindaji wa LSA

Kuanzia **Windows 8.1**, Microsoft iliimarisha usalama wa LSA ili **kuzuia kusoma kwa kumbukumbu au uingizaji wa nambari usiohalali na michakato isiyosadikika**. Kuboresha hii inazuia utendaji wa kawaida wa amri kama vile `mimikatz.exe sekurlsa:logonpasswords`. Ili **kuwezesha ulinzi ulioimarishwa huu**, thamani ya _**RunAsPPL**_ katika _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ inapaswa kurekebishwa kuwa 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Kupita

Inawezekana kukiuka ulinzi huu kwa kutumia dereva wa Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Mlinzi wa Anwani

**Mlinzi wa Anwani**, kipengele pekee kwa **Windows 10 (toleo la Enterprise na la Elimu)**, huzidisha usalama wa anwani za mashine kwa kutumia **Hali Salama ya Kivitual (VSM)** na **Usalama Uliotokana na Kivitualizesheni (VBS)**. Inatumia nyongeza za kivitualizesheni za CPU kwa kufunga michakato muhimu ndani ya nafasi salama ya kumbukumbu, mbali na kufikia kwa mfumo wa uendeshaji wa kuu. Kufungwa huku kunahakikisha hata kernel haiwezi kufikia kumbukumbu katika VSM, ikilinda anwani za mashine kutokana na mashambulizi kama vile **pita-neno-la-hash**. **Mamlaka ya Usalama wa Ndani (LSA)** inafanya kazi ndani ya mazingira haya salama kama trustlet, wakati mchakato wa **LSASS** katika mfumo wa uendeshaji wa kuu unafanya kazi kama mawasiliano tu na LSA ya VSM.

Kwa chaguo-msingi, **Mlinzi wa Anwani** haujaamilishwa na inahitaji kuamilishwa kwa mikono ndani ya shirika. Ni muhimu kwa kuzidisha usalama dhidi ya zana kama **Mimikatz**, ambazo zinakwamishwa katika uwezo wao wa kutoa anwani za mashine. Hata hivyo, udhaifu unaweza bado kutumiwa kupitia kuongeza **Watoa Msaada wa Usalama (SSP)** za kibinafsi ili kukamata anwani za mashine kwa maandishi wazi wakati wa jaribio la kuingia.

Ili kuthibitisha hali ya uamilishaji wa **Mlinzi wa Anwani**, funguo ya usajili _**LsaCfgFlags**_ chini ya _**HKLM\System\CurrentControlSet\Control\LSA**_ inaweza kukaguliwa. Thamani ya "**1**" inaonyesha uamilishaji na **ufunguo wa UEFI**, "**2**" bila funguo, na "**0**" inaonyesha kuwa haijaamilishwa. Ukaguzi huu wa usajili, ingawa ni ishara imara, si hatua pekee ya kuamilisha Mlinzi wa Anwani. Miongozo kamili na script ya PowerShell kwa kuamilisha kipengele hiki zinapatikana mtandaoni.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa uelewa kamili na maagizo ya kuwezesha **Guard ya Sifa** kwenye Windows 10 na uanzishaji wake wa moja kwa moja kwenye mifumo inayoweza kufanya kazi ya **Windows 11 Enterprise na Education (toleo 22H2)**, tembelea [hati ya Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Maelezo zaidi kuhusu utekelezaji wa SSPs za desturi kwa ajili ya kukamata sifa zinapatikana katika [mwongozo huu](../active-directory-methodology/custom-ssp.md).

## Hali ya RDP ya RestrictedAdmin

**Windows 8.1 na Windows Server 2012 R2** iliingiza vipengele vingi vipya vya usalama, ikiwa ni pamoja na _**Hali ya Msimamizi iliyozuiwa kwa RDP**_. Hali hii ililenga kuboresha usalama kwa kupunguza hatari zinazohusiana na mashambulizi ya [**pita hash**](https://blog.ahasayen.com/pass-the-hash/).

Kawaida, unapojiunganisha kwenye kompyuta ya mbali kupitia RDP, sifa zako huhifadhiwa kwenye kompyuta ya lengo. Hii inaleta hatari kubwa ya usalama, hasa unapotumia akaunti zenye mamlaka ya juu. Hata hivyo, kwa kuanzishwa kwa _**Hali ya Msimamizi iliyozuiwa**_, hatari hii inapunguzwa sana.

Unapozindua uhusiano wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, uthibitisho kwa kompyuta ya mbali hufanyika bila kuhifadhi sifa zako kwenye kompyuta hiyo. Hatua hii inahakikisha kwamba, katika tukio la maambukizi ya zisizo au ikiwa mtumiaji mhalifu anapata ufikiaji kwenye seva ya mbali, sifa zako hazitatishiwi, kwani hazihifadhiwi kwenye seva.

Ni muhimu kutambua kwamba katika **Hali ya Msimamizi iliyozuiwa**, jaribio la kupata rasilimali za mtandao kutoka kwenye kikao cha RDP halitatumia sifa zako binafsi; badala yake, **kitambulisho cha mashine** hutumiwa.

Kipengele hiki kinaashiria hatua kubwa mbele katika kusimamia uhusiano wa desktop za mbali na kulinda habari nyeti isifichuliwe katika kesi ya uvunjaji wa usalama.

![](../../.gitbook/assets/RAM.png)

Kwa maelezo zaidi tembelea [rasilimali hii](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Sifa Zilizohifadhiwa

Windows inalinda **sifa za uwanja** kupitia **Mamlaka ya Usalama wa Ndani (LSA)**, ikisaidia mchakato wa kuingia kwa itifaki za usalama kama **Kerberos** na **NTLM**. Kipengele muhimu cha Windows ni uwezo wake wa kuhifadhi **kuingia kwa uwanja kumi uliopita** ili kuhakikisha watumiaji wanaweza bado kupata kompyuta zao hata kama **mudhibiti wa uwanja yuko nje ya mtandao** - faida kwa watumiaji wa kompyuta za mkononi mara nyingi mbali na mtandao wa kampuni yao.

Idadi ya kuingia zilizohifadhiwa inaweza kubadilishwa kupitia **funguo maalum za usajili au sera ya kikundi**. Ili kuona au kubadilisha mipangilio hii, amri ifuatayo hutumiwa:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Upatikanaji wa siri za siri hizi umedhibitiwa kwa karibu, na akaunti ya **SYSTEM** pekee ina ruhusa muhimu ya kuziona. Waendeshaji wanaohitaji kupata habari hii lazima wafanye hivyo kwa ruhusa za mtumiaji wa SYSTEM. Siri hizi zimehifadhiwa kwenye: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** inaweza kutumika kuchimbua siri za siri hizi zilizohifadhiwa kwa kutumia amri `lsadump::cache`.

Kwa maelezo zaidi, chanzo cha asili [kinatoa](http://juggernaut.wikidot.com/cached-credentials) habari kamili.

## Watumiaji Waliohifadhiwa

Uanachama katika kikundi cha **Watumiaji Waliohifadhiwa** unaweka nyongeza kadhaa za usalama kwa watumiaji, ikihakikisha viwango vya juu vya ulinzi dhidi ya wizi na matumizi mabaya ya siri:

* **Utekelezaji wa Siri (CredSSP)**: Hata kama mipangilio ya Sera ya Kikundi kwa **Kuruhusu kutekeleza siri za msingi** imeanzishwa, siri za maandishi wazi za Watumiaji Waliohifadhiwa hazitahifadhiwa.
* **Windows Digest**: Kuanzia **Windows 8.1 na Windows Server 2012 R2**, mfumo hautahifadhi siri za maandishi wazi za Watumiaji Waliohifadhiwa, bila kujali hali ya Windows Digest.
* **NTLM**: Mfumo hautahifadhi siri za maandishi wazi za Watumiaji Waliohifadhiwa au kazi za NT one-way (NTOWF).
* **Kerberos**: Kwa Watumiaji Waliohifadhiwa, uthibitisho wa Kerberos hautazalisha funguo za **DES** au **RC4**, wala hautahifadhi siri za maandishi wazi au funguo za muda mrefu zaidi ya kupata Tiketi ya Kutoa Tiketi ya Kuingia (TGT) ya awali.
* **Ingia Nje ya Mtandao**: Watumiaji Waliohifadhiwa hawatapata uthibitishaji uliohifadhiwa ulioanzishwa wakati wa kuingia au kufungua, maana ingia nje ya mtandao haiungi mkono akaunti hizi.

Kinga hizi zinaanzishwa mara tu mtumiaji, ambaye ni mwanachama wa kikundi cha **Watumiaji Waliohifadhiwa**, anapoingia kwenye kifaa. Hii inahakikisha kuwa hatua muhimu za usalama zimewekwa kulinda dhidi ya njia mbalimbali za kudhoofisha siri.

Kwa maelezo zaidi, tafadhali angalia [nyaraka](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) rasmi.

**Jedwali kutoka** [**nyaraka**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
