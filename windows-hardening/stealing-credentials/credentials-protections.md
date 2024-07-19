# Windows Credentials Protections

## Credentials Protections

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

## WDigest

Protokali ya [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396), iliyozinduliwa na Windows XP, imeundwa kwa ajili ya uthibitishaji kupitia Protokali ya HTTP na **imewezeshwa kwa default kwenye Windows XP hadi Windows 8.0 na Windows Server 2003 hadi Windows Server 2012**. Mpangilio huu wa default unapelekea **hifadhi ya nywila katika maandiko ya wazi kwenye LSASS** (Huduma ya Mamlaka ya Usalama wa Mitaa). Mshambuliaji anaweza kutumia Mimikatz ili **kuchota hizi akidi** kwa kutekeleza:
```bash
sekurlsa::wdigest
```
Ili **kuwasha au kuzima kipengele hiki**, funguo za rejista _**UseLogonCredential**_ na _**Negotiate**_ ndani ya _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ lazima ziwe zimewekwa kuwa "1". Ikiwa funguo hizi **hazipo au zimewekwa kuwa "0"**, WDigest ime **zimwa**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection

Kuanzia na **Windows 8.1**, Microsoft iliboresha usalama wa LSA ili **kuzuia usomaji wa kumbukumbu zisizoidhinishwa au sindikizo la msimbo na michakato isiyoaminika**. Uboreshaji huu unakwamisha utendaji wa kawaida wa amri kama `mimikatz.exe sekurlsa:logonpasswords`. Ili **kuwezesha ulinzi huu ulioimarishwa**, thamani ya _**RunAsPPL**_ katika _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ inapaswa kubadilishwa kuwa 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Inapowezekana kupita ulinzi huu kwa kutumia Mimikatz driver mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, kipengele ambacho ni maalum kwa **Windows 10 (Enterprise na Education editions)**, kinaongeza usalama wa akidi za mashine kwa kutumia **Virtual Secure Mode (VSM)** na **Virtualization Based Security (VBS)**. Kinatumia nyongeza za virtualisasi za CPU kutenga michakato muhimu ndani ya nafasi ya kumbukumbu iliyo salama, mbali na ufikiaji wa mfumo wa uendeshaji mkuu. Kutengwa huku kunahakikisha kwamba hata kernel haiwezi kufikia kumbukumbu katika VSM, kwa ufanisi ikilinda akidi kutokana na mashambulizi kama **pass-the-hash**. **Local Security Authority (LSA)** inafanya kazi ndani ya mazingira haya salama kama trustlet, wakati mchakato wa **LSASS** katika OS kuu unafanya kazi kama mwasiliani tu na LSA ya VSM.

Kwa kawaida, **Credential Guard** haifanyi kazi na inahitaji kuamshwa kwa mikono ndani ya shirika. Ni muhimu kwa kuongeza usalama dhidi ya zana kama **Mimikatz**, ambazo zinakabiliwa na uwezo wao wa kutoa akidi. Hata hivyo, udhaifu bado unaweza kutumiwa kupitia kuongeza **Security Support Providers (SSP)** za kawaida ili kukamata akidi katika maandiko wazi wakati wa majaribio ya kuingia.

Ili kuthibitisha hali ya uanzishaji wa **Credential Guard**, funguo ya rejista _**LsaCfgFlags**_ chini ya _**HKLM\System\CurrentControlSet\Control\LSA**_ inaweza kukaguliwa. Thamani ya "**1**" inaonyesha uanzishaji na **UEFI lock**, "**2**" bila lock, na "**0**" inaashiria haijawashwa. Ukaguzi huu wa rejista, ingawa ni kiashiria kizuri, si hatua pekee ya kuamsha Credential Guard. Mwongozo wa kina na skripti ya PowerShell ya kuamsha kipengele hiki zinapatikana mtandaoni.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kwa ufahamu wa kina na maelekezo juu ya kuwezesha **Credential Guard** katika Windows 10 na uanzishaji wake wa kiotomatiki katika mifumo inayofaa ya **Windows 11 Enterprise na Education (toleo 22H2)**, tembelea [nyaraka za Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Maelezo zaidi juu ya kutekeleza SSPs za kawaida kwa ajili ya kukamata akidi yanapatikana katika [hiki kiongozi](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 na Windows Server 2012 R2** zilileta vipengele vingi vipya vya usalama, ikiwa ni pamoja na _**Restricted Admin mode kwa RDP**_. Hali hii ilipangwa kuboresha usalama kwa kupunguza hatari zinazohusiana na [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) mashambulizi.

Kawaida, unapounganisha na kompyuta ya mbali kupitia RDP, akidi zako zinahifadhiwa kwenye mashine lengwa. Hii inatoa hatari kubwa ya usalama, hasa unapokuwa ukitumia akaunti zenye mamlaka ya juu. Hata hivyo, kwa kuanzishwa kwa _**Restricted Admin mode**_, hatari hii inapunguzwa kwa kiasi kikubwa.

Wakati wa kuanzisha muunganisho wa RDP kwa kutumia amri **mstsc.exe /RestrictedAdmin**, uthibitishaji wa kompyuta ya mbali unafanywa bila kuhifadhi akidi zako kwenye hiyo. Njia hii inahakikisha kwamba, katika tukio la maambukizi ya programu hasidi au ikiwa mtumiaji mbaya atapata ufikiaji wa seva ya mbali, akidi zako hazitakuwa hatarini, kwani hazihifadhiwi kwenye seva.

Ni muhimu kutambua kwamba katika **Restricted Admin mode**, juhudi za kufikia rasilimali za mtandao kutoka kwenye kikao cha RDP hazitatumia akidi zako binafsi; badala yake, **utambulisho wa mashine** unatumika.

Kipengele hiki kinatoa hatua muhimu mbele katika kulinda muunganisho wa desktop ya mbali na kulinda taarifa nyeti zisifichuliwe katika tukio la uvunjaji wa usalama.

![](../../.gitbook/assets/RAM.png)

Kwa maelezo zaidi tembelea [rasilimali hii](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows inalinda **akidi za kikoa** kupitia **Local Security Authority (LSA)**, ikisaidia michakato ya kuingia kwa kutumia itifaki za usalama kama **Kerberos** na **NTLM**. Kipengele muhimu cha Windows ni uwezo wake wa kuhifadhi **kuingia kwa kikoa kumi za mwisho** ili kuhakikisha watumiaji wanaweza kuendelea kufikia kompyuta zao hata kama **kikundi cha kudhibiti kikoa kiko offline**—faida kwa watumiaji wa laptop ambao mara nyingi wako mbali na mtandao wa kampuni yao.

Idadi ya kuingia zilizohifadhiwa inaweza kubadilishwa kupitia **funguo maalum za rejista au sera ya kikundi**. Ili kuona au kubadilisha mipangilio hii, amri ifuatayo inatumika:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

Membership in the **Protected Users group** introduces several security enhancements for users, ensuring higher levels of protection against credential theft and misuse:

* **Credential Delegation (CredSSP)**: Hata kama mipangilio ya Sera ya Kundi kwa **Ruhusu kuhamasisha akiba ya kawaida** imewezeshwa, akiba ya maandiko ya kawaida ya Watumiaji Waliohifadhiwa haitahifadhiwa.
* **Windows Digest**: Kuanzia **Windows 8.1 na Windows Server 2012 R2**, mfumo hautahifadhi akiba ya maandiko ya kawaida ya Watumiaji Waliohifadhiwa, bila kujali hali ya Windows Digest.
* **NTLM**: Mfumo hautahifadhi akiba ya maandiko ya kawaida ya Watumiaji Waliohifadhiwa au kazi za upande mmoja za NT (NTOWF).
* **Kerberos**: Kwa Watumiaji Waliohifadhiwa, uthibitishaji wa Kerberos hautazalisha **DES** au **RC4 keys**, wala hautahifadhi akiba ya maandiko ya kawaida au funguo za muda mrefu zaidi ya upatikanaji wa Tiketi ya Kutoa Tiketi (TGT) ya awali.
* **Offline Sign-In**: Watumiaji Waliohifadhiwa hawatakuwa na mthibitishaji wa akiba ulioundwa wakati wa kuingia au kufungua, ikimaanisha kuwa kuingia bila mtandao hakusaidiwi kwa akaunti hizi.

These protections are activated the moment a user, who is a member of the **Protected Users group**, signs into the device. This ensures that critical security measures are in place to safeguard against various methods of credential compromise.

For more detailed information, consult the official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
