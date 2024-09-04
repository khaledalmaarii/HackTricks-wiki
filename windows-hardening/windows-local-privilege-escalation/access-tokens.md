# Toegangstokens

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Toegangstokens

Elke **gebruiker wat op die stelsel aangemeld is** **besit 'n toegangstoken met sekuriteitsinligting** vir daardie aanmeldsessie. Die stelsel skep 'n toegangstoken wanneer die gebruiker aanmeld. **Elke proses wat** namens die gebruiker **uitgevoer word, het 'n kopie van die toegangstoken**. Die token identifiseer die gebruiker, die gebruiker se groepe, en die gebruiker se voorregte. 'n Token bevat ook 'n aanmeld SID (Sekuriteitsidentifiseerder) wat die huidige aanmeldsessie identifiseer.

Jy kan hierdie inligting sien deur `whoami /all` uit te voer.
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Plaaslike administrateur

Wanneer 'n plaaslike administrateur aanmeld, **word twee toegangstokens geskep**: Een met admin regte en die ander een met normale regte. **Standaard**, wanneer hierdie gebruiker 'n proses uitvoer, word die een met **reguliere** (nie-administrateur) **regte gebruik**. Wanneer hierdie gebruiker probeer om **enige iets** **as administrateur** uit te voer ("Run as Administrator" byvoorbeeld) sal die **UAC** gebruik word om toestemming te vra.\
As jy wil [**meer oor die UAC leer, lees hierdie bladsy**](../authentication-credentials-uac-and-efs/#uac)**.**

### Kredensiële gebruiker impersonasie

As jy **geldige kredensiale van enige ander gebruiker** het, kan jy 'n **nuwe aanmeldsessie** met daardie kredensiale **skep**:
```
runas /user:domain\username cmd.exe
```
Die **toegangsteken** het ook 'n **verwysing** na die aanmeldsessies binne die **LSASS**, dit is nuttig as die proses toegang tot sekere voorwerpe van die netwerk benodig.\
Jy kan 'n proses begin wat **verskillende geloofsbriewe gebruik om toegang tot netwerkdienste te verkry** met:
```
runas /user:domain\username /netonly cmd.exe
```
This is useful if you have useful credentials to access objects in the network but those credentials aren't valid inside the current host as they are only going to be used in the network (in the current host your current user privileges will be used).

### Types of tokens

There are two types of tokens available:

* **Primary Token**: Dit dien as 'n voorstelling van 'n proses se sekuriteitsakkrediteer. Die skepping en assosiasie van primêre tokens met prosesse is aksies wat verhoogde voorregte vereis, wat die beginsel van voorregskeiding beklemtoon. Tipies is 'n verifikasiediens verantwoordelik vir token skepping, terwyl 'n aanmelddiens dit hanteer met die gebruiker se bedryfstelsel-skal. Dit is die moeite werd om op te let dat prosesse die primêre token van hul ouer proses by skepping erf.
* **Impersonation Token**: Bemagtig 'n bedienertoepassing om die kliënt se identiteit tydelik aan te neem vir toegang tot veilige voorwerpe. Hierdie meganisme is gelaag in vier vlakke van werking:
* **Anonymous**: Gee bediener toegang soortgelyk aan dié van 'n onbekende gebruiker.
* **Identification**: Laat die bediener toe om die kliënt se identiteit te verifieer sonder om dit te gebruik vir voorwerp toegang.
* **Impersonation**: Stel die bediener in staat om onder die kliënt se identiteit te werk.
* **Delegation**: Soortgelyk aan Impersonation, maar sluit die vermoë in om hierdie identiteit aanneming uit te brei na afstandstelsels waarmee die bediener interaksie het, wat akkrediteer behoud verseker.

#### Impersonate Tokens

Using the _**incognito**_ module of metasploit if you have enough privileges you can easily **list** and **impersonate** other **tokens**. This could be useful to perform **actions as if you where the other user**. You could also **escalate privileges** with this technique.

### Token Privileges

Learn which **token privileges can be abused to escalate privileges:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Take a look to [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

Learn more about tokens in this tutorials: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) and [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


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
