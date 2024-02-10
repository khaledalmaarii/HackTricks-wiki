# QaD vItlhutlh

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>DaH jImej</strong></a><strong>!</strong></summary>

* **Do you work in a cybersecurity company**? **Do you want to see your company advertised in HackTricks**? **or do you want to have access to the latest version of the PEASS or download HackTricks in PDF**? **Check the SUBSCRIPTION PLANS**!
* **Discover The PEASS Family**, **our collection of exclusive NFTs**
* **Get the official PEASS & HackTricks swag**
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the **telegram group** or **follow** me on **Twitter** 🐦**@carlospolopm**.
* **Share your hacking tricks by submitting PRs to the hacktricks repo and hacktricks-cloud repo**.

</details>

## QaD vItlhutlh

**logon vItlhutlh** **user logged** **DaH** **access token with security information** **holds an access token**. **logon user** **DaH** **access token** **copy of the access token** **Every process executed**. **token** **user**, **user's groups**, **user's privileges** **identify**. **token** **logon SID (Security Identifier)** **identify** **current logon session**.

`whoami /all` **executing** **information** **see**.
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

![](<../../.gitbook/assets/image (321).png>)

### Local administrator

When a local administrator logins, **two access tokens are created**: One with admin rights and other one with normal rights. **By default**, when this user executes a process the one with **regular** (non-administrator) **rights is used**. When this user tries to **execute** anything **as administrator** ("Run as Administrator" for example) the **UAC** will be used to ask for permission.\
If you want to [**learn more about the UAC read this page**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Credentials user impersonation

If you have **valid credentials of any other user**, you can **create** a **new logon session** with those credentials :
```
runas /user:domain\username cmd.exe
```
**access token** **logh** **reference** **LSASS** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **logh** **
```
runas /user:domain\username /netonly cmd.exe
```
**QughmeywI'pu'**: QaghmeywI'pu' jatlhpu' 'e' vItlhutlhvIS 'ej vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS 'e' vItlhutlhvIS vItlhutlhvIS '
