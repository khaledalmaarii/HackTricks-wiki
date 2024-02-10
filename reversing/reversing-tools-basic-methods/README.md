# Reversing Tools & Grundlegende Methoden

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise.
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs.
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter.
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die HackTricks- und HackTricks Cloud-GitHub-Repositories senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. Probieren Sie es noch heute [kostenlos aus](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## ImGui-basierte Reverse-Engineering-Tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm-Decompiler / Wat-Compiler

Online:

- Verwenden Sie [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von Wasm (Binärdatei) nach Wat (Klartext) zu **decompilieren**.
- Verwenden Sie [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von Wat nach Wasm zu **kompilieren**.
- Sie können auch versuchen, [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) zum Decompilieren zu verwenden.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net-Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der verschiedene Formate wie Bibliotheken (.dll), Windows-Metadatendateien (.winmd) und ausführbare Dateien (.exe) **decompiliert und untersucht**. Nach der Dekompilierung kann eine Assembly als Visual Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil hierbei ist, dass bei einem verlorenen Quellcode eine Wiederherstellung aus einer Legacy-Assembly Zeit sparen kann. Darüber hinaus bietet dotPeek eine praktische Navigation durch den dekompilierten Code und ist daher eines der perfekten Tools für die Analyse von Xamarin-Algorithmen.

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-In-Modell und einer API, die das Tool an Ihre genauen Bedürfnisse anpasst, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Werfen wir einen Blick auf die Vielzahl von Reverse-Engineering-Services, die dieses Tool bietet:

- Bietet Einblick in den Datenfluss durch eine Bibliothek oder Komponente
- Bietet Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
- Findet nicht dokumentierte und nicht freigegebene Funktionen, um mehr aus den verwendeten APIs und Technologien herauszuholen.
- Findet Abhängigkeiten und verschiedene Assemblys
- Ermittelt den genauen Ort von Fehlern in Ihrem Code, in Komponenten von Drittanbietern und Bibliotheken.
- Debuggt den Quellcode aller .NET-Code, mit dem Sie arbeiten.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Sie können es in jedem Betriebssystem verwenden (Sie können es direkt von VSCode installieren, kein Git-Download erforderlich. Klicken Sie auf **Erweiterungen** und **suchen Sie nach ILSpy**).\
Wenn Sie **dekompilieren**, **ändern** und **wieder kompilieren** müssen, können Sie [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) verwenden (Rechtsklick -> Methode ändern, um etwas in einer Funktion zu ändern).\
Sie können auch [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/) ausprobieren.

### DNSpy-Protokollierung

Um DNSpy dazu zu bringen, einige Informationen in einer Datei zu protokollieren, können Sie diese .Net-Zeilen verwenden:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, müssen Sie Folgendes tun:

Zuerst ändern Sie die **Assembly-Attribute**, die mit dem **Debugging** zusammenhängen:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
An: 

# Reverse Engineering-Tools und grundlegende Methoden

Dieses Dokument enthält eine Liste von Reverse Engineering-Tools und grundlegenden Methoden, die beim Reverse Engineering von Softwareanwendungen verwendet werden können. Diese Tools und Methoden sind hilfreich, um den Quellcode einer Anwendung zu analysieren und zu verstehen, wie sie funktioniert.

## Tools

- **IDA Pro**: Ein leistungsstarker Disassembler und Debugger, der häufig von Reverse Engineers verwendet wird, um den Maschinencode einer Anwendung zu analysieren.
- **Ghidra**: Ein Open-Source-Framework für Reverse Engineering, das von der National Security Agency (NSA) entwickelt wurde.
- **OllyDbg**: Ein Windows-Debugger, der häufig zum Reverse Engineering von Anwendungen verwendet wird.
- **x64dbg**: Ein Open-Source-Debugger für Windows, der speziell für die Reverse Engineering-Community entwickelt wurde.
- **Hopper**: Ein Disassembler und Debugger für macOS, der es Benutzern ermöglicht, den Maschinencode von Anwendungen zu analysieren.
- **Radare2**: Ein Open-Source-Framework für Reverse Engineering, das eine Vielzahl von Funktionen für die Analyse von Binärdateien bietet.
- **Binary Ninja**: Ein kommerzieller Reverse Engineering-Toolkit, das eine benutzerfreundliche Benutzeroberfläche und leistungsstarke Analysefunktionen bietet.
- **IDA Python**: Eine Python-Bibliothek, die es Benutzern ermöglicht, Skripte zur Automatisierung von Aufgaben in IDA Pro zu schreiben.
- **Cutter**: Ein Open-Source-GUI für Radare2, das eine benutzerfreundliche Oberfläche für die Analyse von Binärdateien bietet.

## Grundlegende Methoden

- **Static Analysis**: Eine Methode, bei der der Quellcode oder der Maschinencode einer Anwendung analysiert wird, ohne dass die Anwendung ausgeführt wird.
- **Dynamic Analysis**: Eine Methode, bei der die Anwendung während ihrer Ausführung analysiert wird, um Informationen über ihr Verhalten zu erhalten.
- **Disassembling**: Der Prozess des Konvertierens von Maschinencode in eine menschenlesbare Form.
- **Decompiling**: Der Prozess des Konvertierens von Maschinencode in den ursprünglichen Quellcode.
- **Debugging**: Der Prozess des Überwachens und Analysierens des Verhaltens einer Anwendung zur Fehlerbehebung oder zum Reverse Engineering.
- **Code Injection**: Eine Technik, bei der zusätzlicher Code in eine Anwendung eingefügt wird, um ihr Verhalten zu ändern oder Informationen zu sammeln.
- **Memory Dumping**: Der Prozess des Extrahierens des Speicherinhalts einer Anwendung, um Informationen über ihre Ausführung zu erhalten.
- **String Analysis**: Eine Methode, bei der nach Zeichenketten im Quellcode oder im Speicher einer Anwendung gesucht wird, um Informationen über ihre Funktionalität zu erhalten.

## Fazit

Reverse Engineering-Tools und grundlegende Methoden sind unerlässlich, um den Quellcode einer Anwendung zu analysieren und zu verstehen. Mit diesen Tools und Methoden können Reverse Engineers den internen Aufbau einer Anwendung untersuchen und Schwachstellen oder Sicherheitslücken identifizieren. Es ist wichtig, diese Tools und Methoden verantwortungsbewusst und ethisch zu verwenden, um die Privatsphäre und Sicherheit von Benutzern zu schützen.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Und klicken Sie auf **Kompilieren**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Speichern Sie dann die neue Datei unter _**Datei >> Modul speichern...**_:

![](<../../.gitbook/assets/image (279).png>)

Dies ist notwendig, da zur **Laufzeit** mehrere **Optimierungen** auf den Code angewendet werden und es möglich sein könnte, dass während des Debuggens ein **Haltepunkt nie erreicht** wird oder einige **Variablen nicht existieren**.

Dann, wenn Ihre .Net-Anwendung von **IIS** ausgeführt wird, können Sie sie mit folgendem Befehl **neu starten**:
```
iisreset /noforce
```
Dann sollten Sie alle geöffneten Dateien schließen und im **Debug-Tab** **Attach to Process...** auswählen:

![](<../../.gitbook/assets/image (280).png>)

Wählen Sie dann **w3wp.exe** aus, um sich an den **IIS-Server** anzuhängen, und klicken Sie auf **attach**:

![](<../../.gitbook/assets/image (281).png>)

Jetzt, da wir den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicken Sie zunächst auf _Debug >> Break All_ und dann auf _**Debug >> Windows >> Modules**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Klicken Sie auf ein beliebiges Modul in **Modules** und wählen Sie **Open All Modules**:

![](<../../.gitbook/assets/image (284).png>)

Klicken Sie mit der rechten Maustaste auf ein beliebiges Modul im **Assembly Explorer** und klicken Sie auf **Sort Assemblies**:

![](<../../.gitbook/assets/image (285).png>)

## Java Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Mit IDA

* **Laden Sie rundll32** (64-Bit in C:\Windows\System32\rundll32.exe und 32-Bit in C:\Windows\SysWOW64\rundll32.exe)
* Wählen Sie den **Windbg**-Debugger
* Wählen Sie "**Suspend on library load/unload**"

![](<../../.gitbook/assets/image (135).png>)

* Konfigurieren Sie die **Parameter** der Ausführung, indem Sie den **Pfad zur DLL** und die Funktion angeben, die Sie aufrufen möchten:

![](<../../.gitbook/assets/image (136).png>)

Wenn Sie nun mit dem Debuggen beginnen, wird die Ausführung angehalten, wenn jede DLL geladen wird. Wenn rundll32 Ihre DLL lädt, wird die Ausführung angehalten.

Aber wie gelangen Sie zum Code der geladenen DLL? Mit dieser Methode weiß ich es nicht.

### Mit x64dbg/x32dbg

* **Laden Sie rundll32** (64-Bit in C:\Windows\System32\rundll32.exe und 32-Bit in C:\Windows\SysWOW64\rundll32.exe)
* **Ändern Sie die Befehlszeile** ( _File --> Change Command Line_ ) und geben Sie den Pfad zur DLL und die Funktion ein, die Sie aufrufen möchten, z.B.: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Ändern Sie _Options --> Settings_ und wählen Sie "**DLL Entry**".
* Starten Sie dann die Ausführung, der Debugger wird bei jedem DLL-Haupt anhalten, an einem Punkt werden Sie im DLL-Einstiegspunkt Ihrer DLL anhalten. Von dort aus suchen Sie einfach nach den Stellen, an denen Sie einen Breakpoint setzen möchten.

Beachten Sie, dass Sie in win64dbg sehen können, **in welchem Code Sie sich befinden**, wenn die Ausführung aus irgendeinem Grund angehalten wird, indem Sie oben im win64dbg-Fenster nachsehen:

![](<../../.gitbook/assets/image (137).png>)

So können Sie sehen, wann die Ausführung in der DLL angehalten wurde, die Sie debuggen möchten.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um herauszufinden, wo wichtige Werte im Speicher eines laufenden Spiels gespeichert sind und sie zu ändern. Weitere Informationen finden Sie unter:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Debuggen eines Shellcodes mit blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) alloziert den Shellcode in einem Speicherbereich, gibt Ihnen die Speicheradresse an, an der der Shellcode alloziert wurde, und stoppt die Ausführung.\
Dann müssen Sie einen Debugger (Ida oder x64dbg) an den Prozess anhängen und einen Breakpoint an der angegebenen Speicheradresse setzen und die Ausführung fortsetzen. Auf diese Weise können Sie den Shellcode debuggen.

Auf der GitHub-Seite der Releases finden Sie ZIP-Dateien mit den kompilierten Versionen: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Sie können eine leicht modifizierte Version von Blobrunner unter folgendem Link finden. Um sie zu kompilieren, erstellen Sie einfach ein C/C++-Projekt in Visual Studio Code, kopieren Sie den Code und erstellen Sie ihn.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debuggen eines Shellcodes mit jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ist sehr ähnlich zu blobrunner. Es alloziert den Shellcode in einem Speicherbereich und startet eine Endlosschleife. Sie müssen dann den Debugger an den Prozess anhängen, die Ausführung starten, 2-5 Sekunden warten und stoppen. Sie befinden sich dann in der Endlosschleife. Springen Sie zur nächsten Anweisung der Endlosschleife, da es sich um einen Aufruf des Shellcodes handelt, und schließlich führen Sie den Shellcode aus.

![](<../../.gitbook/assets/image (397).png>)

Sie können eine kompilierte Version von [jmp2it auf der Releases-Seite](https://github.com/adamkramer/jmp2it/releases/) herunterladen.

### Debuggen von Shellcode mit Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die grafische Benutzeroberfläche von radare. Mit Cutter können Sie den Shellcode emulieren und dynamisch inspizieren.

Beachten Sie, dass Cutter es Ihnen ermöglicht, eine Datei zu öffnen und einen Shellcode zu öffnen. In meinem Fall wurde der Shellcode korrekt dekompiliert, als ich ihn als Datei öffnete, aber nicht, als ich ihn als Shellcode öffnete:

![](<../../.gitbook/assets/image (400).png>)

Um die Emulation an der gewünschten Stelle zu starten, setzen Sie dort einen Breakpoint, und anscheinend startet Cutter die Emulation automatisch von dort aus:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Sie können beispielsweise den Stack in einem Hexdump anzeigen:

![](<../../.gitbook/assets/image (402).png>)

### Deobfuskation von Shellcode und Ermittlung ausgeführter Funktionen

Sie sollten [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152) ausprobieren.\
Es wird Ihnen sagen, welche Funktionen der Shellcode verwendet und ob der Shellcode sich im Speicher selbst decodiert.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg verfügt auch über einen grafischen Launcher, in dem Sie die gewünschten Optionen auswählen und den Shellcode ausführen können.

![](<../../.gitbook/assets/image (398).png>)

Die Option **Create Dump** erstellt einen Dump des endgültigen Shellcodes, wenn Änderungen am Shellcode dynamisch im Speicher vorgenommen werden (nützlich zum Herunterladen des decodierten Shellcodes). Der **Startoffset** kann nützlich sein, um den Shellcode an einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode mit dem scDbg-Terminal zu debuggen (jedoch finde ich eine der zuvor erklärten Optionen in dieser Hinsicht besser, da Sie Ida oder x64dbg verwenden können).

### Disassemblierung mit CyberChef

Laden Sie Ihre Shellcode-Datei als Eingabe hoch und verwenden Sie das folgende Rezept, um es zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator **ändert alle Anweisungen für `mov`** (ja, wirklich cool). Er verwendet auch Unterbrechungen, um die Ausführungsflüsse zu ändern. Weitere Informationen dazu, wie es funktioniert:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Wenn Sie Glück haben, kann [demovfuscator](https://github.com/kirschju/demovfuscator) die Binärdatei wieder entschlüsseln. Es hat mehrere Abhängigkeiten.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [installiere Keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du ein **CTF spielst, könnte dieser Workaround zur Suche nach der Flagge** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finde die wichtigsten Schwachstellen, damit du sie schneller beheben kannst. Intruder verfolgt deine Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in deinem gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probiere es heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Um den **Einstiegspunkt** zu finden, suche nach Funktionen mit `::main`, wie hier:

![](<../../.gitbook/assets/image (612).png>)

In diesem Fall wurde die Binärdatei "authenticator" genannt, daher ist es ziemlich offensichtlich, dass dies die interessante Hauptfunktion ist.\
Wenn du den **Namen** der **aufgerufenen Funktionen** hast, suche im **Internet** nach ihnen, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

## **Delphi**

Für mit Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden.

Wenn du eine Delphi-Binärdatei umkehren musst, empfehle ich dir das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden.

Drücke einfach **ATL+f7** (importiere das Python-Plugin in IDA) und wähle das Python-Plugin aus.

Dieses Plugin führt die Binärdatei aus und löst die Funktionsnamen dynamisch zu Beginn des Debuggings auf. Nach dem Starten des Debuggings drücke erneut die Start-Schaltfläche (die grüne oder f9), und ein Breakpoint wird am Anfang des eigentlichen Codes erreicht.

Es ist auch sehr interessant, weil der Debugger anhält, wenn du in der grafischen Anwendung eine Schaltfläche drückst und die Funktion ausführt, die von dieser Schaltfläche ausgeführt wird.

## Golang

Wenn du eine Golang-Binärdatei umkehren musst, empfehle ich dir das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden.

Drücke einfach **ATL+f7** (importiere das Python-Plugin in IDA) und wähle das Python-Plugin aus.

Dieses Plugin löst die Namen der Funktionen auf.

## Kompiliertes Python

Auf dieser Seite findest du heraus, wie du den Python-Code aus einer ELF/EXE-Python-kompilierten Binärdatei extrahieren kannst:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und **debuggen**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
* [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm) kannst du unter _**Options --> Emulation Setup --> Controls**_\*\* \*\* sehen, wie du die Tasten des Game Boy Advance drücken kannst

![](<../../.gitbook/assets/image (578).png>)

Jeder **Taste ist ein Wert** zugeordnet, um sie zu identifizieren:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
So, in dieser Art von Programmen ist der interessante Teil, wie das Programm die Benutzereingabe behandelt. An der Adresse **0x4000130** finden Sie die häufig vorkommende Funktion: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

In dem vorherigen Bild können Sie sehen, dass die Funktion von **FUN\_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

In dieser Funktion, nach einigen Initialisierungsoperationen (ohne Bedeutung):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Es wurde folgender Code gefunden:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Die letzte if-Anweisung überprüft, ob **`uVar4`** in den **letzten Schlüsseln** enthalten ist und nicht der aktuelle Schlüssel ist, der auch als Loslassen einer Taste bezeichnet wird (der aktuelle Schlüssel wird in **`uVar1`** gespeichert).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Im vorherigen Code sehen Sie, dass wir **uVar1** (den Ort, an dem der **Wert der gedrückten Taste** steht) mit einigen Werten vergleichen:

* Zuerst wird er mit dem **Wert 4** (**SELECT**-Taste) verglichen: In der Herausforderung löscht diese Taste den Bildschirm.
* Dann wird er mit dem **Wert 8** (**START**-Taste) verglichen: In der Herausforderung wird überprüft, ob der Code gültig ist, um die Flagge zu erhalten.
* In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen und wenn der Wert gleich ist, wird bestimmter Code ausgeführt.
* In allen anderen Fällen wird ein Wert (`DAT_030000d4`) überprüft. Es handelt sich um einen Wert, da er unmittelbar nach dem Eingeben des Codes um 1 erhöht wird.\
Wenn er kleiner als 8 ist, wird etwas ausgeführt, das das **Hinzufügen** von Werten zu \*\*`DAT_030000d8` \*\* beinhaltet (im Wesentlichen werden die Werte der gedrückten Tasten in dieser Variable addiert, solange der Wert kleiner als 8 ist).

In dieser Herausforderung mussten Sie also eine Kombination mit einer Länge kleiner als 8 drücken, sodass die resultierende Addition 0xf3 ergibt.

**Referenz für dieses Tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kurse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
