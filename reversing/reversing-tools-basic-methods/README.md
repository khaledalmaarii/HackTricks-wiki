# Reverse Engineering Tools & Basic Methods

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## ImGui-basierte Reverse-Engineering-Tools

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm-Decompiler / Wat-Compiler

Online:

* Verwenden Sie [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), um von wasm (binär) nach wat (Klartext) zu **decompilieren**
* Verwenden Sie [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), um von wat nach wasm zu **kompilieren**
* Sie können auch versuchen, [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) zum decompilieren zu verwenden

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET-Decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ist ein Decompiler, der **mehrere Formate dekompiliert und untersucht**, einschließlich **Bibliotheken** (.dll), **Windows-Metadatendateien** (.winmd) und **Ausführbare Dateien** (.exe). Nach dem Dekompilieren kann eine Assembly als Visual Studio-Projekt (.csproj) gespeichert werden.

Der Vorteil hierbei ist, dass wenn ein verlorener Quellcode aus einer Legacy-Assembly wiederhergestellt werden muss, diese Aktion Zeit sparen kann. Darüber hinaus bietet dotPeek eine praktische Navigation durch den dekompilierten Code, was es zu einem der perfekten Tools für die **Analyse von Xamarin-Algorithmen** macht.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Mit einem umfassenden Add-In-Modell und einer API, die das Tool erweitert, um Ihren genauen Anforderungen zu entsprechen, spart .NET Reflector Zeit und vereinfacht die Entwicklung. Schauen wir uns die Vielzahl von Reverse-Engineering-Services an, die dieses Tool bietet:

* Bietet Einblick, wie die Daten durch eine Bibliothek oder Komponente fließen
* Bietet Einblick in die Implementierung und Verwendung von .NET-Sprachen und -Frameworks
* Findet nicht dokumentierte und nicht freigegebene Funktionalitäten, um mehr aus den verwendeten APIs und Technologien herauszuholen.
* Findet Abhängigkeiten und verschiedene Assemblys
* Lokalisiert genau die Stelle von Fehlern in Ihrem Code, in Drittanbieterkomponenten und Bibliotheken.
* Debuggt in den Quellcode aller .NET-Codes, mit denen Sie arbeiten.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy-Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Sie können es in jedem Betriebssystem haben (Sie können es direkt von VSCode installieren, kein Download des Git erforderlich. Klicken Sie auf **Erweiterungen** und **suchen Sie nach ILSpy**).\
Wenn Sie **dekompilieren**, **ändern** und **erneut kompilieren** müssen, können Sie [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oder eine aktiv gepflegte Abspaltung davon, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases), verwenden. (**Rechtsklick -> Methode ändern**, um etwas innerhalb einer Funktion zu ändern).

### DNSpy-Protokollierung

Um **DNSpy dazu zu bringen, einige Informationen in einer Datei zu protokollieren**, könnten Sie diesen Codeausschnitt verwenden:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Um Code mit DNSpy zu debuggen, müssen Sie folgendes tun:

Zuerst ändern Sie die **Assembly-Eigenschaften**, die sich auf das **Debugging** beziehen:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
An:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Und klicken Sie auf **kompilieren**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Speichern Sie dann die neue Datei über _**Datei >> Modul speichern...**_:

![](<../../.gitbook/assets/image (279).png>)

Dies ist notwendig, da andernfalls zur **Laufzeit** verschiedene **Optimierungen** auf den Code angewendet werden und es möglich sein könnte, dass während des Debuggens ein **Haltepunkt nie erreicht** wird oder einige **Variablen nicht existieren**.

Dann, wenn Ihre .NET-Anwendung von **IIS** ausgeführt wird, können Sie sie **neu starten** mit:
```
iisreset /noforce
```
Dann, um mit dem Debuggen zu beginnen, sollten Sie alle geöffneten Dateien schließen und im **Debug-Tab** **An Prozess anhängen...** auswählen:

![](<../../.gitbook/assets/image (280).png>)

Wählen Sie dann **w3wp.exe** aus, um sich an den **IIS-Server** anzuhängen, und klicken Sie auf **Anhängen**:

![](<../../.gitbook/assets/image (281).png>)

Nun, da wir den Prozess debuggen, ist es an der Zeit, ihn anzuhalten und alle Module zu laden. Klicken Sie zunächst auf _Debug >> Alle anhalten_ und dann auf _**Debug >> Fenster >> Module**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Klicken Sie auf ein beliebiges Modul in **Module** und wählen Sie **Alle Module öffnen**:

![](<../../.gitbook/assets/image (284).png>)

Klicken Sie mit der rechten Maustaste auf ein beliebiges Modul im **Assembly Explorer** und wählen Sie **Assembly sortieren**:

![](<../../.gitbook/assets/image (285).png>)

## Java-Decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debuggen von DLLs

### Mit IDA

* **Rundll32 laden** (64-Bit in C:\Windows\System32\rundll32.exe und 32-Bit in C:\Windows\SysWOW64\rundll32.exe)
* Wählen Sie den **Windbg-Debugger**
* Wählen Sie "**Anhalten bei Bibliotheks-Lade/Entlade**"

![](<../../.gitbook/assets/image (135).png>)

* Konfigurieren Sie die **Parameter** der Ausführung, indem Sie den **Pfad zur DLL** und die Funktion, die Sie aufrufen möchten, angeben:

![](<../../.gitbook/assets/image (136).png>)

Dann, wenn Sie mit dem Debuggen beginnen, wird die Ausführung gestoppt, wenn jede DLL geladen wird. Wenn rundll32 Ihre DLL lädt, wird die Ausführung gestoppt.

Aber wie gelangen Sie zum Code der geladenen DLL? Mit dieser Methode weiß ich nicht, wie.

### Mit x64dbg/x32dbg

* **Rundll32 laden** (64-Bit in C:\Windows\System32\rundll32.exe und 32-Bit in C:\Windows\SysWOW64\rundll32.exe)
* **Ändern Sie die Befehlszeile** ( _Datei --> Befehlszeile ändern_ ) und setzen Sie den Pfad der DLL und die Funktion, die Sie aufrufen möchten, z.B.: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Ändern Sie _Optionen --> Einstellungen_ und wählen Sie "**DLL-Einstieg**".
* Starten Sie dann die Ausführung, der Debugger wird bei jedem DLL-Haupt anhalten, an einem Punkt werden Sie **im DLL-Einstieg Ihrer DLL anhalten**. Von dort aus suchen Sie einfach nach den Stellen, an denen Sie einen Haltepunkt setzen möchten.

Beachten Sie, dass wenn die Ausführung aus irgendeinem Grund in win64dbg gestoppt wird, Sie **im Code sehen können**, in welchem **Teil des win64dbg-Fensters** Sie sich befinden:

![](<../../.gitbook/assets/image (137).png>)

Dann können Sie sehen, wann die Ausführung in der DLL gestoppt wurde, die Sie debuggen möchten.

## GUI-Apps / Videospiele

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) ist ein nützliches Programm, um wichtige Werte im Speicher eines laufenden Spiels zu finden und zu ändern. Weitere Informationen finden Sie unter:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Debuggen eines Shellcodes mit blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) wird den **Shellcode** in einem Speicherbereich **allozieren**, Ihnen die **Speicheradresse** anzeigen, an der der Shellcode alloziert wurde, und die Ausführung **stoppen**.\
Dann müssen Sie einen Debugger (Ida oder x64dbg) an den Prozess anhängen, einen **Haltepunkt an der angegebenen Speicheradresse** setzen und die Ausführung **fortsetzen**. Auf diese Weise debuggen Sie den Shellcode.

Die GitHub-Seite der Veröffentlichungen enthält ZIP-Dateien mit den kompilierten Veröffentlichungen: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Sie finden eine leicht modifizierte Version von Blobrunner unter folgendem Link. Um sie zu kompilieren, erstellen Sie einfach ein C/C++-Projekt in Visual Studio Code, kopieren Sie den Code und erstellen Sie ihn.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debuggen eines Shellcodes mit jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)ist sehr ähnlich zu blobrunner. Es wird den **Shellcode** in einem Speicherbereich **allozieren** und eine **ewige Schleife** starten. Dann müssen Sie den Debugger an den Prozess anhängen, **Start drücken, 2-5 Sekunden warten und Stop drücken**, und Sie werden sich in der **ewigen Schleife** befinden. Springen Sie zur nächsten Anweisung der ewigen Schleife, da es sich um einen Aufruf des Shellcodes handeln wird, und schließlich werden Sie den Shellcode ausführen.

![](<../../.gitbook/assets/image (397).png>)

Sie können eine kompilierte Version von [jmp2it auf der Veröffentlichungsseite herunterladen](https://github.com/adamkramer/jmp2it/releases/).

### Debuggen von Shellcode mit Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) ist die GUI von radare. Mit Cutter können Sie den Shellcode emulieren und dynamisch inspizieren.

Beachten Sie, dass Cutter es Ihnen ermöglicht, eine Datei zu öffnen und Shellcode zu öffnen. In meinem Fall wurde der Shellcode korrekt dekompiliert, als ich ihn als Datei öffnete, aber nicht, als ich ihn als Shellcode öffnete:

![](<../../.gitbook/assets/image (400).png>)

Um die Emulation an der gewünschten Stelle zu starten, setzen Sie dort einen bp, und anscheinend wird Cutter automatisch die Emulation von dort aus starten:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Sie können beispielsweise den Stack in einem Hex-Dump sehen:

![](<../../.gitbook/assets/image (402).png>)

### Deobfuskation von Shellcode und Ermittlung ausgeführter Funktionen

Sie sollten [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152) ausprobieren.\
Es wird Ihnen sagen, welche Funktionen der Shellcode verwendet und ob der Shellcode sich im Speicher entschlüsselt.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg verfügt auch über einen grafischen Launcher, über den Sie die gewünschten Optionen auswählen und das Shellcode ausführen können

![](<../../.gitbook/assets/image (398).png>)

Die **Create Dump**-Option wird den endgültigen Shellcode dumpen, wenn Änderungen am Shellcode dynamisch im Speicher vorgenommen werden (nützlich zum Herunterladen des decodierten Shellcodes). Der **Startoffset** kann nützlich sein, um den Shellcode an einem bestimmten Offset zu starten. Die Option **Debug Shell** ist nützlich, um den Shellcode mit dem scDbg-Terminal zu debuggen (jedoch finde ich eine der zuvor erklärten Optionen für diese Angelegenheit besser, da Sie Ida oder x64dbg verwenden können).

### Disassemblieren mit CyberChef

Laden Sie Ihre Shellcode-Datei als Eingabe hoch und verwenden Sie das folgende Rezept, um es zu dekompilieren: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Dieser Obfuscator **modifiziert alle Anweisungen für `mov`** (ja, wirklich cool). Er verwendet auch Unterbrechungen, um Ausführungsflüsse zu ändern. Für weitere Informationen darüber, wie es funktioniert:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Wenn Sie Glück haben, wird [demovfuscator](https://github.com/kirschju/demovfuscator) das Binärprogramm deobfuskieren. Es hat mehrere Abhängigkeiten
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Und [installiere Keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Wenn du an einem **CTF teilnimmst, könnte dieser Workaround zur Auffindung der Flagge** sehr nützlich sein: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Um den **Einstiegspunkt** zu finden, suche nach Funktionen mit `::main` wie in:

![](<../../.gitbook/assets/image (612).png>)

In diesem Fall wurde die Binärdatei authenticator genannt, daher ist es ziemlich offensichtlich, dass dies die interessante Hauptfunktion ist.\
Nachdem du den **Namen** der **aufgerufenen Funktionen** hast, suche im **Internet** nach ihnen, um mehr über ihre **Eingaben** und **Ausgaben** zu erfahren.

## **Delphi**

Für mit Delphi kompilierte Binärdateien kannst du [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) verwenden

Wenn du eine Delphi-Binärdatei umkehren musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) zu verwenden

Drücke einfach **ATL+f7** (Python-Plugin in IDA importieren) und wähle das Python-Plugin aus.

Dieses Plugin führt die Binärdatei aus und löst die Funktionsnamen dynamisch zu Beginn des Debuggens auf. Nach dem Starten des Debuggens drücke erneut die Start-Schaltfläche (die grüne oder f9), und ein Breakpoint wird am Anfang des echten Codes erreicht.

Es ist auch sehr interessant, weil der Debugger anhält, wenn du in der grafischen Anwendung eine Schaltfläche drückst, die Funktion ausführt.

## Golang

Wenn du eine Golang-Binärdatei umkehren musst, würde ich dir empfehlen, das IDA-Plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) zu verwenden

Drücke einfach **ATL+f7** (Python-Plugin in IDA importieren) und wähle das Python-Plugin aus.

Dies löst die Namen der Funktionen auf.

## Kompiliertes Python

Auf dieser Seite findest du, wie du den Python-Code aus einer ELF/EXE-Python-kompilierten Binärdatei extrahieren kannst:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Wenn du die **Binärdatei** eines GBA-Spiels hast, kannst du verschiedene Tools verwenden, um es zu **emulieren** und zu **debuggen**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Lade die Debug-Version herunter_) - Enthält einen Debugger mit Benutzeroberfläche
* [**mgba** ](https://mgba.io)- Enthält einen CLI-Debugger
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra-Plugin
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra-Plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), unter _**Options --> Emulation Setup --> Controls**_\*\* \*\* kannst du sehen, wie du die Tasten des Game Boy Advance **bedienst**

![](<../../.gitbook/assets/image (578).png>)

Wenn gedrückt, hat jede **Taste einen Wert**, um sie zu identifizieren:
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
Also, in dieser Art von Programm wird der interessante Teil darin bestehen, **wie das Programm die Benutzereingabe behandelt**. An der Adresse **0x4000130** finden Sie die häufig vorkommende Funktion: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Im vorherigen Bild können Sie sehen, dass die Funktion von **FUN\_080015a8** aufgerufen wird (Adressen: _0x080015fa_ und _0x080017ac_).

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
Es wurde dieser Code gefunden:
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
Die letzte if-Abfrage überprüft, ob **`uVar4`** in den **letzten Schlüsseln** enthalten ist und nicht im aktuellen Schlüssel, auch bekannt als Loslassen einer Taste (der aktuelle Schlüssel wird in **`uVar1`** gespeichert).
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
Im vorherigen Code sehen Sie, dass wir **uVar1** (den Ort, an dem der **Wert der gedrückten Taste** liegt) mit einigen Werten vergleichen:

* Zuerst wird er mit dem **Wert 4** (**SELECT**-Taste) verglichen: In der Herausforderung löscht diese Taste den Bildschirm.
* Dann wird er mit dem **Wert 8** (**START**-Taste) verglichen: In der Herausforderung wird überprüft, ob der Code gültig ist, um die Flagge zu erhalten.
* In diesem Fall wird die Variable **`DAT_030000d8`** mit 0xf3 verglichen und wenn der Wert gleich ist, wird ein bestimmter Code ausgeführt.
* In allen anderen Fällen wird ein bestimmter Inhalt (`DAT_030000d4`) überprüft. Es handelt sich um einen Inhalt, weil 1 direkt nach dem Eingeben des Codes hinzugefügt wird.\
Wenn weniger als 8 etwas, das das **Hinzufügen** von Werten zu **`DAT_030000d8`** beinhaltet, durchgeführt wird (im Grunde werden die Werte der gedrückten Tasten in dieser Variablen addiert, solange der Inhalt kleiner als 8 ist).

In dieser Herausforderung mussten Sie also, unter Berücksichtigung der Werte der Tasten, **eine Kombination mit einer Länge kleiner als 8 drücken, sodass die resultierende Addition 0xf3 ergibt**.

**Referenz für dieses Tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kurse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binäre Entschleierung)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
