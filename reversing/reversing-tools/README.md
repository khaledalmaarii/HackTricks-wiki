{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

# Wasm-Dekompilierung und Wat-Kompilierungsanleitung

Im Bereich von **WebAssembly** sind Werkzeuge zum **Dekompilieren** und **Kompilieren** für Entwickler unerlässlich. Diese Anleitung stellt einige Online-Ressourcen und Software für den Umgang mit **Wasm (WebAssembly-Binärdatei)** und **Wat (WebAssembly-Text)**-Dateien vor.

## Online-Tools

- Um Wasm in Wat zu **dekodieren**, ist das Tool unter [Wabt's wasm2wat-Demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) nützlich.
- Für die **Kompilierung** von Wat zurück zu Wasm dient [Wabt's wat2wasm-Demo](https://webassembly.github.io/wabt/demo/wat2wasm/).
- Eine weitere Dekompilierungsoption findet sich unter [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Softwarelösungen

- Für eine robustere Lösung bietet [JEB von PNF Software](https://www.pnfsoftware.com/jeb/demo) umfangreiche Funktionen.
- Das Open-Source-Projekt [wasmdec](https://github.com/wwwg/wasmdec) steht ebenfalls für Dekompilierungsaufgaben zur Verfügung.

# .Net-Dekompilierungsressourcen

Die Dekompilierung von .Net-Assemblies kann mit Tools wie:

- [ILSpy](https://github.com/icsharpcode/ILSpy) erfolgen, das auch ein [Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) anbietet, das plattformübergreifende Nutzung ermöglicht.
- Für Aufgaben, die **Dekompilierung**, **Modifikation** und **Rekompilierung** umfassen, wird [dnSpy](https://github.com/0xd4d/dnSpy/releases) dringend empfohlen. **Rechtsklick** auf eine Methode und Auswahl von **Methode ändern** ermöglicht Codeänderungen.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) ist eine weitere Alternative zur Dekompilierung von .Net-Assemblies.

## Verbesserung von Debugging und Logging mit DNSpy

### DNSpy-Logging
Um Informationen in eine Datei mit DNSpy zu protokollieren, integriere den folgenden .Net-Code-Schnipsel:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Passwort: " + password + "\n");
%%%

### DNSpy-Debugging
Für effektives Debugging mit DNSpy wird eine Abfolge von Schritten empfohlen, um die **Assembly-Attribute** für das Debugging anzupassen und sicherzustellen, dass Optimierungen, die das Debugging behindern könnten, deaktiviert sind. Dieser Prozess umfasst das Ändern der `DebuggableAttribute`-Einstellungen, das Neukompilieren der Assembly und das Speichern der Änderungen.

Darüber hinaus wird empfohlen, um eine .Net-Anwendung, die von **IIS** ausgeführt wird, zu debuggen, `iisreset /noforce` auszuführen, um IIS neu zu starten. Um DNSpy an den IIS-Prozess zum Debuggen anzuhängen, wird in der Anleitung beschrieben, wie man den **w3wp.exe**-Prozess innerhalb von DNSpy auswählt und die Debugging-Sitzung startet.

Für eine umfassende Ansicht der geladenen Module während des Debuggings wird empfohlen, das **Module**-Fenster in DNSpy zu öffnen, gefolgt von der Öffnung aller Module und der Sortierung der Assemblies für eine einfachere Navigation und Debugging.

Diese Anleitung fasst das Wesentliche der WebAssembly- und .Net-Dekompilierung zusammen und bietet Entwicklern einen Weg, diese Aufgaben mit Leichtigkeit zu bewältigen.

## **Java-Dekompilierer**
Um Java-Bytecode zu dekompilieren, können diese Tools sehr hilfreich sein:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugging von DLLs**
### Verwendung von IDA
- **Rundll32** wird aus bestimmten Pfaden für 64-Bit- und 32-Bit-Versionen geladen.
- **Windbg** wird als Debugger ausgewählt, mit der Option, beim Laden/Entladen von Bibliotheken anzuhalten.
- Die Ausführungsparameter umfassen den DLL-Pfad und den Funktionsnamen. Diese Konfiguration stoppt die Ausführung beim Laden jeder DLL.

### Verwendung von x64dbg/x32dbg
- Ähnlich wie bei IDA wird **rundll32** mit Befehlszeilenänderungen geladen, um die DLL und die Funktion anzugeben.
- Die Einstellungen werden angepasst, um beim DLL-Eintritt anzuhalten, sodass ein Haltepunkt am gewünschten DLL-Eintrittspunkt gesetzt werden kann.

### Bilder
- Ausführungshaltepunkte und Konfigurationen werden durch Screenshots veranschaulicht.

## **ARM & MIPS**
- Für die Emulation ist [arm_now](https://github.com/nongiach/arm_now) eine nützliche Ressource.

## **Shellcodes**
### Debugging-Techniken
- **Blobrunner** und **jmp2it** sind Tools zum Zuweisen von Shellcodes im Speicher und zum Debuggen mit Ida oder x64dbg.
- Blobrunner [Releases](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [kompilierte Version](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** bietet eine GUI-basierte Emulation und Inspektion von Shellcode und hebt Unterschiede in der Handhabung von Shellcode als Datei im Vergleich zu direktem Shellcode hervor.

### Deobfuskation und Analyse
- **scdbg** bietet Einblicke in Shellcode-Funktionen und Deobfuskationsfähigkeiten.
%%%bash
scdbg.exe -f shellcode # Grundinformationen
scdbg.exe -f shellcode -r # Analysebericht
scdbg.exe -f shellcode -i -r # Interaktive Hooks
scdbg.exe -f shellcode -d # Dump des dekodierten Shellcodes
scdbg.exe -f shellcode /findsc # Startoffset finden
scdbg.exe -f shellcode /foff 0x0000004D # Ausführung vom Offset
%%%

- **CyberChef** zum Disassemblieren von Shellcode: [CyberChef-Rezept](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Ein Obfuscator, der alle Anweisungen durch `mov` ersetzt.
- Nützliche Ressourcen umfassen eine [YouTube-Erklärung](https://www.youtube.com/watch?v=2VF_wPkiBJY) und [PDF-Folien](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** könnte die Obfuskation von movfuscator rückgängig machen, wobei Abhängigkeiten wie `libcapstone-dev` und `libz3-dev` erforderlich sind, und die Installation von [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Für Delphi-Binärdateien wird [IDR](https://github.com/crypto2011/IDR) empfohlen.


# Kurse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binärdeobfuskation\)



{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
