<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

# Wasm-Dekompilations- und Wat-Kompilationsanleitung

Im Bereich von **WebAssembly** sind Tools zur **Dekompilierung** und **Kompilierung** für Entwickler unerlässlich. Diese Anleitung stellt einige Online-Ressourcen und Software zur Handhabung von **Wasm (WebAssembly-Binärdateien)** und **Wat (WebAssembly-Textdateien)** vor.

## Online-Tools

- Das Tool [Wabt's wasm2wat-Demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) ist nützlich, um Wasm in Wat zu **dekomplilieren**.
- Für die **Kompilierung** von Wat zurück zu Wasm dient [Wabt's wat2wasm-Demo](https://webassembly.github.io/wabt/demo/wat2wasm/).
- Eine weitere Dekompilationsoption finden Sie unter [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Softwarelösungen

- Für eine robustere Lösung bietet [JEB von PNF Software](https://www.pnfsoftware.com/jeb/demo) umfangreiche Funktionen.
- Das Open-Source-Projekt [wasmdec](https://github.com/wwwg/wasmdec) steht ebenfalls für Dekompilationsaufgaben zur Verfügung.

# .Net-Dekompilationsressourcen

Die Dekompilierung von .Net-Assemblys kann mit Tools wie folgenden durchgeführt werden:

- [ILSpy](https://github.com/icsharpcode/ILSpy), das auch ein [Plugin für Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) bietet, das eine plattformübergreifende Verwendung ermöglicht.
- Für Aufgaben, die **Dekompilierung**, **Modifikation** und **Rekompilierung** umfassen, wird [dnSpy](https://github.com/0xd4d/dnSpy/releases) empfohlen. Durch Klicken mit der rechten Maustaste auf eine Methode und Auswahl von **Modify Method** können Codeänderungen vorgenommen werden.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) ist eine weitere Alternative zur Dekompilierung von .Net-Assemblys.

## Verbessern von Debugging und Protokollierung mit DNSpy

### DNSpy-Protokollierung
Um Informationen in einer Datei mit DNSpy zu protokollieren, fügen Sie den folgenden .Net-Codeausschnitt ein:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy-Debugging
Für effektives Debugging mit DNSpy wird eine Abfolge von Schritten empfohlen, um **Assembly-Attribute** für das Debugging anzupassen und sicherzustellen, dass Optimierungen, die das Debugging behindern könnten, deaktiviert sind. Dieser Prozess umfasst das Ändern der Einstellungen des `DebuggableAttribute`, das Rekompilieren der Assembly und das Speichern der Änderungen.

Darüber hinaus wird zum Debuggen einer .Net-Anwendung, die von **IIS** ausgeführt wird, durch Ausführen von `iisreset /noforce` IIS neu gestartet. Um DNSpy an den IIS-Prozess zum Debuggen anzuhängen, wird in der Anleitung erklärt, wie der **w3wp.exe**-Prozess in DNSpy ausgewählt und die Debugging-Sitzung gestartet wird.

Um eine umfassende Ansicht der geladenen Module während des Debuggings zu erhalten, wird empfohlen, das Fenster **Modules** in DNSpy zu öffnen, alle Module zu öffnen und Assemblys zur einfacheren Navigation und zum Debugging zu sortieren.

Diese Anleitung fasst das Wesentliche der WebAssembly- und .Net-Dekompilierung zusammen und bietet Entwicklern einen Weg, diese Aufgaben mühelos zu bewältigen.

## **Java-Dekompiler**
Zur Dekompilierung von Java-Bytecode können diese Tools sehr hilfreich sein:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugging von DLLs**
### Mit IDA
- **Rundll32** wird aus bestimmten Pfaden für 64-Bit- und 32-Bit-Versionen geladen.
- **Windbg** wird als Debugger ausgewählt und die Option zum Anhalten beim Laden/Entladen der Bibliothek aktiviert.
- Die Ausführungsparameter umfassen den DLL-Pfad und den Funktionsnamen. Diese Konfiguration stoppt die Ausführung bei jedem Laden der DLL.

### Mit x64dbg/x32dbg
- Ähnlich wie bei IDA wird **rundll32** mit Befehlszeilenmodifikationen geladen, um die DLL und die Funktion anzugeben.
- Die Einstellungen werden so angepasst, dass beim DLL-Eintritt ein Breakpoint gesetzt werden kann.

### Bilder
- Die Ausführungsstopppunkte und Konfigurationen werden durch Screenshots veranschaulicht.

## **ARM & MIPS**
- Für die Emulation ist [arm_now](https://github.com/nongiach/arm_now) eine nützliche Ressource.

## **Shellcodes**
### Debugging-Techniken
- **Blobrunner** und **jmp2it** sind Tools zum Zuweisen von Shellcodes im Speicher und zum Debuggen mit Ida oder x64dbg.
- Blobrunner [Releases](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [kompilierte Version](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** bietet eine GUI-basierte Emulation und Inspektion von Shellcodes und hebt Unterschiede in der Behandlung von Shellcodes als Datei im Vergleich zu direktem Shellcode hervor.

### Deobfuscation und Analyse
- **scdbg** bietet Einblicke in Shellcode-Funktionen und Deobfuscation-Fähigkeiten.
%%%bash
scdbg.exe -f shellcode # Grundlegende Informationen
scdbg.exe -f shellcode -r # Analysebericht
scdbg.exe -f shellcode -i -r # Interaktive Hooks
scdbg.exe -f shellcode -d # Dekodierten Shellcode ablegen
scdbg.exe -f shellcode /findsc # Startoffset finden
scdbg.exe -f shellcode /foff 0x0000004D # Von Offset ausführen
%%%

- **CyberChef** zur Disassemblierung von Shellcode: [CyberChef-Rezept](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Ein Obfuscator, der alle Anweisungen durch `mov` ersetzt.
- Nützliche Ressourcen sind eine [YouTube-Erklärung](https://www.youtube.com/watch?v=2VF_wPkiBJY) und [PDF-Folien](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** kann die Obfuscation von movfuscator umkehren, erfordert Abhängigkeiten wie `libcapstone-dev` und `libz3-dev` und die Installation von [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).
## **Delphi**
- Für Delphi-Binärdateien wird [IDR](https://github.com/crypto2011/IDR) empfohlen.


# Kurse

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binäre Deobfuscation\)



<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
