<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>

# Przewodnik po dekompilacji Wasm i kompilacji Wat

W dziedzinie **WebAssembly** narzędzia do **dekompilacji** i **kompilacji** są niezbędne dla programistów. Ten przewodnik przedstawia kilka zasobów online i oprogramowania do obsługi plików **Wasm (binarny WebAssembly)** i **Wat (tekstowy WebAssembly)**.

## Narzędzia online

- Do **dekompilacji** Wasm do Wat przydatne jest narzędzie dostępne pod adresem [Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html).
- Do **kompilacji** Wat z powrotem do Wasm służy [Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/).
- Inną opcją dekompilacji jest [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Rozwiązania oprogramowania

- Dla bardziej zaawansowanego rozwiązania, [JEB od PNF Software](https://www.pnfsoftware.com/jeb/demo) oferuje rozległe funkcje.
- Projekt open-source [wasmdec](https://github.com/wwwg/wasmdec) jest również dostępny do zadań związanych z dekompilacją.

# Zasoby do dekompilacji .Net

Dekompilację zestawów .Net można przeprowadzić za pomocą takich narzędzi jak:

- [ILSpy](https://github.com/icsharpcode/ILSpy), które oferuje również [wtyczkę dla Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), umożliwiającą użycie na różnych platformach.
- Do zadań związanych z **dekompilacją**, **modyfikacją** i **rekompilacją**, zaleca się [dnSpy](https://github.com/0xd4d/dnSpy/releases). Wybierając prawym przyciskiem myszy metodę i wybierając opcję **Modify Method**, można dokonywać zmian w kodzie.
- [dotPeek od JetBrains](https://www.jetbrains.com/es-es/decompiler/) to kolejna alternatywa do dekompilacji zestawów .Net.

## Udoskonalanie debugowania i logowania za pomocą DNSpy

### Logowanie w DNSpy
Aby zapisywać informacje do pliku za pomocą DNSpy, należy dołączyć następujący fragment kodu .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Debugowanie w DNSpy
Aby efektywnie debugować za pomocą DNSpy, zaleca się wykonanie sekwencji kroków w celu dostosowania **atrybutów zestawu** do debugowania, zapewniając, że wyłączone są optymalizacje, które mogą utrudniać debugowanie. Proces ten obejmuje zmianę ustawień `DebuggableAttribute`, rekompilację zestawu i zapisanie zmian.

Ponadto, aby debugować aplikację .Net uruchamianą przez **IIS**, wykonanie polecenia `iisreset /noforce` restartuje IIS. Aby dołączyć DNSpy do procesu IIS w celu debugowania, przewodnik instruuje wybranie procesu **w3wp.exe** w DNSpy i rozpoczęcie sesji debugowania.

Aby uzyskać kompleksowy widok załadowanych modułów podczas debugowania, zaleca się uzyskanie dostępu do okna **Modules** w DNSpy, a następnie otwarcie wszystkich modułów i posortowanie zestawów dla ułatwienia nawigacji i debugowania.

Ten przewodnik zawiera istotę dekompilacji WebAssembly i .Net, oferując programistom łatwą ścieżkę do poruszania się w tych zadaniach.

## **Dekompilator Java**
Aby zdekompilować kod bajtowy Javy, mogą być bardzo pomocne następujące narzędzia:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugowanie DLL**
### Za pomocą IDA
- **Rundll32** jest ładowany z określonych ścieżek dla wersji 64-bitowej i 32-bitowej.
- Jako debugger wybrano **Windbg** z włączoną opcją wstrzymywania ładowania/odładowywania bibliotek.
- Parametry wykonania obejmują ścieżkę DLL i nazwę funkcji. Ta konfiguracja zatrzymuje wykonanie przy każdym ładowaniu DLL.

### Za pomocą x64dbg/x32dbg
- Podobnie jak w przypadku IDA, **rundll32** jest ładowany z modyfikacjami w wierszu polecenia, aby określić DLL i funkcję.
- Ustawienia są dostosowane do zatrzymywania na wejściu do DLL, umożliwiając ustawienie punktu przerwania w pożądanym punkcie wejścia do DLL.

### Obrazy
- Punkty zatrzymania wykonania i konfiguracje są ilustrowane za pomocą zrzutów ekranu.

## **ARM i MIPS**
- Do emulacji przydatne jest narzędzie [arm_now](https://github.com/nongiach/arm_now).

## **Kody Shell**
### Techniki debugowania
- Narzędzia **Blobrunner** i **jmp2it** służą do alokowania kodów shell w pamięci i debugowania ich za pomocą Ida lub x64dbg.
- Blobrunner [wersje](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [skompilowana wersja](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** oferuje emulację i inspekcję kodów shell w oparciu o interfejs graficzny, podkreślając różnice w obsłudze kodów shell jako pliku w porównaniu do bezpośredniego kodu shell.

### Deobfuskacja i analiza
- **scdbg** dostarcza informacji o funkcjach kodów shell i możliwości deobfuskacji.
%%%bash
scdbg.exe -f shellcode # Podstawowe informacje
scdbg.exe -f shellcode -r # Raport analizy
scdbg.exe -f shellcode -i -r # Interaktywne hooki
scdbg.exe -f shellcode -d # Zrzut zdekodowanego kodu shell
scdbg.exe -f shellcode /findsc # Znajdź przesunięcie początkowe
scdbg.exe -f shellcode /foff 0x0000004D # Wykonaj od przesunięcia
%%%

- **CyberChef** do rozkładania kodów shell: [Przepis CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Obfuskator, który zamienia wszystkie instrukcje na `mov`.
- Przydatne zasoby obejmują [wyjaśnienie na YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) i [slajdy PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015
## **Delphi**
- Dla plików binarnych Delphi zaleca się użycie [IDR](https://github.com/crypto2011/IDR).


# Kursy

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Deobfuskacja binarna\)



<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
