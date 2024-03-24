# Narzędzia do Odwracania i Podstawowe Metody

<details>

<summary><strong>Zacznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Narzędzia do Odwracania oparte na ImGui

Oprogramowanie:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Dekompilator Wasm / Kompilator Wat

Online:

* Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) do **dekompilacji** z wasm (binarny) do wat (czysty tekst)
* Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) do **kompilacji** z wat do wasm
* Możesz także spróbować użyć [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) do dekompilacji

Oprogramowanie:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych systemu Windows** (.winmd) i **pliki wykonywalne** (.exe). Po dekompilacji, zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony kod źródłowy wymaga przywrócenia z archiwalnego zestawu, ta czynność może zaoszczędzić czas. Ponadto dotPeek zapewnia wygodną nawigację po zdekompilowanym kodzie, co czyni go jednym z doskonałych narzędzi do analizy algorytmów Xamarin.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Z kompleksowym modelem dodatków i interfejsem API rozszerzającym narzędzie, aby dostosować je do swoich dokładnych potrzeb, .NET Reflector oszczędza czas i upraszcza rozwój. Przejrzyjmy mnogość usług inżynierii wstecznej, które oferuje to narzędzie:

* Zapewnia wgląd w sposób przepływu danych przez bibliotekę lub komponent
* Zapewnia wgląd w implementację i użycie języków i frameworków .NET
* Znajduje funkcjonalności nieudokumentowane i nieujawnione, aby uzyskać więcej z używanych interfejsów API i technologii.
* Znajduje zależności i różne zestawy
* Namierza dokładne miejsce błędów w kodzie, komponentach innych firm i bibliotekach.
* Debuguje źródło całego kodu .NET, z którym pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy dla Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz go mieć w dowolnym systemie operacyjnym (możesz zainstalować go bezpośrednio z VSCode, nie trzeba pobierać z git. Kliknij **Extensions** i **szukaj ILSpy**).\
Jeśli musisz **dekompilować**, **modyfikować** i **ponownie kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem -> Zmodyfikuj metodę** aby zmienić coś wewnątrz funkcji).

### Logowanie DNSpy

Aby sprawić, że **DNSpy zaloguje pewne informacje do pliku**, możesz użyć tego fragmentu:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugowanie w DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Po pierwsze, zmień **Atrybuty zestawu** związane z **debugowaniem**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Do:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
I kliknij **skompiluj**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Następnie zapisz nowy plik za pomocą _**Plik >> Zapisz moduł...**_:

![](<../../.gitbook/assets/image (279).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **uruchamiania** kodu zostanie zastosowanych kilka **optymalizacji** i może się zdarzyć, że podczas debugowania **punkt przerwania nie zostanie osiągnięty** lub niektóre **zmienne nie będą istnieć**.

Następnie, jeśli twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **ponownie uruchomić** za pomocą:
```
iisreset /noforce
```
Następnie, aby rozpocząć debugowanie, należy zamknąć wszystkie otwarte pliki i w zakładce **Debug** wybrać opcję **Attach to Process...**:

![](<../../.gitbook/assets/image (280).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do serwera **IIS** i kliknij **attach**:

![](<../../.gitbook/assets/image (281).png>)

Teraz, gdy debugujemy proces, nadszedł czas, aby go zatrzymać i załadować wszystkie moduły. Najpierw kliknij _Debug >> Break All_, a następnie kliknij _**Debug >> Windows >> Modules**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![](<../../.gitbook/assets/image (284).png>)

Kliknij prawym przyciskiem myszy na dowolny moduł w **Assembly Explorer** i wybierz **Sort Assemblies**:

![](<../../.gitbook/assets/image (285).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie plików DLL

### Korzystanie z IDA

* **Załaduj rundll32** (64 bity w C:\Windows\System32\rundll32.exe i 32 bity w C:\Windows\SysWOW64\rundll32.exe)
* Wybierz debugger **Windbg**
* Wybierz "**Suspend on library load/unload**"

![](<../../.gitbook/assets/image (135).png>)

* Skonfiguruj **parametry** wykonania, podając **ścieżkę do pliku DLL** i funkcję, którą chcesz wywołać:

![](<../../.gitbook/assets/image (136).png>)

Następnie, gdy rozpoczniesz debugowanie, **wykonanie zostanie zatrzymane po załadowaniu każdego DLL**, a gdy rundll32 załaduje twoje DLL, wykonanie zostanie zatrzymane.

Ale jak uzyskać dostęp do kodu załadowanego DLL? Korzystając z tej metody, nie wiem jak.

### Korzystanie z x64dbg/x32dbg

* **Załaduj rundll32** (64 bity w C:\Windows\System32\rundll32.exe i 32 bity w C:\Windows\SysWOW64\rundll32.exe)
* **Zmień linię poleceń** ( _File --> Change Command Line_ ) i ustaw ścieżkę do pliku DLL i funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
* Następnie **rozpocznij wykonanie**, debugger zatrzyma się przy każdym głównym punkcie DLL, w pewnym momencie zatrzymasz się w **wejściu DLL twojego DLL**. Następnie wyszukaj punkty, w których chcesz ustawić punkt przerwania.

Zauważ, że gdy wykonanie zostanie zatrzymane z jakiegokolwiek powodu w win64dbg, możesz zobaczyć **w jakim kodzie się znajdujesz** patrząc na **górę okna win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Następnie, patrząc na to, możesz zobaczyć, kiedy wykonanie zostało zatrzymane w interesującym ci DLL.

## Aplikacje GUI / Gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania ważnych wartości zapisanych w pamięci działającej gry i ich zmiany. Więcej informacji znajdziesz tutaj:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellkody

### Debugowanie shellkodu za pomocą blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **przydzieli** **shellkod** w przestrzeni pamięci, wskaże **adres pamięci**, w którym shellkod został przydzielony, a następnie **zatrzyma** wykonanie.\
Następnie musisz **dołączyć debugger** (Ida lub x64dbg) do procesu, ustawić **punkt przerwania na wskazanym adresie pamięci** i **wznowić** wykonanie. W ten sposób będziesz debugować shellkod.

Na stronie wydań na GitHubie znajdziesz skompilowane wersje: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Możesz znaleźć nieco zmodyfikowaną wersję Blobrunner pod następującym linkiem. Aby ją skompilować, wystarczy **utworzyć projekt C/C++ w Visual Studio Code, skopiować i wkleić kod oraz go skompilować**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debugowanie shellkodu za pomocą jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)jest bardzo podobny do blobrunner. **Przydzieli** **shellkod** w przestrzeni pamięci i rozpocznie **wieczną pętlę**. Następnie musisz **dołączyć debugger** do procesu, **rozpocząć działanie, poczekać 2-5 sekund i nacisnąć stop**, aby znaleźć się w **wiecznej pętli**. Przejdź do następnej instrukcji wiecznej pętli, która będzie wywołaniem do shellkodu, a ostatecznie będziesz wykonywać shellkod.

![](<../../.gitbook/assets/image (397).png>)

Możesz pobrać skompilowaną wersję [jmp2it ze strony wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellkodu za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Za pomocą Cuttera możesz emulować shellkod i dynamicznie go analizować.

Zauważ, że Cutter pozwala na "Otwarcie pliku" i "Otwarcie shellkodu". W moim przypadku, gdy otworzyłem shellkod jako plik, został poprawnie zdekompilowany, ale gdy otworzyłem go jako shellkod, nie:

![](<../../.gitbook/assets/image (400).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam punkt przerwania, a Cutter automatycznie rozpocznie emulację od tego miejsca:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Możesz zobaczyć stos na przykład w postaci zrzutu szesnastkowego:

![](<../../.gitbook/assets/image (402).png>)

### Rozszyfrowywanie shellkodu i uzyskiwanie funkcji wykonywanych

Spróbuj użyć [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Pokaże ci, które funkcje używa shellkod i czy shellkod **dekoduje** się w pamięci.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg posiada również graficzny uruchamiacz, w którym możesz wybrać opcje, których chcesz użyć i wykonać shellcode

![](<../../.gitbook/assets/image (398).png>)

Opcja **Create Dump** spowoduje zrzucenie ostatecznego shellcode, jeśli jakakolwiek zmiana zostanie dokonana dynamicznie w pamięci shellcode (przydatne do pobrania zdekodowanego shellcode). **Start offset** może być przydatny do uruchomienia shellcode w określonym przesunięciu. Opcja **Debug Shell** jest przydatna do debugowania shellcode za pomocą terminala scDbg (jednak uważam, że któreś z wcześniej wyjaśnionych opcji są lepsze w tej kwestii, ponieważ będziesz mógł użyć Ida lub x64dbg).

### Rozkładanie na części za pomocą CyberChef

Prześlij plik ze swoim shellcodem jako dane wejściowe i użyj następującego przepisu, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuskator **modyfikuje wszystkie instrukcje dla `mov`** (tak, naprawdę fajne). Wykorzystuje również przerwania do zmiany przepływów wykonania. Aby uzyskać więcej informacji na temat jego działania:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Jeśli masz szczęście, [demovfuscator](https://github.com/kirschju/demovfuscator) zdeobfuskuje binarny plik. Ma kilka zależności.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli bierzesz udział w **CTF, ta metoda znajdowania flagi** może być bardzo przydatna: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje za pomocą `::main` jak w:

![](<../../.gitbook/assets/image (612).png>)

W tym przypadku plik binarny nazywał się authenticator, więc jest dość oczywiste, że to jest interesująca funkcja główna.\
Mając **nazwę** **funkcji**, które są wywoływane, wyszukaj je w **Internecie**, aby dowiedzieć się o ich **wejściach** i **wyjściach**.

## **Delphi**

Dla skompilowanych plików binarnych Delphi można użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz odwrócić binarny plik Delphi, sugeruję użycie wtyczki IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Wystarczy nacisnąć **ATL+f7** (importuj wtyczkę python w IDA) i wybrać wtyczkę python.

Ta wtyczka będzie wykonywać binarny plik i dynamicznie rozwiązywać nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a przerwa zostanie przerwana na początku rzeczywistego kodu.

Jest to również bardzo interesujące, ponieważ jeśli naciśniesz przycisk w aplikacji graficznej, debugger zatrzyma się w funkcji wykonywanej przez ten przycisk.

## Golang

Jeśli musisz odwrócić binarny plik Golang, sugeruję użycie wtyczki IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Wystarczy nacisnąć **ATL+f7** (importuj wtyczkę python w IDA) i wybrać wtyczkę python.

To rozwiąże nazwy funkcji.

## Skompilowany Python

Na tej stronie znajdziesz, jak uzyskać kod pythona z binarnego pliku skompilowanego w formacie ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Jeśli masz **binarny** plik gry GBA, możesz użyć różnych narzędzi do **emulacji** i **debugowania**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debugowania_) - Zawiera debugger z interfejsem
* [**mgba** ](https://mgba.io)- Zawiera debugger CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Wtyczka Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Wtyczka Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Opcje --> Konfiguracja Emulacji --> Kontrole**_\*\* \*\* możesz zobaczyć, jak nacisnąć przyciski Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Naciśnięcie każdego przycisku ma wartość, aby go zidentyfikować:
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
Więc w tego rodzaju programie interesującą częścią będzie **sposób, w jaki program traktuje dane wejściowe użytkownika**. W adresie **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Na poprzednim obrazku możesz zobaczyć, że funkcja jest wywoływana z **FUN\_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po pewnych operacjach inicjalizacyjnych (bez znaczenia):
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
Znaleziono ten kod:
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
Ostatnie if sprawdza, czy **`uVar4`** znajduje się w **ostatnich kluczach** i nie jest to bieżący klucz, zwany również puśczeniem przycisku (bieżący klucz jest przechowywany w **`uVar1`**).
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
W poprzednim kodzie można zobaczyć, że porównujemy **uVar1** (miejsce, gdzie znajduje się **wartość naciśniętego przycisku**) z pewnymi wartościami:

* Po pierwsze, porównujemy go z **wartością 4** (przycisk **SELECT**): W tym wyzwaniu ten przycisk czyści ekran.
* Następnie porównujemy go z **wartością 8** (przycisk **START**): W tym wyzwaniu sprawdzane jest, czy kod jest poprawny, aby uzyskać flagę.
* W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli wartość jest taka sama, wykonywany jest pewien kod.
* W pozostałych przypadkach sprawdzane jest **cont** (`DAT_030000d4`). Jest to **cont**, ponieważ dodaje 1 zaraz po wpisaniu kodu.\
Jeśli jest mniejszy niż 8, wykonywane są działania polegające na **dodawaniu** wartości do **`DAT_030000d8`** (w zasadzie dodawane są wartości naciśniętych klawiszy do tej zmiennej, dopóki cont jest mniejszy niż 8).

W tym wyzwaniu, znając wartości przycisków, musisz **nacisnąć kombinację o długości mniejszej niż 8, tak aby wynikowe dodawanie było równe 0xf3.**
