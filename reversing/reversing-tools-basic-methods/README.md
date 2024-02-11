# Narzędzia do odwracania i podstawowe metody

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub**.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Narzędzia do odwracania oparte na ImGui

Oprogramowanie:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Dekompilator Wasm / Kompilator Wat

Online:

* Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **odkompilować** z formatu wasm (binarnego) do formatu wat (czysty tekst)
* Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **skompilować** z formatu wat do formatu wasm
* Możesz również spróbować użyć [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) do dekompilacji

Oprogramowanie:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Dekompilator .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i analizuje wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych systemu Windows** (.winmd) i **pliki wykonywalne** (.exe). Po dekompilacji, zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony kod źródłowy wymaga przywrócenia z archiwalnego zestawu, ta czynność może zaoszczędzić czas. Ponadto, dotPeek zapewnia wygodną nawigację po dekompilowanym kodzie, co czyni go jednym z doskonałych narzędzi do analizy algorytmów Xamarin.&#x20;

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Dzięki wszechstronnemu modelowi dodatków i interfejsowi API, który rozszerza narzędzie, aby dostosować je do Twoich dokładnych potrzeb, .NET reflector oszczędza czas i upraszcza rozwój. Przyjrzyjmy się mnogości usług inżynierii wstecz, które oferuje to narzędzie:

* Zapewnia wgląd w sposób przepływu danych przez bibliotekę lub komponent
* Zapewnia wgląd w implementację i użycie języków i frameworków .NET
* Znajduje funkcjonalności nieudokumentowane i nieujawnione, aby uzyskać więcej z wykorzystywanych interfejsów API i technologii.
* Znajduje zależności i różne zestawy
* Namierza dokładne położenie błędów w Twoim kodzie, komponentach i bibliotekach innych firm.&#x20;
* Debuguje kod źródłowy wszystkich kodów .NET, z którymi pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy dla Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz go mieć na dowolnym systemie operacyjnym (możesz zainstalować go bezpośrednio z VSCode, nie trzeba pobierać git. Kliknij **Extensions** i **search ILSpy**).\
Jeśli potrzebujesz **dekompilować**, **modyfikować** i **ponownie skompilować**, możesz użyć: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Right Click -> Modify Method** aby zmienić coś wewnątrz funkcji).\
Możesz również spróbować [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### Rejestrowanie DNSpy

Aby **DNSpy zarejestrował pewne informacje w pliku**, można użyć tych linii .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugowanie za pomocą DNSpy

Aby debugować kod za pomocą DNSpy, musisz:

Po pierwsze, zmień **atrybuty zestawu** związane z **debugowaniem**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Do: 

# Narzędzia do odwracania kodu - podstawowe metody

## Wstęp

W procesie odwracania kodu, czyli analizy i zrozumienia działania programu, istnieje wiele narzędzi, które mogą pomóc w tym zadaniu. Poniżej przedstawiamy kilka podstawowych metod i narzędzi, które warto znać.

## Metoda 1: Disassemblery

Disassembler to narzędzie, które przekształca kod maszynowy na kod zrozumiały dla człowieka. Pozwala to na analizę i zrozumienie działania programu na poziomie niższym niż kod źródłowy. Przykładowymi popularnymi disassemblerami są IDA Pro, Ghidra i radare2.

## Metoda 2: Debugger

Debugger to narzędzie, które umożliwia analizę działania programu w czasie rzeczywistym. Pozwala na zatrzymywanie programu w określonych punktach, obserwowanie wartości zmiennych i śledzenie wykonywanych instrukcji. Przykładami popularnych debuggerów są GDB, OllyDbg i x64dbg.

## Metoda 3: Decompiler

Decompiler to narzędzie, które przekształca kod skompilowany na kod źródłowy w języku wysokiego poziomu. Choć decompiler nie zawsze jest w stanie odtworzyć dokładny kod źródłowy, może dostarczyć przydatnych wskazówek dotyczących działania programu. Przykładami popularnych decompilerów są IDA Pro, Ghidra i RetDec.

## Metoda 4: Static Analysis Tools

Narzędzia do statycznej analizy kodu pozwalają na automatyczną analizę programu bez jego uruchamiania. Mogą one wykrywać podatności, nieprawidłowe wywołania funkcji i inne potencjalne problemy. Przykładami popularnych narzędzi do statycznej analizy kodu są SonarQube, FindBugs i PMD.

## Metoda 5: Dynamic Analysis Tools

Narzędzia do dynamicznej analizy kodu pozwalają na analizę programu w czasie jego działania. Mogą one monitorować wywołania funkcji, śledzić wartości zmiennych i wykrywać nieprawidłowe zachowanie. Przykładami popularnych narzędzi do dynamicznej analizy kodu są Wireshark, Fiddler i Burp Suite.

## Podsumowanie

Wyżej wymienione metody i narzędzia stanowią podstawę dla procesu odwracania kodu. Wybór odpowiednich narzędzi zależy od konkretnego przypadku i wymagań. Ważne jest również posiadanie umiejętności analizy i zrozumienia kodu maszynowego oraz kodu źródłowego.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
I kliknij **kompiluj**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Następnie zapisz nowy plik w _**Plik >> Zapisz moduł...**_:

![](<../../.gitbook/assets/image (279).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, podczas **uruchamiania** kodu zostanie zastosowanych wiele **optymalizacji**, co może spowodować, że podczas debugowania **punkt przerwania nie zostanie osiągnięty** lub niektóre **zmienne nie będą istnieć**.

Następnie, jeśli twoja aplikacja .Net jest **uruchamiana** przez **IIS**, możesz ją **ponownie uruchomić** za pomocą:
```
iisreset /noforce
```
Następnie, aby rozpocząć debugowanie, należy zamknąć wszystkie otwarte pliki i w zakładce **Debugowanie** wybrać **Dołącz do procesu...**:

![](<../../.gitbook/assets/image (280).png>)

Następnie wybierz **w3wp.exe**, aby dołączyć do serwera **IIS**, a następnie kliknij **dołącz**:

![](<../../.gitbook/assets/image (281).png>)

Teraz, gdy debugujemy proces, należy go zatrzymać i załadować wszystkie moduły. Najpierw kliknij _Debugowanie >> Zatrzymaj wszystko_, a następnie kliknij _**Debugowanie >> Okna >> Moduły**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Kliknij dowolny moduł na **Modułach** i wybierz **Otwórz wszystkie moduły**:

![](<../../.gitbook/assets/image (284).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Eksploratorze zestawów** i kliknij **Sortuj zestawy**:

![](<../../.gitbook/assets/image (285).png>)

## Dekompilator Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Za pomocą IDA

* **Załaduj rundll32** (64 bity w C:\Windows\System32\rundll32.exe i 32 bity w C:\Windows\SysWOW64\rundll32.exe)
* Wybierz debuger **Windbg**
* Wybierz "**Zawieś przy ładowaniu/odładowywaniu biblioteki**"

![](<../../.gitbook/assets/image (135).png>)

* Skonfiguruj **parametry** wykonania, podając **ścieżkę do DLL** i funkcję, którą chcesz wywołać:

![](<../../.gitbook/assets/image (136).png>)

Następnie, gdy rozpoczynasz debugowanie, **wykonanie zostanie zatrzymane po załadowaniu każdej DLL**, a gdy rundll32 załaduje twoją DLL, wykonanie zostanie zatrzymane.

Ale jak można uzyskać dostęp do kodu załadowanej DLL? Nie wiem, jak to zrobić za pomocą tej metody.

### Za pomocą x64dbg/x32dbg

* **Załaduj rundll32** (64 bity w C:\Windows\System32\rundll32.exe i 32 bity w C:\Windows\SysWOW64\rundll32.exe)
* **Zmień wiersz polecenia** ( _Plik --> Zmień wiersz polecenia_ ) i ustaw ścieżkę do DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Zmień _Opcje --> Ustawienia_ i wybierz "**Wejście DLL**".
* Następnie **uruchom wykonanie**, debugger zatrzyma się przy każdym głównym pliku DLL, w pewnym momencie zatrzymasz się w wejściu DLL twojej DLL. Stamtąd wyszukaj miejsca, w których chcesz ustawić punkt przerwania.

Zauważ, że gdy wykonanie zostanie zatrzymane z jakiegokolwiek powodu w win64dbg, możesz zobaczyć **w jakim kodzie się znajdujesz**, patrząc na **górę okna win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Następnie, patrząc na to, możesz zobaczyć, kiedy wykonanie zostało zatrzymane w żądanej DLL do debugowania.

## Aplikacje GUI / Gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania ważnych wartości zapisanych w pamięci działającej gry i ich zmiany. Więcej informacji znajduje się w:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM i MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellkody

### Debugowanie shellkodu za pomocą blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **zaalokuje** shellkod w przestrzeni pamięci, wskaże adres pamięci, w którym shellkod został zaalokowany, a następnie **zatrzyma** wykonanie.\
Następnie musisz **dołączyć debugger** (Ida lub x64dbg) do procesu i ustawić **punkt przerwania na wskazanym adresie pamięci**, a następnie **wznowić** wykonanie. W ten sposób będziesz debugować shellkod.

Na stronie wydań GitHub znajdują się paczki zawierające skompilowane wersje: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Możesz znaleźć nieco zmodyfikowaną wersję Blobrunner pod poniższym linkiem. Aby ją skompilować, wystarczy **utworzyć projekt C/C++ w Visual Studio Code, skopiować i wkleić kod oraz go zbudować**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Debugowanie shellkodu za pomocą jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)jest bardzo podobny do blobrunner. **Zaalokuje** shellkod w przestrzeni pamięci i uruchomi **wieczną pętlę**. Następnie musisz **dołączyć debugger** do procesu, **rozpocząć wykonanie, poczekać 2-5 sekund i nacisnąć stop**, a znajdziesz się w **wiecznej pętli**. Przejdź do następnej instrukcji wiecznej pętli, ponieważ będzie to wywołanie shellkodu, a na koniec będziesz wykonywać shellkod.

![](<../../.gitbook/assets/image (397).png>)

Możesz pobrać skompilowaną wersję [jmp2it na stronie wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellkodu za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to interfejs graficzny radare. Za pomocą Cuttera możesz emulować shellkod i dynamicznie go analizować.

Należy zauważyć, że Cutter pozwala na "Otwarcie pliku" i "Otwarcie shellkodu". W moim przypadku, gdy otworzyłem shellkod jako plik, został on poprawnie zdekompilowany, ale gdy otworzyłem go jako shellkod, nie został:

![](<../../.gitbook/assets/image (400).png>)

Aby rozpocząć emulację w wybranym miejscu, ustaw tam punkt przerwania, a Cutter automatycznie rozpocznie emulację od tego miejsca:

![](<../../.gitbook/assets/image (399).png>)

Możesz na przykład zobaczyć stos w postaci wydruku szesnastkowego:

![](<../../.gitbook/assets/image (402).png>)

### Deobfuskacja shellkodu i uzyskiwanie wykonywanych funkcji

Powinieneś spróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Powiedzą ci, jakie funkcje używa shellkod i czy shellkod dekoduje się w pamięci.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg posiada również graficzny launcher, w którym można wybrać opcje i uruchomić shellcode.

![](<../../.gitbook/assets/image (398).png>)

Opcja **Create Dump** spowoduje zrzut końcowego shellcode, jeśli w pamięci zostanie dokonana jakakolwiek zmiana w shellcode (przydatne do pobrania zdekodowanego shellcode). **Start offset** może być przydatny do uruchomienia shellcode na określonym przesunięciu. Opcja **Debug Shell** jest przydatna do debugowania shellcode za pomocą terminala scDbg (jednak uważam, że każda z wcześniej opisanych opcji jest lepsza w tej kwestii, ponieważ można użyć Ida lub x64dbg).

### Dezasemblowanie za pomocą CyberChef

Prześlij plik shellcode jako dane wejściowe i użyj następującego przepisu, aby go zdekompilować: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuskator **modyfikuje wszystkie instrukcje dla `mov`** (tak, naprawdę fajne). Wykorzystuje również przerwania do zmiany przepływów wykonania. Aby uzyskać więcej informacji na temat jego działania:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Jeśli masz szczęście, [demovfuscator](https://github.com/kirschju/demovfuscator) zdeobfuskuje plik binarny. Ma kilka zależności.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, ta metoda znajdowania flagi** może być bardzo przydatna: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Aby znaleźć **punkt wejścia**, wyszukaj funkcje za pomocą `::main`, jak w:

![](<../../.gitbook/assets/image (612).png>)

W tym przypadku plik binarny nazywał się authenticator, więc jest dość oczywiste, że to jest interesująca funkcja główna.\
Mając **nazwę** wywoływanych **funkcji**, wyszukaj je w **Internecie**, aby dowiedzieć się o ich **wejściach** i **wyjściach**.

## **Delphi**

Dla skompilowanych plików binarnych Delphi można użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz odwrócić binarny plik Delphi, polecam skorzystanie z wtyczki IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Wciśnij po prostu **ATL+f7** (zaimportuj wtyczkę python w IDA) i wybierz wtyczkę python.

Ta wtyczka uruchomi binarny plik i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania ponownie naciśnij przycisk Start (zielony lub f9), a przerwa zostanie zatrzymana na początku rzeczywistego kodu.

Jest to również bardzo interesujące, ponieważ jeśli naciśniesz przycisk w aplikacji graficznej, debugger zatrzyma się w funkcji wykonywanej przez ten przycisk.

## Golang

Jeśli musisz odwrócić binarny plik Golang, polecam skorzystanie z wtyczki IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Wciśnij po prostu **ATL+f7** (zaimportuj wtyczkę python w IDA) i wybierz wtyczkę python.

To rozwiąże nazwy funkcji.

## Skompilowany Python

Na tej stronie znajdziesz, jak uzyskać kod pythona z binarnego pliku ELF/EXE skompilowanego w Pythonie:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Jeśli masz **binarny** plik gry GBA, możesz użyć różnych narzędzi do **emulacji** i **debugowania**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debugowania_) - Zawiera debugger z interfejsem
* [**mgba** ](https://mgba.io)- Zawiera debugger CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Wtyczka Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Wtyczka Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_\*\* \*\* możesz zobaczyć, jak naciskać przyciski Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Po naciśnięciu każdy **klawisz ma wartość**, która go identyfikuje:
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
Więc, w tego rodzaju programach interesującą częścią będzie **sposób, w jaki program traktuje dane wprowadzone przez użytkownika**. W adresie **0x4000130** znajdziesz często spotykaną funkcję: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Na poprzednim obrazku możesz zobaczyć, że funkcja jest wywoływana z **FUN\_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po kilku operacjach inicjalizacyjnych (bez większego znaczenia):
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
Ostatnie if sprawdza, czy **`uVar4`** znajduje się w **ostatnich kluczach** i nie jest to bieżący klucz, nazywany również puśczeniem przycisku (bieżący klucz jest przechowywany w **`uVar1`**).
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

* Po pierwsze, porównujemy go z **wartością 4** (**przycisk SELECT**): W tym wyzwaniu ten przycisk czyści ekran.
* Następnie porównujemy go z **wartością 8** (**przycisk START**): W tym wyzwaniu sprawdzane jest, czy kod jest poprawny, aby uzyskać flagę.
* W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli wartość jest taka sama, wykonuje się pewien kod.
* W pozostałych przypadkach sprawdzane jest **`DAT_030000d4`**. Jest to zmienna, ponieważ po wprowadzeniu kodu dodawane jest 1.\
Jeśli jest mniejsza niż 8, wykonywane są pewne operacje związane z **dodawaniem** wartości do \*\*`DAT_030000d8` \*\* (w zasadzie dodawane są wartości naciśniętych klawiszy do tej zmiennej, dopóki zmienna `cont` jest mniejsza niż 8).

W tym wyzwaniu, znając wartości przycisków, musisz **nacisnąć kombinację o długości mniejszej niż 8, taką że suma dodawania wynosi 0xf3**.

**Odnośnik do tego samouczka:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kursy

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deobfuskacja binarna)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajduj podatności, które mają największe znaczenie, abyś mógł je szybko naprawić. Intruder śledzi twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
