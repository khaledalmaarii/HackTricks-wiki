# Nadużywanie procesów w macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje o procesach

Proces to instancja działającego pliku wykonywalnego, jednak procesy nie wykonują kodu, to wątki to wykonują. Dlatego **procesy są tylko kontenerami dla działających wątków**, zapewniając pamięć, deskryptory, porty, uprawnienia...

Tradycyjnie procesy były uruchamiane w innych procesach (z wyjątkiem PID 1) poprzez wywołanie **`fork`**, które tworzyłoby dokładną kopię bieżącego procesu, a następnie **proces potomny** zazwyczaj wywoływałby **`execve`**, aby załadować nowy plik wykonywalny i uruchomić go. Następnie wprowadzono **`vfork`**, aby ten proces był szybszy bez kopiowania pamięci.\
Następnie wprowadzono **`posix_spawn`**, łącząc **`vfork`** i **`execve`** w jedno wywołanie i akceptując flagi:

* `POSIX_SPAWN_RESETIDS`: Zresetuj identyfikatory efektywne na rzeczywiste identyfikatory
* `POSIX_SPAWN_SETPGROUP`: Ustaw przynależność do grupy procesów
* `POSUX_SPAWN_SETSIGDEF`: Ustaw domyślne zachowanie sygnału
* `POSIX_SPAWN_SETSIGMASK`: Ustaw maskę sygnału
* `POSIX_SPAWN_SETEXEC`: Wykonaj w tym samym procesie (jak `execve` z większą liczbą opcji)
* `POSIX_SPAWN_START_SUSPENDED`: Rozpocznij wstrzymane
* `_POSIX_SPAWN_DISABLE_ASLR`: Rozpocznij bez ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Użyj Nano alokatora libmalloc
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Zezwalaj na `rwx` na segmentach danych
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Domyślnie zamknij wszystkie opisy plików podczas exec(2)
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Losowo zmieniaj wysokie bity przesunięcia ASLR

Ponadto `posix_spawn` pozwala określić tablicę **`posix_spawnattr`**, która kontroluje niektóre aspekty uruchamianego procesu, oraz **`posix_spawn_file_actions`** do modyfikowania stanu deskryptorów.

Gdy proces umiera, wysyła **kod powrotu do procesu nadrzędnego** (jeśli proces nadrzędny umarł, nowym rodzicem jest PID 1) sygnałem `SIGCHLD`. Proces nadrzędny musi pobrać tę wartość, wywołując `wait4()` lub `waitid()`, aż to się stanie, dziecko pozostaje w stanie zombie, gdzie jest nadal wymienione, ale nie zużywa zasobów.

### PID-y

PID-y, identyfikatory procesów, identyfikują unikalny proces. W XNU **PID-y** są **64-bitowe**, zwiększają się monotonicznie i **nigdy nie zawijają** (aby uniknąć nadużyć).

### Grupy procesów, sesje i koalicje

**Procesy** mogą być umieszczone w **grupach**, aby ułatwić ich obsługę. Na przykład polecenia w skrypcie powłoki będą w tej samej grupie procesów, dzięki czemu jest możliwe **sygnalizowanie ich razem** za pomocą na przykład kill.\
Możliwe jest również **grupowanie procesów w sesje**. Gdy proces rozpoczyna sesję (`setsid(2)`), procesy potomne są umieszczone w sesji, chyba że rozpoczną własną sesję.

Koalicja to inny sposób grupowania procesów w Darwin. Proces dołączający do koalicji pozwala mu uzyskać dostęp do zasobów puli, dzieląc księgę rachunkową lub stawiając czoła Jetsamowi. Koalicje mają różne role: Lider, Usługa XPC, Rozszerzenie.

### Poświadczenia i persony

Każdy proces posiada **poświadczenia**, które **identyfikują jego uprawnienia** w systemie. Każdy proces będzie miał jedno podstawowe `uid` i jedno podstawowe `gid` (choć może należeć do kilku grup).\
Możliwa jest również zmiana identyfikatora użytkownika i grupy, jeśli plik binarny ma ustawiony bit `setuid/setgid`.\
Istnieje kilka funkcji do **ustawiania nowych uid/gid**.

Wywołanie systemowe **`persona`** zapewnia **alternatywne** zestaw **poświadczeń**. Przyjęcie persony zakłada jej uid, gid i przynależności do grup **jednocześnie**. W [**kodzie źródłowym**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) można znaleźć strukturę:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Podstawowe informacje o wątkach

1. **Wątki POSIX (pthreads):** macOS obsługuje wątki POSIX (`pthreads`), które są częścią standardowego interfejsu wątków dla języków C/C++. Implementacja pthreads w macOS znajduje się w `/usr/lib/system/libsystem_pthread.dylib` i pochodzi z publicznie dostępnego projektu `libpthread`. Ta biblioteka dostarcza niezbędne funkcje do tworzenia i zarządzania wątkami.
2. **Tworzenie wątków:** Funkcja `pthread_create()` służy do tworzenia nowych wątków. Wewnętrznie ta funkcja wywołuje `bsdthread_create()`, które jest wywołaniem systemowym na niższym poziomie specyficznym dla jądra XNU (jądro, na którym opiera się macOS). To wywołanie systemowe przyjmuje różne flagi pochodzące z `pthread_attr` (atrybuty), które określają zachowanie wątku, w tym polityki harmonogramowania i rozmiar stosu.
* **Domyślny rozmiar stosu:** Domyślny rozmiar stosu dla nowych wątków to 512 KB, co jest wystarczające dla typowych operacji, ale może być dostosowane za pomocą atrybutów wątku, jeśli potrzebna jest większa lub mniejsza przestrzeń.
3. **Inicjalizacja wątku:** Funkcja `__pthread_init()` jest kluczowa podczas konfiguracji wątku, wykorzystując argument `env[]` do analizy zmiennych środowiskowych, które mogą zawierać szczegóły dotyczące lokalizacji i rozmiaru stosu.

#### Zakończenie wątku w macOS

1. **Zamykanie wątków:** Wątki są zazwyczaj zamykane poprzez wywołanie `pthread_exit()`. Ta funkcja pozwala wątkowi zakończyć się w sposób czysty, wykonując niezbędne czynności porządkujące i umożliwiając wątkowi przesłanie wartości zwrotnej do ewentualnych wątków dołączających.
2. **Porządkowanie wątku:** Po wywołaniu `pthread_exit()`, wywoływana jest funkcja `pthread_terminate()`, która zajmuje się usuwaniem wszystkich powiązanych struktur wątku. Dezalokuje porty wątków Mach (Mach to podsystem komunikacyjny w jądrze XNU) i wywołuje `bsdthread_terminate`, wywołanie systemowe, które usuwa struktury na poziomie jądra związane z wątkiem.

#### Mechanizmy synchronizacji

Aby zarządzać dostępem do współdzielonych zasobów i unikać wyścigów, macOS dostarcza kilka podstawowych mechanizmów synchronizacji. Są one kluczowe w środowiskach wielowątkowych, aby zapewnić integralność danych i stabilność systemu:

1. **Muteksy:**
* **Zwykły muteks (Sygnatura: 0x4D555458):** Standardowy muteks o rozmiarze pamięci 60 bajtów (56 bajtów dla muteksu i 4 bajty dla sygnatury).
* **Szybki muteks (Sygnatura: 0x4d55545A):** Podobny do zwykłego muteksu, ale zoptymalizowany pod kątem szybszych operacji, również o rozmiarze 60 bajtów.
2. **Zmienne warunkowe:**
* Używane do oczekiwania na wystąpienie określonych warunków, o rozmiarze 44 bajty (40 bajtów plus 4-bajtowa sygnatura).
* **Atrybuty zmiennej warunkowej (Sygnatura: 0x434e4441):** Atrybuty konfiguracyjne dla zmiennych warunkowych, o rozmiarze 12 bajtów.
3. **Zmienna jednorazowa (Sygnatura: 0x4f4e4345):**
* Zapewnia, że fragment kodu inicjalizacji jest wykonywany tylko raz. Jej rozmiar to 12 bajtów.
4. **Blokady odczytu-zapisu:**
* Pozwalają na wielu czytelników lub jednego pisarza naraz, ułatwiając efektywny dostęp do danych współdzielonych.
* **Blokada odczytu-zapisu (Sygnatura: 0x52574c4b):** O rozmiarze 196 bajtów.
* **Atrybuty blokady odczytu-zapisu (Sygnatura: 0x52574c41):** Atrybuty dla blokad odczytu-zapisu, o rozmiarze 20 bajtów.

{% hint style="success" %}
Ostatnie 4 bajty tych obiektów są używane do wykrywania przepełnień.
{% endhint %}

### Zmienne lokalne wątku (TLV)

**Zmienne lokalne wątku (TLV)** w kontekście plików Mach-O (format plików wykonywalnych w macOS) służą do deklarowania zmiennych specyficznych dla **każdego wątku** w aplikacji wielowątkowej. Zapewnia to, że każdy wątek ma własną osobną instancję zmiennej, umożliwiając uniknięcie konfliktów i utrzymanie integralności danych bez konieczności użycia jawnie mechanizmów synchronizacji, takich jak muteksy.

W języku C i pokrewnych można zadeklarować zmienną lokalną wątku za pomocą słowa kluczowego **`__thread`**. Oto jak to działa w twoim przykładzie:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
To fragment `tlv_var` jako zmienną lokalną wątku. Każdy wątek uruchamiający ten kod będzie miał swoje własne `tlv_var`, a zmiany dokonywane przez jeden wątek w `tlv_var` nie wpłyną na `tlv_var` w innym wątku.

W pliku Mach-O dane związane z zmiennymi lokalnymi wątku są zorganizowane w określonych sekcjach:

* **`__DATA.__thread_vars`**: Ta sekcja zawiera metadane dotyczące zmiennych lokalnych wątku, takie jak ich typy i status inicjalizacji.
* **`__DATA.__thread_bss`**: Ta sekcja służy do zmiennych lokalnych wątku, które nie są jawnie zainicjowane. Jest to część pamięci przeznaczona na dane zainicjowane zerami.

Mach-O udostępnia również specyficzne API o nazwie **`tlv_atexit`** do zarządzania zmiennymi lokalnymi wątku podczas zakończenia wątku. To API pozwala **rejestrować destruktory** - specjalne funkcje, które czyścić dane lokalne wątku po zakończeniu wątku.

### Priorytety wątków

Zrozumienie priorytetów wątków polega na analizie sposobu, w jaki system operacyjny decyduje, które wątki mają być uruchamiane i kiedy. Ta decyzja jest wpływana przez poziom priorytetu przypisanego każdemu wątkowi. W systemach macOS i podobnych systemach Unixowych jest to obsługiwane za pomocą koncepcji takich jak `nice`, `renice` i klasy Quality of Service (QoS).

#### Nice i Renice

1. **Nice:**
* Wartość `nice` procesu to liczba, która wpływa na jego priorytet. Każdy proces ma wartość `nice` w zakresie od -20 (najwyższy priorytet) do 19 (najniższy priorytet). Domyślna wartość `nice` przy tworzeniu procesu to zazwyczaj 0.
* Niższa wartość `nice` (bliżej -20) sprawia, że proces jest bardziej "samolubny", co daje mu więcej czasu CPU w porównaniu do innych procesów z wyższymi wartościami `nice`.
2. **Renice:**
* `renice` to polecenie używane do zmiany wartości `nice` już działającego procesu. Może to być używane do dynamicznej regulacji priorytetów procesów, zwiększając lub zmniejszając ich alokację czasu CPU na podstawie nowych wartości `nice`.
* Na przykład, jeśli proces potrzebuje tymczasowo więcej zasobów CPU, można obniżyć jego wartość `nice` za pomocą `renice`.

#### Klasy Quality of Service (QoS)

Klasy QoS to bardziej nowoczesne podejście do obsługi priorytetów wątków, zwłaszcza w systemach takich jak macOS, które obsługują **Grand Central Dispatch (GCD)**. Klasy QoS pozwalają programistom **kategoryzować** pracę na różne poziomy w oparciu o ich znaczenie lub pilność. macOS automatycznie zarządza priorytetami wątków na podstawie tych klas QoS:

1. **Interaktywny użytkownika:**
* Ta klasa jest przeznaczona dla zadań, które obecnie współdziałają z użytkownikiem lub wymagają natychmiastowych wyników, aby zapewnić dobrą jakość interakcji z użytkownikiem. Te zadania otrzymują najwyższy priorytet, aby interfejs pozostał responsywny (np. animacje lub obsługa zdarzeń).
2. **Zainicjowany przez użytkownika:**
* Zadania, które użytkownik inicjuje i oczekuje natychmiastowych wyników, takie jak otwarcie dokumentu lub kliknięcie przycisku wymagające obliczeń. Są to zadania o wysokim priorytecie, ale poniżej interaktywnego użytkownika.
3. **Użyteczności:**
* Te zadania są długotrwałe i zazwyczaj wyświetlają wskaźnik postępu (np. pobieranie plików, importowanie danych). Mają one niższy priorytet niż zadania zainicjowane przez użytkownika i nie muszą kończyć się natychmiastowo.
4. **Tło:**
* Ta klasa jest przeznaczona dla zadań działających w tle i niewidocznych dla użytkownika. Mogą to być zadania takie jak indeksowanie, synchronizacja lub tworzenie kopii zapasowych. Mają one najniższy priorytet i minimalny wpływ na wydajność systemu.

Korzystając z klas QoS, programiści nie muszą zarządzać dokładnymi numerami priorytetów, ale skupiają się raczej na charakterze zadania, a system optymalizuje zasoby CPU odpowiednio.

Ponadto istnieją różne **polityki harmonogramowania wątków**, które pozwalają określić zestaw parametrów harmonogramowania, które planista będzie brał pod uwagę. Można to zrobić za pomocą `thread_policy_[set/get]`. Może to być przydatne w atakach na warunki wyścigowe.

## Nadużycia procesów w systemie MacOS

System MacOS, podobnie jak każdy inny system operacyjny, zapewnia różnorodne metody i mechanizmy do **interakcji, komunikacji i udostępniania danych** procesów. Choć te techniki są niezbędne dla efektywnego funkcjonowania systemu, mogą być również nadużywane przez sprawców zagrożeń do **wykonywania działań o charakterze złośliwym**.

### Wstrzykiwanie bibliotek

Wstrzykiwanie bibliotek to technika, w której atakujący **zmusza proces do załadowania złośliwej biblioteki**. Po wstrzyknięciu biblioteka działa w kontekście docelowego procesu, zapewniając atakującemu takie same uprawnienia i dostęp jak proces.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hakowanie funkcji

Hakowanie funkcji polega na **przechwytywaniu wywołań funkcji** lub komunikatów w kodzie oprogramowania. Poprzez hakowanie funkcji atakujący może **modyfikować zachowanie** procesu, obserwować wrażliwe dane lub nawet uzyskać kontrolę nad przepływem wykonania.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Komunikacja międzyprocesowa

Komunikacja międzyprocesowa (IPC) odnosi się do różnych metod, za pomocą których oddzielne procesy **udostępniają i wymieniają dane**. Chociaż IPC jest podstawą wielu legalnych aplikacji, może być również nadużywane do omijania izolacji procesów, ujawniania wrażliwych informacji lub wykonywania nieautoryzowanych działań.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji Electron

Aplikacje Electron uruchamiane z określonymi zmiennymi środowiskowymi mogą być podatne na wstrzykiwanie procesów:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie Chromium

Możliwe jest użycie flag `--load-extension` i `--use-fake-ui-for-media-stream` do przeprowadzenia **ataku typu man in the browser**, pozwalającego na kradzież naciśnięć klawiszy, ruchu, plików cookie, wstrzykiwanie skryptów na stronach...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Brudny NIB

Pliki NIB **definiują elementy interfejsu użytkownika (UI)** i ich interakcje w ramach aplikacji. Jednakże mogą **wykonywać dowolne polecenia** i **Gatekeeper nie blokuje** już uruchomionej aplikacji przed ponownym uruchomieniem, jeśli **plik NIB zostanie zmodyfikowany**. Dlatego mogą być używane do uruchamiania dowolnych programów:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji Java

Możliwe jest nadużycie pewnych możliwości Javy (takich jak zmienna środowiskowa **`_JAVA_OPTS`**) do wykonania przez aplikację Java **dowolnego kodu/polecenia**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji .Net

Możliwe jest wstrzykiwanie kodu do aplikacji .Net poprzez **nadużycie funkcjonalności debugowania .Net** (niechronionej przez zabezpieczenia macOS, takie jak utwardzanie czasu wykonania).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji Perl

Sprawdź różne opcje, aby sprawić, że skrypt Perl wykonuje dowolny kod w:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Wstrzykiwanie aplikacji Ruby

Możliwe jest również nadużycie zmiennych środowiskowych Ruby do wykonania dowolnych skryptów:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}
### Wstrzykiwanie Pythona

Jeśli zmienna środowiskowa **`PYTHONINSPECT`** jest ustawiona, proces pythona przejdzie do interaktywnej konsoli pythona po zakończeniu działania. Można również użyć **`PYTHONSTARTUP`** do wskazania skryptu pythona do wykonania na początku sesji interaktywnej.\
Należy jednak zauważyć, że skrypt **`PYTHONSTARTUP`** nie zostanie wykonany, gdy **`PYTHONINSPECT`** tworzy sesję interaktywną.

Inne zmienne środowiskowe, takie jak **`PYTHONPATH`** i **`PYTHONHOME`**, mogą również być przydatne do wykonania dowolnego kodu za pomocą polecenia pythona.

Należy pamiętać, że pliki wykonywalne skompilowane przy użyciu **`pyinstaller`** nie będą korzystać z tych zmiennych środowiskowych, nawet jeśli są uruchamiane przy użyciu osadzonego pythona.

{% hint style="danger" %}
Ogólnie rzecz biorąc, nie udało mi się znaleźć sposobu na zmuszenie pythona do wykonania dowolnego kodu poprzez nadużycie zmiennych środowiskowych.\
Jednak większość osób instaluje pythona za pomocą **Hombrew**, który zainstaluje pythona w **zapisywalnej lokalizacji** dla domyślnego użytkownika admina. Możesz go przejąć używając na przykład:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Nawet **root** uruchomi ten kod podczas uruchamiania pythona.
{% endhint %}

## Wykrywanie

### Tarcza

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) to otwarte oprogramowanie, które może **wykrywać i blokować działania wstrzykiwania procesów**:

* Korzystanie z **Zmiennych Środowiskowych**: Będzie monitorować obecność dowolnej z następujących zmiennych środowiskowych: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** i **`ELECTRON_RUN_AS_NODE`**
* Korzystanie z wywołań **`task_for_pid`**: Aby dowiedzieć się, kiedy jeden proces chce uzyskać **port zadania innego**, co pozwala na wstrzyknięcie kodu do procesu.
* **Parametry aplikacji Electron**: Ktoś może użyć argumentów wiersza poleceń **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`** aby uruchomić aplikację Electron w trybie debugowania, a tym samym wstrzyknąć do niej kod.
* Korzystanie z **symlinków** lub **hardlinków**: Zwykle najczęstszym nadużyciem jest **umieszczenie linku z uprawnieniami naszego użytkownika**, i **skierowanie go do lokalizacji o wyższych uprawnieniach**. Wykrycie jest bardzo proste zarówno dla hardlinków, jak i symlinków. Jeśli proces tworzący link ma **inne poziomy uprawnień** niż plik docelowy, tworzymy **alert**. Niestety w przypadku symlinków blokowanie nie jest możliwe, ponieważ nie mamy informacji o miejscu docelowym linku przed jego utworzeniem. Jest to ograniczenie frameworka EndpointSecuriy firmy Apple.

### Wywołania dokonywane przez inne procesy

W [**tym poście na blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) możesz dowiedzieć się, jak można użyć funkcji **`task_name_for_pid`** aby uzyskać informacje o innych **procesach wstrzykujących kod w proces** a następnie uzyskać informacje o tym innym procesie.

Zauważ, że aby wywołać tę funkcję, musisz być **tym samym uid** co proces uruchamiający proces lub **root** (i zwraca informacje o procesie, a nie sposób wstrzyknięcia kodu).

## Odnośniki

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF** sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFTów**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
