# Wstrzykiwanie wątków w macOS za pomocą portu zadania

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kod

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Porwanie wątku

Początkowo na porcie zadania wywoływana jest funkcja **`task_threads()`**, aby uzyskać listę wątków z zdalnego zadania. Wybierany jest wątek do porwania. To podejście różni się od konwencjonalnych metod wstrzykiwania kodu, ponieważ tworzenie nowego zdalnego wątku jest zabronione ze względu na nowe zabezpieczenia blokujące `thread_create_running()`.

Aby kontrolować wątek, wywoływane jest **`thread_suspend()`**, zatrzymując jego wykonanie.

Jedyne dozwolone operacje na zdalnym wątku dotyczą jego **zatrzymywania** i **uruchamiania**, **pobierania** i **modyfikowania** jego wartości rejestrów. Wywołania zdalnych funkcji są inicjowane poprzez ustawienie rejestrów `x0` do `x7` na **argumenty**, konfigurację **`pc`** na docelową funkcję i aktywację wątku. Zapewnienie, że wątek nie ulegnie awarii po zakończeniu, wymaga wykrycia zwracanej wartości.

Jedna strategia polega na **zarejestrowaniu obsługi wyjątków** dla zdalnego wątku za pomocą `thread_set_exception_ports()`, ustawieniu rejestru `lr` na nieprawidłowy adres przed wywołaniem funkcji. Powoduje to wywołanie wyjątku po wykonaniu funkcji, wysyłając wiadomość do portu wyjątku, umożliwiając inspekcję stanu wątku w celu odzyskania wartości zwracanej. Alternatywnie, jak w przypadku wykorzystania podwójnego ataku Ian Beer'a, `lr` jest ustawiane na nieskończoną pętlę. Następnie rejestry wątku są ciągle monitorowane, aż **`pc` wskazuje na tę instrukcję**.

## 2. Porty Mach do komunikacji

Kolejny etap polega na ustanowieniu portów Mach w celu ułatwienia komunikacji z zdalnym wątkiem. Te porty są niezbędne do przesyłania dowolnych praw do wysyłania i odbierania między zadaniami.

W celu dwukierunkowej komunikacji tworzone są dwa prawa odbierania Mach: jedno w zadaniu lokalnym, a drugie w zdalnym zadaniu. Następnie prawa wysyłania dla każdego portu są przekazywane do odpowiedniego zadania, umożliwiając wymianę wiadomości.

Skupiając się na porcie lokalnym, prawo odbierania jest przechowywane przez zadanie lokalne. Port jest tworzony za pomocą `mach_port_allocate()`. Wyzwaniem jest przekazanie prawa wysyłania do tego portu do zdalnego zadania.

Jedna strategia polega na wykorzystaniu `thread_set_special_port()` do umieszczenia prawa wysyłania do lokalnego portu w `THREAD_KERNEL_PORT` zdalnego wątku. Następnie zdalny wątek jest instruowany, aby wywołał `mach_thread_self()` w celu pobrania prawa wysyłania.

Dla zdalnego portu proces jest odwrócony. Zdalny wątek jest instruowany, aby wygenerował port Mach za pomocą `mach_reply_port()` (ponieważ `mach_port_allocate()` jest nieodpowiednie ze względu na swoje zachowanie zwracania). Po utworzeniu portu w zdalnym wątku wywoływane jest `mach_port_insert_right()`, aby ustanowić prawo wysyłania. To prawo jest następnie przechowywane w jądrze za pomocą `thread_set_special_port()`. W zadaniu lokalnym używane jest `thread_get_special_port()` na zdalnym wątku, aby uzyskać prawo wysyłania do nowo przydzielonego portu Mach w zdalnym zadaniu.

Ukończenie tych kroków prowadzi do ustanowienia portów Mach, tworząc podstawę do dwukierunkowej komunikacji.

## 3. Podstawowe podstawy odczytu/zapisu pamięci

W tej sekcji skupiamy się na wykorzystaniu podstawowych podstaw odczytu i zapisu pamięci za pomocą podstawowych funkcji wykonawczych. Te początkowe kroki są kluczowe dla uzyskania większej kontroli nad zdalnym procesem, chociaż podstawowe podstawy w tym etapie nie będą służyć wielu celom. Wkrótce zostaną ulepszone do bardziej zaawansowanych wersji.

### Odczyt i zapis pamięci za pomocą podstawowych funkcji wykonawczych

Celem jest wykonanie odczytu i zapisu pamięci za pomocą określonych funkcji. Do odczytu pamięci używane są funkcje o następującej strukturze:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
A do zapisywania do pamięci używane są funkcje podobne do tej struktury:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Te funkcje odpowiadają podanym instrukcjom asemblera:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identyfikowanie odpowiednich funkcji

Skanowanie popularnych bibliotek ujawniło odpowiednie kandydatki na te operacje:

1. **Odczytywanie pamięci:**
Funkcja `property_getName()` z biblioteki [Objective-C runtime library](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) została zidentyfikowana jako odpowiednia funkcja do odczytywania pamięci. Poniżej przedstawiono opis tej funkcji:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Ta funkcja działa efektywnie jak `read_func`, zwracając pierwsze pole `objc_property_t`.

2. **Zapisywanie pamięci:**
Znalezienie gotowej funkcji do zapisywania pamięci jest bardziej wymagające. Jednak funkcja `_xpc_int64_set_value()` z biblioteki libxpc jest odpowiednim kandydatem, oto jej rozkład:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Aby wykonać zapis 64-bitowy pod określonym adresem, zdalne wywołanie jest strukturalne w następujący sposób:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Za pomocą tych podstawowych narzędzi, jesteśmy gotowi do utworzenia pamięci współdzielonej, co stanowi znaczący postęp w kontroli zdalnego procesu.

## 4. Konfiguracja pamięci współdzielonej

Celem jest ustanowienie pamięci współdzielonej między lokalnymi i zdalnymi zadaniami, upraszczając transfer danych i ułatwiając wywoływanie funkcji z wieloma argumentami. Metoda polega na wykorzystaniu `libxpc` i jej obiektu typu `OS_xpc_shmem`, który jest oparty na wpisach pamięci Mach.

### Przegląd procesu:

1. **Alokacja pamięci**:
- Alokuj pamięć do współdzielenia za pomocą `mach_vm_allocate()`.
- Użyj `xpc_shmem_create()` do utworzenia obiektu `OS_xpc_shmem` dla zaalokowanego obszaru pamięci. Ta funkcja zarządza utworzeniem wpisu pamięci Mach i przechowuje prawo wysyłania Mach na przesunięciu `0x18` obiektu `OS_xpc_shmem`.

2. **Tworzenie pamięci współdzielonej w zdalnym procesie**:
- Alokuj pamięć dla obiektu `OS_xpc_shmem` w zdalnym procesie za pomocą zdalnego wywołania `malloc()`.
- Skopiuj zawartość lokalnego obiektu `OS_xpc_shmem` do zdalnego procesu. Jednak to początkowe skopiowanie będzie miało nieprawidłowe nazwy wpisów pamięci Mach na przesunięciu `0x18`.

3. **Poprawianie wpisu pamięci Mach**:
- Wykorzystaj metodę `thread_set_special_port()` do wstawienia prawidła wysyłania dla wpisu pamięci Mach do zdalnego zadania.
- Popraw pole wpisu pamięci Mach na przesunięciu `0x18`, nadpisując je nazwą wpisu pamięci zdalnej.

4. **Finalizowanie konfiguracji pamięci współdzielonej**:
- Zweryfikuj zdalny obiekt `OS_xpc_shmem`.
- Ustanów mapowanie pamięci współdzielonej za pomocą zdalnego wywołania `xpc_shmem_remote()`.

Postępując zgodnie z tymi krokami, pamięć współdzielona między lokalnymi i zdalnymi zadaniami zostanie skonfigurowana w sposób efektywny, umożliwiając prosty transfer danych i wykonywanie funkcji wymagających wielu argumentów.

## Dodatkowe fragmenty kodu

Alokacja pamięci i tworzenie obiektu pamięci współdzielonej:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Do tworzenia i poprawiania obiektu pamięci współdzielonej w zdalnym procesie:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Pamiętaj, aby poprawnie obsługiwać szczegóły portów Mach i nazwy wpisów pamięci, aby zapewnić prawidłowe działanie funkcji udostępniania pamięci.

## 5. Uzyskiwanie pełnej kontroli

Po pomyślnym ustanowieniu pamięci udostępnianej i uzyskaniu możliwości dowolnego wykonywania poleceń, zasadniczo uzyskujemy pełną kontrolę nad procesem docelowym. Kluczowe funkcje umożliwiające tę kontrolę to:

1. **Dowolne operacje na pamięci**:
- Wykonuj dowolne odczyty pamięci, wywołując funkcję `memcpy()` w celu skopiowania danych z obszaru udostępnionego.
- Wykonuj dowolne zapisy pamięci, używając funkcji `memcpy()` do przesyłania danych do obszaru udostępnionego.

2. **Obsługa wywołań funkcji z wieloma argumentami**:
- Dla funkcji wymagających więcej niż 8 argumentów, ułóż dodatkowe argumenty na stosie zgodnie z konwencją wywoływania.

3. **Transfer portów Mach**:
- Przenoś porty Mach między zadaniami za pomocą wiadomości Mach za pośrednictwem wcześniej ustanowionych portów.

4. **Transfer deskryptorów plików**:
- Przenoś deskryptory plików między procesami, używając fileportów, techniki podkreślonej przez Iana Beera w `triple_fetch`.

Ta kompleksowa kontrola jest zawarta w bibliotece [threadexec](https://github.com/bazad/threadexec), która zapewnia szczegółową implementację i przyjazne dla użytkownika API do interakcji z procesem ofiary.

## Ważne uwagi:

- Upewnij się, że funkcję `memcpy()` używasz poprawnie do operacji odczytu/zapisu pamięci, aby utrzymać stabilność systemu i integralność danych.
- Przy przenoszeniu portów Mach lub deskryptorów plików stosuj odpowiednie protokoły i odpowiedzialnie zarządzaj zasobami, aby zapobiec wyciekom lub niezamierzonemu dostępowi.

Przestrzegając tych wytycznych i korzystając z biblioteki `threadexec`, można skutecznie zarządzać i współdziałać z procesami na granularnym poziomie, uzyskując pełną kontrolę nad procesem docelowym.

## Odwołania
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
