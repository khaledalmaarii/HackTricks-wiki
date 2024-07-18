# DDexec / EverythingExec

{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik, musi być dostępny w jakiś sposób poprzez hierarchię systemu plików (tak działa `execve()`). Ten plik może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz ścieżki do niego. To sprawia, że bardzo łatwo kontrolować, co jest uruchamiane w systemie Linux, ułatwia wykrywanie zagrożeń i narzędzi atakujących lub zapobieganie próbom uruchomienia czegokolwiek przez nich (_np._ nie zezwalając nieuprzywilejowanym użytkownikom na umieszczanie plików wykonywalnych w dowolnym miejscu).

Ale ta technika ma na celu zmianę tego wszystkiego. Jeśli nie możesz uruchomić procesu, którego chcesz... **to przejmujesz już istniejący**.

Ta technika pozwala ci **obejść powszechne techniki ochronne, takie jak tylko do odczytu, noexec, białe listy nazw plików, białe listy hashy...**

## Zależności

Ostateczny skrypt zależy od następujących narzędzi, aby działał, muszą być one dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Technika

Jeśli jesteś w stanie dowolnie modyfikować pamięć procesu, możesz go przejąć. Można to wykorzystać do przejęcia już istniejącego procesu i zastąpienia go innym programem. Możemy osiągnąć to albo używając wywołania systemowego `ptrace()` (co wymaga możliwości wykonywania wywołań systemowych lub dostępności gdb w systemie) albo, co ciekawsze, zapisując do `/proc/$pid/mem`.

Plik `/proc/$pid/mem` jest jedno do jednego odwzorowaniem całej przestrzeni adresowej procesu (np. od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczytanie lub zapisanie do tego pliku na przesunięciu `x` jest takie samo jak odczytanie lub modyfikowanie zawartości pod adresem wirtualnym `x`.

Teraz mamy cztery podstawowe problemy do rozwiązania:

* Ogólnie rzecz biorąc, tylko root i właściciel pliku mogą go modyfikować.
* ASLR.
* Jeśli spróbujemy odczytać lub zapisać do adresu spoza zmapowanej przestrzeni adresowej programu, otrzymamy błąd wejścia/wyjścia.

Te problemy mają rozwiązania, które, mimo że nie są idealne, są dobre:

* Większość interpreterów powłoki pozwala na utworzenie deskryptorów plików, które zostaną dziedziczone przez procesy potomne. Możemy utworzyć deskryptor wskazujący na plik `mem` powłoki z uprawnieniami do zapisu... więc procesy potomne korzystające z tego deskryptora będą mogły modyfikować pamięć powłoki.
* ASLR nie stanowi nawet problemu, możemy sprawdzić plik `maps` powłoki lub inny z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
* Musimy więc wykonać `lseek()` na pliku. Z poziomu powłoki nie można tego zrobić chyba że używając niesławnej komendy `dd`.

### Szczegółowe omówienie

Kroki są stosunkowo proste i nie wymagają żadnego rodzaju specjalistycznej wiedzy, aby je zrozumieć:

* Analizujemy binarnik, który chcemy uruchomić oraz loader, aby dowiedzieć się, jakie odwzorowania potrzebują. Następnie tworzymy "shell"code, który będzie wykonywał, ogólnie mówiąc, te same kroki, które jądro wykonuje przy każdym wywołaniu `execve()`:
* Tworzymy wspomniane odwzorowania.
* Wczytujemy do nich binaria.
* Ustawiamy uprawnienia.
* Na koniec inicjalizujemy stos argumentami dla programu i umieszczamy wektor pomocniczy (potrzebny przez loader).
* Skaczemy do loadera i pozwalamy mu zrobić resztę (załaduje biblioteki potrzebne przez program).
* Pobieramy z pliku `syscall` adres, do którego proces powróci po wywołaniu systemowym, który wykonuje.
* Nadpisujemy to miejsce, które będzie wykonywalne, naszym shellcodem (poprzez `mem` możemy modyfikować strony, które nie są zapisywalne).
* Przekazujemy program, który chcemy uruchomić do stdin procesu (będzie odczytany przez wspomniany "shell"code).
* W tym momencie loader ma za zadanie załadować niezbędne biblioteki dla naszego programu i przejść do niego.

**Sprawdź narzędzie na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Istnieje kilka alternatyw do `dd`, jedną z nich jest `tail`, obecnie domyślny program używany do `lseek()` przez plik `mem` (który był jedynym celem użycia `dd`). Wspomniane alternatywy to:
```bash
tail
hexdump
cmp
xxd
```
Ustawiając zmienną `SEEKER` możesz zmienić użytego poszukiwacza, _np._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Jeśli znajdziesz innego ważnego poszukiwacza, który nie został zaimplementowany w skrypcie, nadal możesz go użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokuj to, EDR-y.

## Odnośniki
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
Naucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępnij sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
