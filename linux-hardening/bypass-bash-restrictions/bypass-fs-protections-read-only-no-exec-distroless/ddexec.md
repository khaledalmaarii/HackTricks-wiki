# DDexec / EverythingExec

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik i musi być dostępny w pewien sposób poprzez hierarchię systemu plików (tak działa `execve()`). Ten plik może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz ścieżki dostępu. To sprawia, że kontrolowanie tego, co jest uruchamiane w systemie Linux, jest bardzo łatwe, umożliwia wykrywanie zagrożeń i narzędzi atakujących lub zapobieganie próbom uruchomienia czegokolwiek przez nich (_np._ nie zezwalanie nieuprzywilejowanym użytkownikom na umieszczanie plików wykonywalnych w dowolnym miejscu).

Ale ta technika ma na celu zmienić to wszystko. Jeśli nie możesz uruchomić procesu, którego chcesz... **to przejmujesz już istniejący**.

Ta technika pozwala na **ominięcie powszechnych technik ochrony, takich jak tylko do odczytu, noexec, białe listy nazw plików, białe listy skrótów...**

## Zależności

Ostateczny skrypt zależy od następujących narzędzi, które muszą być dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):
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

Jeśli masz możliwość dowolnej modyfikacji pamięci procesu, możesz go przejąć. Można to wykorzystać do przejęcia istniejącego procesu i zastąpienia go innym programem. Możemy osiągnąć to za pomocą wywołania systemowego `ptrace()` (które wymaga możliwości wykonywania wywołań systemowych lub dostępności gdb na systemie) lub, co ciekawsze, zapisując do `/proc/$pid/mem`.

Plik `/proc/$pid/mem` jest jedno-do-jednego odwzorowaniem całej przestrzeni adresowej procesu (np. od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczytanie lub zapisanie do tego pliku na przesunięciu `x` jest takie samo jak odczytanie lub modyfikowanie zawartości pod adresem wirtualnym `x`.

Teraz mamy cztery podstawowe problemy do rozwiązania:

* Ogólnie rzecz biorąc, tylko root i właściciel pliku mogą go modyfikować.
* ASLR.
* Jeśli spróbujemy odczytać lub zapisać do adresu, który nie jest odwzorowany w przestrzeni adresowej programu, otrzymamy błąd wejścia/wyjścia.

Te problemy mają rozwiązania, które, mimo że nie są doskonałe, są dobre:

* Większość interpreterów powłoki pozwala na tworzenie deskryptorów plików, które zostaną dziedziczone przez procesy potomne. Możemy utworzyć deskryptor pliku wskazujący na plik `mem` powłoki z uprawnieniami do zapisu... więc procesy potomne korzystające z tego deskryptora będą mogły modyfikować pamięć powłoki.
* ASLR nie stanowi problemu, możemy sprawdzić plik `maps` powłoki lub inny z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
* Musimy więc użyć `lseek()` na pliku. Z poziomu powłoki nie można tego zrobić, chyba że użyjemy niesławnej komendy `dd`.

### Szczegóły

Kroki są stosunkowo proste i nie wymagają żadnej specjalistycznej wiedzy, aby je zrozumieć:

* Analizujemy binarnik, który chcemy uruchomić, oraz loader, aby dowiedzieć się, jakie odwzorowania są potrzebne. Następnie tworzymy "kod" powłoki, który będzie wykonywał, ogólnie mówiąc, te same kroki, które jądro wykonuje przy każdym wywołaniu `execve()`:
* Tworzymy te odwzorowania.
* Wczytujemy do nich binarki.
* Ustawiamy uprawnienia.
* Na koniec inicjalizujemy stos argumentami dla programu i umieszczamy wektor pomocniczy (potrzebny loaderowi).
* Skaczemy do loadera i pozwalamy mu zrobić resztę (załadować biblioteki potrzebne przez program).
* Pobieramy z pliku `syscall` adres, do którego proces powróci po wywołaniu systemowym, który wykonuje.
* Nadpisujemy to miejsce, które będzie wykonywalne, naszym "kodem" powłoki (za pomocą `mem` możemy modyfikować strony, które nie są zapisywalne).
* Przekazujemy program, który chcemy uruchomić, do stdin procesu (będzie odczytany przez wspomniany "kod" powłoki).
* W tym momencie to loader ma za zadanie załadować niezbędne biblioteki dla naszego programu i skoczyć do niego.

**Sprawdź narzędzie na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Istnieje kilka alternatyw dla `dd`, z których jedną, `tail`, jest obecnie domyślnym programem używanym do przesuwania pozycji za pomocą `lseek()` w pliku `mem` (co było jedynym celem użycia `dd`). Wymienione alternatywy to:
```bash
tail
hexdump
cmp
xxd
```
Ustawiając zmienną `SEEKER`, możesz zmienić używany seeker, np.:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Jeśli znajdziesz innego ważnego seeker'a, który nie został zaimplementowany w skrypcie, możesz go nadal użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokuj to, EDR-y.

## Referencje
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
