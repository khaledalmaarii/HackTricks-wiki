# Przestrzeń nazw UTS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub**.

</details>

## Podstawowe informacje

Przestrzeń nazw UTS (UNIX Time-Sharing System) to funkcja jądra Linux, która zapewnia **izolację dwóch identyfikatorów systemowych**: **nazwy hosta** i **domeny NIS** (Network Information Service). Ta izolacja pozwala każdej przestrzeni nazw UTS mieć **własną niezależną nazwę hosta i domenę NIS**, co jest szczególnie przydatne w scenariuszach konteneryzacji, gdzie każdy kontener powinien wyglądać jak oddzielny system z własną nazwą hosta.

### Jak to działa:

1. Po utworzeniu nowej przestrzeni nazw UTS, zaczyna ona od **kopi nazwy hosta i domeny NIS z przestrzeni nazw nadrzędnej**. Oznacza to, że przy tworzeniu nowej przestrzeni nazw, **nowa przestrzeń nazw dzieli te same identyfikatory co jej przestrzeń nadrzędna**. Jednak wszelkie późniejsze zmiany nazwy hosta lub domeny NIS wewnątrz przestrzeni nazw nie wpływają na inne przestrzenie nazw.
2. Procesy w ramach przestrzeni nazw UTS **mogą zmieniać nazwę hosta i domenę NIS** za pomocą odpowiednio wywołań systemowych `sethostname()` i `setdomainname()`. Te zmiany są lokalne dla przestrzeni nazw i nie wpływają na inne przestrzenie nazw ani na system hosta.
3. Procesy mogą przenosić się między przestrzeniami nazw za pomocą wywołania systemowego `setns()` lub tworzyć nowe przestrzenie nazw za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWUTS`. Gdy proces przenosi się do nowej przestrzeni nazw lub ją tworzy, zaczyna używać nazwy hosta i domeny NIS powiązanych z tą przestrzenią nazw.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc` za pomocą parametru `--mount-proc`, zapewniasz, że nowa przestrzeń nazw montowania ma dokładny i izolowany widok informacji o procesie specyficznych dla tej przestrzeni nazw.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy polecenie `unshare` jest wykonywane bez opcji `-f`, występuje błąd związany z tym, jak Linux obsługuje nowe przestrzenie nazw PID (Process ID). Poniżej przedstawiono kluczowe szczegóły i rozwiązanie:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa umożliwia procesowi tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany procesem "unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W rezultacie `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces się zakończy, powoduje to oczyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów sierot. Jądro Linuxa wyłączy wtedy przydział PID w tej przestrzeni nazw.

2. **Konsekwencje**:
- Wyjście PID 1 w nowej przestrzeni nazw prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. Powoduje to niepowodzenie funkcji `alloc_pid` w przydzielaniu nowego PID podczas tworzenia nowego procesu, co powoduje błąd "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z poleceniem `unshare`. Ta opcja sprawia, że `unshare` rozwidla nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że samo polecenie `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewnienie, że `unshare` jest uruchamiane z flagą `-f`, umożliwia prawidłowe utrzymanie nowej przestrzeni nazw PID, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w jakim przestrzeni nazw znajduje się Twój proces

Aby sprawdzić, w jakiej przestrzeni nazw znajduje się Twój proces, wykonaj poniższą komendę:

```bash
cat /proc/$$/ns/uts
```

Wynik pokaże identyfikator przestrzeni nazw UTS Twojego procesu.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Znajdź wszystkie przestrzenie nazw UTS

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Wejdź do przestrzeni nazw UTS

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
### Zmiana nazwy hosta

Aby zmienić nazwę hosta, musisz wejść w przestrzeń nazw procesu innego użytkownika. Jednak możesz to zrobić tylko jako użytkownik root. Ponadto, nie możesz wejść do innej przestrzeni nazw bez deskryptora wskazującego na nią (np. `/proc/self/ns/uts`).
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## Odwołania
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
