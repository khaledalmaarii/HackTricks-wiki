# Przestrzeń nazw sieciowych

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

Przestrzeń nazw sieciowych to funkcja jądra Linux, która zapewnia izolację stosu sieciowego, umożliwiając **każdej przestrzeni nazw sieciowych posiadanie własnej niezależnej konfiguracji sieciowej**, interfejsów, adresów IP, tablic routingu i reguł zapory ogniowej. Ta izolacja jest przydatna w różnych scenariuszach, takich jak konteneryzacja, gdzie każdy kontener powinien mieć swoją własną konfigurację sieciową, niezależną od innych kontenerów i systemu hosta.

### Jak to działa:

1. Po utworzeniu nowej przestrzeni nazw sieciowych, rozpoczyna się ona z **całkowicie izolowanym stosie sieciowym**, bez **żadnych interfejsów sieciowych** oprócz interfejsu pętli zwrotnej (lo). Oznacza to, że procesy działające w nowej przestrzeni nazw sieciowych domyślnie nie mogą komunikować się z procesami w innych przestrzeniach nazw ani z systemem hosta.
2. Mogą być tworzone i przenoszone **wirtualne interfejsy sieciowe**, takie jak pary veth, między przestrzeniami nazw sieciowych. Pozwala to na nawiązanie połączenia sieciowego między przestrzeniami nazw lub między przestrzenią nazw a systemem hosta. Na przykład, jeden koniec pary veth może być umieszczony w przestrzeni nazw sieciowej kontenera, a drugi koniec może być podłączony do **mostka** lub innego interfejsu sieciowego w przestrzeni nazw hosta, zapewniając połączenie sieciowe do kontenera.
3. Interfejsy sieciowe w ramach przestrzeni nazw mogą mieć **własne adresy IP, tablice routingu i reguły zapory ogniowej**, niezależne od innych przestrzeni nazw. Pozwala to procesom w różnych przestrzeniach nazw sieciowych mieć różne konfiguracje sieciowe i działać tak, jakby działały na oddzielnych systemach sieciowych.
4. Procesy mogą przenosić się między przestrzeniami nazw za pomocą wywołania systemowego `setns()`, lub tworzyć nowe przestrzenie nazw za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWNET`. Gdy proces przenosi się do nowej przestrzeni nazw lub ją tworzy, zaczyna korzystać z konfiguracji sieciowej i interfejsów powiązanych z tą przestrzenią nazw.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Montując nową instancję systemu plików `/proc` przy użyciu parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy polecenie `unshare` jest wykonywane bez opcji `-f`, występuje błąd związany z tym, jak Linux obsługuje nowe przestrzenie nazw PID (Process ID). Poniżej przedstawiono kluczowe szczegóły i rozwiązanie:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa umożliwia procesowi tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany procesem "unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W rezultacie `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces się zakończy, powoduje to oczyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów sierot. Jądro Linuxa wyłączy wtedy przydział PID w tej przestrzeni nazw.

2. **Konsekwencje**:
- Zakończenie PID 1 w nowej przestrzeni nazw prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Powoduje to niepowodzenie funkcji `alloc_pid` przy przydzielaniu nowego PID podczas tworzenia nowego procesu i pojawienie się błędu "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` wraz z poleceniem `unshare`. Ta opcja powoduje, że `unshare` rozgałęzia nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że samo polecenie `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Poprzez upewnienie się, że polecenie `unshare` jest uruchamiane z flagą `-f`, nowa przestrzeń nazw PID jest poprawnie utrzymywana, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Sprawdź, w jakim przestrzeni nazw znajduje się Twój proces

Aby sprawdzić, w jakiej przestrzeni nazw znajduje się Twój proces, wykonaj poniższą komendę:

```bash
ls -l /proc/$$/ns/net
```

Wynik pokaże Ci, w jakiej przestrzeni nazw znajduje się Twój proces.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Znajdź wszystkie przestrzenie nazw sieciowych

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Wejdź do przestrzeni nazw sieciowych

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Ponadto, możesz **wejść do innego przestrzeni nazw procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw bez deskryptora wskazującego na nią (np. `/proc/self/ns/net`).

## Referencje
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
