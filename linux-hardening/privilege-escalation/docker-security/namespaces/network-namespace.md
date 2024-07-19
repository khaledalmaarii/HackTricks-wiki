# Network Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Podstawowe informacje

Namespace sieciowy to funkcja jądra Linux, która zapewnia izolację stosu sieciowego, umożliwiając **każdemu namespace'owi sieciowemu posiadanie własnej niezależnej konfiguracji sieci**, interfejsów, adresów IP, tabel routingu i reguł zapory. Ta izolacja jest przydatna w różnych scenariuszach, takich jak konteneryzacja, gdzie każdy kontener powinien mieć swoją własną konfigurację sieci, niezależnie od innych kontenerów i systemu gospodarza.

### Jak to działa:

1. Gdy nowy namespace sieciowy jest tworzony, zaczyna z **całkowicie izolowanym stosem sieciowym**, z **brakiem interfejsów sieciowych** poza interfejsem loopback (lo). Oznacza to, że procesy działające w nowym namespace'ie sieciowym nie mogą komunikować się z procesami w innych namespace'ach ani z systemem gospodarza domyślnie.
2. **Wirtualne interfejsy sieciowe**, takie jak pary veth, mogą być tworzone i przenoszone między namespace'ami sieciowymi. Umożliwia to nawiązywanie łączności sieciowej między namespace'ami lub między namespace'em a systemem gospodarza. Na przykład, jeden koniec pary veth może być umieszczony w namespace'ie sieciowym kontenera, a drugi koniec może być podłączony do **mostu** lub innego interfejsu sieciowego w namespace'ie gospodarza, zapewniając łączność sieciową dla kontenera.
3. Interfejsy sieciowe w namespace'ie mogą mieć **własne adresy IP, tabele routingu i reguły zapory**, niezależnie od innych namespace'ów. Umożliwia to procesom w różnych namespace'ach sieciowych posiadanie różnych konfiguracji sieciowych i działanie tak, jakby działały na oddzielnych systemach sieciowych.
4. Procesy mogą przemieszczać się między namespace'ami za pomocą wywołania systemowego `setns()`, lub tworzyć nowe namespace'y za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWNET`. Gdy proces przemieszcza się do nowego namespace'a lub tworzy jeden, zacznie korzystać z konfiguracji sieci i interfejsów związanych z tym namespace'em.

## Laboratorium:

### Tworzenie różnych namespace'ów

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Mountując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły i rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania osieroconych procesów. Jądro Linuxa następnie wyłączy przydzielanie PID w tej przestrzeni.

2. **Konsekwencja**:
- Zakończenie PID 1 w nowej przestrzeni prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni. `/bin/bash` i jego procesy potomne są następnie bezpiecznie zawarte w tej nowej przestrzeni, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Sprawdź, w której przestrzeni nazw znajduje się twój proces
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
{% endcode %}

### Wejście do przestrzeni nazw sieciowej
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Również, możesz **wejść do innej przestrzeni nazw procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (jak `/proc/self/ns/net`).

## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
