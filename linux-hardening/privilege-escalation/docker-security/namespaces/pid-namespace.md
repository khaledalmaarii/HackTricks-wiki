# PID Namespace

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
{% endhint %}

## Podstawowe informacje

Namespace PID (Process IDentifier) to funkcja w jądrze Linux, która zapewnia izolację procesów, umożliwiając grupie procesów posiadanie własnego zestawu unikalnych PID-ów, oddzielnych od PID-ów w innych namespace'ach. Jest to szczególnie przydatne w konteneryzacji, gdzie izolacja procesów jest niezbędna dla bezpieczeństwa i zarządzania zasobami.

Gdy tworzony jest nowy namespace PID, pierwszy proces w tym namespace otrzymuje PID 1. Ten proces staje się procesem "init" nowego namespace i jest odpowiedzialny za zarządzanie innymi procesami w tym namespace. Każdy kolejny proces utworzony w namespace będzie miał unikalny PID w tym namespace, a te PID-y będą niezależne od PID-ów w innych namespace'ach.

Z perspektywy procesu w namespace PID, może on widzieć tylko inne procesy w tym samym namespace. Nie jest świadomy procesów w innych namespace'ach i nie może z nimi interagować za pomocą tradycyjnych narzędzi do zarządzania procesami (np. `kill`, `wait` itp.). Zapewnia to poziom izolacji, który pomaga zapobiegać zakłóceniom między procesami.

### Jak to działa:

1. Gdy tworzony jest nowy proces (np. za pomocą wywołania systemowego `clone()`), proces może być przypisany do nowego lub istniejącego namespace PID. **Jeśli tworzony jest nowy namespace, proces staje się procesem "init" tego namespace**.
2. **Jądro** utrzymuje **mapowanie między PID-ami w nowym namespace a odpowiadającymi PID-ami** w namespace nadrzędnym (tj. namespace, z którego utworzono nowy namespace). To mapowanie **umożliwia jądru tłumaczenie PID-ów w razie potrzeby**, na przykład podczas wysyłania sygnałów między procesami w różnych namespace'ach.
3. **Procesy w namespace PID mogą widzieć i interagować tylko z innymi procesami w tym samym namespace**. Nie są świadome procesów w innych namespace'ach, a ich PID-y są unikalne w ich namespace.
4. Gdy **namespace PID jest niszczony** (np. gdy proces "init" namespace kończy działanie), **wszystkie procesy w tym namespace są kończone**. Zapewnia to, że wszystkie zasoby związane z namespace są odpowiednio sprzątane.

## Laboratorium:

### Tworzenie różnych namespace'ów

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły i rozwiązanie są przedstawione poniżej:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów osieroconych. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni nazw.

2. **Konsekwencja**:
- Zakończenie PID 1 w nowej przestrzeni nazw prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są następnie bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala na działanie `/bin/bash` i jego podprocesów bez napotkania błędu przydzielania pamięci.

</details>

Montaż nowej instancji systemu plików `/proc`, jeśli użyjesz parametru `--mount-proc`, zapewnia, że nowa przestrzeń nazw montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni nazw**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Sprawdź, w którym namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Znajdź wszystkie przestrzenie nazw PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Zauważ, że użytkownik root z początkowej (domyślnej) przestrzeni nazw PID może widzieć wszystkie procesy, nawet te w nowych przestrzeniach nazw PID, dlatego możemy zobaczyć wszystkie przestrzenie nazw PID.

### Wejdź do przestrzeni nazw PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Kiedy wejdziesz do przestrzeni nazw PID z domyślnej przestrzeni nazw, nadal będziesz mógł zobaczyć wszystkie procesy. A proces z tej przestrzeni nazw PID będzie mógł zobaczyć nowego basha w przestrzeni nazw PID.

Również możesz **wejść do innej przestrzeni nazw PID procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (jak `/proc/self/ns/pid`)

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
</details>
{% endhint %}
