# Przestrzeń nazw CGroup

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

Przestrzeń nazw CGroup to funkcja jądra Linux, która zapewnia **izolację hierarchii cgroup dla procesów działających w przestrzeni nazw**. Cgroups, skrót od **grup kontrolnych**, to funkcja jądra, która umożliwia organizowanie procesów w hierarchiczne grupy w celu zarządzania i narzucania **ograniczeń na zasoby systemowe**, takie jak CPU, pamięć i I/O.

Podczas gdy przestrzenie nazw CGroup nie są oddzielnym typem przestrzeni nazw, jak te, o których wcześniej rozmawialiśmy (PID, montowanie, sieć, itp.), są one związane z koncepcją izolacji przestrzeni nazw. **Przestrzenie nazw CGroup wirtualizują widok hierarchii cgroup**, dzięki czemu procesy działające w przestrzeni nazw CGroup mają inny widok hierarchii w porównaniu do procesów działających w hostingu lub innych przestrzeniach nazw.

### Jak to działa:

1. Po utworzeniu nowej przestrzeni nazw CGroup, **rozpoczyna się ona od widoku hierarchii cgroup opartego na cgroup procesu tworzącego**. Oznacza to, że procesy działające w nowej przestrzeni nazw CGroup zobaczą tylko podzbiór całej hierarchii cgroup, ograniczony do poddrzewa cgroup zakorzenionego w cgroup procesu tworzącego.
2. Procesy w przestrzeni nazw CGroup **zobaczą swoją własną cgroup jako korzeń hierarchii**. Oznacza to, że z perspektywy procesów wewnątrz przestrzeni nazw, ich własna cgroup wydaje się być korzeniem, i nie mogą zobaczyć ani uzyskać dostępu do cgroup spoza swojego poddrzewa.
3. Przestrzenie nazw CGroup nie zapewniają bezpośredniej izolacji zasobów; **zapewniają tylko izolację widoku hierarchii cgroup**. **Kontrola i izolacja zasobów są wciąż egzekwowane przez podsystemy cgroup** (np. cpu, pamięć, itp.) samodzielnie.

Aby uzyskać więcej informacji na temat CGroups, sprawdź:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
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
- Wyjście PID 1 z nowej przestrzeni nazw prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Powoduje to niepowodzenie funkcji `alloc_pid` przy przydzielaniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` wraz z poleceniem `unshare`. Ta opcja sprawia, że `unshare` rozgałęzia nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że samo polecenie `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Poprzez upewnienie się, że polecenie `unshare` jest uruchamiane z flagą `-f`, nowa przestrzeń nazw PID jest poprawnie utrzymywana, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w jakim przestrzeni nazw znajduje się Twój proces

Aby sprawdzić, w jakiej przestrzeni nazw znajduje się Twój proces, wykonaj poniższą komendę:

```bash
cat /proc/$$/cgroup
```

Wynik pokaże informacje o przestrzeniach nazw, w których działa Twój proces.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Znajdź wszystkie przestrzenie nazw CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Wejdź do przestrzeni nazw CGroup

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Ponadto, możesz **wejść do innego przestrzeni nazw procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw bez deskryptora wskazującego na nią (np. `/proc/self/ns/cgroup`).

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
