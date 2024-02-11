# Przestrzeń nazw PID

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

Przestrzeń nazw PID (Process IDentifier) to funkcja w jądrze Linuxa, która zapewnia izolację procesów poprzez umożliwienie grupie procesów posiadanie własnego zestawu unikalnych PID-ów, oddzielnych od PID-ów w innych przestrzeniach nazw. Jest to szczególnie przydatne w konteneryzacji, gdzie izolacja procesów jest niezbędna dla bezpieczeństwa i zarządzania zasobami.

Po utworzeniu nowej przestrzeni nazw PID, pierwszy proces w tej przestrzeni jest przypisany do PID 1. Ten proces staje się procesem "init" nowej przestrzeni nazw i jest odpowiedzialny za zarządzanie innymi procesami w tej przestrzeni. Każdy kolejny proces utworzony w tej przestrzeni będzie miał unikalny PID w ramach tej przestrzeni, a te PID-y będą niezależne od PID-ów w innych przestrzeniach nazw.

Z perspektywy procesu w przestrzeni nazw PID, może on widzieć tylko inne procesy w tej samej przestrzeni nazw. Nie jest świadomy procesów w innych przestrzeniach nazw i nie może z nimi współdziałać za pomocą tradycyjnych narzędzi zarządzania procesami (np. `kill`, `wait`, itp.). Zapewnia to poziom izolacji, który pomaga zapobiegać wzajemnym zakłóceniom procesów.

### Jak to działa:

1. Po utworzeniu nowego procesu (np. za pomocą wywołania systemowego `clone()`), proces ten może zostać przypisany do nowej lub istniejącej przestrzeni nazw PID. **Jeśli utworzona zostanie nowa przestrzeń nazw, proces staje się procesem "init" tej przestrzeni**.
2. **Jądro** utrzymuje **mapowanie między PID-ami w nowej przestrzeni nazw a odpowiadającymi PID-ami** w przestrzeni nadrzędnej (tj. przestrzeni, z której utworzono nową przestrzeń nazw). To mapowanie **umożliwia jądrze tłumaczenie PID-ów, gdy jest to konieczne**, na przykład podczas wysyłania sygnałów między procesami w różnych przestrzeniach nazw.
3. **Procesy w ramach przestrzeni nazw PID mogą widzieć i współdziałać tylko z innymi procesami w tej samej przestrzeni nazw**. Nie są świadome procesów w innych przestrzeniach nazw, a ich PID-y są unikalne w ramach ich przestrzeni.
4. Po **zniszczeniu przestrzeni nazw PID** (np. gdy proces "init" przestrzeni opuści), **wszystkie procesy w tej przestrzeni zostaną zakończone**. Zapewnia to, że wszystkie zasoby związane z przestrzenią nazw są odpowiednio oczyszczone.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy polecenie `unshare` jest uruchamiane bez opcji `-f`, występuje błąd związany z tym, jak Linux obsługuje nowe przestrzenie nazw PID (Process ID). Poniżej przedstawiamy kluczowe informacje dotyczące tego problemu oraz rozwiązanie:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa umożliwia procesowi tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` powoduje uruchomienie `/bin/bash` w tym samym procesie co `unshare`. W rezultacie `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces się zakończy, powoduje to wyczyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów sierot. Jądro Linuxa wyłącza wtedy przydział PID w tej przestrzeni nazw.

2. **Konsekwencje**:
- Zakończenie PID 1 w nowej przestrzeni nazw powoduje usunięcie flagi `PIDNS_HASH_ADDING`. Powoduje to niepowodzenie funkcji `alloc_pid` przy przydzielaniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` w poleceniu `unshare`. Ta opcja powoduje, że `unshare` rozgałęzia nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że samo polecenie `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Poprzez upewnienie się, że `unshare` jest uruchamiane z flagą `-f`, nowa przestrzeń nazw PID jest poprawnie utrzymywana, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

Montując nową instancję systemu plików `/proc` przy użyciu parametru `--mount-proc`, zapewniasz, że nowa przestrzeń nazw montowania ma **dokładny i izolowany widok na informacje o procesach specyficzne dla tej przestrzeni nazw**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w jakim przestrzeni nazw znajduje się Twój proces

Aby sprawdzić, w jakiej przestrzeni nazw znajduje się Twój proces, wykonaj poniższą komendę:

```bash
ls -l /proc/<PID>/ns
```

Zastąp `<PID>` odpowiednim identyfikatorem procesu, który chcesz sprawdzić. Komenda ta wyświetli listę plików reprezentujących różne przestrzenie nazw, w których działa dany proces.
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

Należy zauważyć, że użytkownik root z początkowego (domyślnego) przestrzeni nazw PID może zobaczyć wszystkie procesy, nawet te w nowych przestrzeniach nazw PID, dlatego możemy zobaczyć wszystkie przestrzenie nazw PID.

### Wejście do przestrzeni nazw PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Kiedy wejdziesz do przestrzeni nazw PID z przestrzeni nazw domyślnej, nadal będziesz mógł zobaczyć wszystkie procesy. Proces z tej przestrzeni nazw PID będzie również mógł zobaczyć nową powłokę bash w przestrzeni nazw PID.

Ponadto, możesz **wejść do innej przestrzeni nazw PID procesu tylko jako root**. I **nie możesz** **wejść** do innej przestrzeni nazw bez deskryptora wskazującego na nią (np. `/proc/self/ns/pid`).

## Referencje
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
