# IPC Namespace

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

Przestrzeń nazw IPC (Inter-Process Communication) to funkcja jądra Linux, która zapewnia **izolację** obiektów IPC System V, takich jak kolejki komunikatów, segmenty pamięci współdzielonej i semafory. Ta izolacja zapewnia, że procesy w **różnych przestrzeniach nazw IPC nie mogą bezpośrednio uzyskiwać dostępu ani modyfikować obiektów IPC innych procesów**, zapewniając dodatkową warstwę bezpieczeństwa i prywatności między grupami procesów.

### Jak to działa:

1. Po utworzeniu nowej przestrzeni nazw IPC, zaczyna ona działać z **całkowicie izolowanym zestawem obiektów IPC System V**. Oznacza to, że procesy działające w nowej przestrzeni nazw IPC domyślnie nie mogą uzyskać dostępu ani ingerować w obiekty IPC w innych przestrzeniach nazw ani w systemie gospodarza.
2. Obiekty IPC utworzone w ramach przestrzeni nazw są widoczne i **dostępne tylko dla procesów w tej przestrzeni nazw**. Każdy obiekt IPC jest identyfikowany przez unikalny klucz w ramach swojej przestrzeni nazw. Chociaż klucz może być identyczny w różnych przestrzeniach nazw, same obiekty są izolowane i nie można uzyskać do nich dostępu między przestrzeniami nazw.
3. Procesy mogą przenosić się między przestrzeniami nazw za pomocą wywołania systemowego `setns()` lub tworzyć nowe przestrzenie nazw za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWIPC`. Gdy proces przenosi się do nowej przestrzeni nazw lub tworzy ją, zaczyna korzystać z obiektów IPC powiązanych z tą przestrzenią nazw.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
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
- Wyjście PID 1 z nowej przestrzeni nazw prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Powoduje to niepowodzenie funkcji `alloc_pid` przy przydzielaniu nowego PID podczas tworzenia nowego procesu, co powoduje błąd "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` wraz z poleceniem `unshare`. Ta opcja sprawia, że `unshare` rozgałęzia nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że samo polecenie `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewnienie, że polecenie `unshare` jest uruchamiane z flagą `-f`, umożliwia prawidłowe utrzymanie nowej przestrzeni nazw PID, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w jakim przestrzeni nazw znajduje się Twój proces

Aby sprawdzić, w jakiej przestrzeni nazw znajduje się Twój proces, wykonaj poniższą komendę:

```bash
ls -l /proc/$$/ns/ipc
```

Gdzie `$$` oznacza identyfikator bieżącego procesu.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Znajdź wszystkie przestrzenie nazw IPC

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Wejdź do przestrzeni nazw IPC

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
### Tworzenie obiektu IPC

Aby utworzyć obiekt IPC, możemy użyć polecenia `ipcmk`. Polecenie to tworzy nowy obiekt IPC i zwraca jego identyfikator. Na przykład, aby utworzyć nowy semafor, możemy użyć następującego polecenia:

```bash
ipcmk -S
```

Polecenie to utworzy nowy semafor i zwróci jego identyfikator. Możemy również użyć innych opcji, takich jak `-M` dla pamięci współdzielonej lub `-Q` dla kolejki komunikatów, aby utworzyć inne rodzaje obiektów IPC.

### Usuwanie IPC object

Aby usunąć obiekt IPC, możemy użyć polecenia `ipcrm`. Polecenie to usuwa obiekt IPC na podstawie jego identyfikatora. Na przykład, aby usunąć semafor o identyfikatorze 12345, możemy użyć następującego polecenia:

```bash
ipcrm -s 12345
```

Polecenie to usunie semafor o identyfikatorze 12345. Możemy również użyć innych opcji, takich jak `-m` dla pamięci współdzielonej lub `-q` dla kolejki komunikatów, aby usunąć inne rodzaje obiektów IPC.

### Podsumowanie

Tworzenie i usuwanie obiektów IPC jest możliwe tylko w przestrzeni nazw procesu, a nie w przestrzeni nazw IPC. Aby wejść do innej przestrzeni nazw procesu, musimy być rootem i musimy mieć deskryptor wskazujący na tę przestrzeń nazw.
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
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
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
