# Przestrzeń nazw użytkownika

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

Przestrzeń nazw użytkownika to funkcja jądra Linux, która **zapewnia izolację mapowania identyfikatorów użytkownika i grupy**, umożliwiając każdej przestrzeni nazw użytkownika posiadanie **własnego zestawu identyfikatorów użytkownika i grupy**. Ta izolacja umożliwia procesom działającym w różnych przestrzeniach nazw użytkownika **posiadanie różnych uprawnień i właścicieli**, nawet jeśli mają te same identyfikatory użytkownika i grupy numerycznie.

Przestrzenie nazw użytkownika są szczególnie przydatne w konteneryzacji, gdzie każdy kontener powinien mieć własny niezależny zestaw identyfikatorów użytkownika i grupy, co umożliwia lepsze zabezpieczenie i izolację między kontenerami a systemem hosta.

### Jak to działa:

1. Po utworzeniu nowej przestrzeni nazw użytkownika, **rozpoczyna się ona z pustym zestawem mapowania identyfikatorów użytkownika i grupy**. Oznacza to, że każdy proces działający w nowej przestrzeni nazw użytkownika **początkowo nie ma uprawnień poza przestrzenią nazw**.
2. Mapowania identyfikatorów mogą być ustanawiane między identyfikatorami użytkownika i grupy w nowej przestrzeni nazw a tymi w przestrzeni nadrzędnej (lub hosta). **Pozwala to procesom w nowej przestrzeni nazw na posiadanie uprawnień i właścicieli odpowiadających identyfikatorom użytkownika i grupy w przestrzeni nadrzędnej**. Jednak mapowania identyfikatorów mogą być ograniczone do określonych zakresów i podzbiorów identyfikatorów, co umożliwia precyzyjną kontrolę nad uprawnieniami przyznawanymi procesom w nowej przestrzeni nazw.
3. W obrębie przestrzeni nazw użytkownika **procesy mogą mieć pełne uprawnienia roota (UID 0) do operacji wewnątrz przestrzeni nazw**, jednocześnie posiadając ograniczone uprawnienia poza przestrzenią nazw. Pozwala to **kontenerom na uruchamianie się z uprawnieniami podobnymi do roota w ich własnej przestrzeni nazw, bez posiadania pełnych uprawnień roota na systemie hosta**.
4. Procesy mogą przenosić się między przestrzeniami nazw za pomocą wywołania systemowego `setns()` lub tworzyć nowe przestrzenie nazw za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWUSER`. Gdy proces przenosi się do nowej przestrzeni nazw lub ją tworzy, zaczyna korzystać z mapowania identyfikatorów użytkownika i grupy powiązanego z tą przestrzenią nazw.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
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
- Problem można rozwiązać, używając opcji `-f` wraz z `unshare`. Ta opcja powoduje, że `unshare` rozgałęzia nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że samo polecenie `unshare` staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewnienie, że `unshare` jest uruchamiane z flagą `-f`, umożliwia prawidłowe utrzymanie nowej przestrzeni nazw PID, co pozwala `/bin/bash` i jego podprocesom działać bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Aby korzystać z przestrzeni nazw użytkownika, demona Dockera należy uruchomić z opcją **`--userns-remap=default`** (W Ubuntu 14.04 można to zrobić, modyfikując plik `/etc/default/docker`, a następnie wykonując polecenie `sudo service docker restart`).

### Sprawdź, w jakiej przestrzeni nazw znajduje się Twój proces
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Możliwe jest sprawdzenie mapy użytkowników z kontenera Docker za pomocą polecenia:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Lub z hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
```
### Znajdź wszystkie przestrzenie nazw użytkowników

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Wejdź do przestrzeni nazw użytkownika

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Dodatkowo, możesz **wejść do innego przestrzeni nazw procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw bez deskryptora wskazującego na nią (takiego jak `/proc/self/ns/user`).

### Tworzenie nowej przestrzeni nazw użytkownika (z mapowaniem)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Odzyskiwanie uprawnień

W przypadku przestrzeni nazw użytkownika, **po utworzeniu nowej przestrzeni nazw użytkownika, proces, który do niej wchodzi, otrzymuje pełny zestaw uprawnień w ramach tej przestrzeni nazw**. Uprawnienia te pozwalają procesowi wykonywać operacje uprzywilejowane, takie jak **montowanie** **systemów plików**, tworzenie urządzeń lub zmiana właściciela plików, ale **tylko w kontekście swojej przestrzeni nazw użytkownika**.

Na przykład, posiadając uprawnienie `CAP_SYS_ADMIN` w przestrzeni nazw użytkownika, możesz wykonywać operacje, które zwykle wymagają tego uprawnienia, takie jak montowanie systemów plików, ale tylko w kontekście swojej przestrzeni nazw użytkownika. Operacje wykonywane z tym uprawnieniem nie będą miały wpływu na system hosta ani inne przestrzenie nazw.

{% hint style="warning" %}
Dlatego nawet jeśli uzyskanie nowego procesu w nowej przestrzeni nazw użytkownika **przywróci wszystkie uprawnienia** (CapEff: 000001ffffffffff), faktycznie możesz **używać tylko tych związanych z przestrzenią nazw** (np. montowanie), ale nie wszystkich. Samo to nie wystarczy, aby uciec z kontenera Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
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
