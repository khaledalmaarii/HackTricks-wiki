# Przestrzeń nazw montowania

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

Przestrzeń nazw montowania to funkcja jądra Linux, która zapewnia izolację punktów montowania systemu plików widzianych przez grupę procesów. Każda przestrzeń nazw montowania ma swoje własne punkty montowania systemu plików, a **zmiany w punktach montowania w jednej przestrzeni nazw nie wpływają na inne przestrzenie nazw**. Oznacza to, że procesy działające w różnych przestrzeniach nazw montowania mogą mieć różne widoki hierarchii systemu plików.

Przestrzenie nazw montowania są szczególnie przydatne w konteneryzacji, gdzie każdy kontener powinien mieć własny system plików i konfigurację, odizolowany od innych kontenerów i systemu hosta.

### Jak to działa:

1. Po utworzeniu nowej przestrzeni nazw montowania jest ona inicjalizowana **kopią punktów montowania z przestrzeni nazw rodzica**. Oznacza to, że przy tworzeniu nowej przestrzeni nazw nowa przestrzeń udostępnia ten sam widok systemu plików co przestrzeń rodzica. Jednak wszelkie późniejsze zmiany w punktach montowania wewnątrz przestrzeni nazw nie wpływają na przestrzeń rodzica ani inne przestrzenie nazw.
2. Gdy proces modyfikuje punkt montowania w swojej przestrzeni nazw, na przykład montuje lub odmontowuje system plików, **zmiana jest lokalna dla tej przestrzeni nazw** i nie wpływa na inne przestrzenie nazw. Pozwala to każdej przestrzeni nazw mieć niezależną hierarchię systemu plików.
3. Procesy mogą przenosić się między przestrzeniami nazw za pomocą wywołania systemowego `setns()`, lub tworzyć nowe przestrzenie nazw za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWNS`. Gdy proces przenosi się do nowej przestrzeni nazw lub ją tworzy, zaczyna korzystać z punktów montowania powiązanych z tą przestrzenią nazw.
4. **Deskryptory plików i i-węzły są udostępniane między przestrzeniami nazw**, co oznacza, że jeśli proces w jednej przestrzeni nazw ma otwarty deskryptor pliku wskazujący na plik, może **przekazać ten deskryptor pliku** do procesu w innej przestrzeni nazw, i **oba procesy będą miały dostęp do tego samego pliku**. Jednak ścieżka do pliku może być różna w obu przestrzeniach nazw ze względu na różnice w punktach montowania.

## Laboratorium:

### Utwórz różne przestrzenie nazw

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc` przy użyciu parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy polecenie `unshare` jest wykonywane bez opcji `-f`, występuje błąd związany z tym, jak Linux obsługuje nowe przestrzenie nazw PID (Process ID). Poniżej przedstawiono kluczowe szczegóły i rozwiązanie:

1. **Wyjaśnienie problemu**:
- Jądro Linuxa umożliwia procesowi tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany procesem "unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W rezultacie `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces zakończy działanie, powoduje to wyczyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów sierot. Jądro Linuxa wyłączy wtedy przydział PID w tej przestrzeni nazw.

2. **Konsekwencje**:
- Zakończenie PID 1 w nowej przestrzeni nazw prowadzi do wyczyszczenia flagi `PIDNS_HASH_ADDING`. Powoduje to niepowodzenie funkcji `alloc_pid` w przydzielaniu nowego PID podczas tworzenia nowego procesu i pojawienie się błędu "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` wraz z poleceniem `unshare`. Ta opcja powoduje, że `unshare` rozgałęzia nowy proces po utworzeniu nowej przestrzeni nazw PID.
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
ls -l /proc/$$/ns
```

Zwrócone zostaną linki symboliczne do różnych przestrzeni nazw, w których działa Twój proces. Przestrzeń nazw montażu będzie oznaczona jako `mnt`.
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Znajdź wszystkie przestrzenie nazw montowania

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Wejdź do przestrzeni nazw montowania

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Dodatkowo, możesz **wejść do innego przestrzeni nazw procesu tylko jeśli jesteś rootem**. I **nie możesz** **wejść** do innej przestrzeni nazw bez deskryptora wskazującego na nią (takiego jak `/proc/self/ns/mnt`).

Ponieważ nowe montowania są dostępne tylko w obrębie przestrzeni nazw, możliwe jest, że przestrzeń nazw zawiera poufne informacje, które są dostępne tylko z niej.

### Zamontuj coś
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
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
