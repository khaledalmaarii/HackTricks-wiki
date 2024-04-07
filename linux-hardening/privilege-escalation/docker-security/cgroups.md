# CGroups

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

**Linux Control Groups**, czyli **cgroups**, to funkcja jądra Linux, która umożliwia alokację, ograniczanie i priorytetyzację zasobów systemowych, takich jak CPU, pamięć i wejścia/wyjścia dysku, między grupami procesów. Oferują one mechanizm **zarządzania i izolowania użycia zasobów** kolekcji procesów, korzystny w celu ograniczania zasobów, izolacji obciążeń i priorytetyzacji zasobów między różnymi grupami procesów.

Istnieją **dwie wersje cgroups**: wersja 1 i wersja 2. Obydwie mogą być używane równocześnie w systemie. Główną różnicą jest to, że **cgroups wersji 2** wprowadza **hierarchiczną strukturę drzewiastą**, umożliwiając bardziej subtelne i szczegółowe rozdział zasobów między grupami procesów. Dodatkowo, wersja 2 wprowadza różne ulepszenia, w tym:

Oprócz nowej organizacji hierarchicznej, cgroups wersji 2 wprowadziły również **kilka innych zmian i ulepszeń**, takich jak wsparcie dla **nowych kontrolerów zasobów**, lepsze wsparcie dla aplikacji z przeszłości oraz poprawiona wydajność.

Ogólnie rzecz biorąc, cgroups **wersji 2 oferują więcej funkcji i lepszą wydajność** niż wersja 1, ale ta ostatnia nadal może być używana w określonych scenariuszach, gdzie istnieje obawa o zgodność z starszymi systemami.

Możesz wyświetlić cgroups v1 i v2 dla dowolnego procesu, patrząc na jego plik cgroup w /proc/\<pid>. Możesz zacząć od sprawdzenia cgroups swojego powłoki tym poleceniem:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
* **Numery 2–12**: cgroups v1, gdzie każda linia reprezentuje inny cgroup. Kontrolery dla nich są określone obok numeru.
* **Numer 1**: Również cgroups v1, ale wyłącznie do celów zarządzania (ustawiane przez np. systemd) i nie posiada kontrolera.
* **Numer 0**: Reprezentuje cgroups v2. Nie są wymienione żadne kontrolery, a ta linia jest ekskluzywna dla systemów działających wyłącznie na cgroups v2.
* **Nazwy są hierarchiczne**, przypominające ścieżki plików, wskazujące strukturę i relacje między różnymi cgroups.
* **Nazwy takie jak /user.slice lub /system.slice** określają kategoryzację cgroups, gdzie user.slice zazwyczaj dotyczy sesji logowania zarządzanych przez systemd, a system.slice dotyczy usług systemowych.

### Przeglądanie cgroups

System plików jest zazwyczaj wykorzystywany do dostępu do **cgroups**, odbiegając od interfejsu wywołań systemowych Unix tradycyjnie używanego do interakcji z jądrem. Aby zbadać konfigurację cgroup powłoki, należy przejrzeć plik **/proc/self/cgroup**, który ujawnia cgroup powłoki. Następnie, przechodząc do katalogu **/sys/fs/cgroup** (lub **`/sys/fs/cgroup/unified`**) i lokalizując katalog o nazwie cgroup, można obserwować różne ustawienia i informacje o użyciu zasobów istotne dla cgroup.

![System plików Cgroup](<../../../.gitbook/assets/image (1125).png>)

Kluczowe pliki interfejsu dla cgroups mają przedrostek **cgroup**. Plik **cgroup.procs**, który można przeglądać za pomocą standardowych poleceń takich jak cat, wymienia procesy wewnątrz cgroup. Inny plik, **cgroup.threads**, zawiera informacje o wątkach.

![Procesy Cgroup](<../../../.gitbook/assets/image (278).png>)

Cgroups zarządzające powłokami zazwyczaj obejmują dwa kontrolery regulujące użycie pamięci i liczbę procesów. Aby współdziałać z kontrolerem, należy skonsultować pliki z przedrostkiem kontrolera. Na przykład, **pids.current** byłby odniesieniem do ustalenia liczby wątków w cgroup.

![Pamięć Cgroup](<../../../.gitbook/assets/image (674).png>)

Wskazanie **max** w wartości sugeruje brak określonego limitu dla cgroup. Jednakże, ze względu na hierarchiczną naturę cgroups, limity mogą być narzucane przez cgroup na niższym poziomie w hierarchii katalogów.

### Manipulowanie i Tworzenie cgroups

Procesy są przypisywane do cgroups poprzez **zapisanie ich identyfikatora procesu (PID) do pliku `cgroup.procs`**. Wymaga to uprawnień roota. Na przykład, aby dodać proces:
```bash
echo [pid] > cgroup.procs
```
Podobnie, **modyfikowanie atrybutów cgroup, takich jak ustawienie limitu PID**, odbywa się poprzez zapisanie żądanej wartości do odpowiedniego pliku. Aby ustawić maksymalnie 3 000 PID-ów dla cgroup:
```bash
echo 3000 > pids.max
```
**Tworzenie nowych cgroups** polega na utworzeniu nowego podkatalogu w hierarchii cgroup, co powoduje automatyczne wygenerowanie niezbędnych plików interfejsu przez jądro. Chociaż cgroups bez aktywnych procesów można usunąć za pomocą `rmdir`, należy pamiętać o pewnych ograniczeniach:

* **Procesy mogą być umieszczone tylko w liściastych cgroups** (czyli tych najbardziej zagnieżdżonych w hierarchii).
* **Cgroup nie może posiadać kontrolera nieobecnego w swoim rodzicu**.
* **Kontrolery dla cgroups potomnych muszą być wyraźnie zadeklarowane** w pliku `cgroup.subtree_control`. Na przykład, aby włączyć kontrolery CPU i PID w cgroup potomnym:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**Grupa root cgroup** jest wyjątkiem od tych zasad, umożliwiając bezpośrednie umieszczanie procesów. Może to być wykorzystane do usunięcia procesów z zarządzania przez systemd.

**Monitorowanie użycia CPU** wewnątrz cgroup jest możliwe za pomocą pliku `cpu.stat`, który wyświetla całkowity czas CPU zużyty, co jest pomocne do śledzenia użycia przez podprocesy usługi:

<figure><img src="../../../.gitbook/assets/image (905).png" alt=""><figcaption><p>Statystyki użycia CPU widoczne w pliku cpu.stat</p></figcaption></figure>

## Referencje

* **Książka: Jak działa Linux, 3. wydanie: Co każdy superużytkownik powinien wiedzieć autorstwa Briana Warda**
