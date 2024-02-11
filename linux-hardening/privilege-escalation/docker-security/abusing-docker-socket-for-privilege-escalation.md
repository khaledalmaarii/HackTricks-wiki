# Wykorzystywanie gniazda Docker do eskalacji uprawnień

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

Czasami masz **dostęp do gniazda Docker** i chcesz go wykorzystać do **eskalacji uprawnień**. Niektóre działania mogą być podejrzane i możesz chcieć ich uniknąć, dlatego tutaj znajdziesz różne flagi, które mogą być przydatne do eskalacji uprawnień:

### Za pomocą montowania

Możesz **zamontować** różne części **systemu plików** w kontenerze działającym jako root i **uzyskać do nich dostęp**.\
Możesz również **wykorzystać montowanie do eskalacji uprawnień** wewnątrz kontenera.

* **`-v /:/host`** -> Zamontuj system plików hosta w kontenerze, dzięki czemu możesz **odczytywać system plików hosta**.
* Jeśli chcesz **czuć się jak na hoście**, ale być w kontenerze, możesz wyłączyć inne mechanizmy obronne, używając flag takich jak:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> To jest podobne do poprzedniej metody, ale tutaj **montujemy dysk urządzenia**. Następnie w kontenerze uruchom polecenie `mount /dev/sda1 /mnt` i będziesz mógł **uzyskać dostęp** do **systemu plików hosta** w `/mnt`
* Uruchom polecenie `fdisk -l` na hoście, aby znaleźć urządzenie `</dev/sda1>`, które można zamontować
* **`-v /tmp:/host`** -> Jeśli z jakiegoś powodu możesz **tylko zamontować pewien katalog** z hosta i masz dostęp wewnątrz hosta. Zamontuj go i utwórz **`/bin/bash`** z **suid** w zamontowanym katalogu, aby można go było **wykonać z hosta i eskalować uprawnienia do roota**.

{% hint style="info" %}
Zwróć uwagę, że być może nie możesz zamontować folderu `/tmp`, ale możesz zamontować **inny zapisywalny folder**. Możesz znaleźć zapisywalne katalogi, używając polecenia: `find / -writable -type d 2>/dev/null`

**Zwróć uwagę, że nie wszystkie katalogi w maszynie Linux będą obsługiwać bit suid!** Aby sprawdzić, które katalogi obsługują bit suid, uruchom polecenie `mount | grep -v "nosuid"`. Na przykład zazwyczaj `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` nie obsługują bitu suid.

Zwróć również uwagę, że jeśli możesz **zamontować `/etc`** lub dowolny inny folder **zawierający pliki konfiguracyjne**, możesz je zmienić z kontenera Docker jako root, aby **wykorzystać je na hoście** i eskalować uprawnienia (może zmieniając `/etc/shadow`)
{% endhint %}

### Ucieczka z kontenera

* **`--privileged`** -> Za pomocą tej flagi [usuwasz wszystkie izolacje z kontenera](docker-privileged.md#what-affects). Sprawdź techniki [ucieczki z uprzywilejowanych kontenerów jako root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Aby [eskalować uprawnienia, wykorzystując zdolności](../linux-capabilities.md), **przyznaj tej zdolności kontenerowi** i wyłącz inne metody ochrony, które mogą uniemożliwić działanie eksploitu.

### Curl

Na tej stronie omówiliśmy sposoby eskalacji uprawnień za pomocą flag dockerowych, możesz znaleźć **sposoby wykorzystania tych metod za pomocą polecenia curl** na stronie:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
