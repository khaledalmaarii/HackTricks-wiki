<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>


# SELinux w kontenerach

[Wprowadzenie i przykład z dokumentacji redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) to **system oznaczania**. Każdy **proces** i każdy **obiekt systemu plików** ma **oznaczenie**. Polityki SELinux definiują zasady dotyczące tego, co **oznaczenie procesu jest dozwolone do zrobienia z innymi oznaczeniami** w systemie.

Silniki kontenerów uruchamiają **procesy kontenerów z pojedynczym ograniczonym oznaczeniem SELinux**, zwykle `container_t`, a następnie ustawiają kontener wewnątrz kontenera, aby był oznaczony jako `container_file_t`. Zasady polityki SELinux mówią w zasadzie, że **procesy `container_t` mogą tylko czytać/pisać/wykonująć pliki oznaczone jako `container_file_t`**. Jeśli proces kontenera ucieka z kontenera i próbuje zapisywać zawartość na hoście, jądro Linuxa odmawia dostępu i pozwala procesowi kontenera zapisywać tylko do zawartości oznaczonej jako `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Użytkownicy SELinux

W systemie SELinux istnieją użytkownicy SELinux, którzy są dodatkowi do zwykłych użytkowników systemu Linux. Użytkownicy SELinux są częścią polityki SELinux. Każdy użytkownik Linuxa jest mapowany na użytkownika SELinux jako część tej polityki. Dzięki temu użytkownicy Linuxa dziedziczą ograniczenia oraz zasady bezpieczeństwa, które są nakładane na użytkowników SELinux.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do repozytoriów** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
