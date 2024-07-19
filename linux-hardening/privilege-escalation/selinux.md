{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}


# SELinux w kontenerach

[Wprowadzenie i przykład z dokumentacji redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) to **system etykietowania**. Każdy **proces** i każdy **obiekt systemu plików** ma swoją **etykietę**. Polityki SELinux definiują zasady dotyczące tego, co **etykieta procesu może robić z innymi etykietami** w systemie.

Silniki kontenerów uruchamiają **procesy kontenerowe z jedną ograniczoną etykietą SELinux**, zazwyczaj `container_t`, a następnie ustawiają etykietę `container_file_t` dla plików wewnątrz kontenera. Zasady polityki SELinux zasadniczo mówią, że **procesy `container_t` mogą tylko odczytywać/zapisywać/wykonywać pliki oznaczone etykietą `container_file_t`**. Jeśli proces kontenerowy wydostanie się z kontenera i spróbuje zapisać zawartość na hoście, jądro Linuxa odmawia dostępu i pozwala procesowi kontenerowemu tylko na zapis do zawartości oznaczonej etykietą `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Użytkownicy SELinux

Istnieją użytkownicy SELinux oprócz zwykłych użytkowników Linuxa. Użytkownicy SELinux są częścią polityki SELinux. Każdy użytkownik Linuxa jest mapowany na użytkownika SELinux jako część polityki. Umożliwia to użytkownikom Linuxa dziedziczenie ograniczeń oraz zasad i mechanizmów bezpieczeństwa nałożonych na użytkowników SELinux.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
</details>
{% endhint %}
