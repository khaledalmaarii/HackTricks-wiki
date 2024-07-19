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


# SELinux in Containern

[Einführung und Beispiel aus den Red Hat-Dokumenten](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) ist ein **Kennzeichnungssystem**. Jedes **Prozess** und jedes **Dateisystemobjekt** hat ein **Label**. SELinux-Richtlinien definieren Regeln darüber, was ein **Prozesslabel mit allen anderen Labels** im System tun darf.

Container-Engines starten **Containerprozesse mit einem einzigen eingeschränkten SELinux-Label**, normalerweise `container_t`, und setzen dann den Container innerhalb des Containers auf das Label `container_file_t`. Die SELinux-Richtlinien besagen im Wesentlichen, dass die **`container_t` Prozesse nur Dateien lesen/schreiben/ausführen können, die mit `container_file_t` gekennzeichnet sind**. Wenn ein Containerprozess den Container verlässt und versucht, auf Inhalte auf dem Host zu schreiben, verweigert der Linux-Kernel den Zugriff und erlaubt dem Containerprozess nur, auf Inhalte zu schreiben, die mit `container_file_t` gekennzeichnet sind.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux-Benutzer

Es gibt SELinux-Benutzer zusätzlich zu den regulären Linux-Benutzern. SELinux-Benutzer sind Teil einer SELinux-Richtlinie. Jeder Linux-Benutzer wird im Rahmen der Richtlinie einem SELinux-Benutzer zugeordnet. Dies ermöglicht es Linux-Benutzern, die Einschränkungen und Sicherheitsregeln sowie -mechanismen zu erben, die auf SELinux-Benutzer angewendet werden.
