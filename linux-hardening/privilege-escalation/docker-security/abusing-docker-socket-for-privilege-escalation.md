# Abusing Docker Socket for Privilege Escalation

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
{% endhint %}
{% endhint %}
{% endhint %}

Postoje situacije kada imate **pristup docker socket-u** i želite da ga iskoristite za **eskalaciju privilegija**. Neke akcije mogu biti veoma sumnjive i možda ćete želeti da ih izbegnete, pa ovde možete pronaći različite zastavice koje mogu biti korisne za eskalaciju privilegija:

### Via mount

Možete **montirati** različite delove **fajl sistema** u kontejneru koji radi kao root i **pristupiti** im.\
Takođe možete **zloupotrebiti montiranje za eskalaciju privilegija** unutar kontejnera.

* **`-v /:/host`** -> Montirajte fajl sistem host-a u kontejneru kako biste mogli da **pročitate fajl sistem host-a.**
* Ako želite da **imajte osećaj da ste na host-u** dok ste u kontejneru, možete onemogućiti druge mehanizme zaštite koristeći zastavice kao što su:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Ovo je slično prethodnoj metodi, ali ovde montiramo **disk uređaj**. Zatim, unutar kontejnera pokrenite `mount /dev/sda1 /mnt` i možete **pristupiti** **fajl sistemu host-a** u `/mnt`
* Pokrenite `fdisk -l` na host-u da pronađete `</dev/sda1>` uređaj za montiranje
* **`-v /tmp:/host`** -> Ako iz nekog razloga možete **samo montirati neki direktorijum** sa host-a i imate pristup unutar host-a. Montirajte ga i kreirajte **`/bin/bash`** sa **suid** u montiranom direktorijumu kako biste mogli da **izvršite iz host-a i eskalirate na root**.

{% hint style="info" %}
Imajte na umu da možda ne možete montirati folder `/tmp`, ali možete montirati **drugi zapisiv folder**. Možete pronaći zapisive direktorijume koristeći: `find / -writable -type d 2>/dev/null`

**Imajte na umu da ne podržavaju svi direktorijumi na linux mašini suid bit!** Da biste proverili koji direktorijumi podržavaju suid bit, pokrenite `mount | grep -v "nosuid"` Na primer, obično `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` ne podržavaju suid bit.

Takođe imajte na umu da ako možete **montirati `/etc`** ili bilo koji drugi folder **koji sadrži konfiguracione fajlove**, možete ih promeniti iz docker kontejnera kao root kako biste **zloupotrebili na host-u** i eskalirali privilegije (možda menjajući `/etc/shadow`)
{% endhint %}

### Escaping from the container

* **`--privileged`** -> Sa ovom zastavicom [uklanjate svu izolaciju iz kontejnera](docker-privileged.md#what-affects). Proverite tehnike za [izlazak iz privilegovanih kontejnera kao root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Da biste [eskalirali zloupotrebom sposobnosti](../linux-capabilities.md), **dodelite tu sposobnost kontejneru** i onemogućite druge metode zaštite koje mogu sprečiti da eksploatacija funkcioniše.

### Curl

Na ovoj stranici smo razgovarali o načinima za eskalaciju privilegija koristeći docker zastavice, možete pronaći **načine da zloupotrebite ove metode koristeći curl** komandu na stranici:

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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
