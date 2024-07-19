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

Il y a des occasions où vous avez juste **accès au socket docker** et vous voulez l'utiliser pour **escalader les privilèges**. Certaines actions peuvent être très suspectes et vous voudrez peut-être les éviter, donc ici vous pouvez trouver différents drapeaux qui peuvent être utiles pour escalader les privilèges :

### Via mount

Vous pouvez **monter** différentes parties du **système de fichiers** dans un conteneur s'exécutant en tant que root et **y accéder**.\
Vous pourriez également **abuser d'un montage pour escalader les privilèges** à l'intérieur du conteneur.

* **`-v /:/host`** -> Montez le système de fichiers de l'hôte dans le conteneur afin que vous puissiez **lire le système de fichiers de l'hôte.**
* Si vous voulez **vous sentir comme si vous étiez sur l'hôte** mais être dans le conteneur, vous pourriez désactiver d'autres mécanismes de défense en utilisant des drapeaux comme :
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Cela est similaire à la méthode précédente, mais ici nous **montons le disque de l'appareil**. Ensuite, à l'intérieur du conteneur, exécutez `mount /dev/sda1 /mnt` et vous pouvez **accéder** au **système de fichiers de l'hôte** dans `/mnt`
* Exécutez `fdisk -l` sur l'hôte pour trouver le dispositif `</dev/sda1>` à monter
* **`-v /tmp:/host`** -> Si pour une raison quelconque vous ne pouvez **monter qu'un répertoire** de l'hôte et que vous avez accès à l'intérieur de l'hôte. Montez-le et créez un **`/bin/bash`** avec **suid** dans le répertoire monté afin que vous puissiez **l'exécuter depuis l'hôte et escalader vers root**.

{% hint style="info" %}
Notez que vous ne pouvez peut-être pas monter le dossier `/tmp` mais vous pouvez monter un **autre dossier écrivable**. Vous pouvez trouver des répertoires écrits en utilisant : `find / -writable -type d 2>/dev/null`

**Notez que tous les répertoires d'une machine linux ne prendront pas en charge le bit suid !** Pour vérifier quels répertoires prennent en charge le bit suid, exécutez `mount | grep -v "nosuid"` Par exemple, généralement `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` et `/var/lib/lxcfs` ne prennent pas en charge le bit suid.

Notez également que si vous pouvez **monter `/etc`** ou tout autre dossier **contenant des fichiers de configuration**, vous pouvez les modifier depuis le conteneur docker en tant que root afin de **les abuser sur l'hôte** et escalader les privilèges (peut-être en modifiant `/etc/shadow`)
{% endhint %}

### Escaping from the container

* **`--privileged`** -> Avec ce drapeau, vous [supprimez toute l'isolation du conteneur](docker-privileged.md#what-affects). Vérifiez les techniques pour [s'échapper des conteneurs privilégiés en tant que root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Pour [escalader en abusant des capacités](../linux-capabilities.md), **accordez cette capacité au conteneur** et désactivez d'autres méthodes de protection qui pourraient empêcher l'exploitation de fonctionner.

### Curl

Dans cette page, nous avons discuté des moyens d'escalader les privilèges en utilisant des drapeaux docker, vous pouvez trouver **des moyens d'abuser de ces méthodes en utilisant la commande curl** sur la page :

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
