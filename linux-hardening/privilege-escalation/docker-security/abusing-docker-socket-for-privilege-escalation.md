# Abuser du Socket Docker pour l'Élévation de Privilèges

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Il y a des occasions où vous avez simplement **accès au socket docker** et vous souhaitez l'utiliser pour **élever les privilèges**. Certaines actions peuvent être très suspectes et vous voudrez peut-être les éviter, donc ici vous pouvez trouver différents drapeaux qui peuvent être utiles pour élever les privilèges :

### Via mount

Vous pouvez **monter** différentes parties du **système de fichiers** dans un conteneur exécuté en tant que root et y **accéder**.\
Vous pourriez également **abuser d'un montage pour élever les privilèges** à l'intérieur du conteneur.

* **`-v /:/host`** -> Montez le système de fichiers de l'hôte dans le conteneur pour pouvoir **lire le système de fichiers de l'hôte.**
* Si vous voulez **vous sentir comme si vous étiez sur l'hôte** tout en étant dans le conteneur, vous pourriez désactiver d'autres mécanismes de défense en utilisant des drapeaux comme :
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> C'est similaire à la méthode précédente, mais ici nous **montons le disque du périphérique**. Ensuite, dans le conteneur exécutez `mount /dev/sda1 /mnt` et vous pouvez **accéder** au **système de fichiers de l'hôte** dans `/mnt`
* Exécutez `fdisk -l` sur l'hôte pour trouver le périphérique `</dev/sda1>` à monter
* **`-v /tmp:/host`** -> Si pour une raison quelconque vous pouvez **juste monter un répertoire** de l'hôte et que vous y avez accès. Montez-le et créez un **`/bin/bash`** avec **suid** dans le répertoire monté afin que vous puissiez **l'exécuter depuis l'hôte et passer à root**.

{% hint style="info" %}
Notez que peut-être vous ne pouvez pas monter le dossier `/tmp` mais vous pouvez monter un **dossier inscriptible différent**. Vous pouvez trouver des répertoires inscriptibles en utilisant : `find / -writable -type d 2>/dev/null`

**Notez que tous les répertoires d'une machine linux ne supporteront pas le bit suid !** Pour vérifier quels répertoires supportent le bit suid, exécutez `mount | grep -v "nosuid"` Par exemple, habituellement `/dev/shm` , `/run` , `/proc` , `/sys/fs/cgroup` et `/var/lib/lxcfs` ne supportent pas le bit suid.

Notez également que si vous pouvez **monter `/etc`** ou tout autre dossier **contenant des fichiers de configuration**, vous pouvez les modifier depuis le conteneur docker en tant que root afin de **les abuser sur l'hôte** et élever les privilèges (peut-être en modifiant `/etc/shadow`)
{% endhint %}

### S'échapper du conteneur

* **`--privileged`** -> Avec ce drapeau, vous [supprimez toute l'isolation du conteneur](docker-privileged.md#what-affects). Consultez les techniques pour [s'échapper des conteneurs privilégiés en tant que root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Pour [élever les privilèges en abusant des capacités](../linux-capabilities.md), **accordez cette capacité au conteneur** et désactivez d'autres méthodes de protection qui pourraient empêcher l'exploit de fonctionner.

### Curl

Dans cette page, nous avons discuté des moyens d'élever les privilèges en utilisant des drapeaux docker, vous pouvez trouver **des moyens d'abuser de ces méthodes en utilisant la commande curl** dans la page :

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
