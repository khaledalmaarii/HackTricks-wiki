# Abus de la socket Docker pour l'escalade de privilèges

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Il arrive parfois que vous ayez simplement **accès à la socket Docker** et que vous souhaitiez l'utiliser pour **escalader les privilèges**. Certaines actions peuvent être très suspectes et vous voudrez peut-être les éviter, vous trouverez donc ici différents indicateurs qui peuvent être utiles pour escalader les privilèges :

### Via le montage

Vous pouvez **monter** différentes parties du **système de fichiers** dans un conteneur en cours d'exécution en tant que root et **y accéder**.\
Vous pouvez également **abuser d'un montage pour escalader les privilèges** à l'intérieur du conteneur.

* **`-v /:/host`** -> Montez le système de fichiers de l'hôte dans le conteneur pour que vous puissiez **lire le système de fichiers de l'hôte.**
  * Si vous voulez **vous sentir comme sur l'hôte** mais être dans le conteneur, vous pouvez désactiver d'autres mécanismes de défense en utilisant des indicateurs tels que :
    * `--privileged`
    * `--cap-add=ALL`
    * `--security-opt apparmor=unconfined`
    * `--security-opt seccomp=unconfined`
    * `-security-opt label:disable`
    * `--pid=host`
    * `--userns=host`
    * `--uts=host`
    * `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Ceci est similaire à la méthode précédente, mais ici nous sommes en train de **monter le disque de l'appareil**. Ensuite, à l'intérieur du conteneur, exécutez `mount /dev/sda1 /mnt` et vous pouvez **accéder** au **système de fichiers de l'hôte** dans `/mnt`
  * Exécutez `fdisk -l` sur l'hôte pour trouver le périphérique `</dev/sda1>` à monter
* **`-v /tmp:/host`** -> Si pour une raison quelconque vous ne pouvez **monter qu'un répertoire** de l'hôte et que vous y avez accès à l'intérieur de l'hôte. Montez-le et créez un **`/bin/bash`** avec **suid** dans le répertoire monté afin que vous puissiez **l'exécuter depuis l'hôte et escalader vers root**.

{% hint style="info" %}
Notez que vous ne pouvez peut-être pas monter le dossier `/tmp` mais vous pouvez monter un **répertoire différent accessible en écriture**. Vous pouvez trouver des répertoires accessibles en écriture en utilisant : `find / -writable -type d 2>/dev/null`

**Notez que tous les répertoires d'une machine Linux ne prendront pas en charge le bit suid !** Pour vérifier quels répertoires prennent en charge le bit suid, exécutez `mount | grep -v "nosuid"`. Par exemple, généralement `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` et `/var/lib/lxcfs` ne prennent pas en charge le bit suid.

Notez également que si vous pouvez **monter `/etc`** ou tout autre dossier **contenant des fichiers de configuration**, vous pouvez les modifier à partir du conteneur Docker en tant que root afin de **les abuser sur l'hôte** et d'escalader les privilèges (peut-être en modifiant `/etc/shadow`).
{% endhint %}

### Évasion du conteneur

* **`--privileged`** -> Avec cet indicateur, vous [supprimez toute l'isolation du conteneur](docker-privileged.md#what-affects). Consultez les techniques pour [s'échapper des conteneurs privilégiés en tant que root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Pour [escalader en abusant des capacités](../linux-capabilities.md), **accordez cette capacité au conteneur** et désactivez d'autres méthodes de protection qui pourraient empêcher l'exploit de fonctionner.

### Curl

Dans cette page, nous avons discuté des moyens d'escalader les privilèges en utilisant des indicateurs Docker, vous pouvez trouver des **moyens d'abuser de ces méthodes en utilisant la commande curl** dans la page :

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlo
