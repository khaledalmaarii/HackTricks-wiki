# Docker --privileged

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Quels sont les impacts

Lorsque vous exécutez un conteneur en mode privilégié, voici les protections que vous désactivez :

### Monter /dev

Dans un conteneur privilégié, tous les **appareils peuvent être accédés dans `/dev/`**. Par conséquent, vous pouvez **échapper** en **montant** le disque de l'hôte.

{% tabs %}
{% tab title="À l'intérieur du conteneur par défaut" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="À l'intérieur du conteneur privilégié" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
### Systèmes de fichiers du noyau en lecture seule

Les systèmes de fichiers du noyau fournissent un mécanisme permettant à un processus de modifier le comportement du noyau. Cependant, en ce qui concerne les processus de conteneurs, nous voulons les empêcher de faire des modifications au noyau. Par conséquent, nous montons les systèmes de fichiers du noyau en **lecture seule** à l'intérieur du conteneur, garantissant que les processus du conteneur ne peuvent pas modifier le noyau.

{% tabs %}
{% tab title="À l'intérieur du conteneur par défaut" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="À l'intérieur du conteneur privilégié" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
### Masquage des systèmes de fichiers du noyau

Le système de fichiers **/proc** est sélectivement inscriptible mais, pour des raisons de sécurité, certaines parties sont protégées contre l'écriture et la lecture en les superposant avec **tmpfs**, garantissant que les processus du conteneur ne peuvent pas accéder à des zones sensibles.

{% hint style="info" %}
**tmpfs** est un système de fichiers qui stocke tous les fichiers en mémoire virtuelle. tmpfs ne crée aucun fichier sur votre disque dur. Ainsi, si vous démontez un système de fichiers tmpfs, tous les fichiers qui y résident sont perdus pour toujours.
{% endhint %}

{% tabs %}
{% tab title="À l'intérieur du conteneur par défaut" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="À l'intérieur du conteneur privilégié" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
### Capacités Linux

Les moteurs de conteneurs lancent les conteneurs avec un **nombre limité de capacités** pour contrôler ce qui se passe à l'intérieur du conteneur par défaut. Les conteneurs **privilégiés** ont **toutes** les **capacités** accessibles. Pour en savoir plus sur les capacités, consultez :

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="À l'intérieur du conteneur par défaut" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="À l'intérieur du conteneur privilégié" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

Vous pouvez manipuler les capacités disponibles pour un conteneur sans exécuter en mode `--privileged` en utilisant les indicateurs `--cap-add` et `--cap-drop`.

### Seccomp

**Seccomp** est utile pour **limiter** les **appels systèmes** qu'un conteneur peut effectuer. Un profil Seccomp par défaut est activé par défaut lors de l'exécution de conteneurs Docker, mais en mode privilégié, il est désactivé. En savoir plus sur Seccomp ici :

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="À l'intérieur du conteneur privilégié" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Également, notez que lorsque Docker (ou d'autres CRIs) sont utilisés dans un cluster **Kubernetes**, le filtre **seccomp est désactivé par défaut**

### AppArmor

**AppArmor** est une amélioration du noyau pour confiner les **containers** à un **ensemble limité de **ressources** avec des **profils par programme**. Lorsque vous exécutez avec le drapeau `--privileged`, cette protection est désactivée.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

L'exécution d'un conteneur avec le drapeau `--privileged` désactive les **étiquettes SELinux**, le faisant hériter de l'étiquette du moteur de conteneurs, généralement `unconfined`, accordant un accès complet similaire au moteur de conteneurs. En mode sans privilège, il utilise `container_runtime_t`, tandis qu'en mode root, `spc_t` est appliqué.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Ce qui n'affecte pas

### Espaces de noms

Les espaces de noms ne sont **PAS affectés** par le drapeau `--privileged`. Même s'ils n'ont pas les contraintes de sécurité activées, ils **ne voient pas tous les processus sur le système ou le réseau hôte, par exemple**. Les utilisateurs peuvent désactiver des espaces de noms individuels en utilisant les drapeaux des moteurs de conteneurs **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="À l'intérieur du conteneur privilégié par défaut" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="À l'intérieur du conteneur --pid=host" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### Espace utilisateur

**Par défaut, les moteurs de conteneurs n'utilisent pas les espaces utilisateurs, sauf pour les conteneurs sans privilèges**, qui les nécessitent pour le montage du système de fichiers et l'utilisation de plusieurs UID. Les espaces utilisateurs, essentiels pour les conteneurs sans privilèges, ne peuvent pas être désactivés et améliorent considérablement la sécurité en restreignant les privilèges.

## Références

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
