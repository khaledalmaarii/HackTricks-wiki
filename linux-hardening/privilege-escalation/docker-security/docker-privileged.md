## Docker --privileged

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Qu'est-ce qui est affecté

Lorsque vous exécutez un conteneur en mode privilégié, vous désactivez les protections suivantes :

### Montage /dev

Dans un conteneur privilégié, tous les **périphériques peuvent être accédés dans `/dev/`**. Par conséquent, vous pouvez **échapper** en **montant** le disque de l'hôte.

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

Les systèmes de fichiers du noyau fournissent un mécanisme permettant à un processus de modifier la façon dont le noyau s'exécute. Par défaut, nous ne voulons pas que les processus de conteneurs modifient le noyau, nous montons donc les systèmes de fichiers du noyau en lecture seule dans le conteneur.
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
{% endtab %}
{% tab title="Masquage des systèmes de fichiers du noyau" %}

Le système de fichiers **/proc** est conscient de l'espace de noms et certaines écritures peuvent être autorisées, donc nous ne le montons pas en lecture seule. Cependant, des répertoires spécifiques dans le système de fichiers /proc doivent être **protégés contre l'écriture**, et dans certains cas, **contre la lecture**. Dans ces cas, les moteurs de conteneurs montent des systèmes de fichiers **tmpfs** sur des répertoires potentiellement dangereux, empêchant les processus à l'intérieur du conteneur de les utiliser.

{% hint style="info" %}
**tmpfs** est un système de fichiers qui stocke tous les fichiers en mémoire virtuelle. tmpfs ne crée aucun fichier sur votre disque dur. Donc, si vous démontez un système de fichiers tmpfs, tous les fichiers qui y résident sont perdus pour toujours.
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
{% endtab %}
{% tab title="Dans le conteneur par défaut" %}

Les moteurs de conteneurs lancent les conteneurs avec un **nombre limité de capacités** pour contrôler ce qui se passe à l'intérieur du conteneur par défaut. Les capacités **privilégiées** ont **toutes** les **capacités** accessibles. Pour en savoir plus sur les capacités, consultez :

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% endtab %}
{% endtabs %}
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
{% tab title="Sécurité Docker" %}
Vous pouvez manipuler les capacités disponibles pour un conteneur sans exécuter en mode `--privileged` en utilisant les indicateurs `--cap-add` et `--cap-drop`.

### Seccomp

**Seccomp** est utile pour **limiter** les **appels système** qu'un conteneur peut effectuer. Un profil Seccomp par défaut est activé par défaut lors de l'exécution de conteneurs Docker, mais en mode privilégié, il est désactivé. En savoir plus sur Seccomp ici:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="À l'intérieur du conteneur par défaut" %}
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

{% endtab %}
{% endtabs %}

Dans le cas où vous devez utiliser `--privileged` pour exécuter un conteneur, il est recommandé de limiter les capacités du conteneur en utilisant `--cap-drop` et `--cap-add`. Par exemple, si vous avez besoin de monter un système de fichiers, vous pouvez ajouter la capacité `SYS_ADMIN` avec `--cap-add SYS_ADMIN` au lieu d'utiliser `--privileged`.

De plus, il est recommandé de ne pas exécuter de conteneurs avec `--privileged` sur des hôtes partagés ou des hôtes qui exécutent des charges de travail non fiables. Cela peut entraîner des fuites de données et des compromis de sécurité.
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Notez également que lorsque Docker (ou d'autres CRIs) est utilisé dans un cluster **Kubernetes**, le filtre **seccomp** est désactivé par défaut.

**AppArmor** est une amélioration du noyau pour confiner les **conteneurs** à un ensemble **limité** de **ressources** avec des **profils par programme**. Lorsque vous exécutez avec le drapeau `--privileged`, cette protection est désactivée.
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Lorsque vous exécutez avec le drapeau `--privileged`, **les étiquettes SELinux sont désactivées**, et le conteneur s'exécute avec l'**étiquette avec laquelle le moteur de conteneur a été exécuté**. Cette étiquette est généralement `unconfined` et a **un accès complet aux étiquettes que le moteur de conteneur a**. En mode sans privilège, le conteneur s'exécute avec `container_runtime_t`. En mode root, il s'exécute avec `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Ce qui n'est pas affecté

### Espaces de noms

Les espaces de noms ne sont **PAS affectés** par le drapeau `--privileged`. Même s'ils n'ont pas les contraintes de sécurité activées, ils **ne voient pas tous les processus du système ou du réseau hôte, par exemple**. Les utilisateurs peuvent désactiver des espaces de noms individuels en utilisant les drapeaux des moteurs de conteneurs **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="À l'intérieur d'un conteneur privilégié par défaut" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
    1 root      0:00 sh
   18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Conteneur --pid=host interne" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
    1 root      0:03 /sbin/init
    2 root      0:00 [kthreadd]
    3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
### Espace de noms utilisateur

Les moteurs de conteneurs **N'utilisent PAS l'espace de noms utilisateur par défaut**. Cependant, les conteneurs sans privilèges l'utilisent toujours pour monter des systèmes de fichiers et utiliser plus d'un seul UID. Dans le cas sans privilèges, l'espace de noms utilisateur ne peut pas être désactivé; il est nécessaire pour exécuter des conteneurs sans privilèges. Les espaces de noms utilisateur empêchent certains privilèges et ajoutent une sécurité considérable.

## Références

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
