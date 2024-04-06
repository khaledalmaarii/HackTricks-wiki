# Docker --privileged

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cosa viene influenzato

Quando esegui un container come privilegiato, queste sono le protezioni che disabiliti:

### Montaggio di /dev

In un container privilegiato, tutti i **dispositivi possono essere accessibili in `/dev/`**. Pertanto, è possibile **evadere** montando il disco dell'host.

{% tabs %}
{% tab title="All" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="All" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
{% endtab %}
{% endtabs %}

### Sistemi di file del kernel in sola lettura

I sistemi di file del kernel forniscono un meccanismo per un processo per modificare il comportamento del kernel. Tuttavia, quando si tratta di processi del contenitore, vogliamo impedire loro di apportare modifiche al kernel. Pertanto, montiamo i sistemi di file del kernel come **sola lettura** all'interno del contenitore, garantendo che i processi del contenitore non possano modificare il kernel.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="All" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Mascheramento dei file system del kernel

Il file system **/proc** è selettivamente scrivibile ma, per motivi di sicurezza, alcune parti sono protette da accessi in scrittura e lettura sovrapponendole con **tmpfs**, garantendo che i processi del contenitore non possano accedere ad aree sensibili.

{% hint style="info" %}
**tmpfs** è un file system che memorizza tutti i file nella memoria virtuale. tmpfs non crea alcun file sul disco rigido. Quindi, se smonti un file system tmpfs, tutti i file presenti al suo interno vengono persi per sempre.
{% endhint %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="All" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux capabilities

I motori dei container avviano i container con un **numero limitato di capabilities** per controllare ciò che accade all'interno del container per impostazione predefinita. Quelli **privilegiati** hanno **tutte** le **capabilities** accessibili. Per saperne di più sulle capabilities, leggi:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="All" %}
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

È possibile manipolare le capacità disponibili per un contenitore senza eseguire la modalità `--privileged` utilizzando i flag `--cap-add` e `--cap-drop`.

### Seccomp

**Seccomp** è utile per **limitare** le **chiamate di sistema** che un contenitore può effettuare. Un profilo Seccomp predefinito è abilitato di default quando si eseguono contenitori Docker, ma in modalità privilegiata è disabilitato. Per saperne di più su Seccomp, clicca qui:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="All" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="All" %}
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

Inoltre, nota che quando Docker (o altri CRIs) vengono utilizzati in un cluster **Kubernetes**, il filtro **seccomp è disabilitato per impostazione predefinita**.

### AppArmor

**AppArmor** è un miglioramento del kernel per confinare i **container** a un **insieme limitato di risorse** con **profili per programma**. Quando si esegue con il flag `--privileged`, questa protezione viene disabilitata.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```

### SELinux

L'esecuzione di un container con il flag `--privileged` disabilita le **etichette SELinux**, facendo sì che erediti l'etichetta del motore del container, di solito `unconfined`, concedendo pieno accesso simile al motore del container. In modalità senza privilegi, viene utilizzato `container_runtime_t`, mentre in modalità root viene applicato `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```

## Cosa non viene influenzato

### Namespaces

I namespace **NON sono influenzati** dal flag `--privileged`. Anche se non hanno abilitate le restrizioni di sicurezza, **non vedono tutti i processi del sistema o la rete dell'host, ad esempio**. Gli utenti possono disabilitare i singoli namespace utilizzando i flag `--pid=host`, `--net=host`, `--ipc=host`, `--uts=host` dei motori dei container.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="All" %}
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

### Spazio dei nomi utente

**Di default, i motori di container non utilizzano gli spazi dei nomi utente, ad eccezione dei container senza privilegi**, che li richiedono per il montaggio del file system e l'utilizzo di più UID. Gli spazi dei nomi utente, fondamentali per i container senza privilegi, non possono essere disabilitati e migliorano significativamente la sicurezza limitando i privilegi.

## Riferimenti

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al repository** [**hacktricks**](https://github.com/carlospolop/hacktricks) **e al repository** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
