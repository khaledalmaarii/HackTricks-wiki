# Docker --privileged

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

## 影響するもの

特権コンテナを実行すると、無効にする保護は次のとおりです。

### /devのマウント

特権コンテナでは、すべての**デバイスが`/dev/`でアクセス可能です**。したがって、ホストのディスクを**マウント**することで**エスケープ**できます。

{% tabs %}
{% tab title="デフォルトコンテナ内" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="特権コンテナ内" %}
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

### 読み取り専用のカーネルファイルシステム

カーネルファイルシステムは、プロセスがカーネルの動作を変更するためのメカニズムを提供します。しかし、コンテナプロセスに関しては、カーネルに対する変更を防ぎたいと考えています。したがって、カーネルファイルシステムをコンテナ内で**読み取り専用**としてマウントし、コンテナプロセスがカーネルを変更できないようにします。

{% tabs %}
{% tab title="デフォルトコンテナ内" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="特権コンテナ内" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### カーネルファイルシステムのマスキング

**/proc** ファイルシステムは選択的に書き込み可能ですが、セキュリティのために、特定の部分は **tmpfs** でオーバーレイされ、コンテナプロセスが機密領域にアクセスできないように保護されています。

{% hint style="info" %}
**tmpfs** はすべてのファイルを仮想メモリに保存するファイルシステムです。tmpfs はハードドライブ上にファイルを作成しません。したがって、tmpfs ファイルシステムをアンマウントすると、その中に存在するすべてのファイルは永遠に失われます。
{% endhint %}

{% tabs %}
{% tab title="デフォルトコンテナ内" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="特権コンテナ内" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linuxの能力

コンテナエンジンは、デフォルトでコンテナ内で何が行われるかを制御するために、**限られた数の能力**でコンテナを起動します。**特権**のあるものは、**すべての** **能力**にアクセスできます。能力について学ぶには、次を読んでください：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="デフォルトコンテナ内" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="特権コンテナ内" %}
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

コンテナに対して `--privileged` モードで実行せずに、`--cap-add` および `--cap-drop` フラグを使用して利用可能な機能を操作できます。

### Seccomp

**Seccomp** は、コンテナが呼び出すことができる **syscalls** を **制限** するのに役立ちます。デフォルトの seccomp プロファイルは、docker コンテナを実行する際にデフォルトで有効ですが、特権モードでは無効になります。Seccomp についての詳細はこちらをご覧ください：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Inside default container" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="特権コンテナ内" %}
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
また、**Kubernetes** クラスターで Docker（または他の CRI）を使用する場合、**seccomp フィルターはデフォルトで無効**になっていることに注意してください。

### AppArmor

**AppArmor** は、**コンテナ** を **制限された** **リソース** の **セット** に制限するためのカーネル拡張で、**プログラムごとのプロファイル**を使用します。`--privileged` フラグを使用して実行すると、この保護は無効になります。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged` フラグを使用してコンテナを実行すると、**SELinux ラベル**が無効になり、通常は `unconfined` のコンテナエンジンのラベルを継承し、コンテナエンジンと同様のフルアクセスが付与されます。ルートレスモードでは `container_runtime_t` が使用され、ルートモードでは `spc_t` が適用されます。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## 影響を受けないもの

### ネームスペース

ネームスペースは **`--privileged` フラグの影響を受けません**。セキュリティ制約が有効になっていないにもかかわらず、**システム上のすべてのプロセスやホストネットワークを見ることはできません**。ユーザーは **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** コンテナエンジンフラグを使用して、個々のネームスペースを無効にすることができます。

{% tabs %}
{% tab title="デフォルトの特権コンテナ内" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="内部 --pid=host コンテナ" %}
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

### ユーザー名前空間

**デフォルトでは、コンテナエンジンはユーザー名前空間を利用しませんが、ルートレスコンテナはファイルシステムのマウントや複数のUIDを使用するためにそれを必要とします。** ルートレスコンテナに不可欠なユーザー名前空間は無効にできず、特権を制限することでセキュリティを大幅に向上させます。

## 参考文献

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

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
