# Docker --privileged

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅이 되는 AWS 해킹</strong>을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* \*\*[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)\*\*에 PR을 제출하여 여러분의 해킹 기교를 공유해주세요.

</details>

## 영향을 미치는 요소

특권이 부여된 컨테이너를 실행할 때 다음과 같은 보호 기능이 비활성화됩니다:

### /dev 마운트

특권이 부여된 컨테이너에서는 모든 **장치에 `/dev/`에서 접근**할 수 있습니다. 따라서 호스트의 디스크를 **마운트**하여 **탈출**할 수 있습니다.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="권한이 부여된 컨테이너 내부" %}
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

### 읽기 전용 커널 파일 시스템

커널 파일 시스템은 프로세스가 커널의 동작을 수정하는 메커니즘을 제공합니다. 그러나 컨테이너 프로세스의 경우 커널에 대한 모든 변경을 방지하고자 합니다. 따라서 컨테이너 내에서 커널 파일 시스템을 **읽기 전용**으로 마운트하여 컨테이너 프로세스가 커널을 수정할 수 없도록 합니다.

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

{% tab title="권한이 부여된 컨테이너 내부" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### 커널 파일 시스템에 대한 가리기

**/proc** 파일 시스템은 선택적으로 쓰기 가능하지만 보안을 위해 일부 부분은 **tmpfs**로 오버레이하여 쓰기 및 읽기 액세스를 차단하여 컨테이너 프로세스가 민감한 영역에 액세스할 수 없도록 합니다.

{% hint style="info" %}
**tmpfs**는 모든 파일을 가상 메모리에 저장하는 파일 시스템입니다. tmpfs는 하드 드라이브에 파일을 생성하지 않습니다. 따라서 tmpfs 파일 시스템을 마운트 해제하면 그 안에 있는 모든 파일이 영원히 손실됩니다.
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

{% tab title="권한이 부여된 컨테이너 내부" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux capabilities

컨테이너 엔진은 기본적으로 컨테이너 내부에서 발생하는 작업을 제어하기 위해 **제한된 수의 기능**으로 컨테이너를 실행합니다. **Privileged** 컨테이너는 **모든** **기능**에 접근할 수 있습니다. 기능에 대해 자세히 알아보려면 다음을 참조하십시오:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="기본 컨테이너 내부" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="권한이 부여된 컨테이너 내부" %}
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

`--cap-add` allows you to add specific capabilities to a container, while `--cap-drop` allows you to drop specific capabilities from a container.

For example, to add the `SYS_PTRACE` capability to a container, you can use the following command:

```bash
docker run --cap-add=SYS_PTRACE <image>
```

To drop the `SYS_ADMIN` capability from a container, you can use the following command:

```bash
docker run --cap-drop=SYS_ADMIN <image>
```

By manipulating the capabilities of a container, you can control the level of access it has to the host system. This can be useful for hardening the security of your Docker environment.

```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```

```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```

```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```

또한, Docker (또는 다른 CRIs)가 **Kubernetes** 클러스터에서 사용될 때, **seccomp 필터는 기본적으로 비활성화**됩니다.

### AppArmor

**AppArmor**은 **컨테이너**를 **제한된** 리소스 집합과 **프로그램별 프로파일**로 제한하는 커널 개선 기능입니다. `--privileged` 플래그로 실행할 때, 이 보호 기능은 비활성화됩니다.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```

### SELinux

`--privileged` 플래그를 사용하여 컨테이너를 실행하면 **SELinux 레이블**이 비활성화되어 컨테이너 엔진의 레이블을 상속하게 됩니다. 일반적으로 `unconfined`로 설정되어 컨테이너 엔진과 유사한 완전한 액세스 권한을 부여합니다. 루트리스 모드에서는 `container_runtime_t`를 사용하고 루트 모드에서는 `spc_t`가 적용됩니다.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```

## 영향을 주지 않는 요소

### 네임스페이스

네임스페이스는 `--privileged` 플래그에 **영향을 받지 않습니다**. 비록 보안 제약이 활성화되지 않았지만, 예를 들어 시스템의 모든 프로세스나 호스트 네트워크를 볼 수는 없습니다. 사용자는 **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** 컨테이너 엔진 플래그를 사용하여 개별 네임스페이스를 비활성화할 수 있습니다.

{% tabs %}
{% tab title="기본 권한이 있는 컨테이너 내부" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="호스트 내부 --pid=host 컨테이너" %}
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

### 사용자 네임스페이스

**기본적으로, 컨테이너 엔진은 사용자 네임스페이스를 사용하지 않습니다. 단, rootless 컨테이너는 파일 시스템 마운트와 여러 UID 사용을 위해 사용자 네임스페이스를 필요로 합니다.** rootless 컨테이너에 필수적인 사용자 네임스페이스는 비활성화할 수 없으며, 권한을 제한하여 보안을 크게 강화합니다.

## 참고 자료

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 광고하고 싶으신가요**? 또는 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* \*\*[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)\*\*에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
