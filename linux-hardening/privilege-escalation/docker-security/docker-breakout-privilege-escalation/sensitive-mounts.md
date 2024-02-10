<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


`/proc` 및 `/sys`의 적절한 네임스페이스 격리 없이 노출되면 공격 표면 확장 및 정보 노출과 같은 중대한 보안 위험을 초래할 수 있습니다. 이러한 디렉토리에는 잘못 구성되거나 권한이 없는 사용자에 의해 액세스되는 경우 컨테이너 탈출, 호스트 수정 또는 추가 공격에 도움이 되는 정보를 제공할 수 있는 민감한 파일이 포함되어 있습니다. 예를 들어, `-v /proc:/host/proc`를 잘못 마운트하면 경로 기반 특성으로 인해 AppArmor 보호가 우회될 수 있으며, `/host/proc`가 보호되지 않게 됩니다.

**각 잠재적인 취약점에 대한 자세한 내용은 [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)에서 찾을 수 있습니다.**

# procfs 취약점

## `/proc/sys`
이 디렉토리는 일반적으로 `sysctl(2)`를 통해 커널 변수를 수정할 수 있도록 허용하며, 관련된 여러 하위 디렉토리가 포함되어 있습니다:

### **`/proc/sys/kernel/core_pattern`**
- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html)에서 설명되어 있습니다.
- 첫 128바이트를 인수로 사용하여 코어 파일 생성 시 실행할 프로그램을 정의할 수 있습니다. 파일이 파이프 `|`로 시작하는 경우 코드 실행으로 이어질 수 있습니다.
- **테스트 및 Exploitation 예시**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 쓰기 액세스 테스트
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # 사용자 정의 핸들러 설정
sleep 5 && ./crash & # 핸들러 트리거
```

### **`/proc/sys/kernel/modprobe`**
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 자세히 설명되어 있습니다.
- 커널 모듈 로더의 경로를 포함하며, 커널 모듈을 로드하기 위해 호출됩니다.
- **액세스 확인 예시**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobe에 대한 액세스 확인
```

### **`/proc/sys/vm/panic_on_oom`**
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 참조됩니다.
- OOM 조건이 발생할 때 커널이 패닉 또는 OOM 킬러를 호출하는 전역 플래그입니다.

### **`/proc/sys/fs`**
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에 따르면 파일 시스템에 대한 옵션 및 정보가 포함되어 있습니다.
- 쓰기 액세스는 호스트에 대한 다양한 서비스 거부 공격을 활성화할 수 있습니다.

### **`/proc/sys/fs/binfmt_misc`**
- 마법 번호를 기반으로 비네이티브 이진 형식에 대한 인터프리터를 등록할 수 있습니다.
- `/proc/sys/fs/binfmt_misc/register`가 쓰기 가능한 경우 권한 상승 또는 루트 쉘 액세스로 이어질 수 있습니다.
- 관련된 exploit 및 설명:
- [binfmt_misc를 통한 가난한 사람의 루트킷](https://github.com/toffan/binfmt_misc)
- 깊이 있는 튜토리얼: [비디오 링크](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## `/proc`의 기타 항목

### **`/proc/config.gz`**
- `CONFIG_IKCONFIG_PROC`가 활성화된 경우 커널 구성을 노출할 수 있습니다.
- 실행 중인 커널에서 취약점을 식별하는 데 유용합니다.

### **`/proc/sysrq-trigger`**
- Sysrq 명령을 호출할 수 있으며, 즉시 시스템 재부팅이나 기타 중요한 작업을 일으킬 수 있습니다.
- **호스트 재부팅 예시**:
```bash
echo b > /proc/sysrq-trigger # 호스트 재부팅
```

### **`/proc/kmsg`**
- 커널 링 버퍼 메시지를 노출합니다.
- 커널 exploits, 주소 누출 및 민감한 시스템 정보 제공에 도움이 될 수 있습니다.

### **`/proc/kallsyms`**
- 커널 내보낸 심볼과 해당 주소를 나열합니다.
- 특히 KASLR을 극복하기 위해 커널 exploit 개발에 필수적입니다.
- 주소 정보는 `kptr_restrict`가 `1` 또는 `2`로 설정된 경우에 제한됩니다.
- 자세한 내용은 [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 확인할 수 있습니다.

### **`/proc/[pid]/mem`**
- 커널 메모리 장치 `/dev/mem`과 상호 작용합니다.
- 과거에 권한 상승 공격에 취약했습니다.
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 자세한 내용을 확인할 수 있습니다.

### **`/proc/kcore`**
- 시스템의 물리적 메모리를 ELF 코어 형식으로 나타냅니다.
- 읽기는 호스트 시스템 및 다른 컨테이너의 메모리 내용을 노출시킬 수 있습니다.
- 대형 파일 크기는 읽기 문제나 소프트웨어 충돌을 초래할 수 있습니다.
- 사용법에 대한 자세한 내용은 [2019년 /proc/kcore 덤프](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)를 참조하세요.

### **`/proc/kmem`**
- 커널 가상 메모리를 나타내는 `/dev/kmem`의 대체 인터페이스입니다.
- 읽기 및 쓰기가 가능하므로 커널 메모리를 직접 수정할 수 있습니다.

### **`/proc/mem`**
- 물리적 메모리를 나타내는 `/dev/mem`의 대체 인터페이스입니다.
- 읽기 및 쓰기가 가능하며, 모든 메모리의 수정에는 가상 주
### **`/sys/class/thermal`**
- 온도 설정을 제어하며, DoS 공격이나 물리적 손상을 유발할 수 있습니다.

### **`/sys/kernel/vmcoreinfo`**
- 커널 주소를 노출시켜 KASLR을 침해할 수 있습니다.

### **`/sys/kernel/security`**
- `securityfs` 인터페이스를 포함하며, AppArmor와 같은 Linux 보안 모듈의 구성을 허용합니다.
- 액세스하면 컨테이너가 MAC 시스템을 비활성화할 수 있습니다.

### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**
- NVRAM의 EFI 변수와 상호 작용하기 위한 인터페이스를 노출시킵니다.
- 잘못된 구성 또는 악용은 브릭된 노트북이나 부팅할 수 없는 호스트 머신을 초래할 수 있습니다.

### **`/sys/kernel/debug`**
- `debugfs`는 커널에 대한 "규칙이 없는" 디버깅 인터페이스를 제공합니다.
- 제한이 없는 특성으로 인해 보안 문제가 발생한 이력이 있습니다.


## 참고 자료
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
