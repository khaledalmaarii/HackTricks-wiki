# euid, ruid, suid

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 AWS 해킹을 배워보세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전을 사용하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

### 사용자 식별 변수

- **`ruid`**: **실제 사용자 ID**는 프로세스를 시작한 사용자를 나타냅니다.
- **`euid`**: **유효 사용자 ID**로, 시스템이 프로세스 권한을 확인하기 위해 사용하는 사용자 ID입니다. 일반적으로 `euid`는 `ruid`와 동일하지만, SetUID 이진 파일 실행과 같은 경우 `euid`는 파일 소유자의 ID를 가지며 특정 작업에 대한 권한을 부여합니다.
- **`suid`**: 이 **저장된 사용자 ID**는 높은 권한을 가진 프로세스(일반적으로 root로 실행)가 일시적으로 권한을 포기하고 특정 작업을 수행한 후 초기 상승된 상태를 다시 찾을 때 사용됩니다.

#### 중요한 참고 사항
루트가 아닌 프로세스는 현재 `ruid`, `euid`, 또는 `suid`와 일치하도록 `euid`를 수정할 수 있습니다.

### set*uid 함수 이해

- **`setuid`**: 초기 가정과 달리, `setuid`는 주로 `ruid`가 아닌 `euid`를 수정합니다. 특히 권한이 있는 프로세스의 경우, 지정된 사용자(일반적으로 root)와 `ruid`, `euid`, `suid`를 일치시켜 이러한 ID를 덮어쓰기 때문에 이러한 ID가 고정됩니다. 자세한 내용은 [setuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setuid.2.html)에서 확인할 수 있습니다.
- **`setreuid`**와 **`setresuid`**: 이러한 함수는 `ruid`, `euid`, `suid`를 미묘하게 조정할 수 있도록 합니다. 그러나 이러한 기능은 프로세스의 권한 수준에 따라 제한됩니다. 루트가 아닌 프로세스의 경우, 수정은 현재 `ruid`, `euid`, `suid`의 값으로 제한됩니다. 반면, 루트 프로세스 또는 `CAP_SETUID` 기능을 가진 프로세스는 이러한 ID에 임의의 값을 할당할 수 있습니다. 자세한 정보는 [setresuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setresuid.2.html)와 [setreuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setreuid.2.html)에서 확인할 수 있습니다.

이러한 기능은 보안 메커니즘이 아닌 의도된 운영 흐름을 용이하게 하기 위해 설계되었습니다. 예를 들어 프로그램이 유효 사용자 ID를 변경하여 다른 사용자의 ID를 채택하는 경우입니다.

특히 `setuid`는 루트로의 권한 상승을 위한 일반적인 선택지일 수 있지만, 이러한 함수들 간의 차이를 구분하는 것은 다양한 시나리오에서 사용자 ID 동작을 이해하고 조작하는 데 중요합니다.

### Linux에서의 프로그램 실행 메커니즘

#### **`execve` 시스템 콜**
- **기능**: `execve`는 첫 번째 인수로 지정된 프로그램을 시작합니다. 인수와 환경을 위한 두 개의 배열 인수, `argv`와 `envp`를 사용합니다.
- **동작**: 호출자의 메모리 공간은 유지되지만 스택, 힙 및 데이터 세그먼트가 새로 고쳐집니다. 프로그램의 코드는 새로운 프로그램으로 대체됩니다.
- **사용자 ID 보존**:
- `ruid`, `euid` 및 보조 그룹 ID는 변경되지 않습니다.
- 새로운 프로그램에 SetUID 비트가 설정되어 있는 경우 `euid`에 미묘한 변경이 있을 수 있습니다.
- `suid`는 실행 후 `euid`에서 업데이트됩니다.
- **문서**: 자세한 정보는 [`execve` 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/execve.2.html)에서 확인할 수 있습니다.

#### **`system` 함수**
- **기능**: `execve`와 달리, `system`은 `fork`를 사용하여 자식 프로세스를 생성하고 `execl`을 사용하여 해당 자식 프로세스에서 명령을 실행합니다.
- **명령 실행**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`를 사용하여 `sh`를 통해 명령을 실행합니다.
- **동작**: `execl`은 `execve`의 한 형태이므로 새로운 자식 프로세스의 컨텍스트에서 유사한 방식으로 작동합니다.
- **문서**: 자세한 내용은 [`system` 매뉴얼 페이지](https://man7.org/linux/man-pages/man3/system.3.html)에서 확인할 수 있습니다.

#### **SUID가 있는 `bash`와 `sh`의 동작**
- **`bash`**:
- `euid`와 `ruid`가 처리되는 방식에 영향을 주는 `-p` 옵션이 있습니다.
- `-p`가 없으면 `bash`는 초기에 `euid`를 `ruid`로 설정합니다.
- `-p`가 있는 경우 초기 `euid`가 보존됩니다.
- 자세한 내용은 [`bash` 매뉴얼 페이지](https://linux.die.net/man/1/bash)에서 확인할 수 있습니다.
- **`sh`**:
- `bash`의 `-p`와 유사한 메커니즘이 없습니다.
- 사용자 ID에 대한 동작은 명시적으로 언급되지 않았으며, `-i` 옵션 아래에서 `euid`와 `ruid`의 동일성을 강조합니다.
- 추가 정보는 [`sh` 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/sh.1p.html)에서 확인할 수 있습니다.

이러한 동작 방식은 작동 방식에서 차이가 있으며, 사용자 ID가 관리되고 보존되는 방식에 특정한 미묘함이 있어 다양한 프로그램 간의 실행 및 전환에 유연한 옵션을 제공합니다.

### 실행 중인 프로그램에서 사용자 ID 동작 테스트

자세한 내용은 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail에서 확인할 수 있는 예제를 참조하세요.

#### Case 1: `setuid`와 `system`을 함께 사용하기

**목표**: `setuid`를 `system`과 `bash` 또는 `sh`와 함께 사용할 때의 효과 이해하기.

**C 코드**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**컴파일 및 권한:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `ruid`와 `euid`는 각각 99 (nobody)와 1000 (frank)으로 시작합니다.
* `setuid`는 둘 다 1000으로 맞춥니다.
* `system`은 sh에서 bash로의 심볼릭 링크로 인해 `/bin/bash -c id`를 실행합니다.
* `-p` 없이 `bash`는 `euid`를 `ruid`와 일치시키기 위해 99 (nobody)로 조정합니다.

#### Case 2: setreuid와 system 사용

**C 코드**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**컴파일 및 권한:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `setreuid`는 ruid와 euid를 모두 1000으로 설정합니다.
* `system`은 사용자 ID가 동일하기 때문에 사용자 ID를 유지하는 bash를 호출하여 frank로 작동합니다.

#### 케이스 3: execve와 함께 setuid 사용하기
목표: setuid와 execve 간의 상호작용 탐색하기
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `ruid`는 여전히 99로 유지되지만, `euid`는 setuid의 영향으로 1000으로 설정됩니다.

**C 코드 예제 2 (Bash 호출):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `euid`가 `setuid`에 의해 1000으로 설정되었지만, `-p`가 없어서 `bash`는 `ruid` (99)로 `euid`를 재설정합니다.

**C 코드 예제 3 (bash -p 사용):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## 참고 자료
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
