# Seccomp

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 정보

**Seccomp**(Secure Computing mode의 약자)는 **Linux 커널의 보안 기능**으로 시스템 호출을 필터링하는 것을 목적으로 설계되었습니다. 이는 프로세스를 제한된 시스템 호출 집합(`exit()`, `sigreturn()`, `read()`, `write()`)으로 제한합니다. 프로세스가 다른 호출을 시도하면 커널에 의해 SIGKILL 또는 SIGSYS를 사용하여 종료됩니다. 이 메커니즘은 리소스를 가상화하지 않고 프로세스를 리소스로부터 격리시킵니다.

seccomp를 활성화하는 두 가지 방법이 있습니다: `prctl(2)` 시스템 호출과 `PR_SET_SECCOMP`를 사용하거나 Linux 커널 3.17 이상의 경우 `seccomp(2)` 시스템 호출을 사용합니다. `/proc/self/seccomp`에 쓰는 방식으로 seccomp를 활성화하는 구식 방법은 `prctl()`을 선호하는 방식으로 대체되었습니다.

**seccomp-bpf**라는 개선된 모드는 Berkeley Packet Filter (BPF) 규칙을 사용하여 시스템 호출을 필터링하는 기능을 추가합니다. 이 확장은 OpenSSH, vsftpd 및 Chrome OS 및 Linux에서 Chrome/Chromium 브라우저와 같은 소프트웨어에서 사용되며 유연하고 효율적인 시스콜 필터링을 제공합니다. 이는 Linux에서 더 이상 지원되지 않는 systrace에 대한 대안입니다.

### **원래/엄격 모드**

이 모드에서 Seccomp는 이미 열려있는 파일 디스크립터에 대해서만 `exit()`, `sigreturn()`, `read()`, `write()` 시스콜을 허용합니다. 다른 시스콜을 호출하면 프로세스가 SIGKILL을 사용하여 종료됩니다.

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
{% endcode %}

### Seccomp-bpf

이 모드는 Berkeley Packet Filter 규칙을 사용하여 구성 가능한 정책을 구현하여 시스템 호출을 필터링하는 것을 허용합니다.

{% code title="seccomp_bpf.c" %}
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
{% endcode %}

## Docker에서 Seccomp

**Seccomp-bpf**는 **Docker**에서 지원되며, 컨테이너에서의 **syscalls**를 제한하여 효과적으로 표면적을 줄일 수 있습니다. **기본적으로 차단되는 syscalls**는 [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)에서 확인할 수 있으며, **기본 seccomp 프로필**은 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 찾을 수 있습니다.\
다른 seccomp 정책으로 도커 컨테이너를 실행할 수 있습니다.
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
예를 들어, `uname`과 같은 **syscall**을 실행하는 컨테이너를 **금지**하려면 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 기본 프로필을 다운로드하고 목록에서 `uname` 문자열을 **제거**하면 됩니다.\
어떤 이진 파일이 **도커 컨테이너 내에서 작동하지 않도록** 하려면 strace를 사용하여 이진 파일이 사용하는 syscalls를 나열한 다음 금지하면 됩니다.\
다음 예제에서는 `uname`의 **syscalls**가 발견됩니다:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
만약 단순히 애플리케이션을 실행하기 위해 Docker를 사용하는 경우, **`strace`**를 사용하여 애플리케이션의 **프로파일**을 작성하고 필요한 시스템 호출만 허용할 수 있습니다.
{% endhint %}

### Seccomp 정책 예시

[여기에서 가져온 예시](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Seccomp 기능을 설명하기 위해 "chmod" 시스템 호출을 비활성화하는 Seccomp 프로파일을 생성해보겠습니다.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
위의 프로필에서는 기본 동작을 "허용"으로 설정하고 "chmod"를 비활성화하기 위해 블랙리스트를 만들었습니다. 더 안전하게 하기 위해 기본 동작을 거부로 설정하고 시스템 호출을 선택적으로 활성화하기 위해 화이트리스트를 만들 수 있습니다.\
다음 출력은 seccomp 프로필에서 비활성화되어 있기 때문에 "chmod" 호출이 오류를 반환하는 것을 보여줍니다.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
다음 출력은 "docker inspect"가 프로필을 표시하는 것을 보여줍니다:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Docker에서 비활성화하기

플래그 `--security-opt seccomp=unconfined`를 사용하여 컨테이너를 실행합니다.

Kubernetes 1.19부터는 모든 Pod에 대해 seccomp가 기본적으로 활성화되어 있습니다. 그러나 Pod에 적용되는 기본 seccomp 프로필은 "**RuntimeDefault**" 프로필입니다. 이 프로필은 컨테이너 런타임(Docker, containerd 등)에서 제공됩니다. "RuntimeDefault" 프로필은 대부분의 시스템 호출을 허용하면서 컨테이너에게서 위험하거나 일반적으로 필요하지 않은 몇 가지 시스템 호출을 차단합니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
