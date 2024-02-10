# DDexec / EverythingExec

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## Context

리눅스에서 프로그램을 실행하려면 파일로 존재해야하며, 파일 시스템 계층 구조를 통해 어떤 방식으로든 접근 가능해야합니다 (`execve()`가 작동하는 방식입니다). 이 파일은 디스크나 RAM (tmpfs, memfd)에 있을 수 있지만 파일 경로가 필요합니다. 이로 인해 리눅스 시스템에서 실행되는 내용을 쉽게 제어할 수 있으며, 위협이나 공격자의 도구를 감지하거나 그들이 자신의 것을 실행하려는 것을 방지하는 것이 쉬워집니다 (예: 권한이 없는 사용자가 실행 가능한 파일을 어디에든 놓지 못하도록 함).

하지만 이 기술은 이 모든 것을 바꿀 수 있습니다. 원하는 프로세스를 시작할 수 없다면... **이미 존재하는 프로세스를 탈취하세요**.

이 기술을 사용하면 **읽기 전용, noexec, 파일 이름 화이트리스트, 해시 화이트리스트**와 같은 일반적인 보호 기법을 우회할 수 있습니다.

## Dependencies

최종 스크립트는 다음 도구에 종속되어 작동합니다. 공격하는 시스템에서 이 도구에 액세스할 수 있어야 합니다 (기본적으로 모든 곳에서 찾을 수 있습니다).
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## 기술

프로세스의 메모리를 임의로 수정할 수 있다면 해당 프로세스를 제어할 수 있습니다. 이미 존재하는 프로세스를 탈취하고 다른 프로그램으로 대체하는 데 사용할 수 있습니다. 이를 위해 `ptrace()` 시스콜(시스콜 실행 권한이 있거나 시스템에 gdb가 있는 경우) 또는 더 흥미로운 방법으로 `/proc/$pid/mem`에 쓰기를 할 수 있습니다.

`/proc/$pid/mem` 파일은 프로세스의 전체 주소 공간과 일대일 매핑입니다(예: x86-64에서 `0x0000000000000000`에서 `0x7ffffffffffff000`까지). 따라서 오프셋 `x`에서 이 파일을 읽거나 쓰는 것은 가상 주소 `x`에서 내용을 읽거나 수정하는 것과 동일합니다.

이제 우리는 다음 네 가지 기본적인 문제를 해결해야 합니다:

* 일반적으로 루트와 파일의 프로그램 소유자만 수정할 수 있습니다.
* ASLR.
* 프로그램의 주소 공간에 매핑되지 않은 주소로 읽거나 쓰려고 하면 I/O 오류가 발생합니다.

이러한 문제에는 완벽하지 않지만 좋은 해결책이 있습니다:

* 대부분의 쉘 인터프리터는 자식 프로세스에서 상속될 파일 디스크립터를 생성할 수 있습니다. 우리는 쓰기 권한이 있는 쉘의 `mem` 파일을 가리키는 fd를 생성할 수 있습니다. 따라서 해당 fd를 사용하는 자식 프로세스는 쉘의 메모리를 수정할 수 있습니다.
* ASLR은 문제가 아닙니다. procfs의 쉘의 `maps` 파일이나 다른 파일을 사용하여 프로세스의 주소 공간에 대한 정보를 얻을 수 있습니다.
* 따라서 파일 위로 `lseek()`를 수행해야 합니다. 쉘에서는 악명 높은 `dd`를 사용하지 않는 한 이 작업을 수행할 수 없습니다.

### 자세한 내용

단계는 비교적 간단하며 이해하기 위해 특별한 전문 지식이 필요하지 않습니다:

* 실행하려는 이진 파일과 로더를 파싱하여 필요한 매핑을 찾습니다. 그런 다음, 간단히 말해서 `execve()` 호출 시 커널이 수행하는 단계와 거의 동일한 작업을 수행할 "쉘" 코드를 작성합니다.
* 해당 매핑을 생성합니다.
* 이진 파일을 해당 매핑에 읽습니다.
* 권한을 설정합니다.
* 마지막으로 프로그램의 인수로 스택을 초기화하고 로더가 필요로 하는 보조 벡터를 배치합니다.
* 로더로 이동하여 나머지 작업을 수행하게 합니다(프로그램이 필요로 하는 라이브러리를 로드합니다).
* `syscall` 파일에서 시스콜 실행 후 프로세스가 반환될 주소를 얻습니다.
* 해당 위치(실행 가능한 위치)를 우리의 쉘 코드로 덮어씁니다(`mem`을 통해 쓸 수 없는 페이지를 수정할 수 있습니다).
* 실행하려는 프로그램을 프로세스의 stdin으로 전달합니다(해당 "쉘" 코드에서 `read()`될 것입니다).
* 이 시점에서 프로그램을 위해 필요한 라이브러리를 로드하고 해당 프로그램으로 이동하는 것은 로더에 달려 있습니다.

**[https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)에서 도구를 확인하세요.**

## EverythingExec

`dd`에는 여러 대안이 있습니다. 그 중 하나인 `tail`은 현재 `mem` 파일을 `lseek()`하는 데 사용되는 기본 프로그램입니다(`dd`를 사용하는 유일한 목적이었습니다). 해당 대안은 다음과 같습니다:
```bash
tail
hexdump
cmp
xxd
```
변수 `SEEKER`를 설정하여 사용할 seeker를 변경할 수 있습니다. 예를 들어,
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
다른 유효한 seeker를 스크립트에 구현하지 않았다면 `SEEKER_ARGS` 변수를 설정하여 사용할 수 있습니다:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
이것을 차단하십시오, EDRs.

## 참고 자료
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
