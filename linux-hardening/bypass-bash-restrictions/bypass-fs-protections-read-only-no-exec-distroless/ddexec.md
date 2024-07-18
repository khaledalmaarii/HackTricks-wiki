# DDexec / EverythingExec

{% hint style="success" %}
AWS 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

## Context

리눅스에서 프로그램을 실행하려면 파일로 존재해야 하며 파일 시스템 계층 구조를 통해 어떤 방식으로든 접근 가능해야 합니다 (`execve()`가 작동하는 방식입니다). 이 파일은 디스크에 있을 수도 있고 ram (tmpfs, memfd)에 있을 수도 있지만 파일 경로가 필요합니다. 이는 리눅스 시스템에서 실행되는 것을 제어하기 매우 쉽게 만들었으며 위협이나 공격자의 도구를 감지하거나 그들이 자신들의 것을 실행하려고 시도하는 것을 방지하는 것이 쉽게 만들어졌습니다 (_예: 권한이 없는 사용자가 실행 가능한 파일을 어디에든 놓지 못하도록 함).

그러나 이 기술은 이 모든 것을 바꿀 것입니다. 원하는 프로세스를 시작할 수 없다면... **이미 존재하는 하나를 탈취**하세요.

이 기술을 사용하면 **읽기 전용, noexec, 파일 이름 화이트리스트, 해시 화이트리스트와 같은 일반적인 보호 기술을 우회**할 수 있습니다.

## Dependencies

최종 스크립트는 다음 도구에 의존하여 작동합니다. 공격 중인 시스템에서 이 도구들에 액세스할 수 있어야 합니다 (기본적으로 모든 곳에서 찾을 수 있습니다):
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

프로세스의 메모리를 임의로 수정할 수 있다면 해당 프로세스를 인계할 수 있습니다. 이미 존재하는 프로세스를 탈취하고 다른 프로그램으로 대체하는 데 사용할 수 있습니다. 이를 위해 `ptrace()` 시스템 호출을 사용하거나 더 흥미로운 방법으로 `/proc/$pid/mem`에 쓰기를 통해 이를 달성할 수 있습니다.

파일 `/proc/$pid/mem`은 프로세스의 전체 주소 공간과 일대일 매핑입니다 (예: x86-64에서 `0x0000000000000000`부터 `0x7ffffffffffff000`까지). 이는 파일에서 오프셋 `x`로 읽거나 쓰는 것이 가상 주소 `x`에서 내용을 읽거나 수정하는 것과 동일하다는 것을 의미합니다.

이제 우리가 직면해야 할 네 가지 기본 문제가 있습니다:

* 일반적으로 루트 및 파일 소유자만 수정할 수 있습니다.
* ASLR.
* 프로그램의 주소 공간에 매핑되지 않은 주소로 읽거나 쓰려고하면 I/O 오류가 발생합니다.

이러한 문제에는 완벽하지는 않지만 좋은 해결책이 있습니다:

* 대부분의 쉘 인터프리터는 자식 프로세스에서 상속될 파일 디스크립터를 생성하는 것을 허용합니다. 쉘의 메모리를 수정할 수 있는 fd를 가리키는 fd를 만들 수 있습니다.
* ASLR은 문제가 아닙니다. 프로세스의 주소 공간에 대한 정보를 얻기 위해 쉘의 `maps` 파일이나 procfs의 다른 파일을 확인할 수 있습니다.
* 따라서 파일 위로 `lseek()`해야 합니다. 쉘에서는 악명 높은 `dd`를 사용하지 않으면 이 작업을 수행할 수 없습니다.

### 자세히

단계는 비교적 쉽고 이해하기 위해 전문 지식이 필요하지 않습니다:

* 실행하려는 이진 파일 및 로더를 구문 분석하여 필요한 매핑을 찾습니다. 그런 다음 `execve()` 호출 시 커널이 수행하는 단계와 크게 유사한 작업을 수행할 "쉘"코드를 작성합니다.
* 해당 매핑을 생성합니다.
* 바이너리를 읽어들입니다.
* 권한을 설정합니다.
* 프로그램의 인수로 스택을 초기화하고 로더가 필요로 하는 보조 벡터를 배치합니다.
* 로더로 이동하여 나머지 작업을 수행합니다 (프로그램이 필요로 하는 라이브러리를 로드).
* 프로세스가 실행하는 시스템 호출 후 반환할 주소를 `syscall` 파일에서 얻습니다.
* 해당 위치를 덮어씁니다. 이 위치는 실행 가능하며 `mem`을 통해 쓰기 불가능한 페이지를 수정할 수 있습니다.
* 실행하려는 프로그램을 프로세스의 stdin으로 전달합니다 ("쉘"코드에 의해 `read()`될 것입니다).
* 이 시점에서 프로그램에 필요한 라이브러리를로드하고 실행하는 것은 로더에 달려 있습니다.

**도구를 확인하세요** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd`에 대한 여러 대안이 있으며, 그 중 하나인 `tail`은 현재 `mem` 파일을 통해 `lseek()`하는 데 사용되는 기본 프로그램입니다 (`dd`를 사용하는 유일한 목적이었습니다). 해당 대안은 다음과 같습니다:
```bash
tail
hexdump
cmp
xxd
```
변수 `SEEKER`를 설정하여 사용할 seeker를 변경할 수 있습니다. _예시:_
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
만약 스크립트에 구현되지 않은 다른 유효한 seeker를 발견하면 `SEEKER_ARGS` 변수를 설정하여 사용할 수 있습니다:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
## 참고 자료
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 트릭을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
{% endhint %}
