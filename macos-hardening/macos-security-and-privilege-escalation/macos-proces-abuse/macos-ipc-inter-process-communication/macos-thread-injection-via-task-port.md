# macOS Task 포트를 통한 스레드 주입

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 코드

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. 스레드 하이재킹

먼저, 원격 태스크에서 스레드 목록을 얻기 위해 **`task_threads()`** 함수가 태스크 포트에서 호출됩니다. 하이재킹할 스레드가 선택됩니다. 이 접근 방식은 `thread_create_running()`을 차단하는 새로운 방어 기능으로 인해 새로운 원격 스레드를 생성하는 일반적인 코드 주입 방법과 다릅니다.

스레드를 제어하기 위해 **`thread_suspend()`**가 호출되어 실행이 중지됩니다.

원격 스레드에서 허용되는 유일한 작업은 스레드를 **중지**하고 **시작**하며, 레지스터 값을 **검색**하고 **수정**하는 것입니다. 원격 함수 호출은 레지스터 `x0`에서 `x7`을 **인수**로 설정하고, 원하는 함수를 대상으로 **`pc`**를 구성하고, 스레드를 활성화하여 시작됩니다. 반환 후 스레드가 충돌하지 않도록 보장하기 위해 반환을 감지해야 합니다.

한 가지 전략은 원격 스레드에 대한 **예외 핸들러를 등록**하는 것입니다. 이를 위해 `thread_set_exception_ports()`를 사용하여 `lr` 레지스터를 함수 호출 전에 잘못된 주소로 설정합니다. 이렇게 하면 예외가 함수 실행 후에 발생하여 예외 포트로 메시지가 전송되고, 스레드의 상태를 검사하여 반환 값을 복구할 수 있습니다. 또는 Ian Beer의 triple\_fetch exploit에서 채택한 대로 `lr`을 무한히 반복하는 것입니다. 그런 다음 스레드의 레지스터를 계속 모니터링하고 **`pc`가 해당 명령어를 가리킬 때까지** 기다립니다.

## 2. 통신을 위한 Mach 포트

다음 단계에서는 원격 스레드와의 통신을 용이하게하기 위해 Mach 포트를 설정합니다. 이러한 포트는 작업 간에 임의의 송신 및 수신 권한을 전송하는 데 중요한 역할을 합니다.

양방향 통신을 위해 로컬 및 원격 태스크에서 각각 두 개의 Mach 수신 권한이 생성됩니다. 그런 다음 각 포트에 대한 송신 권한이 상대 태스크로 전송되어 메시지 교환을 가능하게 합니다.

로컬 포트에 초점을 맞추면, 수신 권한은 로컬 태스크에 의해 보유됩니다. 포트는 `mach_port_allocate()`를 사용하여 생성됩니다. 로컬 포트로의 송신 권한을 원격 스레드로 전송하는 것이 어려운 부분입니다.

한 가지 전략은 `thread_set_special_port()`를 활용하여 로컬 포트의 송신 권한을 원격 스레드의 `THREAD_KERNEL_PORT`에 배치하는 것입니다. 그런 다음 원격 스레드에게 `mach_thread_self()`를 호출하도록 지시하여 송신 권한을 검색합니다.

원격 포트의 경우, 프로세스는 기본적으로 반대로 진행됩니다. 원격 스레드는 `mach_reply_port()`를 통해 Mach 포트를 생성하도록 지시받습니다(`mach_port_allocate()`는 반환 메커니즘 때문에 적합하지 않습니다). 포트 생성 후, 원격 스레드에서 `mach_port_insert_right()`를 호출하여 송신 권한을 설정합니다. 이 권한은 그런 다음 `thread_set_special_port()`를 사용하여 커널에 저장됩니다. 로컬 태스크에서는 원격 태스크의 원격 스레드에 대한 `thread_get_special_port()`를 사용하여 원격 태스크의 새로 할당된 Mach 포트에 대한 송신 권한을 얻습니다.

이러한 단계를 완료하면 Mach 포트가 설정되어 양방향 통신을 위한 기반을 마련합니다.

## 3. 기본 메모리 읽기/쓰기 기본 도구

이 섹션에서는 실행 기본 도구를 활용하여 기본 메모리 읽기 및 쓰기 기본 도구를 설정하는 데 중점을 둡니다. 이 단계에서의 기본 도구는 원격 프로세스를 더욱 효과적으로 제어하기 위한 중요한 단계이지만, 현재 단계에서는 많은 목적을 제공하지 않습니다. 곧 이러한 기본 도구는 더 고급 버전으로 업그레이드될 것입니다.

### 실행 기본 도구를 사용한 메모리 읽기 및 쓰기

특정 함수를 사용하여 메모리 읽기 및 쓰기를 수행하는 것이 목표입니다. 메모리 읽기에는 다음과 유사한 구조의 함수가 사용됩니다:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
그리고 메모리에 쓰기 위해, 이와 유사한 구조의 함수들이 사용됩니다:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
이러한 함수들은 주어진 어셈블리 명령어와 대응됩니다:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 적합한 함수 식별

일반적인 라이브러리를 스캔한 결과, 이러한 작업에 적합한 후보 함수들을 찾을 수 있었습니다:

1. **메모리 읽기:**
[Objective-C 런타임 라이브러리](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html)의 `property_getName()` 함수가 메모리 읽기에 적합한 함수로 식별되었습니다. 아래에 해당 함수의 개요가 제시되어 있습니다:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
이 함수는 `read_func`과 유사하게 동작하여 `objc_property_t`의 첫 번째 필드를 반환합니다.

2. **메모리 쓰기:**
메모리를 쓰기 위한 미리 작성된 함수를 찾는 것은 더 어려운 과정입니다. 그러나 libxpc의 `_xpc_int64_set_value()` 함수는 다음 어셈블리어와 같이 적합한 후보입니다.
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
특정 주소에 64비트 쓰기를 수행하기 위해 원격 호출은 다음과 같이 구성됩니다:
```c
_xpc_int64_set_value(address - 0x18, value)
```
이러한 기본 요소를 설정하면 원격 프로세스를 제어하는 데 중요한 역할을 하는 공유 메모리를 생성할 수 있습니다.

## 4. 공유 메모리 설정

목표는 로컬 및 원격 작업 간에 공유 메모리를 설정하여 데이터 전송을 간소화하고 여러 인수를 사용하는 함수를 호출하는 것입니다. 이 접근 방식은 `libxpc`와 그 `OS_xpc_shmem` 객체 유형을 활용하는 것으로, 이는 Mach 메모리 항목 위에 구축되어 있습니다.

### 프로세스 개요:

1. **메모리 할당**:
- `mach_vm_allocate()`를 사용하여 공유를 위한 메모리를 할당합니다.
- `xpc_shmem_create()`를 사용하여 할당된 메모리 영역에 대한 `OS_xpc_shmem` 객체를 생성합니다. 이 함수는 Mach 메모리 항목의 생성을 관리하고 `OS_xpc_shmem` 객체의 `0x18` 오프셋에 Mach send right를 저장합니다.

2. **원격 프로세스에서 공유 메모리 생성**:
- 원격 호출로 원격 프로세스에서 `OS_xpc_shmem` 객체에 대한 메모리를 할당합니다.
- 로컬 `OS_xpc_shmem` 객체의 내용을 원격 프로세스로 복사합니다. 그러나 이 초기 복사본은 `0x18` 오프셋에 잘못된 Mach 메모리 항목 이름을 가지고 있을 것입니다.

3. **Mach 메모리 항목 수정**:
- `thread_set_special_port()` 메서드를 사용하여 Mach 메모리 항목에 대한 send right를 원격 작업에 삽입합니다.
- 원격 메모리 항목의 이름으로 `0x18` 오프셋에 있는 Mach 메모리 항목 필드를 덮어씁니다.

4. **공유 메모리 설정 완료**:
- 원격 `OS_xpc_shmem` 객체를 유효성 검사합니다.
- 원격 호출로 공유 메모리 매핑을 설정합니다. (`xpc_shmem_remote()`)

이러한 단계를 따라 로컬 및 원격 작업 간에 공유 메모리가 효율적으로 설정되어 데이터 전송이 간단해지고 여러 인수를 필요로 하는 함수를 실행할 수 있게 됩니다.

## 추가 코드 스니펫

메모리 할당 및 공유 메모리 객체 생성을 위한 코드:
```c
mach_vm_allocate();
xpc_shmem_create();
```
원격 프로세스에서 공유 메모리 객체를 생성하고 수정하기 위해:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Mach 포트와 메모리 엔트리 이름의 세부 사항을 올바르게 처리하여 공유 메모리가 올바르게 설정되도록 해야합니다.


## 5. 완전한 제어 달성

공유 메모리를 성공적으로 설정하고 임의의 실행 능력을 획득한 경우, 우리는 사실상 대상 프로세스를 완전히 제어하게 됩니다. 이러한 제어를 가능하게 하는 주요 기능은 다음과 같습니다:

1. **임의의 메모리 작업**:
- `memcpy()`를 호출하여 공유 영역에서 데이터를 복사하여 임의의 메모리 읽기 수행.
- `memcpy()`를 사용하여 데이터를 공유 영역으로 전송하여 임의의 메모리 쓰기 실행.

2. **다중 인수를 사용하는 함수 호출 처리**:
- 8개 이상의 인수가 필요한 함수의 경우, 호출 규약에 따라 스택에 추가 인수를 배열합니다.

3. **Mach 포트 전송**:
- 이전에 설정한 포트를 통해 Mach 메시지를 통해 Mach 포트를 작업 간에 전송합니다.

4. **파일 디스크립터 전송**:
- `triple_fetch`에서 강조한 fileports를 사용하여 프로세스 간에 파일 디스크립터를 전송합니다.

이 포괄적인 제어는 [threadexec](https://github.com/bazad/threadexec) 라이브러리에 포함되어 있으며, 피해 프로세스와 상호 작용하기 위한 자세한 구현과 사용자 친화적인 API를 제공합니다.

## 중요한 고려 사항:

- 시스템의 안정성과 데이터 무결성을 유지하기 위해 메모리 읽기/쓰기 작업에 `memcpy()`를 올바르게 사용하세요.
- Mach 포트 또는 파일 디스크립터를 전송할 때, 적절한 프로토콜을 따르고 리소스를 책임 있게 처리하여 정보 누출이나 의도하지 않은 액세스를 방지하세요.

이 가이드라인을 준수하고 `threadexec` 라이브러리를 활용함으로써 대상 프로세스를 세밀하게 관리하고 상호 작용할 수 있으며, 대상 프로세스를 완전히 제어할 수 있습니다.

## 참고 자료
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사를 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)로 이루어진 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
