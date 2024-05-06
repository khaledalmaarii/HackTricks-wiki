# macOS MIG - Mach Interface Generator

<details>

<summary><strong>AWS 해킹을 처음부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>와 함께!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>

## 기본 정보

MIG는 Mach IPC 코드 생성 과정을 **간단화**하기 위해 만들어졌습니다. 기본적으로 서버와 클라이언트가 주어진 정의와 통신하기 위해 필요한 코드를 **생성**합니다. 생성된 코드가 어색해 보이더라도 개발자는 그냥 가져와서 이전보다 훨씬 간단한 코드를 작성할 수 있습니다.

정의는 인터페이스 정의 언어(IDL)를 사용하여 `.defs` 확장자를 사용하여 지정됩니다.

이러한 정의에는 5개의 섹션이 있습니다:

* **서브시스템 선언**: 서브시스템 키워드는 **이름**과 **ID**를 나타내는 데 사용됩니다. 또한 서버가 커널에서 실행되어야 하는 경우 **`KernelServer`**로 표시할 수도 있습니다.
* **포함 및 가져오기**: MIG는 C-프리프로세서를 사용하므로 가져오기를 사용할 수 있습니다. 또한 사용자 또는 서버 생성 코드에 대해 `uimport` 및 `simport`를 사용할 수 있습니다.
* **유형 선언**: 데이터 유형을 정의할 수 있지만 일반적으로 `mach_types.defs` 및 `std_types.defs`를 가져올 것입니다. 사용자 정의 유형의 경우 일부 구문을 사용할 수 있습니다:
* \[i`n/out]tran`: 수신 또는 송신 메시지에서 번역해야 하는 함수
* `c[user/server]type`: 다른 C 유형에 매핑
* `destructor`: 유형이 해제될 때 이 함수를 호출합니다.
* **작업**: 이들은 RPC 메서드의 정의입니다. 5가지 다른 유형이 있습니다:
* `routine`: 응답을 기대합니다
* `simpleroutine`: 응답을 기대하지 않습니다
* `procedure`: 응답을 기대합니다
* `simpleprocedure`: 응답을 기대하지 않습니다
* `function`: 응답을 기대합니다

### 예시

아주 간단한 함수가 있는 정의 파일을 만듭니다:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

첫 번째 **인수는 바인딩할 포트**이며 MIG는 **자동으로 응답 포트를 처리**합니다 (클라이언트 코드에서 `mig_get_reply_port()`를 호출하지 않는 한). 또한 **작업의 ID**는 지정된 서브시스템 ID부터 시작하는 **연속적**일 것입니다 (따라서 작업이 폐기되면 삭제되고 `skip`이 사용되어 여전히 해당 ID를 사용합니다).

이제 MIG를 사용하여 서로 통신할 수 있는 서버 및 클라이언트 코드를 생성하여 Subtract 함수를 호출하십시오:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
현재 디렉토리에 여러 개의 새 파일이 생성됩니다.

{% hint style="success" %}
시스템에서 더 복잡한 예제를 찾을 수 있습니다: `mdfind mach_port.defs`\
그리고 파일이 있는 폴더에서 다음과 같이 컴파일할 수 있습니다: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

**`myipcServer.c`** 및 **`myipcServer.h`** 파일에서는 **`SERVERPREFmyipc_subsystem`** 구조체의 선언과 정의를 찾을 수 있습니다. 이 구조체는 기본적으로 수신된 메시지 ID에 따라 호출할 함수를 정의합니다 (시작 번호로 500을 지정했습니다):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% endtab %}

{% tab title="myipcServer.h" %}서버 코드를 작성하고 IPC를 통해 클라이언트로부터 요청을 수신하는 방법을 보여줍니다. 이 코드는 MIG를 사용하여 Mach RPC를 구현합니다. 클라이언트가 요청을 보내면 서버는 해당 요청을 처리하고 결과를 반환합니다. 이를 통해 프로세스 간 통신을 구현할 수 있습니다.{% endtab %}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

이전 구조를 기반으로 **`myipc_server_routine`** 함수는 **메시지 ID**를 받아 적절한 호출할 함수를 반환합니다:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
이 예제에서는 정의된 함수가 하나뿐이지만, 더 많은 함수를 정의했다면 이들은 **`SERVERPREFmyipc_subsystem`** 배열 내에 있었을 것이며, 첫 번째 함수는 **500** ID에 할당되었을 것이고, 두 번째 함수는 **501** ID에 할당되었을 것입니다...

함수가 **reply**를 보내기를 기대한다면, 함수 `mig_internal kern_return_t __MIG_check__Reply__<name>`도 존재했을 것입니다.

실제로 이 관계를 **`myipcServer.h`**의 **`subsystem_to_name_map_myipc`** 구조체에서 확인할 수 있습니다 (**다른 파일에서는 **`subsystem_to_name_map_***`**):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
마지막으로, 서버가 작동하도록 하는 데 중요한 기능 중 하나인 **`myipc_server`**가 있습니다. 이 함수는 실제로 받은 ID에 관련된 함수를 **호출**할 것입니다:

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* 최소 크기: 다르면 routine()에서 업데이트 */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

이전에 강조된 줄을 확인하여 ID에 따라 호출할 함수에 액세스합니다.

다음은 서버와 클라이언트를 만들기 위한 코드이며, 클라이언트는 서버에서 함수를 호출할 수 있습니다. 서버에서 Subtract 함수를 호출하는 간단한 **서버** 및 **클라이언트** 코드는 다음과 같습니다:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %}클라이언트 코드는 서버와 통신하기 위해 `mach_msg()` 함수를 사용합니다. 이 함수는 MIG 생성 코드에서 자동으로 생성된 함수를 호출하는 데 사용됩니다. 클라이언트는 서버에 메시지를 보내고 응답을 받기 위해 이 함수를 사용합니다. 이 코드는 클라이언트 측의 IPC 동작을 보여줍니다.{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{% endtab %}
{% endtabs %}

### NDR\_record

NDR\_record은 `libsystem_kernel.dylib`에 의해 내보내어지며, 시스템에 대해 중립적인 데이터로 변환할 수 있게 해주는 구조체입니다. MIG는 서로 다른 시스템 간에 사용되도록 고안되었기 때문에 동일한 기계에서만 사용되는 것이 아닙니다.

이는 `_NDR_record`가 이진 파일에서 종속성으로 발견된다면 (`jtool2 -S <binary> | grep NDR` 또는 `nm`), 해당 이진 파일이 MIG 클라이언트 또는 서버임을 의미합니다.

또한 **MIG 서버**는 디스패치 테이블을 `__DATA.__const`에 가지고 있습니다 (또는 macOS 커널의 `__CONST.__constdata` 및 다른 \*OS 커널의 `__DATA_CONST.__const`에 있음). 이는 **`jtool2`**를 사용하여 덤프할 수 있습니다.

그리고 **MIG 클라이언트**는 `__mach_msg`로 서버에게 보내기 위해 `__NDR_record`를 사용할 것입니다.

## 이진 분석

### jtool

많은 바이너리가 이제 MIG를 노출하기 위해 mach 포트를 사용하므로, MIG가 사용되었는지 **식별하는 방법**과 각 메시지 ID마다 MIG가 실행하는 **함수를 식별하는 것**을 알아보는 것이 흥미로울 것입니다.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2)는 Mach-O 이진 파일에서 MIG 정보를 구문 분석하여 메시지 ID를 나타내고 실행할 함수를 식별할 수 있습니다:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
게다가, MIG 함수는 호출되는 실제 함수의 래퍼일 뿐이므로, 해당 함수의 어셈블리를 가져와 BL을 찾으면 호출되는 실제 함수를 찾을 수도 있습니다:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### 어셈블리

이전에 **수신된 메시지 ID에 따라 올바른 함수를 호출하는 함수**는 `myipc_server`라고 언급되었습니다. 그러나 보통 이진 파일의 심볼(함수 이름 없음)을 가지고 있지 않기 때문에, 이 함수가 어떻게 디컴파일된 것처럼 보이는지 **확인하는 것이 흥미로울 것**입니다. (이 함수의 코드는 노출된 함수와 독립적이기 때문에 항상 매우 유사할 것입니다):

{% tabs %}
{% tab title="myipc_server 디컴파일 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// 적절한 함수 포인터를 찾기 위한 초기 명령문
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// 이 함수를 식별하는 데 도움이 되는 sign_extend_64 호출
// 이는 호출해야 하는 호출 지점의 포인터를 rax에 저장
// 주소 0x100004040(함수 주소 배열)의 사용 확인
// 0x1f4 = 500 (시작 ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// if - else, if는 false를 반환하고 else는 올바른 함수를 호출하고 true를 반환
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 2개의 인수로 올바른 함수를 호출하는 계산된 주소
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server 디컴파일 2" %}
다른 Hopper 무료 버전에서 디컴파일된 동일한 함수입니다:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// 적절한 함수 포인터를 찾기 위한 초기 명령문
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (시작 ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// 이전 버전과 동일한 if else
// 주소 0x100004040(함수 주소 배열)의 사용 확인
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// 함수가 있어야 하는 계산된 주소 호출
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

실제로 **`0x100004000` 함수**로 이동하면 **`routine_descriptor`** 구조체 배열을 찾을 수 있습니다. 구조체의 첫 번째 요소는 **함수가 구현된 주소**이며, **구조체는 0x28 바이트**를 차지하므로 각 0x28 바이트(바이트 0부터 시작)마다 8바이트를 얻을 수 있고, 그것이 **호출될 함수의 주소**가 됩니다:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

이 데이터는 [**이 Hopper 스크립트를 사용하여**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) 추출할 수 있습니다.
### 디버그

MIG에 의해 생성된 코드는 또한 `kernel_debug`를 호출하여 진입 및 종료에 대한 작업 로그를 생성합니다. **`trace`** 또는 **`kdv`**를 사용하여 이를 확인할 수 있습니다: `kdv all | grep MIG`

## 참고 자료

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하고 싶다면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
