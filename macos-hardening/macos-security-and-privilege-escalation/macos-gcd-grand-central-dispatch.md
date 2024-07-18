# macOS GCD - Grand Central Dispatch

{% hint style="success" %}
AWS 해킹 배우고 실습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 실습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## 기본 정보

**Grand Central Dispatch (GCD)**, 또는 **libdispatch**(`libdispatch.dyld`),은 macOS와 iOS 모두에서 사용할 수 있습니다. 이는 Apple이 개발한 기술로, 멀티코어 하드웨어에서 동시(멀티스레드) 실행을 최적화하기 위한 애플리케이션 지원을 위한 기술입니다.

**GCD**는 애플리케이션이 **블록 객체 형태로 작업을 제출**할 수 있는 **FIFO 큐**를 제공하고 관리합니다. 디스패치 큐에 제출된 블록은 시스템에 의해 완전히 관리되는 스레드 풀에서 실행됩니다. GCD는 디스패치 큐에서 작업을 실행하기 위해 자동으로 스레드를 생성하고 해당 작업을 사용 가능한 코어에서 실행할 수 있도록 일정을 조정합니다.

{% hint style="success" %}
요약하면, **병렬로 코드를 실행**하기 위해 프로세스는 **GCD에 코드 블록을 보낼 수 있으며**, GCD가 그 실행을 처리합니다. 따라서 프로세스는 새로운 스레드를 생성하지 않습니다; **GCD는 자체 스레드 풀로 주어진 코드를 실행**합니다(필요에 따라 증가 또는 감소할 수 있음).
{% endhint %}

이는 병렬 실행을 성공적으로 관리하는 데 매우 도움이 되며, 프로세스가 생성하는 스레드 수를 크게 줄이고 병렬 실행을 최적화합니다. 이는 **큰 병렬성**(무차별 대입?)을 필요로 하는 작업이나 주 스레드를 차단해서는 안 되는 작업에 이상적입니다. 예를 들어, iOS의 주 스레드는 UI 상호작용을 처리하므로 앱이 멈추는 것을 방지해야 하는 다른 기능(검색, 웹 접근, 파일 읽기 등)은 이 방식으로 처리됩니다.

### 블록

블록은 **코드의 독립된 섹션** (인수를 사용하여 값을 반환하는 함수와 유사)이며 바운드 변수를 지정할 수도 있습니다.\
그러나 컴파일러 수준에서는 블록이 존재하지 않고 `os_object`입니다. 이러한 객체 각각은 두 개의 구조체로 구성됩니다:

* **블록 리터럴**:
* 블록의 클래스를 가리키는 **`isa`** 필드로 시작합니다:
* `NSConcreteGlobalBlock`(`__DATA.__const`의 블록)
* `NSConcreteMallocBlock` (힙에 있는 블록)
* `NSConcreateStackBlock` (스택에 있는 블록)
* 블록 설명자에 존재하는 필드를 나타내는 **`flags`** 및 일부 예약된 바이트
* 호출할 함수 포인터
* 블록 설명자에 대한 포인터
* 가져온 변수(있는 경우)
* **블록 설명자**: 존재하는 데이터에 따라 크기가 달라집니다(이전 플래그에서 지정된대로)
* 일부 예약된 바이트
* 크기
* 보통 매개변수에 필요한 공간이 얼마나 필요한지 알기 위해 Objective-C 스타일 서명을 가리키는 포인터가 포함됩니다(플래그 `BLOCK_HAS_SIGNATURE`)
* 변수가 참조되는 경우, 이 블록은 값 복사 도우미(처음 값 복사) 및 해제 도우미(해제)에 대한 포인터도 가질 것입니다.

### 큐

디스패치 큐는 블록을 실행하기 위한 FIFO 순서를 제공하는 이름이 지정된 객체입니다.

블록은 실행을 위해 큐에 설정되며, 이러한 큐는 `DISPATCH_QUEUE_SERIAL` 및 `DISPATCH_QUEUE_CONCURRENT` 두 가지 모드를 지원합니다. 물론 **시리얼**은 **경쟁 조건이 발생하지 않을 것**이므로 이전 블록이 완료될 때까지 다음 블록이 실행되지 않습니다. 그러나 **다른 유형의 큐는 그렇지 않을 수 있습니다**.

기본 큐:

* `.main-thread`: `dispatch_get_main_queue()`에서
* `.libdispatch-manager`: GCD의 큐 관리자
* `.root.libdispatch-manager`: GCD의 큐 관리자
* `.root.maintenance-qos`: 가장 낮은 우선순위 작업
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND`로 사용 가능
* `.root.background-qos.overcommit`
* `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`로 사용 가능
* `.root.utility-qos.overcommit`
* `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT`로 사용 가능
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH`로 사용 가능
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: 가장 높은 우선순위
* `.root.background-qos.overcommit`

각 시점에서 **시스템이 어떤 스레드가 어떤 큐를 처리할지 결정**합니다(여러 스레드가 동일한 큐에서 작업할 수도 있고 동일한 스레드가 어느 시점에서는 다른 큐에서 작업할 수도 있음)

#### 속성

**`dispatch_queue_create`**로 큐를 생성할 때 세 번째 인수는 `dispatch_queue_attr_t`이며, 일반적으로 `DISPATCH_QUEUE_SERIAL`(실제로는 NULL) 또는 `DISPATCH_QUEUE_CONCURRENT`(큐의 일부 매개변수를 제어할 수 있는 `dispatch_queue_attr_t` 구조체에 대한 포인터) 중 하나입니다.

### 디스패치 객체

libdispatch가 사용하는 여러 객체가 있으며, 큐와 블록은 그 중 2개뿐입니다. 이러한 객체를 `dispatch_object_create`로 생성할 수 있습니다:

* `block`
* `data`: 데이터 블록
* `group`: 블록 그룹
* `io`: 비동기 I/O 요청
* `mach`: Mach 포트
* `mach_msg`: Mach 메시지
* `pthread_root_queue`: pthread 스레드 풀 및 작업 큐가 없는 큐
* `queue`
* `semaphore`
* `source`: 이벤트 소스

## Objective-C

Objective-C에서는 병렬로 실행할 블록을 보내기 위한 다양한 함수가 있습니다:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): 블록을 디스패치 큐에서 비동기로 실행하고 즉시 반환합니다.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): 블록 객체를 실행하고 해당 블록이 실행을 마친 후에 반환합니다.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): 애플리케이션의 수명 동안 블록 객체를 한 번만 실행합니다.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): 작업 항목을 실행하고 해당 작업이 완료될 때까지만 반환합니다. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)와 달리 이 함수는 큐의 모든 속성을 존준하여 블록을 실행합니다.

이러한 함수는 다음 매개변수를 기대합니다: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

이것이 **블록의 구조**입니다:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
그리고 이것은 **`dispatch_async`**를 사용하여 **병렬성**을 사용하는 예시입니다:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`**은 C로 원래 작성된 Grand Central Dispatch (GCD) 프레임워크에 대한 **Swift 바인딩**을 제공하는 라이브러리입니다.\
**`libswiftDispatch`** 라이브러리는 C GCD API를 더 Swift 친화적 인터페이스로 래핑하여 Swift 개발자가 GCD와 더 쉽고 직관적으로 작업할 수 있도록 합니다.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**코드 예시**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## 프리다

다음 프리다 스크립트를 사용하여 여러 `dispatch` 함수에 **후크**하여 대기열 이름, 백트레이스 및 블록을 추출할 수 있습니다: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

현재 Ghidra는 ObjectiveC **`dispatch_block_t`** 구조와 **`swift_dispatch_block`** 구조를 이해하지 못합니다.

그러므로 이를 이해하도록 하려면 그냥 **선언**해야 합니다:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

그런 다음, 코드에서 **사용**되는 위치를 찾으세요:

{% hint style="success" %}
"block"에 대한 모든 참조를 주목하여 해당 구조체가 사용되는 방법을 이해할 수 있습니다.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

변수를 마우스 오른쪽 클릭 -> 변수 유형 변경을 선택하고 이 경우에는 **`swift_dispatch_block`**을 선택하세요:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra가 자동으로 모든 것을 다시 작성할 것입니다:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
