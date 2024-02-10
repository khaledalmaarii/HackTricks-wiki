# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

## 기본 정보

**Grand Central Dispatch (GCD)** 또는 **libdispatch**는 macOS와 iOS에서 모두 사용할 수 있습니다. 이는 Apple이 개발한 기술로, 다중 코어 하드웨어에서 동시 (멀티스레드) 실행을 위한 응용 프로그램 지원을 최적화하는 데 사용됩니다.

**GCD**는 응용 프로그램이 **블록 객체** 형태로 **작업을 제출**할 수 있는 **FIFO 큐**를 제공하고 관리합니다. 디스패치 큐에 제출된 블록은 시스템에 의해 완전히 관리되는 스레드 풀에서 실행됩니다. GCD는 디스패치 큐에서 작업을 실행하기 위해 스레드를 자동으로 생성하고 해당 작업을 사용 가능한 코어에서 실행하도록 일정합니다.

{% hint style="success" %}
요약하면, **병렬로** 코드를 실행하기 위해 프로세스는 **코드 블록을 GCD에 전송**할 수 있으며, GCD가 실행을 처리합니다. 따라서 프로세스는 새로운 스레드를 생성하지 않으며, **GCD는 자체 스레드 풀에서 주어진 코드를 실행**합니다.
{% endhint %}

이는 병렬 실행을 성공적으로 관리하는 데 매우 유용하며, 프로세스가 생성하는 스레드 수를 크게 줄이고 병렬 실행을 최적화하는 데 도움이 됩니다. 이는 **큰 병렬성**을 필요로 하는 작업 (무차별 대입?)이나 주 스레드를 차단해서는 안 되는 작업에 이상적입니다. 예를 들어, iOS의 주 스레드는 UI 상호작용을 처리하므로 앱이 멈추는 것을 방지하기 위해 다른 기능 (검색, 웹 접근, 파일 읽기 등)은 이 방식으로 처리됩니다.

## Objective-C

Objective-C에서는 블록을 병렬로 실행하기 위해 다양한 함수가 있습니다:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): 블록을 비동기적으로 실행하기 위해 디스패치 큐에 제출하고 즉시 반환합니다.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): 블록 객체를 실행하기 위해 제출하고 해당 블록이 실행을 마친 후에 반환합니다.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): 응용 프로그램의 수명 동안 블록 객체를 한 번만 실행합니다.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): 작업 항목을 실행하고 해당 작업이 완료될 때까지만 반환합니다. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)와 달리 이 함수는 블록을 실행할 때 큐의 모든 속성을 존중합니다.

이러한 함수는 다음 매개변수를 기대합니다: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

이것은 **블록의 구조**입니다:
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
그리고 이것은 **`dispatch_async`**를 사용하여 **병렬 처리**를 하는 예시입니다:
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
## 스위프트

**`libswiftDispatch`**는 원래 C로 작성된 Grand Central Dispatch (GCD) 프레임워크에 대한 **스위프트 바인딩**을 제공하는 라이브러리입니다.\
**`libswiftDispatch`** 라이브러리는 C GCD API를 더 스위프트 친화적인 인터페이스로 래핑하여 스위프트 개발자가 GCD와 더 쉽고 직관적으로 작업할 수 있도록 합니다.

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
## Frida

다음 Frida 스크립트는 여러 `dispatch` 함수에 **후킹(hooking)**을 적용하고 큐 이름, 백트레이스 및 블록을 추출하는 데 사용할 수 있습니다: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

현재 Ghidra는 ObjectiveC의 **`dispatch_block_t`** 구조와 **`swift_dispatch_block`** 구조를 이해하지 못합니다.

따라서 이를 이해하도록 하려면 그냥 **선언**해주면 됩니다:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

그런 다음 코드에서 이들이 **사용**되는 곳을 찾으세요:

{% hint style="success" %}
"block"에 대한 모든 참조를 찾아 구조체가 사용되는 방법을 이해하세요.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

변수를 마우스 오른쪽 클릭 -> 변수 형식 재지정을 선택하고 이 경우에는 **`swift_dispatch_block`**을 선택하세요:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra가 자동으로 모든 것을 다시 작성할 것입니다:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
