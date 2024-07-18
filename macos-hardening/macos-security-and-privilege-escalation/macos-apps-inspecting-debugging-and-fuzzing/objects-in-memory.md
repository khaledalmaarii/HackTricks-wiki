# 内存中的对象

{% hint style="success" %}
学习并练习 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## CFRuntimeClass

CF\* 对象来自 CoreFoundation，提供了 50 多个类的对象，如 `CFString`、`CFNumber` 或 `CFAllocatior`。

所有这些类都是 `CFRuntimeClass` 类的实例，当调用时，它会返回到 `__CFRuntimeClassTable` 的索引。CFRuntimeClass 在 [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) 中定义：
```objectivec
// Some comments were added to the original code

enum { // Version field constants
_kCFRuntimeScannedObject =     (1UL << 0),
_kCFRuntimeResourcefulObject = (1UL << 2),  // tells CFRuntime to make use of the reclaim field
_kCFRuntimeCustomRefCount =    (1UL << 3),  // tells CFRuntime to make use of the refcount field
_kCFRuntimeRequiresAlignment = (1UL << 4),  // tells CFRuntime to make use of the requiredAlignment field
};

typedef struct __CFRuntimeClass {
CFIndex version;  // This is made a bitwise OR with the relevant previous flags

const char *className; // must be a pure ASCII string, nul-terminated
void (*init)(CFTypeRef cf);  // Initializer function
CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf); // Copy function, taking CFAllocatorRef and CFTypeRef to copy
void (*finalize)(CFTypeRef cf); // Finalizer function
Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2); // Function to be called by CFEqual()
CFHashCode (*hash)(CFTypeRef cf); // Function to be called by CFHash()
CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions); // Provides a CFStringRef with a textual description of the object// return str with retain
CFStringRef (*copyDebugDesc)(CFTypeRef cf);	// CFStringRed with textual description of the object for CFCopyDescription

#define CF_RECLAIM_AVAILABLE 1
void (*reclaim)(CFTypeRef cf); // Or in _kCFRuntimeResourcefulObject in the .version to indicate this field should be used
// It not null, it's called when the last reference to the object is released

#define CF_REFCOUNT_AVAILABLE 1
// If not null, the following is called when incrementing or decrementing reference count
uint32_t (*refcount)(intptr_t op, CFTypeRef cf); // Or in _kCFRuntimeCustomRefCount in the .version to indicate this field should be used
// this field must be non-NULL when _kCFRuntimeCustomRefCount is in the .version field
// - if the callback is passed 1 in 'op' it should increment the 'cf's reference count and return 0
// - if the callback is passed 0 in 'op' it should return the 'cf's reference count, up to 32 bits
// - if the callback is passed -1 in 'op' it should decrement the 'cf's reference count; if it is now zero, 'cf' should be cleaned up and deallocated (the finalize callback above will NOT be called unless the process is running under GC, and CF does not deallocate the memory for you; if running under GC, finalize should do the object tear-down and free the object memory); then return 0
// remember to use saturation arithmetic logic and stop incrementing and decrementing when the ref count hits UINT32_MAX, or you will have a security bug
// remember that reference count incrementing/decrementing must be done thread-safely/atomically
// objects should be created/initialized with a custom ref-count of 1 by the class creation functions
// do not attempt to use any bits within the CFRuntimeBase for your reference count; store that in some additional field in your CF object

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#define CF_REQUIRED_ALIGNMENT_AVAILABLE 1
// If not 0, allocation of object must be on this boundary
uintptr_t requiredAlignment; // Or in _kCFRuntimeRequiresAlignment in the .version field to indicate this field should be used; the allocator to _CFRuntimeCreateInstance() will be ignored in this case; if this is less than the minimum alignment the system supports, you'll get higher alignment; if this is not an alignment the system supports (e.g., most systems will only support powers of two, or if it is too high), the result (consequences) will be up to CF or the system to decide

} CFRuntimeClass;
```
## Objective-C

### 使用的内存部分

ObjectiveC运行时使用的大部分数据在执行过程中会发生变化，因此它使用内存中**\_\_DATA**段中的一些部分：

- **`__objc_msgrefs`** (`message_ref_t`): 消息引用
- **`__objc_ivar`** (`ivar`): 实例变量
- **`__objc_data`** (`...`): 可变数据
- **`__objc_classrefs`** (`Class`): 类引用
- **`__objc_superrefs`** (`Class`): 超类引用
- **`__objc_protorefs`** (`protocol_t *`): 协议引用
- **`__objc_selrefs`** (`SEL`): 选择器引用
- **`__objc_const`** (`...`): 类`r/o`数据和其他（希望是）常量数据
- **`__objc_imageinfo`** (`version, flags`): 在加载图像时使用：当前版本为`0`；标志指定预优化的GC支持等。
- **`__objc_protolist`** (`protocol_t *`): 协议列表
- **`__objc_nlcatlist`** (`category_t`): 指向二进制文件中定义的非延迟类别的指针
- **`__objc_catlist`** (`category_t`): 指向二进制文件中定义的类别的指针
- **`__objc_nlclslist`** (`classref_t`): 指向二进制文件中定义的非延迟Objective-C类的指针
- **`__objc_classlist`** (`classref_t`): 指向二进制文件中定义的所有Objective-C类的指针

它还使用**`__TEXT`**段中的一些部分来存储常量值，如果不可能在此部分中写入：

- **`__objc_methname`** (C字符串): 方法名称
- **`__objc_classname`** (C字符串): 类名称
- **`__objc_methtype`** (C字符串): 方法类型

### 类型编码

Objective-C使用一些混淆来编码简单和复杂类型的选择器和变量类型：

- 基本类型使用类型的第一个字母，如 `i` 代表 `int`，`c` 代表 `char`，`l` 代表 `long`... 如果是无符号的，则使用大写字母（`L` 代表 `unsigned Long`）。
- 其他数据类型的字母已被使用或是特殊的，使用其他字母或符号，如 `q` 代表 `long long`，`b` 代表 `位域`，`B` 代表 `布尔值`，`#` 代表 `类`，`@` 代表 `id`，`*` 代表 `char指针`，`^` 代表通用 `指针`，`?` 代表 `未定义`。
- 数组、结构体和联合使用 `[`, `{` 和 `(`

#### 示例方法声明

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

选择器将是 `processString:withOptions:andError:`

#### 类型编码

* `id` 被编码为 `@`
* `char *` 被编码为 `*`

该方法的完整类型编码为：
```less
@24@0:8@16*20^@24
```
#### 详细分解

1. **返回类型 (`NSString *`)**: 编码为 `@`，长度为 24
2. **`self` (对象实例)**: 编码为 `@`，在偏移量 0
3. **`_cmd` (选择器)**: 编码为 `:`，在偏移量 8
4. **第一个参数 (`char * input`)**: 编码为 `*`，在偏移量 16
5. **第二个参数 (`NSDictionary * options`)**: 编码为 `@`，在偏移量 20
6. **第三个参数 (`NSError ** error`)**: 编码为 `^@`，在偏移量 24

**通过选择器和编码，您可以重构方法。**

### **类**

Objective-C 中的类是一个带有属性、方法指针等的结构体。可以在[**源代码**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)中找到 `objc_class` 结构体：
```objectivec
struct objc_class : objc_object {
// Class ISA;
Class superclass;
cache_t cache;             // formerly cache pointer and vtable
class_data_bits_t bits;    // class_rw_t * plus custom rr/alloc flags

class_rw_t *data() {
return bits.data();
}
void setData(class_rw_t *newData) {
bits.setData(newData);
}

void setInfo(uint32_t set) {
assert(isFuture()  ||  isRealized());
data()->setFlags(set);
}
[...]
```
这个类使用isa字段的一些位来指示关于类的一些信息。

然后，结构体有一个指向存储在磁盘上的`class_ro_t`结构体的指针，其中包含类的属性，如名称、基本方法、属性和实例变量。\
在运行时，还会使用一个额外的结构`class_rw_t`，其中包含可以更改的指针，如方法、协议、属性...
