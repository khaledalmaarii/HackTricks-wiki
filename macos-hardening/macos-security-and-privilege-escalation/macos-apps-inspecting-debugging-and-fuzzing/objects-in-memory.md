# メモリ内のオブジェクト

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}

## CFRuntimeClass

CF\*オブジェクトはCoreFoundationから来ており、`CFString`、`CFNumber`、`CFAllocatior`などの50以上のオブジェクトクラスを提供しています。

これらのクラスはすべて`CFRuntimeClass`クラスのインスタンスであり、呼び出されると`__CFRuntimeClassTable`へのインデックスを返します。CFRuntimeClassは[**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html)で定義されています。
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

### 使用されるメモリセクション

ObjectiveCランタイムによって使用されるデータのほとんどは実行中に変化するため、メモリ内の**\_\_DATA**セグメントからいくつかのセクションを使用します:

* **`__objc_msgrefs`** (`message_ref_t`): メッセージの参照
* **`__objc_ivar`** (`ivar`): インスタンス変数
* **`__objc_data`** (`...`): ミュータブルデータ
* **`__objc_classrefs`** (`Class`): クラスの参照
* **`__objc_superrefs`** (`Class`): 親クラスの参照
* **`__objc_protorefs`** (`protocol_t *`): プロトコルの参照
* **`__objc_selrefs`** (`SEL`): セレクタの参照
* **`__objc_const`** (`...`): クラスの`r/o`データおよびその他の（おそらく）定数データ
* **`__objc_imageinfo`** (`version, flags`): イメージの読み込み中に使用されます: 現在のバージョンは`0`です。フラグは事前に最適化されたGCサポートなどを指定します。
* **`__objc_protolist`** (`protocol_t *`): プロトコルリスト
* **`__objc_nlcatlist`** (`category_t`): このバイナリで定義されたNon-Lazyカテゴリへのポインタ
* **`__objc_catlist`**** (`category_t`): このバイナリで定義されたカテゴリへのポインタ
* **`__objc_nlclslist`** (`classref_t`): このバイナリで定義されたNon-Lazy Objective-Cクラスへのポインタ
* **`__objc_classlist`** (`classref_t`): このバイナリで定義されたすべてのObjective-Cクラスへのポインタ

また、定数値を格納するために**`__TEXT`**セグメント内のいくつかのセクションを使用します:

* **`__objc_methname`** (C-String): メソッド名
* **`__objc_classname`** (C-String): クラス名
* **`__objc_methtype`** (C-String): メソッドの型

### 型エンコーディング

Objective-Cは、単純および複雑な型のセレクターおよび変数の型をエンコードするためにいくつかのマングリングを使用します:

* プリミティブ型は、型の最初の文字を使用します。たとえば、`int`の場合は`i`、`char`の場合は`c`、`long`の場合は`l`... そして、符号なしの場合は大文字を使用します（`unsigned Long`の場合は`L`）。
* 他のデータ型で使用される文字や特殊な文字を使用する場合は、`q`は`long long`、`b`は`ビットフィールド`、`B`は`ブール値`、`#`は`クラス`、`@`は`id`、`*`は`charポインタ`、`^`は一般的な`ポインタ`、`?`は`未定義`です。
* 配列、構造体、および共用体は、`[`, `{`, `(`を使用します。

#### メソッド宣言の例

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

セレクタは `processString:withOptions:andError:` になります。

#### タイプエンコーディング

- `id` は `@` とエンコードされます
- `char *` は `*` とエンコードされます

メソッドの完全なタイプエンコーディングは:
```less
@24@0:8@16*20^@24
```
#### 詳細な分析

1. **戻り値の型 (`NSString *`)**: `@` としてエンコードされ、長さ 24 で表される
2. **`self` (オブジェクトインスタンス)**: `@` としてエンコードされ、オフセット 0 に位置する
3. **`_cmd` (セレクタ)**: `:` としてエンコードされ、オフセット 8 に位置する
4. **最初の引数 (`char * input`)**: `*` としてエンコードされ、オフセット 16 に位置する
5. **二番目の引数 (`NSDictionary * options`)**: `@` としてエンコードされ、オフセット 20 に位置する
6. **三番目の引数 (`NSError ** error`)**: `^@` としてエンコードされ、オフセット 24 に位置する

**セレクタとエンコーディングを組み合わせることで、メソッドを再構築できます。**

### **クラス**

Objective-Cにおけるクラスは、プロパティ、メソッドポインタなどを持つ構造体です。[**ソースコード**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html)内で `objc_class` 構造体を見つけることができます。
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
このクラスは、isaフィールドの一部ビットを使用してクラスに関する情報を示します。

その後、構造体には、クラスの名前、基本メソッド、プロパティ、インスタンス変数などの属性を含むディスク上に保存された構造体`class_ro_t`へのポインタがあります。\
ランタイム中には、メソッド、プロトコル、プロパティなどを変更できるポインタを含む追加の構造体`class_rw_t`が使用されます。
