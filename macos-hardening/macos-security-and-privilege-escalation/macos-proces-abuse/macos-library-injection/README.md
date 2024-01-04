# macOS 库注入

<details>

<summary><strong>从零到英雄学习 AWS 黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

{% hint style="danger" %}
**dyld 的代码是开源的**，可以在 [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) 找到，并且可以使用类似 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) 的**URL**下载 tar 包。
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> 这是一个以冒号分隔的**动态库列表**，要在**程序指定的库之前加载**。这允许您通过加载一个只包含新模块的临时动态共享库来测试现有动态共享库中使用的新模块。请注意，这对使用动态共享库构建的两级命名空间图像没有影响，除非也使用了 DYLD\_FORCE\_FLAT\_NAMESPACE。

这类似于 [**Linux 上的 LD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)。

这种技术也可以**用作 ASEP 技术**，因为每个安装的应用程序都有一个名为 "Info.plist" 的 plist，允许使用名为 `LSEnvironmental` 的键**分配环境变量**。

{% hint style="info" %}
自 2012 年以来，**Apple 大幅减少了** **`DYLD_INSERT_LIBRARIES`** 的功能。

转到代码并**检查 `src/dyld.cpp`**。在函数 **`pruneEnvironmentVariables`** 中，您可以看到 **`DYLD_*`** 变量被移除。

在函数 **`processRestricted`** 中设置了限制的原因。检查该代码，您可以看到原因是：

* 二进制文件是 `setuid/setgid`
* macho 二进制文件中存在 `__RESTRICT/__restrict` 部分。
* 软件具有权利（加固的运行时）而没有 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) 权利
* 使用以下命令检查二进制文件的**权利**：`codesign -dv --entitlements :- </path/to/bin>`

在更新的版本中，您可以在函数 **`configureProcessRestrictions`** 的第二部分找到这个逻辑。然而，在较新版本中执行的是函数**开始检查**（您可以删除与 iOS 或模拟相关的 if，因为这些在 macOS 中不会使用。
{% endhint %}

### 库验证

即使二进制文件允许使用 **`DYLD_INSERT_LIBRARIES`** 环境变量，如果二进制文件检查要加载的库的签名，它不会加载自定义内容。

为了加载自定义库，二进制文件需要具有以下**之一的权利**：

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

或者二进制文件**不应该**有**加固的运行时标志**或**库验证标志**。

您可以使用 `codesign --display --verbose <bin>` 检查二进制文件是否具有**加固的运行时**，检查 **`CodeDirectory`** 中的 runtime 标志，如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

您还可以加载一个库，如果它**与二进制文件使用相同的证书签名**。

在以下位置找到如何（滥用）此功能并检查限制的示例：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib 劫持

{% hint style="danger" %}
记住，**之前的库验证限制也适用于**执行 Dylib 劫持攻击。
{% endhint %}

与 Windows 一样，在 MacOS 中，您也可以**劫持 dylibs** 以使**应用程序** **执行** **任意** **代码**。\
然而，**MacOS** 应用程序**加载**库的方式比 Windows 更**受限制**。这意味着**恶意软件**开发人员仍然可以使用这种技术进行**隐身**，但能够**滥用此功能以提升权限的可能性要低得多**。

首先，更常见的是发现**MacOS 二进制文件指示加载库的完整路径**。其次，**MacOS 从不在** **$PATH** 文件夹中搜索库。

与此功能相关的**主要**部分**代码**在 `ImageLoader.cpp` 中的 **`ImageLoader::recursiveLoadLibraries`**。

macho 二进制文件可以使用四种不同的头部命令来加载库：

* **`LC_LOAD_DYLIB`** 命令是加载 dylib 的常见命令。
* **`LC_LOAD_WEAK_DYLIB`** 命令的工作原理与前一个相同，但如果找不到 dylib，执行将继续而不会出现任何错误。
* **`LC_REEXPORT_DYLIB`** 命令它代理（或重新导出）来自不同库的符号。
* **`LC_LOAD_UPWARD_DYLIB`** 命令在两个库相互依赖时使用（这称为向上依赖）。

然而，有**两种类型的 dylib 劫持**：

* **缺少弱链接库**：这意味着应用程序将尝试加载一个不存在的库，配置为 **LC\_LOAD\_WEAK\_DYLIB**。然后，**如果攻击者将 dylib 放在预期的位置，它将被加载**。
* 链接是“弱”的事实意味着即使找不到库，应用程序也会继续运行。
* 与此相关的**代码**在 `ImageLoaderMachO.cpp` 中的函数 `ImageLoaderMachO::doGetDependentLibraries` 中，其中 `lib->required` 仅在 `LC_LOAD_WEAK_DYLIB` 为真时为 `false`。
* **在二进制文件中查找弱链接库**（稍后您有一个如何创建劫持库的示例）：
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **配置为 @rpath**：Mach-O 二进制文件可以有命令 **`LC_RPATH`** 和 **`LC_LOAD_DYLIB`**。基于这些命令的**值**，**库**将从**不同的目录**中**加载**。
* **`LC_RPATH`** 包含二进制文件用于加载库的一些文件夹的路径。
* **`LC_LOAD_DYLIB`** 包含要加载的特定库的路径。这些路径可以包含 **`@rpath`**，它将被 **`LC_RPATH`** 中的值**替换**。如果 **`LC_RPATH`** 中有几个路径，每个人都将被用来搜索要加载的库。例如：
* 如果 **`LC_LOAD_DYLIB`** 包含 `@rpath/library.dylib` 并且 **`LC_RPATH`** 包含 `/application/app.app/Contents/Framework/v1/` 和 `/application/app.app/Contents/Framework/v2/`。两个文件夹都将被用来加载 `library.dylib`**。** 如果库在 `[...]/v1/` 中不存在，并且攻击者可以将其放在那里以劫持 `[...]/v2/` 中的库加载，因为遵循 **`LC_LOAD_DYLIB`** 中的路径顺序。
* **在二进制文件中查找 rpath 路径和库**：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：是指向包含**主执行文件**的目录的**路径**。

**`@loader_path`**：是指向包含包含加载命令的**Mach-O 二进制文件**的**目录**的**路径**。

* 在可执行文件中使用时，**`@loader_path`** 实际上与 **`@executable_path`** **相同**。
* 在 **dylib** 中使用时，**`@loader_path`** 提供了指向 **dylib** 的**路径**。
{% endhint %}

通过滥用此功能**提升权限**的方式将是在罕见的情况下，一个**由 root 执行的应用程序**正在**寻找**某个**库**，攻击者在其中拥有写权限的某个文件夹。

{% hint style="success" %}
一个不错的**扫描器**来查找应用程序中的**缺失库**是 [**Dylib 劫持扫描器**](https://objective-see.com/products/dhs.html) 或 [**CLI 版本**](https://github.com/pandazheng/DylibHijack)。\
关于这项技术的**技术细节报告**可以在[**这里**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)找到。
{% endhint %}

**示例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen 劫持

{% hint style="danger" %}
记住，**之前的库验证限制也适用于**执行 Dlopen 劫持攻击。
{% endhint %}

从 **`man dlopen`**：

* 当路径**不包含斜杠字符**（即它只是一个叶子名称）时，**dlopen() 将进行搜索**。如果在启动时设置了 **`$DYLD_LIBRARY_PATH`**，dyld 首先将**在该目录中查找**。接下来，如果调用 mach-o 文件或主执行文件指定了 **`LC_RPATH`**，那么 dyld 将**在这些目录中查找**。接下来，如果进程**不受限制**，dyld 将在**当前工作目录**中搜索。最后，对于旧的二进制文件，dyld 将尝试一些后备方案。如果在启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 将在**这些目录中搜索**，否则，dyld 将在 **`/usr/local/lib/`** 中查找（如果进程不受限制），然后在 **`/usr/lib/`** 中查找（此信息取自 **`man dlopen`**）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(如果不受限制)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (如果不受限制)
6. `/usr/lib/`

{% hint style="danger" %}
如果名称中没有斜杠，有两种方式可以进行劫持：

* 如果任何 **`LC_RPATH`** 是**可写的**（但签名会被检查，所以对此你还需要二进制文件不受限制）
* 如果二进制文件**不受限制**，那么可以从 CWD 加载某些内容（或滥用上述提到的环境变量）
{% endhint %}

* 当路径**看起来像框架路径**（例如 `/stuff/foo.framework/foo`），如果在启动时设置了 **`$DYLD_FRAMEWORK_PATH`**，dyld 首先会在该目录中查找**框架部分路径**（例如 `foo.framework/foo`）。接下来，dyld 将尝试**按原样提供的路径**（对于相对路径使用当前工作目录）。最后，对于旧的二进制文件，dyld 将尝试一些后备方案。如果在启动时设置了 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**，dyld 将搜索这些目录。否则，它将搜索 **`/Library/Frameworks`**（在 macOS 上如果进程不受限制），然后是 **`/System/Library/Frameworks`**。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供的路径（如果不受限制，使用当前工作目录的相对路径）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (如果不受限制)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
如果是框架路径，劫持的方式将是：

* 如果进程**不受限制**，滥用**相对于 CWD 的相对路径**提到的环境变量（即使在文档中没有说如果进程受限制 DYLD\_\* 环境变量会被移除）
{% endhint %}

* 当路径**包含斜杠但不是框架路径**（即完整路径或指向 dylib 的部分路径）时，dlopen() 首先在（如果设置）**`$DYLD_LIBRARY_PATH`** 中查找（带有路径的叶子部分）。接下来，dyld **尝试提供的路径**（对于相对路径使用当前工作目录（但仅适用于不受限制的进程））。最后，对于较旧的二进制文件，dyld 将尝试后备方案。如果在启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 将在这些目录中搜索，否则，dyld 将在 **`/usr/local/lib/`** 中查找（如果进程不受限制），然后在 **`/usr/lib/`** 中查找。
1. `$DYLD_LIBRARY_PATH`
2. 提供的路径（如果不
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
如果您编译并执行它，您可以看到**每个库未成功搜索的位置**。此外，您还可以**过滤FS日志**：
```bash
sudo fs_usage | grep "dlopentest"
```
## 相对路径劫持

如果一个**具有特权的二进制文件/应用程序**（如 SUID 或具有强大权限的某些二进制文件）正在**加载相对路径库**（例如使用 `@executable_path` 或 `@loader_path`）并且**禁用了库验证**，那么有可能将二进制文件移动到攻击者可以**修改相对路径加载库**的位置，并滥用它在进程中注入代码。

## 清除 `DYLD_*` 和 `LD_LIBRARY_PATH` 环境变量

在文件 `dyld-dyld-832.7.1/src/dyld2.cpp` 中，可以找到函数**`pruneEnvironmentVariables`**，它将删除任何以 **`DYLD_`** 开头和 **`LD_LIBRARY_PATH=`** 的环境变量。

对于**suid** 和 **sgid** 二进制文件，它还会将环境变量 **`DYLD_FALLBACK_FRAMEWORK_PATH`** 和 **`DYLD_FALLBACK_LIBRARY_PATH`** 特别设置为**空**。

如果针对 OSX，这个函数会从同一文件的 **`_main`** 函数中被调用，如下所示：
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
和这些布尔标志在代码中的同一个文件中设置：
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
## 检查限制

### SUID & SGID

基本上意味着，如果二进制文件是 **suid** 或 **sgid**，或者在头部有 **RESTRICT** 段，或者它是用 **CS\_RESTRICT** 标志签名的，那么 **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** 将为真，环境变量将被剪裁。

注意，如果 CS\_REQUIRE\_LV 为真，则变量不会被剪裁，但库验证将检查它们是否使用与原始二进制文件相同的证书。
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### 部分 `__RESTRICT` 与段 `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### 强化运行时

在钥匙串中创建一个新证书，并使用它来对二进制文件进行签名：

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
请注意，即使有些二进制文件被标记为 **`0x0(none)`**，它们在执行时也可能动态获得 **`CS_RESTRICT`** 标志，因此这种技术在这些进程上不会起作用。

您可以使用以下命令检查进程是否具有此标志（获取 [**csops 在这里**](https://github.com/axelexic/CSOps)）：&#x20;
```bash
csops -status <pid>
```
然后检查是否启用了标志0x800。
{% endhint %}

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
