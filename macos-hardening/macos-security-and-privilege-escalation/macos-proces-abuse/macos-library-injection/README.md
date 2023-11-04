# macOS库注入

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="danger" %}
**dyld的代码是开源的**，可以在[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)找到，并且可以使用类似[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)的URL下载tar文件。
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> 这是一个以冒号分隔的**动态库列表**，在指定程序之前加载。这使您可以通过加载一个临时的动态共享库，其中只包含新模块，来测试用于平面命名空间映像中使用的现有动态共享库的新模块。请注意，这对于使用动态共享库构建的二级命名空间映像没有任何影响，除非还使用了DYLD\_FORCE\_FLAT\_NAMESPACE。

这类似于Linux上的[**LD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)。

这种技术也可以作为ASEP技术使用，因为每个安装的应用程序都有一个名为"Info.plist"的plist文件，允许使用名为`LSEnvironmental`的键来分配环境变量。

{% hint style="info" %}
自2012年以来，**Apple已大大降低了`DYLD_INSERT_LIBRARIES`的权限**。

转到代码并检查`src/dyld.cpp`。在函数`pruneEnvironmentVariables`中，您可以看到`DYLD_*`变量被删除。

在函数`processRestricted`中，设置了限制的原因。检查该代码，您可以看到原因是：

* 二进制文件是`setuid/setgid`
* 在macho二进制文件中存在`__RESTRICT/__restrict`部分。
* 软件具有没有[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)权限的授权（强化运行时）
* 使用以下命令检查二进制文件的授权：`codesign -dv --entitlements :- </path/to/bin>`

在更新的版本中，您可以在函数`configureProcessRestrictions`的第二部分找到此逻辑。然而，在较新的版本中执行的是函数的**开始检查**（您可以删除与iOS或模拟相关的if语句，因为这些在macOS中不会使用）。
{% endhint %}

### 库验证

即使二进制文件允许使用**`DYLD_INSERT_LIBRARIES`**环境变量，如果二进制文件检查要加载的库的签名，它将不会加载自定义库。

为了加载自定义库，二进制文件需要具有以下权限之一：

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

或者二进制文件**不应该**具有**强化运行时标志**或**库验证标志**。

您可以使用`codesign --display --verbose <bin>`检查二进制文件是否具有**强化运行时**，并检查**`CodeDirectory`**中的标志运行时，例如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

如果**使用与二进制文件相同的证书签名**，也可以加载库。

在以下示例中找到如何（滥用）使用此功能并检查限制：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}
## Dylib劫持

{% hint style="danger" %}
请记住，执行Dylib劫持攻击时，**之前的库验证限制也适用**。
{% endhint %}

与Windows一样，在MacOS中，您也可以**劫持dylibs**以使**应用程序**执行**任意代码**。\
然而，MacOS应用程序加载库的方式比Windows更受限制。这意味着**恶意软件**开发人员仍然可以使用这种技术进行**隐蔽**，但是滥用此技术以**提升权限的可能性要低得多**。

首先，**更常见的是**在**MacOS二进制文件中找到指示库的完整路径**。其次，**MacOS从不在$PATH文件夹中搜索**库。

与此功能相关的**代码的主要部分**位于`ImageLoader.cpp`中的**`ImageLoader::recursiveLoadLibraries`**中。

Macho二进制文件可以使用**4个不同的头命令**来加载库：

* **`LC_LOAD_DYLIB`**命令是加载dylib的常见命令。
* **`LC_LOAD_WEAK_DYLIB`**命令与前一个命令类似，但如果找不到dylib，则继续执行而不会出现任何错误。
* **`LC_REEXPORT_DYLIB`**命令代理（或重新导出）来自不同库的符号。
* **`LC_LOAD_UPWARD_DYLIB`**命令在两个库相互依赖时使用（这称为_向上依赖_）。

然而，有**2种类型的dylib劫持**：

* **缺少弱链接库**：这意味着应用程序将尝试加载一个使用**LC\_LOAD\_WEAK\_DYLIB**配置的不存在的库。然后，**如果攻击者将dylib放在预期位置，它将被加载**。
* 链接是“弱链接”的事实意味着即使找不到库，应用程序也将继续运行。
* 与此相关的**代码**位于`ImageLoaderMachO.cpp`的`ImageLoaderMachO::doGetDependentLibraries`函数中，其中`lib->required`仅在`LC_LOAD_WEAK_DYLIB`为true时为`false`。
* 在二进制文件中**查找带有弱链接库**（稍后您将看到如何创建劫持库的示例）：
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **配置为@rpath**：Mach-O二进制文件可以具有**`LC_RPATH`**和**`LC_LOAD_DYLIB`**命令。根据这些命令的**值**，将从**不同目录**加载**库**。
* **`LC_RPATH`**包含用于通过二进制文件加载库的某些文件夹的路径。
* **`LC_LOAD_DYLIB`**包含要加载的特定库的路径。这些路径可以包含**`@rpath`**，它将被**`LC_RPATH`**中的值**替换**。如果**`LC_RPATH`**中有多个路径，每个路径都将用于搜索要加载的库。示例：
* 如果**`LC_LOAD_DYLIB`**包含`@rpath/library.dylib`，而**`LC_RPATH`**包含`/application/app.app/Contents/Framework/v1/`和`/application/app.app/Contents/Framework/v2/`。两个文件夹都将用于加载`library.dylib`**。**如果库在`[...]/v1/`中不存在，并且攻击者可以将其放在`[...]/v2/`中以劫持库的加载，因为遵循**`LC_LOAD_DYLIB`**中路径的顺序。
* 在二进制文件中使用以下命令**查找rpath路径和库**：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：是包含**主可执行文件**的**目录路径**。

**`@loader_path`**：是包含包含加载命令的**Mach-O二进制文件**的**目录路径**。

* 在可执行文件中使用时，**`@loader_path`**实际上与**`@executable_path`**相同。
* 在**dylib**中使用时，**`@loader_path`**给出了**dylib**的路径。
{% endhint %}

滥用此功能以**提升权限**的方式是在**以root身份执行的应用程序**中，该应用程序正在**查找**某个**具有写权限的文件夹中的某个库**。

{% hint style="success" %}
一个很好的用于查找应用程序中**缺少库**的**扫描工具**是[Dylib Hijack Scanner](https://objective-see.com/products/dhs.html)或[CLI版本](https://github.com/pandazheng/DylibHijack)。
关于此技术的技术细节的一个很好的**报告**可以在[这里](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)找到。
{% endhint %}

**示例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen劫持

{% hint style="danger" %}
请记住，执行Dlopen劫持攻击时，**之前的库验证限制也适用**。
{% endhint %}

来自**`man dlopen`**：

* 当路径**不包含斜杠字符**（即只是一个叶子名称）时，**dlopen()将进行搜索**。如果在启动时设置了**`$DYLD_LIBRARY_PATH`**，dyld将首先在该目录中**查找**。接下来，如果调用的mach-o文件或主可执行文件指定了**`LC_RPATH`**，那么dyld将在这些目录中**查找**。接下来，如果进程是**不受限制的**，dyld将在**当前工作目录**中搜索。最后，对于旧的二进制文件，dyld将尝试一些回退。如果在启动时设置了**`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld将在**这些目录**中搜索，否则，dyld将在**`/usr/local/lib/`**（如果进程是不受限制的）中搜索，然后在**`/usr/lib/`**中搜索（此信息来自**`man dlopen`**）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（如果不受限制）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（如果不受限制）
6. `/usr/lib/`

{% hint style="danger" %}
如果名称中没有斜杠，有两种方法可以进行劫持：

* 如果任何**`LC_RPATH`**是**可写的**（但是签名已经被检查，所以您还需要二进制文件是不受限制的）
* 如果二进制文件是**不受限制的**，那么可以从CWD中加载某些内容（或滥用其中提到的环境变量之一）
{% endhint %}
* 当路径**看起来像是框架**路径（例如`/stuff/foo.framework/foo`）时，如果在启动时设置了**`$DYLD_FRAMEWORK_PATH`**，dyld将首先在该目录中查找**框架的部分路径**（例如`foo.framework/foo`）。接下来，dyld将尝试使用**提供的路径**（对于相对路径，使用当前工作目录）进行查找。最后，对于旧的二进制文件，dyld将尝试一些回退。如果在启动时设置了**`$DYLD_FALLBACK_FRAMEWORK_PATH`**，dyld将在这些目录中搜索。否则，它将在**`/Library/Frameworks`**（在macOS上，如果进程不受限制）和**`/System/Library/Frameworks`**中搜索。

1. `$DYLD_FRAMEWORK_PATH`
2. 提供的路径（对于相对路径，如果不受限制，则使用当前工作目录）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（如果不受限制）
5. `/System/Library/Frameworks`

{% hint style="danger" %}
如果是框架路径，劫持的方法是：

* 如果进程**不受限制**，滥用来自CWD的**相对路径**和上述环境变量（即使文档中没有提到进程是否受限制，DYLD\_\*环境变量会被删除）
{% endhint %}

* 当路径**包含斜杠但不是框架路径**（即完整路径或dylib的部分路径）时，dlopen()首先在（如果设置了）**`$DYLD_LIBRARY_PATH`**中查找（使用路径的末尾部分）。接下来，dyld将尝试使用**提供的路径**（对于相对路径，仅对于不受限制的进程）进行查找。最后，对于旧的二进制文件，dyld将尝试一些回退。如果在启动时设置了**`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld将在这些目录中搜索，否则，dyld将在**`/usr/local/lib/`**（如果进程不受限制）和**`/usr/lib/`**中查找。

1. `$DYLD_LIBRARY_PATH`
2. 提供的路径（对于相对路径，如果不受限制，则使用当前工作目录）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（如果不受限制）
5. `/usr/lib/`

{% hint style="danger" %}
如果名称中包含斜杠而不是框架，劫持的方法是：

* 如果二进制文件**不受限制**，则可以从CWD或`/usr/local/lib`加载内容（或滥用上述环境变量之一）
{% endhint %}

{% hint style="info" %}
注意：**没有**配置文件来**控制dlopen搜索**。

注意：如果主可执行文件是**set\[ug]id二进制文件或使用授权签名**，则**所有环境变量都会被忽略**，只能使用完整路径（有关更详细的信息，请查看[检查DYLD\_INSERT\_LIBRARIES限制](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions)）。

注意：Apple平台使用“通用”文件来组合32位和64位库。这意味着**没有单独的32位和64位搜索路径**。

注意：在Apple平台上，大多数操作系统dylib都**合并到dyld缓存中**，并且不存在于磁盘上。因此，调用**`stat()`**来预先检查操作系统dylib是否存在**不起作用**。但是，**`dlopen_preflight()`**使用与**`dlopen()`**相同的步骤来查找兼容的mach-o文件。
{% endhint %}

**检查路径**

让我们使用以下代码检查所有选项：
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
如果您编译并执行它，您可以看到**每个库未成功搜索的位置**。此外，您可以**过滤文件系统日志**：
```bash
sudo fs_usage | grep "dlopentest"
```
## 删除`DYLD_*`和`LD_LIBRARY_PATH`环境变量

在文件`dyld-dyld-832.7.1/src/dyld2.cpp`中，可以找到函数**`pruneEnvironmentVariables`**，它将删除任何以**`DYLD_`**和**`LD_LIBRARY_PATH=`**开头的环境变量。

对于**suid**和**sgid**二进制文件，它还会将环境变量**`DYLD_FALLBACK_FRAMEWORK_PATH`**和**`DYLD_FALLBACK_LIBRARY_PATH`**设置为**null**。

如果目标是OSX，该函数将从同一文件的**`_main`**函数中调用，如下所示：
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
并且这些布尔标志在代码中的同一个文件中设置：
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
这基本上意味着，如果二进制文件是**suid**或**sgid**，或者在头部有一个**RESTRICT**段，或者使用**CS\_RESTRICT**标志进行签名，那么**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**为真，环境变量将被修剪。

请注意，如果CS\_REQUIRE\_LV为真，则变量不会被修剪，但库验证将检查它们是否使用与原始二进制文件相同的证书。

## 检查限制

### SUID和SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### `__RESTRICT`部分与`__restrict`段

The `__RESTRICT` section is a segment in macOS that is used to restrict access to certain libraries and prevent unauthorized processes from injecting code into them. This section is specifically designed to enhance the security of macOS by preventing privilege escalation attacks through library injection.

The `__restrict` segment, on the other hand, is a specific area within the `__RESTRICT` section that contains code and data that are restricted from modification or injection. This segment is heavily protected by macOS to ensure the integrity and security of the libraries it contains.

By leveraging the `__RESTRICT` section and the `__restrict` segment, macOS can effectively mitigate the risks associated with library injection attacks, making it more difficult for malicious actors to exploit vulnerabilities and gain unauthorized access to sensitive system resources.

### `__RESTRICT`部分与`__restrict`段

`__RESTRICT`部分是macOS中的一个段，用于限制对某些库的访问，并防止未经授权的进程向其注入代码。该部分专门设计用于增强macOS的安全性，通过防止通过库注入进行权限提升攻击。

另一方面，`__restrict`段是`__RESTRICT`部分中的一个特定区域，其中包含受限制的代码和数据，禁止进行修改或注入。macOS对该段进行了严格保护，以确保其中包含的库的完整性和安全性。

通过利用`__RESTRICT`部分和`__restrict`段，macOS可以有效地减轻与库注入攻击相关的风险，使恶意行为者更难利用漏洞并未授权地访问敏感系统资源。
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### 强化运行时

在钥匙串中创建一个新的证书，并使用它对二进制文件进行签名：

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
请注意，即使有用标志**`0x0(none)`**签名的二进制文件，当执行时它们也可以动态地获得**`CS_RESTRICT`**标志，因此这种技术在它们上面不起作用。

您可以使用以下命令检查进程是否具有此标志（获取[**csops here**](https://github.com/axelexic/CSOps)）：&#x20;
```bash
csops -status <pid>
```
然后检查是否启用了标志位0x800。
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
