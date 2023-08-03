# macOS库注入

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="danger" %}
**dyld的代码是开源的**，可以在[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)找到，并且可以使用**URL（例如**[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)**）下载tar文件。**
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> 这是一个以冒号分隔的**动态库列表**，用于在程序指定的库之前加载。这使您可以通过加载一个临时的动态共享库，其中只包含新模块，来测试用于平面命名空间映像中使用的现有动态共享库的新模块。请注意，这对使用动态共享库构建的二级命名空间映像没有任何影响，除非还使用了DYLD\_FORCE\_FLAT\_NAMESPACE。

这类似于Linux上的[**LD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)。

这种技术也可以用作ASEP技术，因为每个安装的应用程序都有一个名为"Info.plist"的plist文件，允许使用名为`LSEnvironmental`的键来分配环境变量。

{% hint style="info" %}
自2012年以来，**Apple已大大降低了**`DYLD_INSERT_LIBRARIES`的权限。

转到代码并**检查`src/dyld.cpp`**。在函数**`pruneEnvironmentVariables`**中，您可以看到**`DYLD_*`**变量被删除。

在函数**`processRestricted`**中，设置了限制的原因。检查该代码，您可以看到原因是：

* 二进制文件是`setuid/setgid`
* 在macho二进制文件中存在`__RESTRICT/__restrict`部分。
* 软件具有没有[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)权限或[`com.apple.security.cs.disable-library-validation`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)权限的权限（硬化运行时）。
* 使用以下命令检查二进制文件的权限：`codesign -dv --entitlements :- </path/to/bin>`
* 如果库与二进制文件使用不同的证书签名
* 如果库和二进制文件使用相同的证书签名，这将绕过先前的限制
* 具有权限**`system.install.apple-software`**和**`system.install.apple-software.standar-user`**的程序可以在不要求用户输入密码的情况下安装由Apple签名的软件（特权升级）

在更新的版本中，您可以在函数**`configureProcessRestrictions`**的第二部分找到此逻辑。但是，在较新的版本中执行的是函数的**开始检查**（您可以删除与iOS或模拟相关的if语句，因为这些在macOS中不会使用）。
{% endhint %}

您可以使用`codesign --display --verbose <bin>`检查二进制文件是否具有**硬化运行时**，并检查**`CodeDirectory`**中的标志运行时，例如：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

在以下位置找到有关如何（滥用）使用此功能并检查限制的示例：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib劫持

{% hint style="danger" %}
请记住，**先前的限制也适用于**执行Dylib劫持攻击。
{% endhint %}

与Windows一样，在MacOS中，您也可以**劫持dylib**以使**应用程序执行**任意**代码**。\
然而，MacOS应用程序加载库的方式比Windows更加受限制。这意味着**恶意软件**开发人员仍然可以使用这种技术进行**隐蔽**，但是滥用此技术以提升权限的可能性要低得多。

首先，**更常见**的是发现**MacOS二进制文件指示加载库的完整路径**。其次，**MacOS从不在$PATH的文件夹中搜索库**。

与此功能相关的**主要代码**部分位于`ImageLoader.cpp`中的**`ImageLoader::recursiveLoadLibraries`**中。

然而，有**2种类型的dylib劫持**：

* **缺少弱链接库**：这意味着应用程序将尝试加载一个使用**LC\_LOAD\_WEAK\_DYLIB**配置的不存在的库。然后，**如果攻击者将dylib放在预期位置，它将被加载**。
* 链接是"weak"的事实意味着即使找不到库，应用程序也将继续运行。
* 与此相关的**代码**位于`ImageLoaderMachO.cpp`的`ImageLoaderMachO::doGetDependentLibraries`函数中，当`LC_LOAD_WEAK_DYLIB`为true时，`lib->required`仅为false。
* 使用以下命令在二进制文件中**查找弱链接库**（稍后有一个示例，说明如何创建劫持库）：
* ```
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **配置为 @rpath**：Mach-O 二进制文件可以有命令 **`LC_RPATH`** 和 **`LC_LOAD_DYLIB`**。根据这些命令的 **值**，**库**将从**不同的目录**加载。
* **`LC_RPATH`** 包含用于加载库的一些文件夹的路径。
* **`LC_LOAD_DYLIB`** 包含要加载的特定库的路径。这些路径可以包含 **`@rpath`**，它将被 **`LC_RPATH`** 中的值替换。如果 **`LC_RPATH`** 中有多个路径，每个路径都将用于搜索要加载的库。例如：
* 如果 **`LC_LOAD_DYLIB`** 包含 `@rpath/library.dylib`，而 **`LC_RPATH`** 包含 `/application/app.app/Contents/Framework/v1/` 和 `/application/app.app/Contents/Framework/v2/`。两个文件夹都将用于加载 `library.dylib`。如果库在 `[...]/v1/` 中不存在，并且攻击者可以将其放在 `[...]/v2/` 中以劫持库的加载，因为遵循 **`LC_LOAD_DYLIB`** 中路径的顺序。
* 使用以下命令在二进制文件中查找 rpath 路径和库：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：是包含**主可执行文件**的目录的**路径**。

**`@loader_path`**：是包含包含加载命令的 Mach-O 二进制文件的**目录**的**路径**。

* 在可执行文件中使用时，**`@loader_path`** 实际上与 **`@executable_path`** 相同。
* 在 **dylib** 中使用时，**`@loader_path`** 给出了 **dylib** 的路径。
{% endhint %}

滥用此功能进行**提权**的方式是，在**以 root 身份执行的应用程序**中，寻找某个**库**位于攻击者具有写权限的某个文件夹中的**罕见情况**。

{% hint style="success" %}
一个很好的用于查找应用程序中**缺失库**的扫描器是 [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) 或者 [**CLI 版本**](https://github.com/pandazheng/DylibHijack)。
关于这种技术的一个带有技术细节的很好的报告可以在[**这里**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)找到。
{% endhint %}

**示例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

### Dlopen Hijacking

来自 **`man dlopen`**：

* 当路径**不包含斜杠字符**（即只是一个叶子名称）时，**dlopen() 将进行搜索**。如果在启动时设置了 **`$DYLD_LIBRARY_PATH`**，dyld 将首先在该目录中查找。接下来，如果调用的 mach-o 文件或主可执行文件指定了 **`LC_RPATH`**，那么 dyld 将在这些目录中查找。接下来，如果进程是**无限制的**，dyld 将在**当前工作目录**中搜索。最后，对于旧的二进制文件，dyld 将尝试一些回退。如果在启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 将在**这些目录**中搜索，否则，dyld 将在 **`/usr/local/lib/`**（如果进程是无限制的）中查找，然后在 **`/usr/lib/`** 中查找。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（如果无限制）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（如果无限制）
6. `/usr/lib/`
* 当路径**看起来像是框架路径**（例如 /stuff/foo.framework/foo）时，如果在启动时设置了 **`$DYLD_FRAMEWORK_PATH`**，dyld 将首先在该目录中查找框架的部分路径（例如 foo.framework/foo）。接下来，dyld 将尝试**使用提供的路径**（对于相对路径，使用当前工作目录）。最后，对于旧的二进制文件，dyld 将尝试一些回退。如果在启动时设置了 **`$DYLD_FALLBACK_FRAMEWORK_PATH`**，dyld 将在这些目录中搜索。否则，它将在 **`/Library/Frameworks`**（在 macOS 上，如果进程是无限制的）中搜索，然后在 **`/System/Library/Frameworks`** 中搜索。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供的路径（对于相对路径，使用当前工作目录）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`（如果无限制）
4. `/Library/Frameworks`（如果无限制）
5. `/System/Library/Frameworks`
* 当路径**包含斜杠但不是框架路径**时（即完整路径或 dylib 的部分路径），dlopen() 首先在（如果设置了）**`$DYLD_LIBRARY_PATH`** 中查找（使用路径的叶子部分）。接下来，dyld **尝试提供的路径**（对于无限制的进程，使用当前工作目录的相对路径）。最后，对于旧的二进制文件，dyld 将尝试一些回退。如果在启动时设置了 **`$DYLD_FALLBACK_LIBRARY_PATH`**，dyld 将在这些目录中搜索，否则，dyld 将在 **`/usr/local/lib/`**（如果进程是无限制的）中查找，然后在 **`/usr/lib/`** 中查找。
1. `$DYLD_LIBRARY_PATH`
2. 提供的路径（对于无限制的进程，使用当前工作目录的相对路径）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（如果无限制）
5. `/usr/lib/`

注意：如果主可执行文件是一个**set\[ug]id 二进制文件或带有授权签名**，则**所有环境变量都会被忽略**，只能使用完整路径。

**检查路径**

让我们使用以下代码检查所有选项：
```c
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

return 0;
}
```
如果您编译并执行它，您可以看到**每个库未成功搜索的位置**。此外，您可以**过滤文件系统日志**：
```bash
sudo fs_usage | grep "dlopentest"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
