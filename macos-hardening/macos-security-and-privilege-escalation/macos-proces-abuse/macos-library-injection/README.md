# macOS Library Injection

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% hint style="danger" %}
**dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**URLのようなもので**tarとしてダウンロードできます：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Dyldプロセス**

Dyldがバイナリ内でライブラリを読み込む方法を確認してください：

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

これは[**LinuxのLD\_PRELOAD**](../../../../linux-hardening/privilege-escalation/#ld\_preload)のようなものです。特定のライブラリをパスから読み込むために実行されるプロセスを指定することができます（環境変数が有効な場合）。

この技術は、すべてのインストールされたアプリケーションに「Info.plist」と呼ばれるplistがあり、`LSEnvironmental`というキーを使用して**環境変数を割り当てることができるため**、**ASEP技術としても使用される可能性があります**。

{% hint style="info" %}
2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の権限を大幅に制限しました**。

コードを確認し、**`src/dyld.cpp`**をチェックしてください。関数**`pruneEnvironmentVariables`**では、**`DYLD_*`**変数が削除されることがわかります。

関数**`processRestricted`**では、制限の理由が設定されます。そのコードを確認すると、理由は次のとおりです：

* バイナリが`setuid/setgid`である
* machoバイナリに`__RESTRICT/__restrict`セクションが存在する
* ソフトウェアに[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)権限なしで権限がある（ハードンされたランタイム）
* バイナリの**権限**を確認するには：`codesign -dv --entitlements :- </path/to/bin>`

より新しいバージョンでは、このロジックは関数**`configureProcessRestrictions`**の後半に見つけることができます。ただし、新しいバージョンで実行されるのは関数の**最初のチェック**です（iOSやシミュレーションに関連するifを削除できます。これらはmacOSでは使用されません）。
{% endhint %}

### ライブラリの検証

バイナリが**`DYLD_INSERT_LIBRARIES`**環境変数の使用を許可していても、バイナリが読み込むライブラリの署名をチェックする場合、カスタムライブラリは読み込まれません。

カスタムライブラリを読み込むには、バイナリが次の**いずれかの権限**を持っている必要があります：

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリは**ハードンされたランタイムフラグ**または**ライブラリ検証フラグ**を持っていない必要があります。

バイナリが**ハードンされたランタイム**を持っているかどうかは、`codesign --display --verbose <bin>`を使用して、**`CodeDirectory`**内のフラグruntimeを確認できます：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

バイナリが**同じ証明書で署名されている**場合、ライブラリを読み込むこともできます。

この方法を（悪用）する方法と制限を確認する例を見つけてください：

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylibハイジャック

{% hint style="danger" %}
**以前のライブラリ検証制限もDylibハイジャック攻撃を実行するために適用されることを忘れないでください。**
{% endhint %}

Windowsと同様に、MacOSでも**dylibsをハイジャック**して**アプリケーション**に**任意の**コードを**実行**させることができます（実際には、通常のユーザーからは、`.app`バンドル内に書き込むためにTCC権限が必要なため、これは不可能かもしれません）。\
ただし、**MacOS**アプリケーションが**ライブラリを読み込む**方法は**Windowsよりも制限されています**。これは、**マルウェア**開発者がこの技術を**隠密性**のために使用できる可能性があることを意味しますが、**権限を昇格させるために悪用できる可能性ははるかに低くなります**。

まず第一に、**MacOSバイナリがライブラリを読み込むための完全なパスを示すことが**より一般的です。第二に、**MacOSはライブラリのために**$PATH**のフォルダを決して検索しません**。

この機能に関連する**コードの主な部分**は、`ImageLoader.cpp`の**`ImageLoader::recursiveLoadLibraries`**にあります。

machoバイナリがライブラリを読み込むために使用できる**4つの異なるヘッダーコマンド**があります：

* **`LC_LOAD_DYLIB`**コマンドはdylibを読み込むための一般的なコマンドです。
* **`LC_LOAD_WEAK_DYLIB`**コマンドは前のコマンドと同様に機能しますが、dylibが見つからない場合、エラーなしで実行が続行されます。
* **`LC_REEXPORT_DYLIB`**コマンドは、別のライブラリからシンボルをプロキシ（または再エクスポート）します。
* **`LC_LOAD_UPWARD_DYLIB`**コマンドは、2つのライブラリが互いに依存している場合に使用されます（これは_上向き依存関係_と呼ばれます）。

ただし、**dylibハイジャックには2種類あります**：

* **欠落している弱リンクライブラリ**：これは、アプリケーションが**LC\_LOAD\_WEAK\_DYLIB**で構成された存在しないライブラリを読み込もうとすることを意味します。次に、**攻撃者が期待される場所にdylibを配置すると、それが読み込まれます**。
* リンクが「弱い」ということは、ライブラリが見つからなくてもアプリケーションは実行を続けることを意味します。
* **これに関連するコード**は、`ImageLoaderMachO::doGetDependentLibraries`の関数内にあり、`lib->required`は`LC_LOAD_WEAK_DYLIB`がtrueのときのみ`false`です。
* バイナリ内の**弱リンクライブラリを見つける**には（後でハイジャックライブラリを作成する方法の例があります）：
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **@rpathで構成されている**：Mach-Oバイナリは**`LC_RPATH`**および**`LC_LOAD_DYLIB`**コマンドを持つことができます。これらのコマンドの**値**に基づいて、**ライブラリ**は**異なるディレクトリ**から**読み込まれます**。
* **`LC_RPATH`**には、バイナリによってライブラリを読み込むために使用されるいくつかのフォルダのパスが含まれています。
* **`LC_LOAD_DYLIB`**には、読み込む特定のライブラリへのパスが含まれています。これらのパスには**`@rpath`**が含まれる場合があり、これは**`LC_RPATH`**の値によって**置き換えられます**。**`LC_RPATH`**に複数のパスがある場合、すべてがライブラリを読み込むために使用されます。例：
* **`LC_LOAD_DYLIB`**に`@rpath/library.dylib`が含まれ、**`LC_RPATH`**に`/application/app.app/Contents/Framework/v1/`および`/application/app.app/Contents/Framework/v2/`が含まれている場合。両方のフォルダが`library.dylib`を読み込むために使用されます。ライブラリが`[...] /v1/`に存在しない場合、攻撃者はそこに配置して`[...] /v2/`のライブラリの読み込みをハイジャックできます。**`LC_LOAD_DYLIB`**のパスの順序が守られます。
* バイナリ内の**rpathパスとライブラリを見つける**には：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：は**メイン実行可能ファイル**を含むディレクトリへの**パス**です。

**`@loader_path`**：は**ロードコマンド**を含む**Mach-Oバイナリ**を含む**ディレクトリ**への**パス**です。

* 実行可能ファイルで使用されると、**`@loader_path`**は実質的に**`@executable_path`**と同じです。
* **dylib**で使用されると、**`@loader_path`**は**dylib**への**パス**を提供します。
{% endhint %}

この機能を悪用して**権限を昇格させる**方法は、**root**によって実行されている**アプリケーション**が**攻撃者が書き込み権限を持つフォルダ内のライブラリを探している**という稀なケースにあります。

{% hint style="success" %}
アプリケーション内の**欠落しているライブラリ**を見つけるための優れた**スキャナー**は[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)または[**CLIバージョン**](https://github.com/pandazheng/DylibHijack)です。\
この技術に関する**技術的詳細**を含む優れた**レポート**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で見つけることができます。
{% endhint %}

**例**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopenハイジャック

{% hint style="danger" %}
**以前のライブラリ検証制限もDlopenハイジャック攻撃を実行するために適用されることを忘れないでください。**
{% endhint %}

**`man dlopen`**から：

* パスに**スラッシュ文字が含まれていない**場合（つまり、単なるリーフ名の場合）、**dlopen()は検索を行います**。**`$DYLD_LIBRARY_PATH`**が起動時に設定されている場合、dyldは最初にそのディレクトリを**検索します**。次に、呼び出し元のmach-oファイルまたはメイン実行可能ファイルが**`LC_RPATH`**を指定している場合、dyldは**それらの**ディレクトリを**検索します**。次に、プロセスが**制限されていない**場合、dyldは**現在の作業ディレクトリ**を検索します。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_LIBRARY_PATH`**が起動時に設定されている場合、dyldは**それらのディレクトリを検索します**。そうでない場合、dyldは**`/usr/local/lib/`**（プロセスが制限されていない場合）を検索し、その後**`/usr/lib/`**を検索します（この情報は**`man dlopen`**から取得されました）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（制限されていない場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（制限されていない場合）
6. `/usr/lib/`

{% hint style="danger" %}
名前にスラッシュがない場合、ハイジャックを行う方法は2つあります：

* いずれかの**`LC_RPATH`**が**書き込み可能**である場合（ただし署名がチェックされるため、これにはバイナリが制限されていない必要があります）
* バイナリが**制限されていない**場合、CWDから何かを読み込むことが可能です（または前述の環境変数のいずれかを悪用することができます）
{% endhint %}

* パスが**フレームワークのように見える**場合（例：`/stuff/foo.framework/foo`）、**`$DYLD_FRAMEWORK_PATH`**が起動時に設定されている場合、dyldは最初にそのディレクトリで**フレームワーク部分パス**（例：`foo.framework/foo`）を検索します。次に、dyldは**提供されたパスをそのまま試みます**（相対パスの場合は現在の作業ディレクトリを使用）。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_FRAMEWORK_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。そうでない場合、dyldは**`/Library/Frameworks`**（macOSでプロセスが制限されていない場合）、次に**`/System/Library/Frameworks`**を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供されたパス（制限されていない場合は相対パスに現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（制限されていない場合）
5. `/System/Library/Frameworks`

{% hint style="danger" %}
フレームワークパスの場合、ハイジャックする方法は次のとおりです：

* プロセスが**制限されていない**場合、CWDからの**相対パス**を悪用することができます。前述の環境変数（プロセスが制限されている場合はDYLD\_\*環境変数が削除されると文書には記載されていませんが）を使用します。
{% endhint %}

* パスに**スラッシュが含まれているがフレームワークパスではない**場合（つまり、dylibへの完全なパスまたは部分的なパス）、dlopen()は最初に（設定されている場合）**`$DYLD_LIBRARY_PATH`**（パスのリーフ部分を使用）を検索します。次に、dyldは**提供されたパスを試みます**（相対パスの場合は現在の作業ディレクトリを使用しますが、制限されていないプロセスの場合のみ）。最後に、古いバイナリの場合、dyldはフォールバックを試みます。**`$DYLD_FALLBACK_LIBRARY_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。そうでない場合、dyldは**`/usr/local/lib/`**（プロセスが制限されていない場合）を検索し、その後**`/usr/lib/`**を検索します。
1. `$DYLD_LIBRARY_PATH`
2. 提供されたパス（制限されていない場合は相対パスに現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（制限されていない場合）
5. `/usr/lib/`

{% hint style="danger" %}
名前にスラッシュがあり、フレームワークでない場合、ハイジャックする方法は次のとおりです：

* バイナリが**制限されていない**場合、CWDまたは`/usr/local/lib`から何かを読み込むことが可能です（または前述の環境変数のいずれかを悪用することができます）
{% endhint %}

{% hint style="info" %}
注意：**dlopen検索を制御するための**設定ファイルは**ありません**。

注意：メイン実行可能ファイルが**set\[ug]idバイナリまたは権限でコードサインされている場合、**すべての環境変数は無視され**、完全なパスのみが使用できます（詳細情報については[DYLD\_INSERT\_LIBRARIES制限を確認してください](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions)）

注意：Appleプラットフォームは、32ビットと64ビットのライブラリを組み合わせるために「ユニバーサル」ファイルを使用します。これは、**32ビットと64ビットの検索パスが別々に存在しないことを意味します**。

注意：Appleプラットフォームでは、ほとんどのOS dylibが**dyldキャッシュに統合され**、ディスク上には存在しません。したがって、OS dylibが存在するかどうかを事前確認するために**`stat()`**を呼び出すことは**機能しません**。ただし、**`dlopen_preflight()`**は、互換性のあるmach-oファイルを見つけるために**`dlopen()`**と同じ手順を使用します。
{% endhint %}

**パスを確認する**

次のコードを使用してすべてのオプションを確認しましょう：
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
もしコンパイルして実行すれば、**各ライブラリがどこで見つからなかったか**を見ることができます。また、**FSログをフィルタリングすることもできます**:
```bash
sudo fs_usage | grep "dlopentest"
```
## 相対パスハイジャック

もし**特権バイナリ/アプリ**（SUIDや強力な権限を持つバイナリなど）が**相対パス**ライブラリを**読み込んでいる**（例えば`@executable_path`や`@loader_path`を使用して）場合、かつ**ライブラリ検証が無効**になっていると、攻撃者が**相対パスで読み込まれるライブラリを変更**できる場所にバイナリを移動させ、プロセスにコードを注入するためにそれを悪用することが可能です。

## `DYLD_*`および`LD_LIBRARY_PATH`環境変数の削除

ファイル`dyld-dyld-832.7.1/src/dyld2.cpp`には、**`pruneEnvironmentVariables`**という関数があり、**`DYLD_`**で始まる任意の環境変数と**`LD_LIBRARY_PATH=`**を削除します。

また、**suid**および**sgid**バイナリのために、特に環境変数**`DYLD_FALLBACK_FRAMEWORK_PATH`**と**`DYLD_FALLBACK_LIBRARY_PATH`**を**null**に設定します。

この関数は、OSXをターゲットにする場合、同じファイルの**`_main`**関数から呼び出されます。
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
そして、それらのブールフラグはコード内の同じファイルに設定されています：
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
基本的には、バイナリが**suid**または**sgid**であるか、ヘッダーに**RESTRICT**セグメントがあるか、**CS\_RESTRICT**フラグで署名されている場合、**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**が真となり、環境変数は削除されます。

CS\_REQUIRE\_LVが真である場合、変数は削除されませんが、ライブラリの検証はそれらが元のバイナリと同じ証明書を使用しているかどうかを確認します。

## 制限の確認

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### セクション `__RESTRICT` とセグメント `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### ハードンされたランタイム

Keychainで新しい証明書を作成し、それを使用してバイナリに署名します：

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
注意してください。**`0x0(none)`** フラグで署名されたバイナリがあっても、実行時に **`CS_RESTRICT`** フラグを動的に取得することができるため、この技術はそれらには機能しません。

プロセスがこのフラグを持っているかどうかは、（[**csops こちら**](https://github.com/axelexic/CSOps)）で確認できます：
```bash
csops -status <pid>
```
そして、フラグ0x800が有効になっているか確認します。
{% endhint %}

## 参考文献

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
