# macOS Apps - Inspecting, debugging and Fuzzing

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、企業やその顧客が **stealer malwares** によって **compromised** されているかどうかを確認するための **無料** 機能を提供する **ダークウェブ** に基づいた検索エンジンです。

WhiteIntel の主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、**無料** でエンジンを試すことができます:

{% embed url="https://whiteintel.io" %}

***

## Static Analysis

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}
```bash
nm -m ./tccd # List of symbols
```
### jtool2 & Disarm

あなたは[**ここから disarm をダウンロードできます**](https://newosxbook.com/tools/disarm.html)。
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
ここから[**jtool2をダウンロード**](http://www.newosxbook.com/tools/jtool.html)するか、`brew`を使ってインストールできます。
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
{% hint style="danger" %}
**jtoolはdisarmに取って代わられました**
{% endhint %}

### コード署名 / ldid

{% hint style="success" %}
**`Codesign`**は**macOS**にあり、**`ldid`**は**iOS**にあります
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) は、**.pkg** ファイル（インストーラー）を検査し、インストールする前にその内容を確認するのに役立つツールです。\
これらのインストーラーには、マルウェア作成者が通常悪用する `preinstall` および `postinstall` bash スクリプトがあります。これにより、**マルウェア**を**持続**させることができます。

### hdiutil

このツールは、Apple のディスクイメージ（**.dmg**）ファイルを**マウント**して、何かを実行する前に検査することを可能にします：
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
It will be mounted in `/Volumes`

### Packed binaries

* 高エントロピーをチェック
* 文字列をチェック（理解できる文字列がほとんどない場合、パックされている）
* MacOS用のUPXパッカーは「\_\_XHDR」というセクションを生成します

## Static Objective-C analysis

### Metadata

{% hint style="danger" %}
Objective-Cで書かれたプログラムは、[Mach-Oバイナリ](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)にコンパイルされるときに、クラス宣言を**保持**します。このようなクラス宣言には、以下の名前とタイプが**含まれます**：
{% endhint %}

* 定義されたインターフェース
* インターフェースメソッド
* インターフェースインスタンス変数
* 定義されたプロトコル

これらの名前は、バイナリのリバースエンジニアリングを難しくするために難読化される可能性があることに注意してください。

### Function calling

Objective-Cを使用するバイナリで関数が呼び出されると、コンパイルされたコードはその関数を呼び出すのではなく、**`objc_msgSend`**を呼び出します。これが最終的な関数を呼び出します：

![](<../../../.gitbook/assets/image (305).png>)

この関数が期待するパラメータは次のとおりです：

* 最初のパラメータ（**self**）は「**メッセージを受け取るクラスのインスタンスを指すポインタ**」です。簡単に言えば、これはメソッドが呼び出されるオブジェクトです。メソッドがクラスメソッドの場合、これはクラスオブジェクトのインスタンス（全体）になりますが、インスタンスメソッドの場合、selfはクラスのインスタンス化されたインスタンスをオブジェクトとして指します。
* 2番目のパラメータ（**op**）は「メッセージを処理するメソッドのセレクタ」です。再度、簡単に言えば、これは単に**メソッドの名前**です。
* 残りのパラメータは、メソッド（op）によって必要とされる**値**です。

この情報を**ARM64で`lldb`を使って簡単に取得する方法**をこのページで確認してください：

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argument**      | **Register**                                                    | **(for) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: メソッドが呼び出されるオブジェクト**         |
| **2nd argument**  | **rsi**                                                         | **op: メソッドの名前**                               |
| **3rd argument**  | **rdx**                                                         | **メソッドへの1番目の引数**                           |
| **4th argument**  | **rcx**                                                         | **メソッドへの2番目の引数**                           |
| **5th argument**  | **r8**                                                          | **メソッドへの3番目の引数**                           |
| **6th argument**  | **r9**                                                          | **メソッドへの4番目の引数**                           |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(スタック上)</strong></p> | **メソッドへの5番目以降の引数**                       |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump)は、Objective-Cバイナリをクラスダンプするためのツールです。GitHubではdylibsが指定されていますが、実行可能ファイルでも動作します。
```bash
./dynadump dump /path/to/bin
```
執筆時点では、これは**現在最も効果的なものです**。

#### 一般的なツール
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) は、Objective-C 形式のコード内のクラス、カテゴリ、およびプロトコルの宣言を生成するための元のツールです。

古くてメンテナンスされていないため、正しく動作しない可能性があります。

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) は、現代的でクロスプラットフォームの Objective-C クラスダンプです。既存のツールと比較して、iCDump は Apple エコシステムから独立して実行でき、Python バインディングを公開しています。
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static Swift analysis

Swiftバイナリでは、Objective-Cとの互換性があるため、時々[class-dump](https://github.com/nygard/class-dump/)を使用して宣言を抽出できますが、常に可能ではありません。

**`jtool -l`**または**`otool -l`**コマンドラインを使用すると、**`__swift5`**プレフィックスで始まるいくつかのセクションを見つけることができます：
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
さらに、[**このセクションに保存されている情報についての詳細はこのブログ記事で見つけることができます**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)。

さらに、**Swiftバイナリにはシンボルが含まれている可能性があります**（例えば、ライブラリはその関数を呼び出すためにシンボルを保存する必要があります）。**シンボルには通常、関数名と属性に関する情報が含まれています**が、見栄えが悪いため非常に便利であり、元の名前を取得できる「**デマンガラー**」があります：
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## 動的分析

{% hint style="warning" %}
バイナリをデバッグするには、**SIPを無効にする必要があります**（`csrutil disable`または`csrutil enable --without debug`）またはバイナリを一時フォルダにコピーし、`codesign --remove-signature <binary-path>`で**署名を削除する**か、バイナリのデバッグを許可する必要があります（[このスクリプト](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)を使用できます）。
{% endhint %}

{% hint style="warning" %}
macOSで**システムバイナリ**（例えば`cloudconfigurationd`）を**計測する**には、**SIPを無効にする必要があります**（署名を削除するだけでは機能しません）。
{% endhint %}

### API

macOSはプロセスに関する情報を提供するいくつかの興味深いAPIを公開しています：

* `proc_info`: 各プロセスに関する多くの情報を提供する主要なAPIです。他のプロセスの情報を取得するにはroot権限が必要ですが、特別な権限やmachポートは必要ありません。
* `libsysmon.dylib`: XPCで公開された関数を介してプロセスに関する情報を取得することを可能にしますが、`com.apple.sysmond.client`の権限が必要です。

### スタックショットとマイクロスタックショット

**スタックショット**は、プロセスの状態をキャプチャするための技術で、すべての実行中のスレッドのコールスタックを含みます。これは、デバッグ、パフォーマンス分析、特定の時点でのシステムの動作を理解するのに特に役立ちます。iOSおよびmacOSでは、**`sample`**や**`spindump`**などのツールや方法を使用してスタックショットを実行できます。

### Sysdiagnose

このツール（`/usr/bini/ysdiagnose`）は、`ps`、`zprint`などの異なるコマンドを数十個実行して、コンピュータから多くの情報を収集します。

**root**として実行する必要があり、デーモン`/usr/libexec/sysdiagnosed`は、`com.apple.system-task-ports`や`get-task-allow`などの非常に興味深い権限を持っています。

そのplistは`/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`にあり、3つのMachServicesを宣言しています：

* `com.apple.sysdiagnose.CacheDelete`: /var/rmp内の古いアーカイブを削除します
* `com.apple.sysdiagnose.kernel.ipc`: 特殊ポート23（カーネル）
* `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-Cクラスを介したユーザーモードインターフェース。辞書内に3つの引数（`compress`、`display`、`run`）を渡すことができます。

### 統一ログ

MacOSは、アプリケーションを実行して**何をしているのか**を理解する際に非常に役立つ多くのログを生成します。

さらに、いくつかのログには`<private>`タグが含まれ、**ユーザー**または**コンピュータ**の**識別可能**な情報を**隠す**ために使用されます。ただし、**この情報を開示するための証明書をインストールすることが可能です**。詳細は[**こちら**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)を参照してください。

### Hopper

#### 左パネル

Hopperの左パネルでは、バイナリのシンボル（**ラベル**）、手続きと関数のリスト（**Proc**）、および文字列（**Str**）を見ることができます。これらはすべての文字列ではなく、Mac-Oファイルのいくつかの部分で定義されたもの（_cstringや`objc_methname`など）です。

#### 中央パネル

中央パネルでは、**逆アセンブルされたコード**を見ることができます。また、**生の**逆アセンブル、**グラフ**、**デコンパイルされた**もの、**バイナリ**としてそれぞれのアイコンをクリックすることで表示できます：

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

コードオブジェクトを右クリックすると、そのオブジェクトへの**参照**や**そのオブジェクトからの参照**を見ることができ、名前を変更することもできます（これはデコンパイルされた擬似コードでは機能しません）：

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

さらに、**中央下部ではPythonコマンドを入力することができます**。

#### 右パネル

右パネルでは、**ナビゲーション履歴**（現在の状況にどのように到達したかを知るため）、**コールグラフ**（この関数を呼び出すすべての**関数**と、この関数が呼び出すすべての関数を見ることができます）、および**ローカル変数**の情報など、興味深い情報を見ることができます。

### dtrace

これは、ユーザーがアプリケーションに非常に**低レベル**でアクセスできるようにし、プログラムを**トレース**し、その実行フローを変更する方法を提供します。Dtraceは、**カーネル全体に配置された**プローブを使用し、システムコールの開始と終了などの場所にあります。

DTraceは、各システムコールのプローブを作成するために**`dtrace_probe_create`**関数を使用します。これらのプローブは、各システムコールの**エントリポイントとエグジットポイント**で発火することができます。DTraceとのインタラクションは、/dev/dtraceを介して行われ、これはrootユーザーのみが利用可能です。

{% hint style="success" %}
SIP保護を完全に無効にせずにDtraceを有効にするには、リカバリモードで次のコマンドを実行できます：`csrutil enable --without dtrace`

また、**`dtrace`**または**`dtruss`**バイナリを**自分でコンパイルした**ものを使用することもできます。
{% endhint %}

dtraceの利用可能なプローブは次のコマンドで取得できます：
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
プローブ名は、プロバイダー、モジュール、関数、および名前（`fbt:mach_kernel:ptrace:entry`）の4つの部分で構成されています。名前の一部を指定しない場合、Dtraceはその部分をワイルドカードとして適用します。

DTraceを構成してプローブをアクティブにし、発火したときに実行するアクションを指定するには、D言語を使用する必要があります。

より詳細な説明と例については、[https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)を参照してください。

#### 例

`man -k dtrace`を実行して**利用可能なDTraceスクリプト**のリストを表示します。例：`sudo dtruss -n binary`

* 行
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* スクリプト
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

これはカーネルトレース機能です。文書化されたコードは **`/usr/share/misc/trace.codes`** にあります。

`latency`、`sc_usage`、`fs_usage`、および `trace` のようなツールは内部でこれを使用します。

`kdebug` とインターフェースするために、`sysctl` が `kern.kdebug` 名前空間を介して使用され、使用する MIB は `bsd/kern/kdebug.c` に実装された関数を持つ `sys/sysctl.h` にあります。

カスタムクライアントで kdebug と対話するための一般的な手順は次のとおりです：

* KERN\_KDSETREMOVE で既存の設定を削除
* KERN\_KDSETBUF と KERN\_KDSETUP でトレースを設定
* KERN\_KDGETBUF を使用してバッファエントリの数を取得
* KERN\_KDPINDEX でトレースから自分のクライアントを取得
* KERN\_KDENABLE でトレースを有効化
* KERN\_KDREADTR を呼び出してバッファを読み取る
* 各スレッドをそのプロセスにマッチさせるために KERN\_KDTHRMAP を呼び出す。

この情報を取得するために、Apple のツール **`trace`** またはカスタムツール [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** を使用することができます。**

**Kdebug は同時に 1 つの顧客にのみ利用可能であることに注意してください。** したがって、同時に実行できる k-debug 対応ツールは 1 つだけです。

### ktrace

`ktrace_*` API は `libktrace.dylib` から来ており、これが `Kdebug` のラッパーです。クライアントは `ktrace_session_create` と `ktrace_events_[single/class]` を呼び出して特定のコードにコールバックを設定し、次に `ktrace_start` で開始できます。

**SIP が有効な状態でもこれを使用できます。**

クライアントとしてユーティリティ `ktrace` を使用できます：
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

これはカーネルレベルのプロファイリングを行うために使用され、`Kdebug` コールアウトを使用して構築されています。

基本的に、グローバル変数 `kernel_debug_active` がチェックされ、設定されている場合は `kperf_kdebug_handler` を `Kdebug` コードとカーネルフレームのアドレスで呼び出します。`Kdebug` コードが選択されたものと一致する場合、ビットマップとして構成された「アクション」を取得します（オプションについては `osfmk/kperf/action.h` を確認してください）。

Kperf には sysctl MIB テーブルもあります：（root として）`sysctl kperf`。これらのコードは `osfmk/kperf/kperfbsd.c` にあります。

さらに、Kperf の機能の一部は `kpc` に存在し、マシンのパフォーマンスカウンタに関する情報を提供します。

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) は、プロセスが実行しているプロセス関連のアクションを確認するための非常に便利なツールです（例えば、プロセスが作成している新しいプロセスを監視します）。

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) は、プロセス間の関係を印刷するツールです。\
**`sudo eslogger fork exec rename create > cap.json`** のようなコマンドで Mac を監視する必要があります（このターミナルを起動するには FDA が必要です）。その後、このツールに json を読み込ませてすべての関係を表示できます：

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) は、ファイルイベント（作成、変更、削除など）を監視し、そのようなイベントに関する詳細情報を提供します。

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) は、Windows ユーザーが Microsoft Sysinternal の _Procmon_ から知っているかもしれないルックアンドフィールを持つ GUI ツールです。このツールは、さまざまなイベントタイプの記録を開始および停止でき、ファイル、プロセス、ネットワークなどのカテゴリによってこれらのイベントをフィルタリングでき、記録されたイベントを json 形式で保存する機能を提供します。

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) は、アプリケーションのパフォーマンスを監視し、メモリリークを特定し、ファイルシステムのアクティビティを追跡するために使用される Xcode の開発者ツールの一部です。

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

プロセスによって実行されるアクションを追跡することができます：
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) は、バイナリで使用されている **ライブラリ**、使用中の **ファイル**、および **ネットワーク** 接続を確認するのに便利です。\
また、バイナリプロセスを **virustotal** と照合し、バイナリに関する情報を表示します。

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**このブログ記事**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) では、SIP が無効になっていてもデバッグを防ぐために **`PT_DENY_ATTACH`** を使用した **実行中のデーモンをデバッグする** 方法の例を見つけることができます。

### lldb

**lldb** は **macOS** バイナリ **デバッグ** のための事実上のツールです。
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
あなたは、次の行を含む**`.lldbinit`**というファイルをホームフォルダに作成することで、lldbを使用する際にintelフレーバーを設定できます:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb内で、`process save-core`を使用してプロセスをダンプします
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) コマンド</strong></td><td><strong>説明</strong></td></tr><tr><td><strong>run (r)</strong></td><td>実行を開始し、ブレークポイントがヒットするかプロセスが終了するまで継続します。</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>エントリポイントで停止する実行を開始します</td></tr><tr><td><strong>continue (c)</strong></td><td>デバッグ中のプロセスの実行を続けます。</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>次の命令を実行します。このコマンドは関数呼び出しをスキップします。</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>次の命令を実行します。nextiコマンドとは異なり、このコマンドは関数呼び出しに入ります。</td></tr><tr><td><strong>finish (f)</strong></td><td>現在の関数（“フレーム”）内の残りの命令を実行し、戻って停止します。</td></tr><tr><td><strong>control + c</strong></td><td>実行を一時停止します。プロセスが実行（r）または続行（c）されている場合、これはプロセスを現在実行中の場所で停止させます。</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #mainと呼ばれる任意の関数</p><p><code>b &#x3C;binname>`main</code> #バイナリのメイン関数</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #指定されたバイナリのメイン関数</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #任意のNSFileManagerメソッド</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> #そのライブラリのすべての関数でブレーク</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #ブレークポイントリスト</p><p><code>br e/dis &#x3C;num></code> #ブレークポイントを有効/無効にする</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #ブレークポイントコマンドのヘルプを取得</p><p>help memory write #メモリへの書き込みのヘルプを取得</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>メモリをヌル終端の文字列として表示します。</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>メモリをアセンブリ命令として表示します。</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>メモリをバイトとして表示します。</td></tr><tr><td><strong>print object (po)</strong></td><td><p>これは、パラメータで参照されるオブジェクトを印刷します</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>AppleのObjective-C APIやメソッドのほとんどはオブジェクトを返すため、"print object" (po) コマンドを介して表示する必要があります。poが意味のある出力を生成しない場合は、<code>x/b</code>を使用してください。</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #そのアドレスにAAAAを書き込みます<br>memory write -f s $rip+0x11f+7 "AAAA" #そのアドレスにAAAAを書き込みます</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #現在の関数を逆アセンブル</p><p>dis -n &#x3C;funcname> #関数を逆アセンブル</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #関数を逆アセンブル<br>dis -c 6 #6行を逆アセンブル<br>dis -c 0x100003764 -e 0x100003768 #1つのアドレスから別のアドレスまで<br>dis -p -c 4 #現在のアドレスから逆アセンブルを開始</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1レジスタの3コンポーネントの配列を確認</td></tr><tr><td><strong>image dump sections</strong></td><td>現在のプロセスメモリのマップを印刷します</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #CoreNLPのすべてのシンボルのアドレスを取得</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`**関数を呼び出すと、**rsi**レジスタには**メソッドの名前**がヌル終端の（“C”）文字列として格納されます。lldbを介して名前を印刷するには、次のようにします：

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### 動的解析防止

#### VM検出

* コマンド**`sysctl hw.model`**は、**ホストがMacOSの場合**は"Mac"を返しますが、VMの場合は異なる値を返します。
* **`hw.logicalcpu`**と**`hw.physicalcpu`**の値を操作することで、一部のマルウェアはVMかどうかを検出しようとします。
* 一部のマルウェアは、MACアドレス（00:50:56）に基づいて**VMware**であるかどうかを**検出**することもできます。
* 簡単なコードを使用して、**プロセスがデバッグされているかどうか**を確認することも可能です：
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //プロセスがデバッグされています }`
* **`ptrace`**システムコールを**`PT_DENY_ATTACH`**フラグで呼び出すこともできます。これにより、デバッガがアタッチしてトレースするのを防ぎます。
* **`sysctl`**または**`ptrace`**関数が**インポートされているかどうか**を確認できます（ただし、マルウェアは動的にインポートする可能性があります）。
* この書き込みで指摘されているように、「[デバッグ防止技術の克服：macOS ptraceバリアント](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)」：\
“_メッセージProcess # exited with **status = 45 (0x0000002d)**は、デバッグ対象が**PT\_DENY\_ATTACH**を使用していることを示す兆候です_”

## コアダンプ

コアダンプは次の場合に作成されます：

* `kern.coredump` sysctlが1に設定されている（デフォルト）
* プロセスがsuid/sgidでない場合、または`kern.sugid_coredump`が1である（デフォルトは0）
* `AS_CORE`制限が操作を許可します。`ulimit -c 0`を呼び出すことでコアダンプの作成を抑制でき、`ulimit -c unlimited`で再度有効にできます。

これらのケースでは、コアダンプは`kern.corefile` sysctlに従って生成され、通常は`/cores/core/.%P`に保存されます。

## ファジング

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrashは**クラッシュしたプロセスを分析し、クラッシュレポートをディスクに保存します**。クラッシュレポートには、**開発者がクラッシュの原因を診断するのに役立つ情報**が含まれています。\
ユーザーごとのlaunchdコンテキストで**実行されているアプリケーションや他のプロセス**の場合、ReportCrashはLaunchAgentとして実行され、ユーザーの`~/Library/Logs/DiagnosticReports/`にクラッシュレポートを保存します。\
デーモン、システムlaunchdコンテキストで**実行されている他のプロセス**および他の特権プロセスの場合、ReportCrashはLaunchDaemonとして実行され、システムの`/Library/Logs/DiagnosticReports`にクラッシュレポートを保存します。

クラッシュレポートが**Appleに送信されることを心配している場合**は、それを無効にできます。そうでない場合、クラッシュレポートは**サーバーがどのようにクラッシュしたかを把握するのに役立ちます**。
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### スリープ

MacOSでファジングを行う際は、Macがスリープしないようにすることが重要です：

* systemsetup -setsleep Never
* pmset, システム環境設定
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH切断

SSH接続を介してファジングを行っている場合、セッションが切断されないようにすることが重要です。次のようにsshd\_configファイルを変更してください：

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**次のページを確認してください** どのアプリが **指定されたスキームまたはプロトコルを処理しているかを見つける方法:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerating Network Processes

ネットワークデータを管理しているプロセスを見つけるのは興味深いです:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
または `netstat` または `lsof` を使用します。

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLIツールに対応しています。

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUIツールで「**そのまま動作します**」。いくつかのmacOSアプリには、ユニークなファイル名、正しい拡張子、サンドボックスからファイルを読み取る必要があるなど、特定の要件があります（`~/Library/Containers/com.apple.Safari/Data`）...

いくつかの例： 

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### More Fuzzing MacOS Info

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ** によって駆動される検索エンジンで、企業やその顧客が **スティーラーマルウェア** によって **侵害** されているかどうかを確認するための **無料** 機能を提供しています。

WhiteIntel の主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料** でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
