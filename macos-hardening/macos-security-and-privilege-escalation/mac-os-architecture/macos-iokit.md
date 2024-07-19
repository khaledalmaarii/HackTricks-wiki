# macOS IOKit

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

## 基本情報

I/O Kitは、XNUカーネル内のオープンソースのオブジェクト指向**デバイスドライバーフレームワーク**であり、**動的にロードされたデバイスドライバー**を処理します。これにより、さまざまなハードウェアをサポートするために、モジュールコードをカーネルにオンザフライで追加できます。

IOKitドライバーは基本的に**カーネルから関数をエクスポート**します。これらの関数パラメータの**型**は**事前定義**されており、検証されます。さらに、XPCと同様に、IOKitは**Machメッセージの上にある別のレイヤー**です。

**IOKit XNUカーネルコード**は、Appleによって[https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit)でオープンソース化されています。さらに、ユーザースペースのIOKitコンポーネントもオープンソースです[https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser)。

しかし、**IOKitドライバーは**オープンソースではありません。とはいえ、時折、デバッグを容易にするシンボルを持つドライバーのリリースがあるかもしれません。ここで[**ファームウェアからドライバー拡張を取得する方法**](./#ipsw)**を確認してください。**

これは**C++**で書かれています。デマングルされたC++シンボルを取得するには：
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **公開された関数**は、クライアントが関数を呼び出そうとする際に**追加のセキュリティチェック**を実行する可能性がありますが、アプリは通常、IOKit関数と相互作用できる**サンドボックス**によって**制限**されています。
{% endhint %}

## ドライバー

macOSでは、次の場所にあります：

* **`/System/Library/Extensions`**
* OS Xオペレーティングシステムに組み込まれたKEXTファイル。
* **`/Library/Extensions`**
* サードパーティソフトウェアによってインストールされたKEXTファイル

iOSでは、次の場所にあります：

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
9までのリストされたドライバーは**アドレス0にロードされています**。これは、それらが実際のドライバーではなく、**カーネルの一部であり、アンロードできないことを意味します**。

特定の拡張機能を見つけるには、次のコマンドを使用できます：
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
カーネル拡張をロードおよびアンロードするには、次のようにします:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**は、macOSおよびiOSのIOKitフレームワークの重要な部分であり、システムのハードウェア構成と状態を表すデータベースとして機能します。これは、**システムにロードされたすべてのハードウェアとドライバを表すオブジェクトの階層的コレクション**であり、それらの相互関係を示しています。

IORegistryは、cli **`ioreg`**を使用してコンソールから検査することができ（特にiOSに便利です）。
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**を**Xcode Additional Tools**から[**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/)でダウンロードし、**macOS IORegistry**を**グラフィカル**インターフェースを通じて検査できます。

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorerでは、「プレーン」はIORegistry内の異なるオブジェクト間の関係を整理し表示するために使用されます。各プレーンは、特定のタイプの関係またはシステムのハードウェアとドライバ構成の特定のビューを表します。IORegistryExplorerで遭遇する可能性のある一般的なプレーンは以下の通りです：

1. **IOService Plane**: これは最も一般的なプレーンで、ドライバとナブ（ドライバ間の通信チャネル）を表すサービスオブジェクトを表示します。これらのオブジェクト間のプロバイダ-クライアント関係を示します。
2. **IODeviceTree Plane**: このプレーンは、デバイスがシステムに接続される物理的な接続を表します。USBやPCIのようなバスを介して接続されたデバイスの階層を視覚化するために使用されることがよくあります。
3. **IOPower Plane**: 電力管理の観点からオブジェクトとその関係を表示します。どのオブジェクトが他のオブジェクトの電力状態に影響を与えているかを示すことができ、電力関連の問題のデバッグに役立ちます。
4. **IOUSB Plane**: USBデバイスとその関係に特化しており、USBハブと接続されたデバイスの階層を示します。
5. **IOAudio Plane**: このプレーンは、システム内のオーディオデバイスとその関係を表すためのものです。
6. ...

## ドライバ通信コード例

以下のコードは、IOKitサービス`"YourServiceNameHere"`に接続し、セレクタ0内の関数を呼び出します。そのために：

* まず**`IOServiceMatching`**と**`IOServiceGetMatchingServices`**を呼び出してサービスを取得します。
* 次に、**`IOServiceOpen`**を呼び出して接続を確立します。
* 最後に、セレクタ0を示す**`IOConnectCallScalarMethod`**を使用して関数を呼び出します（セレクタは呼び出したい関数に割り当てられた番号です）。
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
他にも **`IOConnectCallScalarMethod`** の他に **`IOConnectCallMethod`**、**`IOConnectCallStructMethod`** などの IOKit 関数を呼び出すために使用できる関数があります。

## ドライバエントリポイントのリバースエンジニアリング

これらは例えば [**ファームウェアイメージ (ipsw)**](./#ipsw) から取得できます。その後、お気に入りのデコンパイラにロードします。

**`externalMethod`** 関数のデコンパイルを開始できます。これは呼び出しを受け取り、正しい関数を呼び出すドライバ関数です：

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

そのひどい呼び出しのデマグルは次の意味です： 

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

前の定義では **`self`** パラメータが欠けていることに注意してください。良い定義は次のようになります：

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

実際、真の定義は[https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388)で見つけることができます:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
この情報を使って、Ctrl+Right -> `Edit function signature` を再記述し、既知の型を設定できます：

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

新しい逆コンパイルされたコードは次のようになります：

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

次のステップでは、**`IOExternalMethodDispatch2022`** 構造体を定義する必要があります。これは [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) でオープンソースです。これを定義できます：

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

今、`(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` に従って、多くのデータが見えます：

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

データ型を **`IOExternalMethodDispatch2022:`** に変更します：

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

変更後：

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

そして、今そこにあるのは **7つの要素の配列** です（最終的な逆コンパイルコードを確認してください）。7つの要素の配列を作成するためにクリックします：

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

配列が作成された後、すべてのエクスポートされた関数が見えます：

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
覚えておいてください、ユーザースペースから **エクスポートされた** 関数を **呼び出す** には、関数の名前を呼び出す必要はなく、**セレクタ番号** を呼び出す必要があります。ここでは、セレクタ **0** が関数 **`initializeDecoder`**、セレクタ **1** が **`startDecoder`**、セレクタ **2** が **`initializeEncoder`** であることがわかります...
{% endhint %}

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**テレグラムグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}
