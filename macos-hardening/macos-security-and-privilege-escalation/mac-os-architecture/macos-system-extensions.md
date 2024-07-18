# macOSシステム拡張機能

{% hint style="success" %}
AWSハッキングの学習と実践：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}

## システム拡張機能 / エンドポイントセキュリティフレームワーク

カーネル拡張機能とは異なり、**システム拡張機能はカーネルスペースではなくユーザースペースで実行**されるため、拡張機能の誤作動によるシステムクラッシュのリスクが低減されます。

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

システム拡張機能には、**DriverKit**拡張機能、**Network**拡張機能、および**Endpoint Security**拡張機能の3種類があります。

### **DriverKit拡張機能**

DriverKitは、**ハードウェアサポートを提供する**カーネル拡張機能の代替となるものです。これにより、デバイスドライバ（USB、シリアル、NIC、HIDドライバなど）がカーネルスペースではなくユーザースペースで実行されるようになります。DriverKitフレームワークには、**特定のI/O Kitクラスのユーザースペースバージョン**が含まれており、カーネルは通常のI/O Kitイベントをユーザースペースに転送して、これらのドライバが実行される安全な環境を提供します。

### **Network拡張機能**

Network拡張機能は、ネットワーク動作をカスタマイズする機能を提供します。いくつかのタイプのNetwork拡張機能があります：

* **App Proxy**: これは、接続（またはフロー）に基づいてネットワークトラフィックを処理するカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。
* **Packet Tunnel**: これは、個々のパケットに基づいてネットワークトラフィックを処理するカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。
* **Filter Data**: これは、ネットワークの「フロー」をフィルタリングするために使用されます。ネットワークデータをフローレベルで監視または変更できます。
* **Filter Packet**: これは、個々のネットワークパケットをフィルタリングするために使用されます。ネットワークデータをパケットレベルで監視または変更できます。
* **DNS Proxy**: これは、カスタムDNSプロバイダを作成するために使用されます。DNSリクエストと応答を監視または変更するために使用できます。

## エンドポイントセキュリティフレームワーク

macOSで提供されているAppleのフレームワークであるエンドポイントセキュリティは、システムセキュリティのための一連のAPIを提供します。これは、**悪意のある活動を特定し、防御するための製品を構築するためにセキュリティベンダーや開発者が使用することを意図**しています。

このフレームワークは、プロセスの実行、ファイルシステムイベント、ネットワークおよびカーネルイベントなど、**システム活動を監視および制御するためのAPIのコレクション**を提供します。

このフレームワークの中核は、**カーネルに実装されたカーネル拡張機能（KEXT）**であり、**`/System/Library/Extensions/EndpointSecurity.kext`**に配置されています。このKEXTは、いくつかの主要なコンポーネントで構成されています：

* **EndpointSecurityDriver**: これはカーネル拡張機能との主要なやり取りポイントであり、OSとエンドポイントセキュリティフレームワークとの主要な相互作用ポイントです。
* **EndpointSecurityEventManager**: このコンポーネントは、カーネルフックを実装する責任があります。カーネルフックにより、フレームワークはシステムコールを傍受してシステムイベントを監視できます。
* **EndpointSecurityClientManager**: これは、ユーザースペースクライアントとの通信を管理し、接続されているクライアントとイベント通知を受け取る必要があるクライアントを追跡します。
* **EndpointSecurityMessageManager**: これは、メッセージとイベント通知をユーザースペースクライアントに送信します。

エンドポイントセキュリティフレームワークが監視できるイベントは、次のカテゴリに分類されます：

* ファイルイベント
* プロセスイベント
* ソケットイベント
* カーネルイベント（カーネル拡張機能の読み込み/アンロードやI/O Kitデバイスのオープンなど）

### エンドポイントセキュリティフレームワークのアーキテクチャ

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

エンドポイントセキュリティフレームワークとの**ユーザースペース通信**は、IOUserClientクラスを介して行われます。呼び出し元のタイプに応じて、異なるサブクラスが使用されます：

* **EndpointSecurityDriverClient**: これには`com.apple.private.endpoint-security.manager`権限が必要であり、これはシステムプロセス`endpointsecurityd`のみが保持しています。
* **EndpointSecurityExternalClient**: これには`com.apple.developer.endpoint-security.client`権限が必要です。これは通常、エンドポイントセキュリティフレームワークとやり取りする必要があるサードパーティのセキュリティソフトウェアに使用されます。

エンドポイントセキュリティ拡張機能:**`libEndpointSecurity.dylib`**は、システム拡張機能がカーネルと通信するために使用するCライブラリです。このライブラリはI/O Kit (`IOKit`)を使用してエンドポイントセキュリティKEXTと通信します。

**`endpointsecurityd`**は、エンドポイントセキュリティシステム拡張機能を管理および起動するために関与する主要なシステムデーモンです。**`NSEndpointSecurityEarlyBoot`**が`Info.plist`ファイルでマークされた**システム拡張機能のみ**がこの早期起動処理を受け取ります。

別のシステムデーモンである**`sysextd`**は、システム拡張機能を検証し、適切なシステムの場所に移動させます。その後、関連するデーモンに拡張機能の読み込みを要求します。**`SystemExtensions.framework`**は、システム拡張機能の有効化および無効化を担当しています。

## ESFのバイパス

ESFは、レッドチームを検出しようとするセキュリティツールによって使用されるため、これを回避する方法に関する情報は興味深いものです。

### CVE-2021-30965

重要なのは、セキュリティアプリケーションが**完全ディスクアクセス権限**を持っている必要があることです。したがって、攻撃者がそれを削除できれば、ソフトウェアの実行を防ぐことができます。
```bash
tccutil reset All
```
**さらなる情報**については、この回避策および関連する回避策については、以下のトークをチェックしてください：[#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最終的には、新しい権限 **`kTCCServiceEndpointSecurityClient`** を **`tccd`** によって管理されるセキュリティアプリに付与することで、`tccutil` がアプリの権限をクリアしないようにし、実行を妨げることが防がれました。

## 参考文献

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする！
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する！

</details>
{% endhint %}
