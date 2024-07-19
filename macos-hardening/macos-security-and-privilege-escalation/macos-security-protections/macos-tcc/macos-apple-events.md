# macOS Apple Events

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

**Apple Events** は、アプリケーションが互いに通信できるようにする、AppleのmacOSの機能です。これは、プロセス間通信を処理するmacOSオペレーティングシステムのコンポーネントである**Apple Event Manager**の一部です。このシステムにより、あるアプリケーションが別のアプリケーションにメッセージを送信し、ファイルを開く、データを取得する、またはコマンドを実行するなどの特定の操作を実行するように要求できます。

minaデーモンは`/System/Library/CoreServices/appleeventsd`で、サービス`com.apple.coreservices.appleevents`を登録します。

イベントを受信できるすべてのアプリケーションは、このデーモンに自分のApple Event Mach Portを提供して確認します。そして、アプリがイベントを送信したい場合、アプリはデーモンからこのポートを要求します。

サンドボックス化されたアプリケーションは、イベントを送信できるようにするために、`allow appleevent-send`や`(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`のような権限が必要です。`com.apple.security.temporary-exception.apple-events`のような権限は、イベントを送信するアクセスを制限する可能性があり、`com.apple.private.appleevents`のような権限が必要になります。

{% hint style="success" %}
環境変数**`AEDebugSends`**を使用して、送信されたメッセージに関する情報をログに記録することが可能です:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
