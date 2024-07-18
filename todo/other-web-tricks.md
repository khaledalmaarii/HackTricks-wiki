# その他のWebトリック

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}

### ホストヘッダー

バックエンドは何度か**ホストヘッダー**を信頼して、特定のアクションを実行します。たとえば、その値を使用して**パスワードリセットを送信するドメイン**として使用することがあります。つまり、パスワードをリセットするためのリンクが含まれたメールを受け取ったとき、使用されているドメインはホストヘッダーに入力したものです。その後、他のユーザーのパスワードリセットをリクエストし、ドメインを自分がコントロールするものに変更して、彼らのパスワードリセットコードを盗むことができます。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。

{% hint style="warning" %}
ユーザーがリセットパスワードリンクをクリックするのを待つ必要がないかもしれないことに注意してください。**スパムフィルターや他の中間デバイス/ボットが分析するためにクリックする**かもしれません。
{% endhint %}

### セッションブール値

時々、バックエンドは何らかの検証を正しく完了すると、**セッションに"True"という値のブール値をセキュリティ属性に追加**するだけです。その後、別のエンドポイントは、そのチェックを正常に通過したかどうかを知ることができます。\
ただし、そのチェックを**パス**し、セッションがセキュリティ属性に"True"の値が付与された場合、**アクセス権を持っていないはずの同じ属性に依存する他のリソースにアクセス**を試みることができます。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。

### 登録機能

既存のユーザーとして登録しようとしてみてください。同等の文字（ドット、多くのスペース、Unicode）を使用しても試してみてください。

### メールアカウントの乗っ取り

メールアカウントを登録し、確認する前にメールアドレスを変更し、その後、新しい確認メールが最初に登録されたメールアドレスに送信される場合、任意のメールアカウントを乗っ取ることができます。または、最初のメールアドレスを確認することができれば、2番目のメールアドレスを有効にすることもでき、任意のアカウントを乗っ取ることができます。

### Atlassianを使用する企業の内部サービスデスクへのアクセス

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACEメソッド

開発者は、本番環境でさまざまなデバッグオプションを無効にするのを忘れることがあります。たとえば、HTTPの`TRACE`メソッドは診断目的で設計されています。有効になっている場合、Webサーバーは`TRACE`メソッドを使用するリクエストに応答して、受信した正確なリクエストをレスポンスでエコーします。この動作はしばしば無害ですが、場合によっては、リバースプロキシによってリクエストに追加される内部認証ヘッダーの名前など、情報の漏洩につながることがあります。![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
