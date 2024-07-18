# macOS Chromium Injection

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して**ハッキングトリックを共有**してください。

</details>
{% endhint %}

## 基本情報

Google Chrome、Microsoft Edge、BraveなどのChromiumベースのブラウザ。これらのブラウザはChromiumオープンソースプロジェクト上に構築されており、共通のベースを共有しているため、類似の機能と開発者オプションを持っています。

#### `--load-extension` フラグ

`--load-extension` フラグは、コマンドラインやスクリプトからChromiumベースのブラウザを起動する際に使用されます。このフラグにより、**ブラウザの起動時に1つ以上の拡張機能を自動的に読み込む**ことができます。

#### `--use-fake-ui-for-media-stream` フラグ

`--use-fake-ui-for-media-stream` フラグは、Chromiumベースのブラウザを起動する際に使用できる別のコマンドラインオプションです。このフラグは、カメラやマイクからメディアストリームにアクセスする許可を求める通常のユーザープロンプトを**バイパス**するために設計されています。このフラグを使用すると、ブラウザはカメラやマイクへのアクセスを要求する任意のウェブサイトやアプリケーションに自動的に許可を与えます。

### ツール

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 例
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## 参考文献

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
