# macOS Dirty NIB

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

**技術の詳細については、元の投稿を確認してください: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** ここに要約があります:

NIBファイルは、Appleの開発エコシステムの一部であり、アプリケーション内の**UI要素**とその相互作用を定義するために使用されます。これらはウィンドウやボタンなどのシリアライズされたオブジェクトを含み、実行時にロードされます。現在も使用されていますが、Appleはより包括的なUIフローの視覚化のためにStoryboardを推奨しています。

### NIBファイルに関するセキュリティの懸念
**NIBファイルはセキュリティリスクになる可能性がある**ことに注意することが重要です。これらは**任意のコマンドを実行する**可能性があり、アプリ内のNIBファイルの変更は、Gatekeeperがアプリを実行するのを妨げないため、重大な脅威となります。

### ダーティNIBインジェクションプロセス
#### NIBファイルの作成と設定
1. **初期設定**:
- XCodeを使用して新しいNIBファイルを作成します。
- インターフェースにオブジェクトを追加し、そのクラスを`NSAppleScript`に設定します。
- ユーザー定義のランタイム属性を介して初期`source`プロパティを設定します。

2. **コード実行ガジェット**:
- この設定により、必要に応じてAppleScriptを実行できます。
- `Apple Script`オブジェクトをアクティブにするボタンを統合し、特に`executeAndReturnError:`セレクタをトリガーします。

3. **テスト**:
- テスト用のシンプルなApple Script:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- XCodeデバッガーで実行し、ボタンをクリックしてテストします。

#### アプリケーションのターゲット（例: Pages）
1. **準備**:
- ターゲットアプリ（例: Pages）を別のディレクトリ（例: `/tmp/`）にコピーします。
- Gatekeeperの問題を回避し、アプリを起動します。

2. **NIBファイルの上書き**:
- 既存のNIBファイル（例: About Panel NIB）を作成したDirtyNIBファイルで置き換えます。

3. **実行**:
- アプリと対話することで実行をトリガーします（例: `About`メニュー項目を選択）。

#### 概念実証: ユーザーデータへのアクセス
- ユーザーの同意なしに、写真などのユーザーデータにアクセスして抽出するようにAppleScriptを変更します。

### コードサンプル: 悪意のある.xibファイル
- 任意のコードを実行することを示す[**悪意のある.xibファイルのサンプル**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)にアクセスして確認します。

### 起動制約への対処
- 起動制約は、予期しない場所（例: `/tmp`）からのアプリの実行を妨げます。
- 起動制約によって保護されていないアプリを特定し、NIBファイルのインジェクションをターゲットにすることが可能です。

### 追加のmacOS保護
macOS Sonoma以降、アプリバンドル内の変更が制限されています。ただし、以前の方法は次のように行われました:
1. アプリを別の場所（例: `/tmp/`）にコピーします。
2. 初期保護を回避するためにアプリバンドル内のディレクトリの名前を変更します。
3. Gatekeeperに登録するためにアプリを実行した後、アプリバンドルを変更します（例: MainMenu.nibをDirty.nibに置き換えます）。
4. ディレクトリの名前を戻し、アプリを再実行してインジェクトされたNIBファイルを実行します。

**注意**: 最近のmacOSのアップデートにより、Gatekeeperキャッシュ後にアプリバンドル内のファイルの変更が防止され、この脆弱性が無効化されました。

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
