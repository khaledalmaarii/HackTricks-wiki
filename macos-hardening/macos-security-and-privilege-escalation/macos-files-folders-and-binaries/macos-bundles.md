# macOS バンドル

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}

## 基本情報

macOSのバンドルは、アプリケーション、ライブラリ、およびその他の必要なファイルを含むさまざまなリソースのコンテナとして機能し、おなじみの `*.app` ファイルなど、Finderで単一のオブジェクトとして表示されます。最も一般的に遭遇するバンドルは `.app` バンドルですが、`.framework`、`.systemextension`、`.kext` などの他のタイプも一般的です。

### バンドルの必須コンポーネント

バンドル内、特に `<application>.app/Contents/` ディレクトリ内には、さまざまな重要なリソースが格納されています:

* **\_CodeSignature**: このディレクトリには、アプリケーションの整合性を検証するために重要なコード署名の詳細が保存されています。次のようなコマンドを使用してコード署名情報を調べることができます: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: ユーザーの操作に応じて実行されるアプリケーションの実行可能バイナリが含まれています。
* **Resources**: 画像、ドキュメント、およびインターフェースの説明（nib/xibファイル）など、アプリケーションのユーザーインターフェースコンポーネントのリポジトリです。
* **Info.plist**: アプリケーションのメイン構成ファイルとして機能し、システムがアプリケーションを適切に認識して対話するために重要です。

#### Info.plist の重要なキー

`Info.plist` ファイルは、アプリケーションの構成の基盤であり、次のようなキーを含んでいます:

* **CFBundleExecutable**: `Contents/MacOS` ディレクトリにあるメイン実行ファイルの名前を指定します。
* **CFBundleIdentifier**: アプリケーションのためのグローバル識別子を提供し、macOSがアプリケーション管理に広く使用します。
* **LSMinimumSystemVersion**: アプリケーションの実行に必要なmacOSの最小バージョンを示します。

### バンドルの探索

`Safari.app` などのバンドルの内容を探索するには、次のコマンドを使用できます: `bash ls -lR /Applications/Safari.app/Contents`

この探索により、`_CodeSignature`、`MacOS`、`Resources` などのディレクトリや `Info.plist` のようなファイルが表示され、それぞれがアプリケーションのセキュリティを確保したり、ユーザーインターフェースや操作パラメータを定義したりするための独自の目的を果たしています。

#### 追加のバンドルディレクトリ

一般的なディレクトリ以外に、バンドルには次のようなものが含まれる場合があります:

* **Frameworks**: アプリケーションで使用されるバンドル化されたフレームワークが含まれています。フレームワークは、追加のリソースを持つdylibsのようなものです。
* **PlugIns**: アプリケーションの機能を拡張するプラグインや拡張機能のためのディレクトリです。
* **XPCServices**: アプリケーションがプロセス外通信に使用するXPCサービスを保持します。

この構造により、すべての必要なコンポーネントがバンドル内にカプセル化され、モジュラーで安全なアプリケーション環境が実現されます。

`Info.plist` キーとその意味に関する詳細情報については、Appleの開発者ドキュメントが包括的なリソースを提供しています: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}
