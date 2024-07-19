# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

アプリケーションは、権限 **`com.apple.security.temporary-exception.sbpl`** を使用して **カスタムサンドボックス** を使用しており、このカスタムサンドボックスでは、ファイル名が `~$` で始まる限り、どこにでもファイルを書き込むことができます: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、エスケープは **`plist`** LaunchAgent を `~/Library/LaunchAgents/~$escape.plist` に書き込むのと同じくらい簡単でした。

[**元のレポートはこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)を確認してください。

### Word Sandbox bypass via Login Items and zip

最初のエスケープから、Word は `~$` で始まる任意のファイルを書き込むことができることを思い出してください。ただし、前の脆弱性のパッチ後は、`/Library/Application Scripts` や `/Library/LaunchAgents` に書き込むことはできませんでした。

サンドボックス内から **Login Item**（ユーザーがログインしたときに実行されるアプリ）を作成できることが発見されました。ただし、これらのアプリは **ノータライズされていない限り** 実行されず、**引数を追加することはできません**（したがって、単に **`bash`** を使用してリバースシェルを実行することはできません）。

前のサンドボックスバイパスから、Microsoft は `~/Library/LaunchAgents` にファイルを書き込むオプションを無効にしました。ただし、**Login Item** として **zip ファイル** を置くと、`Archive Utility` はその場所に **解凍** します。したがって、デフォルトでは `~/Library` の `LaunchAgents` フォルダーが作成されないため、`LaunchAgents/~$escape.plist` に plist を **zip** し、**`~/Library`** に zip ファイルを **配置** することで、解凍時に永続性の宛先に到達することができました。

[**元のレポートはこちら**](https://objective-see.org/blog/blog\_0x4B.html)を確認してください。

### Word Sandbox bypass via Login Items and .zshenv

（最初のエスケープから、Word は `~$` で始まる任意のファイルを書き込むことができることを思い出してください）。

ただし、前の技術には制限があり、**`~/Library/LaunchAgents`** フォルダーが他のソフトウェアによって作成されている場合、失敗します。したがって、これに対して異なる Login Items チェーンが発見されました。

攻撃者は、実行するペイロードを持つ **`.bash_profile`** と **`.zshenv`** ファイルを作成し、それらを zip して **被害者の** ユーザーフォルダーに書き込むことができます: **`~/~$escape.zip`**。

次に、zip ファイルを **Login Items** に追加し、**`Terminal`** アプリを追加します。ユーザーが再ログインすると、zip ファイルはユーザーファイルに解凍され、**`.bash_profile`** と **`.zshenv`** が上書きされ、そのためターミナルはこれらのファイルのいずれかを実行します（bash または zsh が使用されるかによって異なります）。

[**元のレポートはこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)を確認してください。

### Word Sandbox Bypass with Open and env variables

サンドボックス化されたプロセスからは、**`open`** ユーティリティを使用して他のプロセスを呼び出すことがまだ可能です。さらに、これらのプロセスは **独自のサンドボックス内** で実行されます。

open ユーティリティには、**特定の環境** 変数でアプリを実行するための **`--env`** オプションがあることが発見されました。したがって、サンドボックス内のフォルダーに **`.zshenv` ファイル** を作成し、`open` を使用して `--env` で **`HOME` 変数** をそのフォルダーに設定し、その `Terminal` アプリを開くことで、`.zshenv` ファイルを実行することができます（理由は不明ですが、`__OSINSTALL_ENVIROMENT` 変数を設定する必要もありました）。

[**元のレポートはこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)を確認してください。

### Word Sandbox Bypass with Open and stdin

**`open`** ユーティリティは **`--stdin`** パラメータもサポートしていました（前のバイパス後は `--env` を使用できなくなりました）。

問題は、**`python`** が Apple によって署名されていても、**`quarantine`** 属性を持つスクリプトは **実行されない** ということです。ただし、stdin からスクリプトを渡すことができるため、クアランティンされているかどうかをチェックしませんでした:&#x20;

1. 任意の Python コマンドを含む **`~$exploit.py`** ファイルをドロップします。
2. _open_ **`–stdin='~$exploit.py' -a Python`** を実行します。これにより、Python アプリが標準入力としてドロップしたファイルを使用して実行されます。Python は喜んでコードを実行し、これは _launchd_ の子プロセスであるため、Word のサンドボックスルールに束縛されません。

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
