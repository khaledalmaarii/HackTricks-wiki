# DDexec / EverythingExec

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

## コンテキスト

Linuxでは、プログラムを実行するためには、ファイルとして存在する必要があり、ファイルシステム階層を通じて何らかの方法でアクセスできる必要があります（これは単に `execve()` が動作する方法です）。このファイルはディスク上にあるか、ram（tmpfs、memfd）にあるかもしれませんが、ファイルパスが必要です。これにより、Linuxシステムで実行されるものを制御することが非常に簡単になり、脅威や攻撃者のツールを検出したり、特権のないユーザーが実行可能ファイルをどこにでも配置することを防止したりすることが簡単になります。

しかし、このテクニックはすべてを変えるためにここにあります。あなたが望むプロセスを開始できない場合は... **すでに存在するプロセスを乗っ取ります**。

このテクニックにより、**読み取り専用、noexec、ファイル名のホワイトリスト、ハッシュのホワイトリストなどの一般的な保護技術をバイパス**できます。

## 依存関係

最終スクリプトは、動作するために以下のツールに依存しています。攻撃しているシステムでこれらのツールにアクセスできる必要があります（デフォルトではどこでも見つけることができます）。
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## テクニック

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは既存のプロセスを乗っ取り、別のプログラムで置き換えるために使用できます。これは、`ptrace()` シスコールを使用するか(`/proc/$pid/mem` に書き込むこともできます)。

ファイル `/proc/$pid/mem` はプロセスのアドレス空間全体の1対1のマッピングです（例: x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）。これは、オフセット `x` でこのファイルから読み取るか書き込むことは、仮想アドレス `x` の内容を読み取るか変更することと同じです。

さて、私たちは4つの基本的な問題に直面しています:

* 一般的に、ルートとファイルのプログラム所有者のみが変更できます。
* ASLR。
* プログラムのアドレス空間にマップされていないアドレスに読み取りまたは書き込みを試みると、I/O エラーが発生します。

これらの問題には、完璧ではないが解決策があります:

* ほとんどのシェルインタプリタは、子プロセスで継承されるファイルディスクリプタの作成を許可します。書き込み権限を持つ `mem` ファイルを指す fd を作成できます... その fd を使用する子プロセスはシェルのメモリを変更できます。
* ASLR は問題ではありません。プロセスのアドレス空間に関する情報を取得するために、シェルの `maps` ファイルや procfs の他のファイルをチェックできます。
* したがって、ファイル上で `lseek()` を行う必要があります。シェルからは、悪名高い `dd` を使用しない限り、これはできません。

### より詳細に

手順は比較的簡単であり、理解するために専門知識は必要ありません:

* 実行したいバイナリとローダーを解析して、必要なマッピングを見つけます。その後、`execve()` の各呼び出しでカーネルが行う手順と大まかに同じ手順を実行する "シェル"コードを作成します:
* これらのマッピングを作成します。
* バイナリを読み込みます。
* 権限を設定します。
* プログラムの引数でスタックを初期化し、ローダーが必要とする補助ベクトルを配置します。
* ローダーにジャンプし、残りの処理をさせます（プログラムが必要とするライブラリをロードします）。
* 実行中のシスコールの後にプロセスが戻るアドレスを `syscall` ファイルから取得します。
* その場所（実行可能な場所）を上書きし、`mem` を介して書き込み不可なページを変更できます。
* 実行したいプログラムをプロセスの stdin に渡します（"シェル"コードによって `read()` されます）。
* この時点で、プログラムを実行するために必要なライブラリをロードし、それにジャンプするかどうかはローダー次第です。

**ツールを確認してください** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` には他にもいくつかの代替手段がありますが、そのうちの1つである `tail` は現在、`mem` ファイルを `lseek()` するためにデフォルトで使用されています（`dd` を使用する唯一の目的でした）。これらの代替手段は次のとおりです:
```bash
tail
hexdump
cmp
xxd
```
変数`SEEKER`を設定すると、使用するシーカーを変更できます。 例：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
もしスクリプトに実装されていない別の有効なシーカーを見つけた場合は、`SEEKER_ARGS`変数を設定してそれを使用することができます:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
## 参照

* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}
