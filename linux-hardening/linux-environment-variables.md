# Linux 環境変数

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

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## グローバル変数

グローバル変数は**子プロセス**によって**継承されます**。

現在のセッションのためにグローバル変数を作成するには、次のようにします:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセス可能です。

変数を**削除**するには、次のようにします:
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数**は**現在のシェル/スクリプト**によってのみ**アクセス**できます。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 現在の変数のリスト
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X**によって使用されるディスプレイ。この変数は通常**:0.0**に設定されており、これは現在のコンピュータの最初のディスプレイを意味します。
* **EDITOR** – ユーザーの好みのテキストエディタ。
* **HISTFILESIZE** – 履歴ファイルに含まれる最大行数。
* **HISTSIZE** – ユーザーがセッションを終了したときに履歴ファイルに追加される行数。
* **HOME** – あなたのホームディレクトリ。
* **HOSTNAME** – コンピュータのホスト名。
* **LANG** – あなたの現在の言語。
* **MAIL** – ユーザーのメールスプールの場所。通常は**/var/spool/mail/USER**。
* **MANPATH** – マニュアルページを検索するためのディレクトリのリスト。
* **OSTYPE** – オペレーティングシステムの種類。
* **PS1** – bashのデフォルトプロンプト。
* **PATH** – バイナリファイルを実行するためにファイル名を指定するだけで済むすべてのディレクトリのパスを格納します。
* **PWD** – 現在の作業ディレクトリ。
* **SHELL** – 現在のコマンドシェルへのパス（例：**/bin/bash**）。
* **TERM** – 現在の端末タイプ（例：**xterm**）。
* **TZ** – あなたのタイムゾーン。
* **USER** – あなたの現在のユーザー名。

## Interesting variables for hacking

### **HISTFILESIZE**

この変数の**値を0に変更**すると、**セッションを終了**したときに**履歴ファイル**（\~/.bash\_history）が**削除されます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

この**変数の値を0に変更**してください。そうすれば、**セッションを終了**すると、任意のコマンドが**履歴ファイル**（\~/.bash\_history）に追加されます。
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

プロセスは、**http または https** を通じてインターネットに接続するために、ここで宣言された **proxy** を使用します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

プロセスは**これらの環境変数**で示された証明書を信頼します。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

プロンプトの見た目を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

ルート:

![](<../.gitbook/assets/image (897).png>)

通常のユーザー:

![](<../.gitbook/assets/image (740).png>)

バックグラウンドジョブが1つ、2つ、3つ:

![](<../.gitbook/assets/image (145).png>)

バックグラウンドジョブが1つ、停止したジョブが1つ、最後のコマンドが正しく終了しなかった:

![](<../.gitbook/assets/image (715).png>)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
