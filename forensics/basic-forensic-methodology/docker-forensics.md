# Docker Forensics

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}

## コンテナの変更

あるDockerコンテナが侵害された可能性があるという疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
あなたは簡単に次のコマンドで、このコンテナに対してイメージに関して行われた変更を見つけることができます:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
前のコマンドで **C** は **変更** を意味し、**A,** は **追加** を意味します。\
もし `/etc/shadow` のような興味深いファイルが変更されたことがわかった場合、悪意のある活動をチェックするためにそのファイルをコンテナからダウンロードできます:
```bash
docker cp wordpress:/etc/shadow.
```
あなたは新しいコンテナを実行し、ファイルを取り出すことで、元のものと比較することもできます。
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
もし**いくつかの怪しいファイルが追加された**とわかった場合は、コンテナにアクセスして確認できます：
```bash
docker exec -it wordpress bash
```
## 画像の変更

エクスポートされたDockerイメージ（おそらく`.tar`形式）が与えられた場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)を使用して**変更の概要を抽出**できます。
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
その後、イメージを**展開**して**ブロブにアクセス**し、変更履歴で見つけた疑わしいファイルを検索できます：
```bash
tar -xf image.tar
```
### 基本的な分析

実行中のイメージから**基本情報**を取得できます：
```bash
docker inspect <image>
```
あなたはまた、次のようにして**変更履歴の要約**を取得することもできます：
```bash
docker history --no-trunc <image>
```
あなたはまた、次のようにしてイメージから**dockerfileを生成**することもできます：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Dockerイメージ内の追加/変更されたファイルを見つけるためには、[**dive**](https://github.com/wagoodman/dive)（[**リリース**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)からダウンロード）ユーティリティを使用することもできます。
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**Dockerイメージの異なるブロブをナビゲート**して、変更/追加されたファイルを確認できます。**赤**は追加されたファイルを、**黄色**は変更されたファイルを示します。**Tab** キーを使用して他のビューに移動し、**スペース** キーを使用してフォルダを折りたたんだり開いたりします。

これにより、イメージの異なるステージのコンテンツにアクセスできなくなります。それを行うには、**各レイヤーを展開してアクセスする必要があります**。\
イメージが展開されたディレクトリから、イメージのすべてのレイヤーを展開することができます。
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの資格情報

ホスト内でdockerコンテナを実行すると、ホストから`ps -ef`を実行するだけでコンテナで実行中のプロセスを見ることができます。

したがって（rootとして）、ホストからプロセスのメモリをダンプして、[**次の例のように**](../../linux-hardening/privilege-escalation/#process-memory)資格情報を検索することができます。
