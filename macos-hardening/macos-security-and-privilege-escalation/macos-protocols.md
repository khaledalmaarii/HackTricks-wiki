# macOS ネットワークサービスとプロトコル

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

## リモートアクセスサービス

これらは、macOSにリモートでアクセスするための一般的なサービスです。\
これらのサービスは`システム設定` --> `共有`で有効/無効にできます。

* **VNC**、通称「画面共有」（tcp:5900）
* **SSH**、通称「リモートログイン」（tcp:22）
* **Apple Remote Desktop**（ARD）、または「リモート管理」（tcp:3283、tcp:5900）
* **AppleEvent**、通称「リモートAppleイベント」（tcp:3031）

有効になっているかどうかを確認するには、次のコマンドを実行します：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) は、macOS 向けに特別に設計された [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) の強化版で、追加機能を提供します。ARD の顕著な脆弱性は、制御画面パスワードの認証方法で、パスワードの最初の 8 文字のみを使用するため、[ブルートフォース攻撃](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) に対して脆弱であり、Hydra や [GoRedShell](https://github.com/ahhh/GoRedShell/) のようなツールを使用することができます。デフォルトのレート制限がないためです。

脆弱なインスタンスは、**nmap** の `vnc-info` スクリプトを使用して特定できます。`VNC Authentication (2)` をサポートするサービスは、8 文字のパスワード切り捨てのため、特にブルートフォース攻撃に対して脆弱です。

特権昇格、GUI アクセス、またはユーザー監視などのさまざまな管理タスクのために ARD を有効にするには、次のコマンドを使用します：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARDは、観察、共有制御、完全制御を含む多様な制御レベルを提供し、ユーザーパスワードの変更後もセッションは持続します。管理者ユーザーとしてルートでUnixコマンドを直接送信し、実行することができます。タスクスケジューリングやリモートSpotlight検索は注目すべき機能であり、複数のマシンにわたる機密ファイルのリモートで低影響の検索を容易にします。

## Bonjourプロトコル

Bonjourは、Appleが設計した技術で、**同じネットワーク上のデバイスが互いに提供するサービスを検出する**ことを可能にします。Rendezvous、**ゼロコンフィギュレーション**、またはZeroconfとも呼ばれ、デバイスがTCP/IPネットワークに参加し、**自動的にIPアドレスを選択し**、他のネットワークデバイスにサービスをブロードキャストすることを可能にします。

Bonjourが提供するゼロコンフィギュレーションネットワーキングにより、デバイスは以下を実行できます：
* **DHCPサーバーがない場合でも自動的にIPアドレスを取得**する。
* **DNSサーバーを必要とせずに名前からアドレスへの変換**を行う。
* **ネットワーク上で利用可能なサービスを発見**する。

Bonjourを使用するデバイスは、**169.254/16範囲のIPアドレスを自動的に割り当て**、ネットワーク上での一意性を確認します。Macはこのサブネットのルーティングテーブルエントリを維持し、`netstat -rn | grep 169`で確認できます。

DNSに関して、Bonjourは**マルチキャストDNS（mDNS）プロトコル**を利用します。mDNSは**ポート5353/UDP**で動作し、**標準DNSクエリ**を使用しますが、**マルチキャストアドレス224.0.0.251**をターゲットにします。このアプローチにより、ネットワーク上のすべてのリスニングデバイスがクエリを受信し応答できるようになり、レコードの更新が促進されます。

ネットワークに参加すると、各デバイスは通常**.local**で終わる名前を自己選択し、ホスト名から派生するか、ランダムに生成されます。

ネットワーク内のサービス発見は、**DNSサービス発見（DNS-SD）**によって促進されます。DNS SRVレコードの形式を利用し、DNS-SDは**DNS PTRレコード**を使用して複数のサービスのリストを可能にします。特定のサービスを探しているクライアントは、`<Service>.<Domain>`のPTRレコードを要求し、サービスが複数のホストから利用可能な場合、`<Instance>.<Service>.<Domain>`形式のPTRレコードのリストを受け取ります。

`dns-sd`ユーティリティは、**ネットワークサービスの発見と広告**に使用できます。以下はその使用例です：

### SSHサービスの検索

ネットワーク上のSSHサービスを検索するには、次のコマンドを使用します：
```bash
dns-sd -B _ssh._tcp
```
このコマンドは、_ssh._tcp サービスのブラウジングを開始し、タイムスタンプ、フラグ、インターフェース、ドメイン、サービスの種類、インスタンス名などの詳細を出力します。

### HTTP サービスの広告

HTTP サービスを広告するには、次のようにします:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
このコマンドは、ポート80で`/index.html`のパスを持つ「Index」という名前のHTTPサービスを登録します。

次に、ネットワーク上のHTTPサービスを検索するには:
```bash
dns-sd -B _http._tcp
```
サービスが開始されると、その存在をマルチキャストしてサブネット上のすべてのデバイスに利用可能であることを通知します。これらのサービスに興味のあるデバイスは、リクエストを送信する必要はなく、単にこれらの通知を聞くだけです。

よりユーザーフレンドリーなインターフェースのために、Apple App Storeで利用可能な**Discovery - DNS-SD Browser**アプリは、ローカルネットワーク上で提供されているサービスを視覚化できます。

また、`python-zeroconf`ライブラリを使用してサービスをブラウズおよび発見するためのカスタムスクリプトを作成することもできます。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)スクリプトは、`_http._tcp.local.`サービスのためのサービスブラウザを作成し、追加または削除されたサービスを印刷することを示しています。
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Bonjourの無効化
セキュリティに関する懸念やその他の理由でBonjourを無効にする必要がある場合、次のコマンドを使用してオフにできます:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
