# macOS Keychain

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、または **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## メインキーチェーン

* **ユーザーキーチェーン** (`~/Library/Keychains/login.keycahin-db`) は、アプリケーションパスワード、インターネットパスワード、ユーザー生成証明書、ネットワークパスワード、ユーザー生成の公開/秘密鍵などの**ユーザー固有の資格情報**を保存するために使用されます。
* **システムキーチェーン** (`/Library/Keychains/System.keychain`) は、WiFiパスワード、システムルート証明書、システムの秘密鍵、システムアプリケーションパスワードなどの**システム全体の資格情報**を保存します。

### パスワードキーチェーンアクセス

これらのファイルは、固有の保護を持たず、**ダウンロード**できますが、**ユーザーの平文パスワードが必要**です。[**Chainbreaker**](https://github.com/n0fate/chainbreaker)のようなツールを使用して復号化できます。

## キーチェーンエントリの保護

### ACLs

キーチェーン内の各エントリは、**アクセス制御リスト（ACLs）**によって管理され、キーチェーンエントリでさまざまなアクションを実行できるユーザーを規定します。これには以下が含まれます：

* **ACLAuhtorizationExportClear**：保持者が秘密のクリアテキストを取得できるようにします。
* **ACLAuhtorizationExportWrapped**：保持者が別の提供されたパスワードで暗号化されたクリアテキストを取得できるようにします。
* **ACLAuhtorizationAny**：保持者が任意のアクションを実行できるようにします。

ACLsには、プロンプトなしでこれらのアクションを実行できる**信頼されたアプリケーションのリスト**が付属しています。これには以下が含まれます：

* **N`il`**（認証不要、**誰もが信頼されている**）
* 空のリスト（**誰もが信頼されていない**）
* 特定の**アプリケーション**の**リスト**。

また、エントリには**`ACLAuthorizationPartitionID`**というキーが含まれており、**teamid、apple、cdhash**を識別するために使用されます。

* **teamid**が指定されている場合、**エントリの値にアクセス**するためには、使用されるアプリケーションが**同じteamid**を持っている必要があります。
* **apple**が指定されている場合、アプリは**Apple**によって**署名**されている必要があります。
* **cdhash**が示されている場合、**アプリ**は特定の**cdhash**を持っている必要があります。

### キーチェーンエントリの作成

**`Keychain Access.app`**を使用して**新しい** **エントリ**を作成する場合、次のルールが適用されます：

* すべてのアプリが暗号化できます。
* **アプリは**エクスポート/復号化を行うことができません（ユーザーにプロンプトを表示せず）。
* すべてのアプリが整合性チェックを見ることができます。
* どのアプリもACLを変更することはできません。
* **partitionID**は**`apple`**に設定されています。

**アプリケーションがキーチェーンにエントリを作成する**場合、ルールは若干異なります：

* すべてのアプリが暗号化できます。
* エクスポート/復号化を行うことができるのは、**作成アプリケーション**（または明示的に追加された他のアプリ）だけです（ユーザーにプロンプトを表示せず）。
* すべてのアプリが整合性チェックを見ることができます。
* どのアプリもACLを変更することはできません。
* **partitionID**は**`teamid:[ここにteamID]`**に設定されています。

## キーチェーンへのアクセス

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
**キーチェーンの列挙とダンプ**は、[**LockSmith**](https://github.com/its-a-feature/LockSmith)というツールを使用して、**プロンプトを生成しない**シークレットを取得できます。
{% endhint %}

各キーチェーンエントリの**情報**をリスト化および取得：

* API **`SecItemCopyMatching`** は各エントリに関する情報を提供し、使用時に設定できるいくつかの属性があります：
* **`kSecReturnData`**：trueの場合、データの復号を試みます（ポップアップを回避するにはfalseに設定）
* **`kSecReturnRef`**：キーチェーンアイテムへの参照も取得します（後でポップアップなしで復号できることがわかった場合にtrueに設定）
* **`kSecReturnAttributes`**：エントリに関するメタデータを取得します
* **`kSecMatchLimit`**：返す結果の数
* **`kSecClass`**：どの種類のキーチェーンエントリか

各エントリの**ACL**を取得：

* API **`SecAccessCopyACLList`** を使用すると、**キーチェーンアイテムのACL**を取得し、ACLのリスト（`ACLAuhtorizationExportClear`などの以前に言及されたもの）が返されます。各リストには次のものが含まれます：
* 説明
* **信頼されたアプリケーションリスト**。これには次のようなものが含まれます：
* アプリ：/Applications/Slack.app
* バイナリ：/usr/libexec/airportd
* グループ：group://AirPort

データのエクスポート：

* API **`SecKeychainItemCopyContent`** は平文を取得します
* API **`SecItemExport`** はキーと証明書をエクスポートしますが、コンテンツを暗号化してエクスポートするにはパスワードを設定する必要があります

そして、**プロンプトを生成せずにシークレットをエクスポート**するための**要件**は次のとおりです：

* **1つ以上の信頼された**アプリがリストされている場合：
* 適切な**認可**が必要（**`Nil`**、またはシークレット情報にアクセスするための認可されたアプリのリストの一部である必要があります）
* コード署名が**PartitionID**と一致する必要があります
* コード署名が1つの**信頼されたアプリ**と一致する必要があります（または適切なKeychainAccessGroupのメンバーである必要があります）
* **すべてのアプリケーションが信頼されている**場合：
* 適切な**認可**が必要
* コード署名が**PartitionID**と一致する必要があります
* **PartitionID**がない場合、これは必要ありません

{% hint style="danger" %}
したがって、**1つのアプリケーションがリストされている**場合、そのアプリケーションに**コードをインジェクトする**必要があります。

**PartitionID**に**apple**が指定されている場合、**`osascript`**を使用してアクセスできます。つまり、PartitionIDにappleを含むすべてのアプリケーションを信頼しているものにアクセスできます。**`Python`**もこれに使用できます。
{% endhint %}

### 2つの追加属性

* **Invisible**：UIキーチェーンアプリからエントリを**非表示**にするためのブールフラグです
* **General**：**メタデータ**を保存するためのものです（つまり、**暗号化されていない**）
* Microsoftは、機密エンドポイントにアクセスするためのすべてのリフレッシュトークンを平文で保存していました。

## 参考文献

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンであり、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWSハッキングの学習と実践：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
