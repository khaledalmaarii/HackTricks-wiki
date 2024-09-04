# ハッシュ長拡張攻撃

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}


## 攻撃の概要

サーバーが**データ**に**秘密**を**追加**してからそのデータをハッシュ化して**署名**していると想像してください。もしあなたが知っていることがあれば：

* **秘密の長さ**（これは与えられた長さの範囲からもブルートフォース可能です）
* **クリアテキストデータ**
* **アルゴリズム（そしてそれがこの攻撃に対して脆弱であること）**
* **パディングが知られている**
* 通常はデフォルトのものが使用されるので、他の3つの要件が満たされていれば、これもそうです
* パディングは秘密+データの長さによって異なるため、秘密の長さが必要です

その場合、**攻撃者**は**データを追加**し、**前のデータ + 追加データ**の有効な**署名**を**生成**することが可能です。

### どうやって？

基本的に、脆弱なアルゴリズムは最初に**データのブロックをハッシュ化**し、その後、**以前に作成された**ハッシュ（状態）から**次のデータブロックを追加**して**ハッシュ化**します。

次に、秘密が「secret」でデータが「data」の場合、「secretdata」のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が「append」という文字列を追加したい場合、彼は次のことができます：

* 64の「A」のMD5を生成する
* 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更する
* 文字列「append」を追加する
* ハッシュを完了し、結果のハッシュは「secret」 + 「data」 + 「padding」 + 「append」の**有効なもの**になります

### **ツール**

{% embed url="https://github.com/iagox86/hash_extender" %}

### 参考文献

この攻撃については、[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)でよく説明されています。



{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
