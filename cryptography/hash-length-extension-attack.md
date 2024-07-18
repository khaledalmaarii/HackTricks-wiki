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


# 攻撃の概要

サーバーがある**データ**に**秘密**を**追加**し、そのデータをハッシュ化して**署名**していると想像してください。以下を知っている場合：

* **秘密の長さ**（これは与えられた長さ範囲からもブルートフォースできる）
* **クリアテキストデータ**
* **アルゴリズム（およびこの攻撃に対して脆弱である）**
* **パディングが既知**
* 通常、デフォルトのものが使用されるため、他の3つの要件が満たされている場合、これも満たされる
* パディングは秘密+データの長さに応じて異なるため、秘密の長さが必要

その後、**攻撃者**は**データ**を**追加**し、**以前のデータ+追加されたデータ**の有効な**署名**を**生成**することが可能です。

## 方法

基本的に、脆弱なアルゴリズムは、まず**データのブロックをハッシュ化**し、その後、**以前に**作成された**ハッシュ**（状態）から、**次のデータのブロック**を**追加**して**ハッシュ化**します。

その後、秘密が「secret」でデータが「data」であると想像してください、「secretdata」のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が文字列「append」を追加したい場合：

* 64個の「A」のMD5を生成
* 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更
* 文字列「append」を追加
* ハッシュを完了し、結果のハッシュは「secret」+「data」+「パディング」+「append」に対して**有効**なものになります

## **ツール**

{% embed url="https://github.com/iagox86/hash_extender" %}

## 参考文献

この攻撃について詳しく説明されている[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


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
