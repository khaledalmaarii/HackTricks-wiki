# macOS シリアル番号

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## 基本情報

2010年以降のAppleデバイスのシリアル番号は、**12の英数字**で構成されており、各セグメントは特定の情報を伝えます：

- **最初の3文字**：**製造場所**を示します。
- **4文字目と5文字目**：**製造年と週**を示します。
- **6文字目から8文字目**：各デバイスの**ユニーク識別子**として機能します。
- **最後の4文字**：**モデル番号**を指定します。

例えば、シリアル番号**C02L13ECF8J2**はこの構造に従っています。

### **製造場所（最初の3文字）**
特定のコードは特定の工場を表します：
- **FC, F, XA/XB/QP/G8**：アメリカのさまざまな場所。
- **RN**：メキシコ。
- **CK**：アイルランドのコーク。
- **VM**：チェコ共和国のフォックスコン。
- **SG/E**：シンガポール。
- **MB**：マレーシア。
- **PT/CY**：韓国。
- **EE/QT/UV**：台湾。
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**：中国のさまざまな場所。
- **C0, C3, C7**：中国の特定の都市。
- **RM**：再生品。

### **製造年（4文字目）**
この文字は、'C'（2010年上半期を表す）から'Z'（2019年下半期）まで変化し、異なる文字が異なる上半期または下半期を示します。

### **製造週（5文字目）**
数字1-9は週1-9に対応します。文字C-Y（母音と'S'を除く）は週10-27を表します。年の後半の場合、この数字に26が加算されます。

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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}ハッキングトリックを共有してください。** [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

{% endhint %}
</details>
{% endhint %}
