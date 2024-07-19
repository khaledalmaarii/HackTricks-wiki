# 暗号化/圧縮アルゴリズム

## 暗号化/圧縮アルゴリズム

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

## アルゴリズムの特定

コードが**シフト右と左、XORおよびいくつかの算術演算**を使用している場合、それは**暗号化アルゴリズム**の実装である可能性が高いです。ここでは、**各ステップを逆にすることなく使用されているアルゴリズムを特定する方法**をいくつか示します。

### API関数

**CryptDeriveKey**

この関数が使用されている場合、第二のパラメータの値を確認することで**使用されているアルゴリズム**を見つけることができます：

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

可能なアルゴリズムとその割り当てられた値の表はここで確認できます：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

指定されたデータバッファを圧縮および解凍します。

**CryptAcquireContext**

[ドキュメント](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)から：**CryptAcquireContext**関数は、特定の暗号サービスプロバイダー（CSP）内の特定のキーコンテナへのハンドルを取得するために使用されます。**この返されたハンドルは、選択されたCSPを使用するCryptoAPI**関数への呼び出しで使用されます。

**CryptCreateHash**

データストリームのハッシュ化を開始します。この関数が使用されている場合、第二のパラメータの値を確認することで**使用されているアルゴリズム**を見つけることができます：

![](<../../.gitbook/assets/image (376).png>)

\
可能なアルゴリズムとその割り当てられた値の表はここで確認できます：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード定数

時には、特別でユニークな値を使用する必要があるため、アルゴリズムを特定するのが非常に簡単です。

![](<../../.gitbook/assets/image (370).png>)

最初の定数をGoogleで検索すると、次のような結果が得られます：

![](<../../.gitbook/assets/image (371).png>)

したがって、逆コンパイルされた関数は**sha256計算機**であると推測できます。\
他の定数を検索すると、（おそらく）同じ結果が得られます。

### データ情報

コードに重要な定数がない場合、**.dataセクションから情報を読み込んでいる可能性があります**。\
そのデータにアクセスし、**最初のDWORDをグループ化**し、前のセクションで行ったようにGoogleで検索できます：

![](<../../.gitbook/assets/image (372).png>)

この場合、**0xA56363C6**を検索すると、**AESアルゴリズムのテーブル**に関連していることがわかります。

## RC4 **（対称暗号）**

### 特徴

3つの主要な部分で構成されています：

* **初期化ステージ/**：**0x00から0xFFまでの値のテーブル**（合計256バイト、0x100）を作成します。このテーブルは一般に**置換ボックス**（またはSBox）と呼ばれます。
* **スクランブルステージ**：前に作成したテーブルを**ループ**し（0x100回のイテレーションのループ）、各値を**半ランダム**なバイトで修正します。この半ランダムなバイトを作成するために、RC4**キーが使用されます**。RC4**キー**は**1バイトから256バイトの長さ**である可能性がありますが、通常は5バイト以上を推奨します。一般的に、RC4キーは16バイトの長さです。
* **XORステージ**：最後に、平文または暗号文は**前に作成した値とXORされます**。暗号化と復号化の関数は同じです。これには、作成された256バイトを必要な回数だけループします。これは通常、逆コンパイルされたコードで**%256（mod 256）**として認識されます。

{% hint style="info" %}
**逆アセンブル/逆コンパイルされたコードでRC4を特定するには、サイズ0x100の2つのループ（キーを使用）を確認し、その後、入力データを前の2つのループで作成された256の値とXORすることを確認します。おそらく%256（mod 256）を使用します。**
{% endhint %}

### **初期化ステージ/置換ボックス：**（カウンタとして使用される256という数字と、256文字の各場所に0が書かれていることに注意）

![](<../../.gitbook/assets/image (377).png>)

### **スクランブルステージ：**

![](<../../.gitbook/assets/image (378).png>)

### **XORステージ：**

![](<../../.gitbook/assets/image (379).png>)

## **AES（対称暗号）**

### **特徴**

* **置換ボックスとルックアップテーブルの使用**
* **特定のルックアップテーブル値**（定数）の使用によりAESを**区別することが可能です**。_注意：**定数**は**バイナリに**保存されることもあれば、_ _**動的に**_作成されることもあります。_
* **暗号化キー**は**16で割り切れる**必要があります（通常32B）し、通常は16Bの**IV**が使用されます。

### SBox定数

![](<../../.gitbook/assets/image (380).png>)

## Serpent **（対称暗号）**

### 特徴

* それを使用しているマルウェアを見つけるのは稀ですが、例（Ursnif）があります。
* アルゴリズムがSerpentかどうかは、その長さ（非常に長い関数）に基づいて簡単に判断できます。

### 特定

次の画像では、定数**0x9E3779B9**が使用されていることに注意してください（この定数は**TEA**（Tiny Encryption Algorithm）などの他の暗号アルゴリズムでも使用されています）。\
また、**ループのサイズ**（**132**）と**逆アセンブル**命令および**コード**例における**XOR操作の数**にも注意してください：

![](<../../.gitbook/assets/image (381).png>)

前述のように、このコードは**非常に長い関数**として任意の逆コンパイラ内で視覚化できます。内部に**ジャンプ**がないためです。逆コンパイルされたコードは次のように見えることがあります：

![](<../../.gitbook/assets/image (382).png>)

したがって、**マジックナンバー**と**初期XOR**を確認し、**非常に長い関数**を見て、**長い関数のいくつかの命令を**（左に7シフトし、22に左回転するような）**実装と比較することで、このアルゴリズムを特定することが可能です。**

## RSA **（非対称暗号）**

### 特徴

* 対称アルゴリズムよりも複雑です。
* 定数はありません！（カスタム実装は特定が難しい）
* KANAL（暗号アナライザー）はRSAに関するヒントを示すことができず、定数に依存しています。

### 比較による特定

![](<../../.gitbook/assets/image (383).png>)

* 左の行11には`+7) >> 3`があり、右の行35と同じです：`+7) / 8`
* 左の行12は`modulus_len < 0x040`を確認しており、右の行36では`inputLen+11 > modulusLen`を確認しています。

## MD5 & SHA（ハッシュ）

### 特徴

* 3つの関数：Init、Update、Final
* 初期化関数が似ています。

### 特定

**Init**

定数を確認することで両方を特定できます。sha\_initにはMD5にはない1つの定数があることに注意してください：

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

より多くの定数の使用に注意してください。

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（ハッシュ）

* より小さく、データの偶発的な変更を見つけるために効率的です。
* ルックアップテーブルを使用します（したがって、定数を特定できます）。

### 特定

**ルックアップテーブル定数**を確認してください：

![](<../../.gitbook/assets/image (387).png>)

CRCハッシュアルゴリズムは次のようになります：

![](<../../.gitbook/assets/image (386).png>)

## APLib（圧縮）

### 特徴

* 認識可能な定数はありません。
* アルゴリズムをPythonで書いて、オンラインで類似のものを検索することを試みることができます。

### 特定

グラフはかなり大きいです：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

それを認識するために**3つの比較**を確認してください：

![](<../../.gitbook/assets/image (384).png>)

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
