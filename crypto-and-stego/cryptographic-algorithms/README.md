# 暗号化/圧縮アルゴリズム

## 暗号化/圧縮アルゴリズム

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**または**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して**ハッキングトリックを共有**してください。

</details>
{% endhint %}

## アルゴリズムの特定

コードが**シフト右および左、XOR、およびいくつかの算術演算**を使用している場合、それが**暗号化アルゴリズム**の実装である可能性が非常に高いです。ここでは、**各ステップを逆にする必要なしに使用されているアルゴリズムを特定する方法**を示します。

### API関数

**CryptDeriveKey**

この関数が使用されている場合、第2パラメータの値をチェックすることで、**使用されているアルゴリズムを特定**できます:

![](<../../.gitbook/assets/image (156).png>)

ここで、可能なアルゴリズムとそれに割り当てられた値の表を確認できます: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

与えられたデータバッファを圧縮および解凍します。

**CryptAcquireContext**

[ドキュメント](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)によると、**CryptAcquireContext**関数は、特定の暗号化サービスプロバイダ（CSP）内の特定のキーコンテナへのハンドルを取得するために使用されます。**この返されたハンドルは、選択したCSPを使用するCryptoAPI関数の呼び出しで使用**されます。

**CryptCreateHash**

データストリームのハッシュ化を開始します。この関数が使用されている場合、第2パラメータの値をチェックすることで、**使用されているアルゴリズムを特定**できます:

![](<../../.gitbook/assets/image (549).png>)

\
ここで、可能なアルゴリズムとそれに割り当てられた値の表を確認できます: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード定数

アルゴリズムを特定するのが非常に簡単な場合があります。それは特別でユニークな値を使用する必要があるためです。

![](<../../.gitbook/assets/image (833).png>)

最初の定数をGoogleで検索すると、次のようになります:

![](<../../.gitbook/assets/image (529).png>)

したがって、逆コンパイルされた関数が**sha256計算機**であると仮定できます。\
他の定数のいずれかを検索すると、おそらく同じ結果が得られます。

### データ情報

コードに有意義な定数がない場合、**.dataセクションから情報を読み込んでいる**可能性があります。\
そのデータにアクセスし、最初のdwordを**グループ化**して、前述のセクションで行ったようにGoogleで検索できます:

![](<../../.gitbook/assets/image (531).png>)

この場合、**0xA56363C6**を検索すると、**AESアルゴリズムのテーブル**に関連していることがわかります。

## RC4 **（対称暗号）**

### 特徴

* **初期化ステージ/**: 0x00から0xFF（合計256バイト、0x100）までの値の**テーブル**を作成します。このテーブルは一般的に**置換ボックス**（またはSBox）と呼ばれます。
* **スクランブルステージ**: 以前に作成されたテーブルをループします（0x100回のループ、再び）し、各値を**半ランダム**バイトで変更します。この半ランダムバイトを作成するために、RC4 **キーが使用**されます。RC4 **キー**は**1から256バイトの長さ**である可能性がありますが、通常は5バイト以上であることが推奨されています。一般的に、RC4キーは16バイトの長さです。
* **XORステージ**: 最後に、平文または暗号文が以前に作成された値と**XORされます**。暗号化および復号化のための関数は同じです。これにより、作成された256バイトを**必要な回数だけループ**します。これは通常、逆コンパイルされたコードで**%256（mod 256）**として認識されます。

{% hint style="info" %}
**逆アセンブリ/逆コンパイルされたコードでRC4を特定するには、2つの0x100サイズのループ（キーを使用）をチェックし、おそらく%256（mod 256）を使用して2つのループで作成された256値との入力データのXORを行うことを確認できます。**
{% endhint %}

### **初期化ステージ/置換ボックス:**（256というカウンターと、256文字の各場所に0が書かれていることに注目）

![](<../../.gitbook/assets/image (584).png>)

### **スクランブルステージ:**

![](<../../.gitbook/assets/image (835).png>)

### **XORステージ:**

![](<../../.gitbook/assets/image (904).png>)

## **AES（対称暗号）**

### **特徴**

* **置換ボックスとルックアップテーブルの使用**
* 特定のルックアップテーブル値（定数）の使用により、AESを**区別**することができます。_**定数**はバイナリに**格納**されるか、_**動的に作成**される_ _**ことができます。_
* **暗号化キー**は**16で割り切れる**必要があります（通常32B）、通常16BのIVが使用されます。

### SBox定数

![](<../../.gitbook/assets/image (208).png>)

## Serpent **（対称暗号）**

### 特徴

* 使用例は少ないですが、マルウェアが使用している例もあります（Ursnif）
* 非常に長い関数に基づいて、アルゴリズムがSerpentであるかどうかを簡単に判断できます。

### 特定

次の画像で、定数**0x9E3779B9**が使用されていることに注目してください（この定数は**TEA**（Tiny Encryption Algorithm）などの他の暗号アルゴリズムでも使用されていることに注意してください）。\
また、**ループのサイズ**（**132**）、**XOR操作の数**（**逆アセンブリ**命令および**コード**例で）に注目してください:

![](<../../.gitbook/assets/image (547).png>)

前述のように、このコードは**非常に長い関数**として任意のデコンパイラ内で視覚化でき、内部に**ジャンプがない**ため、次のように見える可能性があります:

![](<../../.gitbook/assets/image (513).png>)

したがって、**マジックナンバー**と**初期XOR**をチェックし、**非常に長い関数**を見て、**いくつかの命令**を**実装**と比較することで、このアルゴリズムを特定することができます。
## RSA **(非対称暗号)**

### 特徴

* 対称暗号より複雑
* 定数が存在しない！（カスタム実装は難しい）
* RSAに関するヒントを示すKANAL（暗号解析ツール）は定数に依存していないため失敗する。

### 比較による識別

![](<../../.gitbook/assets/image (1113).png>)

* 11行目（左）には `+7) >> 3` があり、35行目（右）には `+7) / 8` がある
* 12行目（左）は `modulus_len < 0x040` をチェックしており、36行目（右）は `inputLen+11 > modulusLen` をチェックしている

## MD5 & SHA（ハッシュ）

### 特徴

* 初期化、更新、終了の3つの関数
* 似たような初期化関数

### 識別

**初期化**

両方を識別するには定数をチェックできます。MD5には存在しない1つの定数がsha_initにあることに注意してください：

![](<../../.gitbook/assets/image (406).png>)

**MD5変換**

より多くの定数の使用に注意してください

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC（ハッシュ）

* データの偶発的な変更を見つけるための関数としてより小さく効率的
* ルックアップテーブルを使用する（定数を識別できる）

### 識別

**ルックアップテーブルの定数**をチェック：

![](<../../.gitbook/assets/image (508).png>)

CRCハッシュアルゴリズムは次のようになります：

![](<../../.gitbook/assets/image (391).png>)

## APLib（圧縮）

### 特徴

* 識別できない定数
* Pythonでアルゴリズムを書いて類似のものをオンラインで検索できます

### 識別

グラフはかなり大きいです：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

**それを認識するための3つの比較**をチェック：

![](<../../.gitbook/assets/image (430).png>)
