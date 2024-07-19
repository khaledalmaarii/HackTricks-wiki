# 赤外線

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

## 赤外線の仕組み <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**赤外線は人間には見えません**。IRの波長は**0.7から1000ミクロン**です。家庭用リモコンはデータ伝送にIR信号を使用し、波長範囲は0.75..1.4ミクロンです。リモコン内のマイクロコントローラーは、特定の周波数で赤外線LEDを点滅させ、デジタル信号をIR信号に変換します。

IR信号を受信するために**フォトレシーバー**が使用されます。これは**IR光を電圧パルスに変換**し、すでに**デジタル信号**です。通常、受信機内には**ダークライトフィルター**があり、**望ましい波長のみを通過させ**、ノイズをカットします。

### IRプロトコルの多様性 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IRプロトコルは3つの要素で異なります：

* ビットエンコーディング
* データ構造
* キャリア周波数 — 通常36..38 kHzの範囲

#### ビットエンコーディングの方法 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. パルス距離エンコーディング**

ビットはパルス間の間隔の持続時間を変調することによってエンコードされます。パルス自体の幅は一定です。

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. パルス幅エンコーディング**

ビットはパルス幅の変調によってエンコードされます。パルスバースト後の間隔の幅は一定です。

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 位相エンコーディング**

マンチェスターエンコーディングとも呼ばれます。論理値はパルスバーストと間隔の間の遷移の極性によって定義されます。「間隔からパルスバースト」は論理「0」を示し、「パルスバーストから間隔」は論理「1」を示します。

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 前述のものと他のエキゾチックな組み合わせ**

{% hint style="info" %}
いくつかのデバイスタイプに対して**ユニバーサルになろうとしている**IRプロトコルがあります。最も有名なものはRC5とNECです。残念ながら、最も有名であることは**最も一般的であることを意味しません**。私の環境では、NECリモコンを2つしか見かけず、RC5のものはありませんでした。

メーカーは、同じデバイスの範囲内でも独自のユニークなIRプロトコルを使用するのが好きです（例えば、TVボックス）。したがって、異なる会社のリモコンや、同じ会社の異なるモデルのリモコンは、同じタイプの他のデバイスと連携できないことがあります。
{% endhint %}

### IR信号の探索

リモコンのIR信号がどのように見えるかを確認する最も信頼性の高い方法は、オシロスコープを使用することです。これは受信信号を復調したり反転したりせず、「そのまま」表示されます。これはテストやデバッグに役立ちます。NEC IRプロトコルの例で期待される信号を示します。

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

通常、エンコードされたパケットの最初にはプレアンブルがあります。これにより、受信機はゲインとバックグラウンドのレベルを決定できます。プレアンブルのないプロトコルもあります。例えば、シャープです。

次にデータが送信されます。構造、プレアンブル、およびビットエンコーディング方法は、特定のプロトコルによって決まります。

**NEC IRプロトコル**は、短いコマンドとリピートコードを含み、ボタンが押されている間に送信されます。コマンドとリピートコードの両方は、最初に同じプレアンブルを持っています。

NECの**コマンド**は、プレアンブルに加えて、デバイスが何を実行する必要があるかを理解するためのアドレスバイトとコマンド番号バイトで構成されています。アドレスとコマンド番号バイトは、伝送の整合性を確認するために逆の値で複製されます。コマンドの最後には追加のストップビットがあります。

**リピートコード**は、プレアンブルの後に「1」があり、これはストップビットです。

**論理「0」と「1」**のために、NECはパルス距離エンコーディングを使用します：最初にパルスバーストが送信され、その後に間隔があり、その長さがビットの値を設定します。

### エアコン

他のリモコンとは異なり、**エアコンは押されたボタンのコードだけを送信しません**。ボタンが押されると、**すべての情報を送信**して、**エアコンとリモコンが同期していることを確認します**。\
これにより、20ºCに設定された機械が1つのリモコンで21ºCに上昇し、別のリモコンがまだ20ºCの温度を持っている場合、さらに温度を上げると、21ºCに「上昇」することを避けることができます（21ºCにいると思って22ºCにはならない）。

### 攻撃

Flipper Zeroを使用して赤外線を攻撃できます：

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
