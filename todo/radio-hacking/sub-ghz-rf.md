# Sub-GHz RF

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

## ガレージドア

ガレージドアオープナーは通常、300-190 MHzの範囲で動作し、最も一般的な周波数は300 MHz、310 MHz、315 MHz、390 MHzです。この周波数範囲は、他の周波数帯域よりも混雑が少なく、他のデバイスからの干渉を受けにくいため、ガレージドアオープナーに一般的に使用されます。

## 車のドア

ほとんどの車のキーフォブは、**315 MHzまたは433 MHz**のいずれかで動作します。これらはどちらも無線周波数で、さまざまなアプリケーションで使用されています。2つの周波数の主な違いは、433 MHzの方が315 MHzよりも長い範囲を持つことです。つまり、433 MHzはリモートキーなしのエントリーなど、より長い範囲を必要とするアプリケーションに適しています。\
ヨーロッパでは433.92MHzが一般的に使用されており、アメリカと日本では315MHzです。

## **ブルートフォース攻撃**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

各コードを5回送信する代わりに（受信者が受け取ることを確認するためにこのように送信される）、1回だけ送信すると、時間は6分に短縮されます：

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

信号間の**2 msの待機**時間を削除すると、**時間を3分に短縮**できます。

さらに、デ・ブルイン列（すべての潜在的なバイナリ番号をブルートフォースするために送信する必要のあるビット数を減らす方法）を使用することで、この**時間はわずか8秒に短縮**されます：

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

この攻撃の例は、[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)に実装されています。

**プレアンブルを要求することでデ・ブルイン列の**最適化を回避し、**ロールコードはこの攻撃を防ぎます**（コードがブルートフォースできないほど長いと仮定します）。

## Sub-GHz攻撃

これらの信号をFlipper Zeroで攻撃するには、次を確認してください：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## ローリングコード保護

自動ガレージドアオープナーは通常、ガレージドアを開閉するためにワイヤレスリモコンを使用します。リモコンは**無線周波数（RF）信号**をガレージドアオープナーに送信し、モーターを作動させてドアを開閉します。

誰かがコードグラバーと呼ばれるデバイスを使用してRF信号を傍受し、後で使用するために記録することが可能です。これは**リプレイ攻撃**として知られています。この種の攻撃を防ぐために、多くの現代のガレージドアオープナーは**ロールコード**システムと呼ばれるより安全な暗号化方法を使用しています。

**RF信号は通常、ロールコードを使用して送信されます**。これは、使用するたびにコードが変わることを意味します。これにより、誰かが信号を**傍受**し、ガレージに**不正アクセス**するために**使用**することが**難しく**なります。

ロールコードシステムでは、リモコンとガレージドアオープナーは**共有アルゴリズム**を持ち、リモコンが使用されるたびに**新しいコードを生成**します。ガレージドアオープナーは**正しいコード**にのみ応答し、コードをキャプチャするだけでガレージに不正アクセスすることが非常に難しくなります。

### **ミッシングリンク攻撃**

基本的に、ボタンを聞いて、**リモコンがデバイスの範囲外にある間に信号をキャプチャ**します（例えば、車やガレージ）。その後、デバイスに移動し、**キャプチャしたコードを使用して開けます**。

### フルリンクジャミング攻撃

攻撃者は、**車両または受信機の近くで信号をジャミング**することができるため、**受信機は実際にコードを「聞く」ことができません**。その状態が発生すると、単に**コードをキャプチャして再生**することができます。

被害者はある時点で**鍵を使って車をロック**しますが、その後攻撃者は**「ドアを閉める」コードを十分に記録**し、再送信してドアを開けることができることを期待します（**周波数の変更が必要な場合があります**。同じコードを使用して開閉する車があり、異なる周波数で両方のコマンドを聞くためです）。

{% hint style="warning" %}
**ジャミングは機能します**が、目立ちます。**車をロックする人が単にドアをテスト**してロックされていることを確認すると、車がロックされていないことに気付くでしょう。さらに、彼らがそのような攻撃を認識している場合、ドアがロック**音**を出さなかったり、車の**ライト**が「ロック」ボタンを押したときに点滅しなかったことを聞くことができるかもしれません。
{% endhint %}

### **コードグラビング攻撃（別名「ロールジャム」）**

これはより**ステルスジャミング技術**です。攻撃者は信号をジャミングし、被害者がドアをロックしようとすると機能しませんが、攻撃者は**このコードを記録**します。その後、被害者は**ボタンを押して再度車をロックしようとし、車はこの2番目のコードを**記録します。\
この後すぐに、**攻撃者は最初のコードを送信**し、**車はロックされます**（被害者は2回目の押下で閉じたと思うでしょう）。その後、攻撃者は**盗まれた2番目のコードを送信して車を開ける**ことができます（**「車を閉じる」コードも使用できると仮定します**）。周波数の変更が必要な場合があります（同じコードを使用して開閉する車があり、異なる周波数で両方のコマンドを聞くためです）。

攻撃者は**車の受信機をジャミングし、自分の受信機をジャミングしない**ことができます。なぜなら、車の受信機が例えば1MHzの広帯域で聞いている場合、攻撃者はリモコンが使用する正確な周波数を**ジャミング**するのではなく、**そのスペクトル内の近い周波数をジャミング**し、**攻撃者の受信機はより小さな範囲でリモコン信号を**ジャミング信号なしで聞くことができるからです。

{% hint style="warning" %}
仕様に見られる他の実装は、**ロールコードが送信される全体のコードの一部**であることを示しています。つまり、送信されるコードは**24ビットキー**で、最初の**12ビットがロールコード**、**次の8ビットがコマンド**（ロックまたはアンロックなど）、最後の4ビットが**チェックサム**です。このタイプを実装している車両は、攻撃者がロールコードセグメントを置き換えるだけで、両方の周波数で**任意のロールコードを使用できるため、自然に脆弱です**。
{% endhint %}

{% hint style="danger" %}
被害者が攻撃者が最初のコードを送信している間に3番目のコードを送信すると、最初と2番目のコードは無効になります。
{% endhint %}

### アラーム音ジャミング攻撃

車に取り付けられたアフターマーケットのロールコードシステムに対するテストでは、**同じコードを2回送信**すると、すぐに**アラーム**とイモビライザーが作動し、ユニークな**サービス拒否**の機会を提供しました。皮肉なことに、**アラーム**とイモビライザーを**無効にする手段**は**リモコンを押す**ことであり、攻撃者に**継続的にDoS攻撃を実行する能力**を提供しました。また、被害者ができるだけ早く攻撃を止めたいと思うため、**前の攻撃と組み合わせてより多くのコードを取得**することもできます。

## 参考文献

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

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
