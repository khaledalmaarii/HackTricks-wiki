# iButton

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

## Intro

iButtonは、**コイン型の金属容器**に詰め込まれた電子識別キーの一般的な名称です。これは**Dallas Touch**メモリまたは接触メモリとも呼ばれます。しばしば「磁気」キーと誤って呼ばれますが、実際には**磁気的なものは何もありません**。実際には、デジタルプロトコルで動作する完全な**マイクロチップ**が内部に隠されています。

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常、iButtonはキーとリーダーの物理的な形状を指し、2つの接点を持つ丸いコインです。その周囲のフレームには、穴のある最も一般的なプラスチックホルダーからリング、ペンダントなど、さまざまなバリエーションがあります。

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

キーがリーダーに到達すると、**接点が接触し**、キーが**IDを送信するために電源が入ります**。時には、**インターホンの接触PSDが大きすぎる**ため、キーが**すぐに読み取られない**ことがあります。その場合、キーとリーダーの外形が接触できません。その場合は、リーダーの壁の1つの上にキーを押し付ける必要があります。

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallasキーは1-Wireプロトコルを使用してデータを交換します。データ転送用の接点は1つだけで、両方向（マスターからスレーブ、またその逆）で動作します。1-Wireプロトコルはマスター-スレーブモデルに従って動作します。このトポロジーでは、マスターが常に通信を開始し、スレーブがその指示に従います。

キー（スレーブ）がインターホン（マスター）に接触すると、キー内部のチップが起動し、インターホンによって電源が供給され、キーが初期化されます。その後、インターホンがキーIDを要求します。次に、このプロセスを詳しく見ていきます。

Flipperはマスターとスレーブの両方のモードで動作できます。キー読み取りモードでは、Flipperはリーダーとして機能し、つまりマスターとして動作します。そして、キーエミュレーションモードでは、Flipperはキーのふりをし、スレーブモードにあります。

### Dallas, Cyfral & Metakom keys

これらのキーの動作についての情報は、ページ[https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)を確認してください。

### Attacks

iButtonsはFlipper Zeroで攻撃できます：

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
