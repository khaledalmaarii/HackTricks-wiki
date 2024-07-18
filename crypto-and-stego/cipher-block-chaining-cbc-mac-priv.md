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


# CBC

もし**cookie**が**ユーザー名**だけである場合（またはcookieの最初の部分がユーザー名である場合）で、ユーザー名を**"admin"**に偽装したい場合、ユーザー名**"bdmin"**を作成し、cookieの**最初のバイト**を**ブルートフォース**することができます。

# CBC-MAC

**Cipher block chaining message authentication code**（**CBC-MAC**）は、暗号学で使用される方法です。メッセージをブロックごとに暗号化し、各ブロックの暗号化が前のブロックにリンクされるように機能します。このプロセスにより、元のメッセージの1ビットでも変更すると、暗号化されたデータの最後のブロックに予測不可能な変更が生じます。この変更を行うか逆にするには、暗号化キーが必要であり、セキュリティが確保されます。

メッセージmのCBC-MACを計算するには、mをゼロ初期化ベクトルでCBCモードで暗号化し、最後のブロックを保持します。次の図は、秘密鍵kとブロック暗号Eを使用して、メッセージをブロック![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)でCBC-MACを計算する過程を示しています。

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 脆弱性

通常、CBC-MACでは使用される**IVは0**です。\
これは、2つの既知のメッセージ（`m1`と`m2`）が独立して2つの署名（`s1`と`s2`）を生成するという問題があります。つまり：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

その後、m1とm2を連結したメッセージ（m3）は、2つの署名（s31とs32）を生成します：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**これは、暗号化の鍵を知らなくても計算可能です。**

8バイトのブロックで名前**Administrator**を暗号化していると想像してください：

* `Administ`
* `rator\00\00\00`

ユーザー名**Administ**（m1）の署名（s1）を取得できます。\
次に、`rator\00\00\00 XOR s1`の結果となるユーザー名を作成できます。これにより、`E(m2 XOR s1 XOR 0)`が生成され、s32が得られます。\
これで、s32をフルネーム**Administrator**の署名として使用できます。

### 要約

1. ユーザー名**Administ**（m1）の署名であるs1を取得します。
2. ユーザー名**rator\x00\x00\x00 XOR s1 XOR 0**の署名であるs32を取得します。
3. cookieをs32に設定すると、ユーザー**Administrator**の有効なcookieになります。

# IVの制御攻撃

使用されるIVを制御できる場合、攻撃は非常に簡単になります。\
cookieが単に暗号化されたユーザー名である場合、ユーザー**"administrator"**を作成し、そのcookieを取得できます。\
そして、IVを制御できる場合、IVの最初のバイトを変更して**IV\[0] XOR "A" == IV'\[0] XOR "a"**とし、ユーザー**Administrator**のcookieを再生成できます。このcookieは、初期の**IV**で**administrator**ユーザーを**偽装**するために有効です。

## 参考文献

詳細は[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)を参照してください。


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
