# macOS Kernel Extensions

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

## 基本情報

カーネル拡張（Kext）は、**`.kext`** 拡張子を持つ **パッケージ** であり、**macOS カーネル空間に直接ロードされる**ことで、主要なオペレーティングシステムに追加機能を提供します。

### 要件

明らかに、これは非常に強力であるため、**カーネル拡張をロードするのは複雑です**。カーネル拡張がロードされるために満たすべき **要件** は次のとおりです：

* **リカバリモードに入るとき**、カーネル **拡張がロードされることを許可する必要があります**：

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* カーネル拡張は、**Appleによってのみ付与されるカーネルコード署名証明書で署名されている必要があります**。誰が会社とその必要性を詳細にレビューします。
* カーネル拡張はまた、**公証されている必要があります**。Appleはそれをマルウェアのチェックができます。
* 次に、**root** ユーザーが **カーネル拡張をロードできる**唯一のユーザーであり、パッケージ内のファイルは **rootに属する必要があります**。
* アップロードプロセス中、パッケージは **保護された非rootの場所** に準備される必要があります：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement` の付与が必要です）。
* 最後に、ロードを試みると、ユーザーは [**確認リクエストを受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) 。受け入れられた場合、コンピュータは **再起動** されてロードされる必要があります。

### ロードプロセス

カタリナでは次のようでした：**検証** プロセスは **ユーザーランド** で発生することに注意することが興味深いです。しかし、**`com.apple.private.security.kext-management`** の付与を持つアプリケーションのみが **カーネルに拡張をロードするよう要求できます**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** CLI **が** 拡張のロードのための **検証** プロセスを **開始します**
* **`kextd`** に **Machサービス** を使用して送信します。
2. **`kextd`** は、**署名** などのいくつかのことをチェックします
* **`syspolicyd`** に話しかけて、拡張が **ロードできるかどうかを確認します**。
3. **`syspolicyd`** は、拡張が以前にロードされていない場合、**ユーザーにプロンプトを表示します**。
* **`syspolicyd`** は結果を **`kextd`** に報告します
4. **`kextd`** は最終的に **カーネルに拡張をロードするよう指示できます**

もし **`kextd`** が利用できない場合、**`kextutil`** は同じチェックを実行できます。

## 参考文献

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
