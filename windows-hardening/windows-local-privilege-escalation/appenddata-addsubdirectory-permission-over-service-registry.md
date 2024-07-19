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


**元の投稿は** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 概要

現在のユーザーによって書き込み可能な2つのレジストリキーが見つかりました：

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper**サービスの権限を**regedit GUI**を使用して確認することが提案されました。特に、**Advanced Security Settings**ウィンドウの**Effective Permissions**タブを使用します。このアプローチにより、各アクセス制御エントリ（ACE）を個別に調べることなく、特定のユーザーまたはグループに付与された権限を評価できます。

スクリーンショットには、低特権ユーザーに割り当てられた権限が示されており、その中で**Create Subkey**権限が注目されました。この権限は、**AppendData/AddSubdirectory**とも呼ばれ、スクリプトの結果と一致します。

特定の値を直接変更できない一方で、新しいサブキーを作成する能力があることが指摘されました。例として、**ImagePath**値を変更しようとした際にアクセス拒否メッセージが表示されたことが挙げられました。

これらの制限にもかかわらず、**RpcEptMapper**サービスのレジストリ構造内の**Performance**サブキーを利用することで特権昇格の可能性が特定されました。このサブキーはデフォルトでは存在しません。これにより、DLLの登録とパフォーマンス監視が可能になります。

**Performance**サブキーに関する文書とそのパフォーマンス監視への利用について調査し、**OpenPerfData**、**CollectPerfData**、および**ClosePerfData**関数の実装を示す概念実証DLLを開発しました。このDLLは**rundll32**を介してテストされ、動作の成功が確認されました。

目標は、作成したPerformance DLLを**RPC Endpoint Mapper service**に読み込ませることでした。観察結果から、PowerShellを介してパフォーマンスデータに関連するWMIクラスクエリを実行すると、ログファイルが作成され、**LOCAL SYSTEM**コンテキストで任意のコードを実行できることが明らかになり、特権が昇格されました。

この脆弱性の持続性と潜在的な影響が強調され、ポストエクスプロイト戦略、横移動、およびアンチウイルス/EDRシステムの回避における関連性が示されました。

この脆弱性は、スクリプトを通じて意図せずに最初に開示されましたが、その悪用は古いWindowsバージョン（例：**Windows 7 / Server 2008 R2**）に制限され、ローカルアクセスが必要であることが強調されました。

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
