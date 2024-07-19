# macOS AppleFS

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple 独自ファイルシステム (APFS)

**Apple File System (APFS)** は、階層型ファイルシステムプラス (HFS+) に代わるように設計された現代的なファイルシステムです。その開発は、**パフォーマンス、セキュリティ、効率の向上**の必要性によって推進されました。

APFSの主な特徴は以下の通りです：

1. **スペース共有**: APFSは、複数のボリュームが**単一の物理デバイス上で同じ基盤となる空きストレージを共有する**ことを可能にします。これにより、ボリュームは手動でのサイズ変更や再パーティションなしに動的に増減できるため、より効率的なスペース利用が実現します。
1. これは、ファイルディスクの従来のパーティションと比較して、**APFSでは異なるパーティション（ボリューム）がすべてのディスクスペースを共有する**ことを意味しますが、通常のパーティションは固定サイズでした。
2. **スナップショット**: APFSは**スナップショットの作成をサポート**しており、これは**読み取り専用**の時点でのファイルシステムのインスタンスです。スナップショットは効率的なバックアップと簡単なシステムのロールバックを可能にし、最小限の追加ストレージを消費し、迅速に作成または復元できます。
3. **クローン**: APFSは、**元のストレージを共有するファイルまたはディレクトリのクローンを作成**でき、クローンまたは元のファイルが変更されるまでそのストレージを共有します。この機能は、ストレージスペースを重複させることなくファイルやディレクトリのコピーを作成する効率的な方法を提供します。
4. **暗号化**: APFSは、**ディスク全体の暗号化**だけでなく、ファイルごとおよびディレクトリごとの暗号化も**ネイティブにサポート**しており、さまざまな使用ケースにおけるデータセキュリティを強化します。
5. **クラッシュ保護**: APFSは、**ファイルシステムの整合性を確保するコピーオンライトメタデータスキームを使用**しており、突然の電源喪失やシステムクラッシュの際でもデータの破損リスクを低減します。

全体として、APFSはAppleデバイス向けに、パフォーマンス、信頼性、セキュリティの向上に重点を置いた、より現代的で柔軟かつ効率的なファイルシステムを提供します。
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` ボリュームは **`/System/Volumes/Data`** にマウントされています（これを `diskutil apfs list` で確認できます）。

firmlinks のリストは **`/usr/share/firmlinks`** ファイルにあります。
```bash
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
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
