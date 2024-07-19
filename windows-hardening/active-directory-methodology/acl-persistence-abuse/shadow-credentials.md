# Shadow Credentials

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

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

要約すると、ユーザー/コンピュータの**msDS-KeyCredentialLink**プロパティに書き込むことができれば、そのオブジェクトの**NTハッシュを取得**できます。

投稿では、ターゲットのNTLMハッシュを含むユニークな**サービスチケット**を取得するための**公開鍵-秘密鍵認証資格情報**を設定する方法が概説されています。このプロセスには、復号可能な特権属性証明書（PAC）内の暗号化されたNTLM_SUPPLEMENTAL_CREDENTIALが含まれます。

### Requirements

この技術を適用するには、特定の条件を満たす必要があります：
- 最低1台のWindows Server 2016ドメインコントローラーが必要です。
- ドメインコントローラーには、サーバー認証デジタル証明書がインストールされている必要があります。
- Active DirectoryはWindows Server 2016機能レベルである必要があります。
- ターゲットオブジェクトのmsDS-KeyCredentialLink属性を変更するための委任権を持つアカウントが必要です。

## Abuse

コンピュータオブジェクトに対するKey Trustの悪用は、チケット付与チケット（TGT）とNTLMハッシュの取得を超えるステップを含みます。オプションには以下が含まれます：
1. 意図したホストで特権ユーザーとして機能するための**RC4シルバーチケット**を作成すること。
2. **S4U2Self**を使用して**特権ユーザー**のなりすましを行うために、サービス名にサービスクラスを追加するためにサービスチケットを変更する必要があります。

Key Trustの悪用の大きな利点は、攻撃者が生成した秘密鍵に制限され、潜在的に脆弱なアカウントへの委任を回避し、削除が難しいコンピュータアカウントの作成を必要としないことです。

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

これは、攻撃のためのC#インターフェースを提供するDSInternalsに基づいています。WhiskerとそのPythonの対応物である**pyWhisker**は、ターゲットオブジェクトの`msDS-KeyCredentialLink`属性を操作してActive Directoryアカウントを制御することを可能にします。これらのツールは、ターゲットオブジェクトからキー資格情報を追加、リスト、削除、クリアするなど、さまざまな操作をサポートしています。

**Whisker**の機能には以下が含まれます：
- **Add**: キーペアを生成し、キー資格情報を追加します。
- **List**: すべてのキー資格情報エントリを表示します。
- **Remove**: 指定されたキー資格情報を削除します。
- **Clear**: すべてのキー資格情報を消去し、正当なWHfBの使用を妨げる可能性があります。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

UNIXベースのシステムにWhiskerの機能を拡張し、ImpacketとPyDSInternalsを活用して、KeyCredentialsのリスト、追加、削除を含む包括的なエクスプロイト機能を提供し、JSON形式でのインポートおよびエクスポートも可能です。
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSprayは、**ドメインオブジェクトに対して広範なユーザーグループが持つ可能性のあるGenericWrite/GenericAll権限を悪用して、ShadowCredentialsを広く適用することを目的としています**。これには、ドメインにログインし、ドメインの機能レベルを確認し、ドメインオブジェクトを列挙し、TGT取得とNTハッシュ開示のためにKeyCredentialsを追加しようとすることが含まれます。クリーンアップオプションと再帰的な悪用戦術がその有用性を高めます。

## References

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

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
