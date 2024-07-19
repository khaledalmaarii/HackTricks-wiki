# macOS XPC 接続プロセスチェック

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

## XPC 接続プロセスチェック

XPCサービスへの接続が確立されると、サーバーは接続が許可されているかどうかを確認します。通常、以下のチェックが行われます：

1. 接続している**プロセスがApple署名の**証明書で署名されているか確認します（Appleからのみ発行されます）。
* これが**確認されない場合**、攻撃者は**偽の証明書**を作成して他のチェックに合致させることができます。
2. 接続しているプロセスが**組織の証明書**で署名されているか確認します（チームIDの確認）。
* これが**確認されない場合**、Appleの**任意の開発者証明書**が署名に使用され、サービスに接続できます。
3. 接続しているプロセスが**適切なバンドルID**を含んでいるか確認します。
* これが**確認されない場合**、同じ組織によって**署名された任意のツール**がXPCサービスと対話するために使用される可能性があります。
4. (4または5) 接続しているプロセスが**適切なソフトウェアバージョン番号**を持っているか確認します。
* これが**確認されない場合**、古い、脆弱なクライアントがプロセスインジェクションに対して脆弱であり、他のチェックが行われていてもXPCサービスに接続される可能性があります。
5. (4または5) 接続しているプロセスが危険な権限のない**ハードンされたランタイム**を持っているか確認します（任意のライブラリを読み込むことを許可するものやDYLD環境変数を使用するものなど）。
* これが**確認されない場合**、クライアントは**コードインジェクションに対して脆弱**である可能性があります。
6. 接続しているプロセスがサービスに接続することを許可する**権限**を持っているか確認します。これはAppleのバイナリに適用されます。
7. **検証**は接続している**クライアントの監査トークン**に**基づく**べきであり、そのプロセスID（**PID**）ではなく、前者は**PID再利用攻撃**を防ぎます。
* 開発者は**監査トークン**API呼び出しを**ほとんど使用しない**ため、これは**プライベート**であり、Appleはいつでも**変更**できる可能性があります。さらに、プライベートAPIの使用はMac App Storeアプリでは許可されていません。
* **`processIdentifier`**メソッドが使用される場合、脆弱である可能性があります。
* **`xpc_dictionary_get_audit_token`**は**`xpc_connection_get_audit_token`**の代わりに使用されるべきであり、後者は特定の状況で[脆弱である可能性があります](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。

### コミュニケーション攻撃

PID再利用攻撃についての詳細は以下を確認してください：

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

**`xpc_connection_get_audit_token`**攻撃についての詳細は以下を確認してください：

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - ダウングレード攻撃防止

TrustcacheはApple Siliconマシンで導入された防御方法で、AppleバイナリのCDHSAHのデータベースを保存し、許可された非修正バイナリのみが実行されるようにします。これにより、ダウングレードバージョンの実行が防止されます。

### コード例

サーバーはこの**検証**を**`shouldAcceptNewConnection`**という関数で実装します。

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

オブジェクト NSXPCConnection には **プライベート** プロパティ **`auditToken`** （使用すべきものだが変更される可能性がある）と **パブリック** プロパティ **`processIdentifier`** （使用すべきでないもの）がある。

接続プロセスは次のように検証できる：

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

もし開発者がクライアントのバージョンを確認したくない場合、少なくともクライアントがプロセスインジェクションに対して脆弱でないことを確認することができます：

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
{% endcode %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
