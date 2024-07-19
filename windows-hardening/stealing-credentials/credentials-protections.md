# Windows Credentials Protections

## Credentials Protections

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

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) プロトコルは、Windows XPで導入され、HTTPプロトコルを介した認証のために設計されており、**Windows XPからWindows 8.0およびWindows Server 2003からWindows Server 2012までデフォルトで有効になっています**。このデフォルト設定により、**LSASS（ローカルセキュリティ認証サブシステムサービス）にプレーンテキストのパスワードが保存されます**。攻撃者はMimikatzを使用して、次のコマンドを実行することで**これらの資格情報を抽出**できます：
```bash
sekurlsa::wdigest
```
この機能を**オフまたはオンに切り替える**には、_**UseLogonCredential**_ および _**Negotiate**_ レジストリキーを _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内で "1" に設定する必要があります。これらのキーが**存在しないか "0" に設定されている**場合、WDigestは**無効**になります。
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA保護

**Windows 8.1**以降、MicrosoftはLSAのセキュリティを強化し、**信頼されていないプロセスによる不正なメモリ読み取りやコード注入をブロック**するようにしました。この強化により、`mimikatz.exe sekurlsa:logonpasswords`のようなコマンドの通常の機能が妨げられます。この**強化された保護を有効にする**には、_**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_内の_**RunAsPPL**_値を1に調整する必要があります：
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### バイパス

この保護を Mimikatz ドライバー mimidrv.sys を使用してバイパスすることが可能です：

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** は **Windows 10 (Enterprise and Education editions)** 専用の機能で、**Virtual Secure Mode (VSM)** と **Virtualization Based Security (VBS)** を使用してマシンの資格情報のセキュリティを強化します。これは、CPU の仮想化拡張を利用して、主要なプロセスを保護されたメモリ空間内に隔離し、メインオペレーティングシステムの手の届かない場所に置きます。この隔離により、カーネルでさえ VSM 内のメモリにアクセスできず、**pass-the-hash** のような攻撃から資格情報を効果的に保護します。**Local Security Authority (LSA)** はこの安全な環境内でトラストレットとして動作し、メイン OS の **LSASS** プロセスは VSM の LSA と通信するだけの役割を果たします。

デフォルトでは、**Credential Guard** はアクティブではなく、組織内で手動での有効化が必要です。これは、資格情報を抽出する能力が制限されるため、**Mimikatz** のようなツールに対するセキュリティを強化するために重要です。ただし、カスタム **Security Support Providers (SSP)** を追加することで、ログイン試行中に平文で資格情報をキャプチャするために脆弱性が悪用される可能性があります。

**Credential Guard** のアクティベーション状態を確認するには、_**HKLM\System\CurrentControlSet\Control\LSA**_ の下にあるレジストリキー _**LsaCfgFlags**_ を調べることができます。値が "**1**" の場合は **UEFI ロック** 付きのアクティブ、"**2**" はロックなし、"**0**" は無効を示します。このレジストリチェックは強力な指標ですが、Credential Guard を有効にするための唯一のステップではありません。この機能を有効にするための詳細なガイダンスと PowerShell スクリプトはオンラインで入手可能です。
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/ja-jp/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 と Windows Server 2012 R2** は、_**RDPの制限付き管理者モード**_ などの新しいセキュリティ機能をいくつか導入しました。このモードは、[**パス・ザ・ハッシュ**](https://blog.ahasayen.com/pass-the-hash/) 攻撃に関連するリスクを軽減することで、セキュリティを強化することを目的としています。

従来、RDPを介してリモートコンピュータに接続する際、資格情報はターゲットマシンに保存されます。これは、特に特権のあるアカウントを使用する場合に、重大なセキュリティリスクをもたらします。しかし、_**制限付き管理者モード**_ の導入により、このリスクは大幅に軽減されます。

**mstsc.exe /RestrictedAdmin** コマンドを使用してRDP接続を開始すると、リモートコンピュータへの認証は、資格情報を保存することなく行われます。このアプローチにより、マルウェア感染や悪意のあるユーザーがリモートサーバーにアクセスした場合でも、資格情報がサーバーに保存されていないため、危険にさらされることはありません。

**制限付き管理者モード** では、RDPセッションからネットワークリソースにアクセスしようとする試みは、個人の資格情報を使用せず、代わりに **マシンのアイデンティティ** が使用されることに注意が必要です。

この機能は、リモートデスクトップ接続のセキュリティを強化し、セキュリティ侵害が発生した場合に機密情報が露出するのを防ぐための重要なステップです。

![](../../.gitbook/assets/RAM.png)

For more detailed information on visit [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windowsは、**ローカルセキュリティ機関 (LSA)** を通じて **ドメイン資格情報** を保護し、**Kerberos** や **NTLM** などのセキュリティプロトコルを使用してログオンプロセスをサポートします。Windowsの重要な機能の一つは、**最後の10回のドメインログイン** をキャッシュする能力であり、これにより **ドメインコントローラーがオフライン** の場合でもユーザーがコンピュータにアクセスできるようになります。これは、会社のネットワークから離れていることが多いノートパソコンユーザーにとって大きな利点です。

キャッシュされたログインの数は、特定の **レジストリキーまたはグループポリシー** を介して調整可能です。この設定を表示または変更するには、次のコマンドが使用されます:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

**Protected Users group**へのメンバーシップは、ユーザーに対していくつかのセキュリティ強化を導入し、資格情報の盗難や悪用に対するより高い保護レベルを確保します：

* **Credential Delegation (CredSSP)**: **Allow delegating default credentials**のグループポリシー設定が有効であっても、Protected Usersのプレーンテキスト資格情報はキャッシュされません。
* **Windows Digest**: **Windows 8.1およびWindows Server 2012 R2**以降、システムはProtected Usersのプレーンテキスト資格情報をキャッシュしません。Windows Digestの状態に関係なく。
* **NTLM**: システムはProtected Usersのプレーンテキスト資格情報やNT一方向関数（NTOWF）をキャッシュしません。
* **Kerberos**: Protected Usersの場合、Kerberos認証は**DES**または**RC4キー**を生成せず、プレーンテキスト資格情報や初期のチケット授与チケット（TGT）取得を超える長期キーをキャッシュしません。
* **Offline Sign-In**: Protected Usersはサインインまたはロック解除時にキャッシュされた検証子が作成されないため、これらのアカウントではオフラインサインインはサポートされません。

これらの保護は、**Protected Users group**のメンバーであるユーザーがデバイスにサインインした瞬間に有効になります。これにより、資格情報の妥協に対するさまざまな方法から保護するための重要なセキュリティ対策が講じられます。

詳細な情報については、公式の[documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)を参照してください。

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

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
