# AD Certificates

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

## Introduction

### Components of a Certificate

- 証明書の**Subject**はその所有者を示します。
- **Public Key**は、証明書を正当な所有者にリンクするために、プライベートキーとペアになっています。
- **Validity Period**は、**NotBefore**および**NotAfter**の日付によって定義され、証明書の有効期間を示します。
- 一意の**Serial Number**は、証明書を識別するために証明書発行機関（CA）によって提供されます。
- **Issuer**は、証明書を発行したCAを指します。
- **SubjectAlternativeName**は、識別の柔軟性を高めるために、主題の追加名を許可します。
- **Basic Constraints**は、証明書がCA用かエンドエンティティ用かを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)**は、オブジェクト識別子（OIDs）を通じて、コード署名やメール暗号化など、証明書の特定の目的を示します。
- **Signature Algorithm**は、証明書に署名する方法を指定します。
- **Signature**は、発行者のプライベートキーで作成され、証明書の真正性を保証します。

### Special Considerations

- **Subject Alternative Names (SANs)**は、証明書の適用範囲を複数のアイデンティティに拡張し、複数のドメインを持つサーバーにとって重要です。攻撃者がSAN仕様を操作することによる偽装リスクを避けるために、安全な発行プロセスが重要です。

### Certificate Authorities (CAs) in Active Directory (AD)

AD CSは、指定されたコンテナを通じてADフォレスト内のCA証明書を認識し、それぞれが独自の役割を果たします：

- **Certification Authorities**コンテナは、信頼されたルートCA証明書を保持します。
- **Enrolment Services**コンテナは、エンタープライズCAとその証明書テンプレートの詳細を示します。
- **NTAuthCertificates**オブジェクトは、AD認証のために承認されたCA証明書を含みます。
- **AIA (Authority Information Access)**コンテナは、中間CAおよびクロスCA証明書を使用して証明書チェーンの検証を容易にします。

### Certificate Acquisition: Client Certificate Request Flow

1. リクエストプロセスは、クライアントがエンタープライズCAを見つけることから始まります。
2. 公開鍵とその他の詳細を含むCSRが作成され、公開鍵とプライベート鍵のペアが生成された後に行われます。
3. CAは、利用可能な証明書テンプレートに対してCSRを評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認後、CAはプライベートキーで証明書に署名し、クライアントに返します。

### Certificate Templates

AD内で定義されているこれらのテンプレートは、証明書を発行するための設定と権限を概説し、許可されたEKUや登録または変更権限を含み、証明書サービスへのアクセス管理において重要です。

## Certificate Enrollment

証明書の登録プロセスは、管理者が**証明書テンプレートを作成**し、それがエンタープライズ証明書発行機関（CA）によって**公開**されることから始まります。これにより、クライアントの登録に利用可能なテンプレートが作成され、Active Directoryオブジェクトの`certificatetemplates`フィールドにテンプレート名を追加することで達成されます。

クライアントが証明書をリクエストするには、**登録権限**が付与されている必要があります。これらの権限は、証明書テンプレートおよびエンタープライズCA自体のセキュリティ記述子によって定義されます。リクエストが成功するためには、両方の場所で権限が付与される必要があります。

### Template Enrollment Rights

これらの権限は、アクセス制御エントリ（ACE）を通じて指定され、次のような権限が詳細に示されます：
- **Certificate-Enrollment**および**Certificate-AutoEnrollment**権限は、それぞれ特定のGUIDに関連付けられています。
- **ExtendedRights**は、すべての拡張権限を許可します。
- **FullControl/GenericAll**は、テンプレートに対する完全な制御を提供します。

### Enterprise CA Enrollment Rights

CAの権限は、そのセキュリティ記述子に記載されており、証明書発行機関管理コンソールを介してアクセス可能です。一部の設定では、低権限のユーザーにリモートアクセスを許可することもあり、これはセキュリティ上の懸念となる可能性があります。

### Additional Issuance Controls

特定の制御が適用される場合があります：
- **Manager Approval**：リクエストを保留状態にし、証明書マネージャーによる承認を待ちます。
- **Enrolment Agents and Authorized Signatures**：CSRに必要な署名の数と必要なアプリケーションポリシーOIDを指定します。

### Methods to Request Certificates

証明書は次の方法でリクエストできます：
1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)、DCOMインターフェースを使用。
2. **ICertPassage Remote Protocol** (MS-ICPR)、名前付きパイプまたはTCP/IPを介して。
3. **証明書登録ウェブインターフェース**、証明書発行機関ウェブ登録役割がインストールされていること。
4. **Certificate Enrollment Service** (CES)、証明書登録ポリシー（CEP）サービスと連携。
5. **Network Device Enrollment Service** (NDES)は、ネットワークデバイス用に、シンプル証明書登録プロトコル（SCEP）を使用。

Windowsユーザーは、GUI（`certmgr.msc`または`certlm.msc`）またはコマンドラインツール（`certreq.exe`またはPowerShellの`Get-Certificate`コマンド）を介しても証明書をリクエストできます。
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 証明書認証

Active Directory (AD) は、主に **Kerberos** と **Secure Channel (Schannel)** プロトコルを利用して証明書認証をサポートしています。

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーのチケット授与チケット (TGT) の要求がユーザーの証明書の **秘密鍵** を使用して署名されます。この要求は、ドメインコントローラーによって、証明書の **有効性**、**パス**、および **失効状況** を含むいくつかの検証を受けます。検証には、証明書が信頼できるソースからのものであることの確認や、発行者が **NTAUTH 証明書ストア** に存在することの確認も含まれます。検証が成功すると、TGT が発行されます。AD の **`NTAuthCertificates`** オブジェクトは、次の場所にあります:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is central to establishing trust for certificate authentication.

### Secure Channel (Schannel) Authentication

Schannelは、安全なTLS/SSL接続を促進します。ハンドシェイク中に、クライアントは証明書を提示し、成功裏に検証されるとアクセスが許可されます。証明書をADアカウントにマッピングするには、Kerberosの**S4U2Self**機能や証明書の**Subject Alternative Name (SAN)**など、他の方法が関与する場合があります。

### AD Certificate Services Enumeration

ADの証明書サービスは、LDAPクエリを通じて列挙でき、**Enterprise Certificate Authorities (CAs)**およびその構成に関する情報を明らかにします。これは、特別な権限なしにドメイン認証されたユーザーによってアクセス可能です。**[Certify](https://github.com/GhostPack/Certify)**や**[Certipy](https://github.com/ly4k/Certipy)**のようなツールは、AD CS環境での列挙と脆弱性評価に使用されます。

Commands for using these tools include:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 参考文献

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
