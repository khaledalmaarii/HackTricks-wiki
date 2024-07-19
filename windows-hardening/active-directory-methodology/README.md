# Active Directory Methodology

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

## 基本概要

**Active Directory**は、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、および**オブジェクト**を効率的に作成および管理できるようにする基盤技術です。これはスケーラブルに設計されており、膨大な数のユーザーを管理可能な**グループ**および**サブグループ**に整理し、さまざまなレベルで**アクセス権**を制御します。

**Active Directory**の構造は、**ドメイン**、**ツリー**、および**フォレスト**の3つの主要な層で構成されています。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトのコレクションを含みます。**ツリー**は、共有構造によってリンクされたこれらのドメインのグループであり、**フォレスト**は、**信頼関係**を通じて相互接続された複数のツリーのコレクションを表し、組織構造の最上層を形成します。特定の**アクセス**および**通信権**は、これらの各レベルで指定できます。

**Active Directory**内の主要な概念には以下が含まれます：

1. **ディレクトリ** – Active Directoryオブジェクトに関するすべての情報を保持します。
2. **オブジェクト** – ディレクトリ内のエンティティを示し、**ユーザー**、**グループ**、または**共有フォルダー**を含みます。
3. **ドメイン** – ディレクトリオブジェクトのコンテナとして機能し、**フォレスト**内で複数のドメインが共存でき、それぞれが独自のオブジェクトコレクションを維持します。
4. **ツリー** – 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** – Active Directoryにおける組織構造の頂点であり、**信頼関係**を持ついくつかのツリーで構成されています。

**Active Directory Domain Services (AD DS)**は、ネットワーク内の集中管理および通信に不可欠な一連のサービスを含みます。これらのサービスには以下が含まれます：

1. **ドメインサービス** – データストレージを集中化し、**ユーザー**と**ドメイン**間の相互作用を管理し、**認証**および**検索**機能を含みます。
2. **証明書サービス** – 安全な**デジタル証明書**の作成、配布、および管理を監督します。
3. **軽量ディレクトリサービス** – **LDAPプロトコル**を通じてディレクトリ対応アプリケーションをサポートします。
4. **ディレクトリフェデレーションサービス** – 複数のWebアプリケーションでのユーザー認証を単一のセッションで行う**シングルサインオン**機能を提供します。
5. **権利管理** – 著作権資料を保護するために、その無許可の配布および使用を規制します。
6. **DNSサービス** – **ドメイン名**の解決に重要です。

詳細な説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active\_directory)を確認してください。

### **Kerberos認証**

**ADを攻撃する方法**を学ぶには、**Kerberos認証プロセス**を非常によく**理解する**必要があります。\
[**まだその仕組みを知らない場合はこのページを読んでください。**](kerberos-authentication.md)

## チートシート

ADを列挙/悪用するために実行できるコマンドの概要を迅速に確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io)を参照してください。

## Active Directoryの偵察（クレデンシャル/セッションなし）

AD環境にアクセスできるが、クレデンシャル/セッションがない場合は、次のことができます：

* **ネットワークをペンテストする：**
* ネットワークをスキャンし、マシンやオープンポートを見つけ、**脆弱性を悪用**したり、そこから**クレデンシャルを抽出**したりします（例えば、[プリンターは非常に興味深いターゲットになる可能性があります](ad-information-in-printers.md)）。
* DNSを列挙することで、ドメイン内の主要なサーバーに関する情報を得ることができます。ウェブ、プリンター、共有、VPN、メディアなど。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* これを行う方法についての詳細は、一般的な[**ペンテスト手法**](../../generic-methodologies-and-resources/pentesting-methodology.md)を確認してください。
* **smbサービスでのnullおよびGuestアクセスを確認する**（これは最新のWindowsバージョンでは機能しません）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* SMBサーバーを列挙する方法についての詳細なガイドはここにあります：

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Ldapを列挙する**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* LDAPを列挙する方法についての詳細なガイドはここにあります（**匿名アクセスに特に注意してください**）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **ネットワークを毒する**
* [**Responderを使用してサービスを偽装してクレデンシャルを収集する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* [**リレー攻撃を悪用してホストにアクセスする**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* [**悪意のあるUPnPサービスを公開してクレデンシャルを収集する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* 内部文書、ソーシャルメディア、サービス（主にウェブ）からユーザー名/名前を抽出し、公開されている情報からも収集します。
* 会社の従業員の完全な名前を見つけた場合、さまざまなADの**ユーザー名の規則**を試すことができます（[**これを読む**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最も一般的な規則は：_NameSurname_、_Name.Surname_、_NamSur_（各3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3つの_ランダムな文字と3つのランダムな数字_（abc123）です。
* ツール：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

* **匿名SMB/LDAP列挙：** [**ペンテストSMB**](../../network-services-pentesting/pentesting-smb/)および[**ペンテストLDAP**](../../network-services-pentesting/pentesting-ldap.md)ページを確認してください。
* **Kerbrute列挙**：**無効なユーザー名が要求される**と、サーバーは**Kerberosエラー**コード_KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_を使用して応答し、ユーザー名が無効であることを判断できます。**有効なユーザー名**は、**AS-REP**応答で**TGT**を引き起こすか、エラー_KRB5KDC\_ERR\_PREAUTH\_REQUIRED_を示し、ユーザーが事前認証を行う必要があることを示します。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) サーバー**

ネットワーク内にこれらのサーバーのいずれかを見つけた場合、**ユーザー列挙を実行することもできます**。たとえば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます：
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
ユーザー名のリストは[**このGitHubリポジトリ**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\*やこのリポジトリ（[**統計的に可能性の高いユーザー名**](https://github.com/insidetrust/statistically-likely-usernames)）で見つけることができます。

ただし、これを行う前に実施したリコンステップから、**会社で働いている人々の名前**を持っている必要があります。名前と姓があれば、スクリプト[**namemash.py**](https://gist.github.com/superkojiman/11076951)を使用して、潜在的な有効なユーザー名を生成できます。
{% endhint %}

### 1つまたは複数のユーザー名を知っている場合

さて、有効なユーザー名はわかっているがパスワードがない場合... 次のことを試してみてください：

* [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT\_REQ\_PREAUTH_ を持っていない場合、そのユーザーのために**AS\_REPメッセージを要求**でき、ユーザーのパスワードの派生によって暗号化されたデータが含まれます。
* [**パスワードスプレー**](password-spraying.md): 発見した各ユーザーに対して最も**一般的なパスワード**を試してみましょう。もしかしたら、あるユーザーが悪いパスワードを使用しているかもしれません（パスワードポリシーに注意してください！）。
* OWAサーバーを**スプレー**して、ユーザーのメールサーバーへのアクセスを試みることもできます。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NSポイズニング

**ネットワーク**のいくつかのプロトコルを**ポイズニング**することで、いくつかのチャレンジ**ハッシュ**を**取得**できるかもしれません：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTMLリレー

アクティブディレクトリを列挙できた場合、**より多くのメールとネットワークの理解が得られます**。NTML [**リレー攻撃**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\*を強制してAD環境にアクセスできるかもしれません。

### NTLMクレデンシャルの盗難

**ヌルまたはゲストユーザー**で他のPCや共有に**アクセス**できる場合、**ファイルを配置**（SCFファイルなど）して、何らかの形でアクセスされると**NTML認証をトリガー**し、**NTLMチャレンジを盗む**ことができます：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 資格情報/セッションを使用したアクティブディレクトリの列挙

このフェーズでは、**有効なドメインアカウントの資格情報またはセッションを侵害している必要があります。** 有効な資格情報またはドメインユーザーとしてのシェルがある場合、**前に示したオプションは他のユーザーを侵害するためのオプションとして依然として有効です**。

認証された列挙を開始する前に、**Kerberosダブルホップ問題**が何であるかを知っておく必要があります。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 列挙

アカウントを侵害することは、**ドメイン全体を侵害するための大きなステップ**です。なぜなら、**アクティブディレクトリの列挙を開始できるからです**：

[**ASREPRoast**](asreproast.md)に関しては、今やすべての可能な脆弱なユーザーを見つけることができ、[**パスワードスプレー**](password-spraying.md)に関しては、**すべてのユーザー名のリスト**を取得し、侵害されたアカウントのパスワード、空のパスワード、新しい有望なパスワードを試すことができます。

* [**CMDを使用して基本的なリコンを実行**](../basic-cmd-for-pentesters.md#domain-info)できます。
* [**PowerShellを使用してリコン**](../basic-powershell-for-pentesters/)することもでき、よりステルス性があります。
* より詳細な情報を抽出するために[**PowerViewを使用**](../basic-powershell-for-pentesters/powerview.md)することもできます。
* アクティブディレクトリのリコンにおいてもう1つの素晴らしいツールは[**BloodHound**](bloodhound.md)です。これは**あまりステルス性がありません**（使用する収集方法によります）が、**それを気にしないのであれば**、ぜひ試してみてください。ユーザーがRDPできる場所を見つけたり、他のグループへのパスを見つけたりします。
* **他の自動化されたAD列挙ツールは：** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
* [**ADのDNSレコード**](ad-dns-records.md)は、興味深い情報を含んでいるかもしれません。
* ディレクトリを列挙するために使用できる**GUIツール**は、**SysInternal**スイートの**AdExplorer.exe**です。
* **ldapsearch**を使用してLDAPデータベース内を検索し、_userPassword_および_unixUserPassword_フィールド内の資格情報や、_Description_を探すこともできます。cf. [PayloadsAllTheThingsのADユーザーコメント内のパスワード](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)で他の方法を確認してください。
* **Linux**を使用している場合、[**pywerview**](https://github.com/the-useless-one/pywerview)を使用してドメインを列挙することもできます。
* 自動化ツールとして次のものを試すこともできます：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **すべてのドメインユーザーの抽出**

Windowsからすべてのドメインユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`または`wmic useraccount get name,sid`）。Linuxでは、次のコマンドを使用できます：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`または`enum4linux -a -u "user" -p "password" <DC IP>`

> この列挙セクションは小さく見えるかもしれませんが、これはすべての中で最も重要な部分です。リンクにアクセスし（主にcmd、powershell、powerview、BloodHoundのもの）、ドメインを列挙する方法を学び、快適に感じるまで練習してください。評価中、これはDAへの道を見つけるための重要な瞬間であり、何もできないと決定する瞬間でもあります。

### Kerberoast

Kerberoastingは、ユーザーアカウントに関連付けられたサービスによって使用される**TGSチケット**を取得し、その暗号化をクラックすることを含みます—これはユーザーパスワードに基づいており、**オフライン**で行われます。

これに関する詳細は：

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### リモート接続（RDP、SSH、FTP、Win-RMなど）

いくつかの資格情報を取得したら、**マシン**へのアクセスがあるかどうかを確認できます。そのために、**CrackMapExec**を使用して、ポートスキャンに応じて異なるプロトコルで複数のサーバーに接続を試みることができます。

### ローカル特権昇格

資格情報または通常のドメインユーザーとしてのセッションを侵害し、**ドメイン内の任意のマシンにこのユーザーでアクセス**できる場合、**ローカルで特権を昇格させ、資格情報を探す**方法を見つけるべきです。これは、ローカル管理者権限がないと、他のユーザーのハッシュをメモリ（LSASS）やローカル（SAM）で**ダンプ**できないためです。

この本には[**Windowsにおけるローカル特権昇格**](../windows-local-privilege-escalation/)に関する完全なページと[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)を使用することを忘れないでください。

### 現在のセッションチケット

**予期しないリソースにアクセスするための許可を与える**チケットを現在のユーザーが見つけることは非常に**ありそうにありません**が、確認することができます：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

もしアクティブディレクトリを列挙できたなら、**より多くのメールとネットワークの理解を得ることができるでしょう**。NTML [**リレー攻撃**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制することができるかもしれません。**

### **コンピュータ共有内のクレデンシャルを探す**

基本的なクレデンシャルを持っているので、**AD内で共有されている興味深いファイルを見つけることができるか確認するべきです**。手動で行うこともできますが、非常に退屈で繰り返しの作業です（特に確認する必要がある文書が何百も見つかった場合はなおさらです）。

[**使用できるツールについて学ぶにはこのリンクをフォローしてください。**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### NTLMクレデンシャルを盗む

他のPCや共有に**アクセスできる場合**、**ファイル**（SCFファイルなど）を**配置することができ**、それにアクセスされると**NTML認証があなたに対してトリガーされる**ので、**NTLMチャレンジを盗む**ことができます：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証された任意のユーザーが**ドメインコントローラーを侵害する**ことができました。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 特権クレデンシャル/セッションを使用したアクティブディレクトリの特権昇格

**以下の技術には、通常のドメインユーザーでは不十分で、これらの攻撃を実行するためには特別な特権/クレデンシャルが必要です。**

### ハッシュ抽出

幸運にも、[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を含むリレー、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの特権昇格](../windows-local-privilege-escalation/)を使用して**ローカル管理者**アカウントを**侵害することができた**ことを願っています。\
次に、メモリとローカルのすべてのハッシュをダンプする時です。\
[**ハッシュを取得するためのさまざまな方法についてこのページを読んでください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### パス・ザ・ハッシュ

**ユーザーのハッシュを持っている場合**、それを使用して**なりすます**ことができます。\
その**ハッシュ**を使用して**NTLM認証を実行する**ための**ツール**を使用する必要があります。**または**、新しい**sessionlogon**を作成し、その**ハッシュ**を**LSASS**内に**注入**することができます。そうすれば、任意の**NTLM認証が実行されると**、その**ハッシュが使用されます**。最後のオプションはmimikatzが行うことです。\
[**詳細についてはこのページを読んでください。**](../ntlm/#pass-the-hash)

### オーバーパス・ザ・ハッシュ/パス・ザ・キー

この攻撃は、**ユーザーのNTLMハッシュを使用してKerberosチケットを要求する**ことを目的としています。これは、一般的なNTLMプロトコルを介したパス・ザ・ハッシュの代替手段です。したがって、これは特に**NTLMプロトコルが無効にされているネットワーク**で、**Kerberosのみが認証プロトコルとして許可されている**場合に**特に有用です**。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### パス・ザ・チケット

**パス・ザ・チケット（PTT）**攻撃手法では、攻撃者は**ユーザーの認証チケットを盗む**代わりに、パスワードやハッシュ値を盗みます。この盗まれたチケットは、その後**ユーザーになりすます**ために使用され、ネットワーク内のリソースやサービスへの不正アクセスを得ることができます。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### クレデンシャルの再利用

**ローカル管理者のハッシュ**または**パスワード**を持っている場合は、それを使用して他の**PCにローカルでログイン**しようとするべきです。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
このことは非常に**騒がしい**ものであり、**LAPS**が**軽減**します。
{% endhint %}

### MSSQLの悪用と信頼されたリンク

ユーザーが**MSSQLインスタンスにアクセスする権限**を持っている場合、MSSQLホストで**コマンドを実行**したり（SAとして実行されている場合）、NetNTLMの**ハッシュ**を**盗む**ことができたり、さらには**リレー攻撃**を行うことができるかもしれません。\
また、MSSQLインスタンスが別のMSSQLインスタンスによって信頼されている場合、信頼されたデータベースに対する権限を持つユーザーは、**信頼関係を利用して他のインスタンスでもクエリを実行**できるようになります。これらの信頼は連鎖することができ、ユーザーはコマンドを実行できる誤って構成されたデータベースを見つけることができるかもしれません。\
**データベース間のリンクは、フォレストの信頼を越えても機能します。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 制約のない委任

[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)属性を持つコンピュータオブジェクトを見つけ、コンピュータにドメイン権限がある場合、コンピュータにログインするすべてのユーザーのメモリからTGTをダンプすることができます。\
したがって、**ドメイン管理者がコンピュータにログインすると**、そのTGTをダンプして[Pass the Ticket](pass-the-ticket.md)を使用して彼を偽装することができます。\
制約のある委任のおかげで、**プリントサーバーを自動的に侵害する**ことさえ可能です（できればDCであることを願っています）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 制約された委任

ユーザーまたはコンピュータが「制約された委任」を許可されている場合、**コンピュータ内のいくつかのサービスにアクセスするために任意のユーザーを偽装**することができます。\
その後、**このユーザー/コンピュータのハッシュを侵害**すると、**任意のユーザー**（ドメイン管理者を含む）を偽装していくつかのサービスにアクセスすることができます。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### リソースベースの制約された委任

リモートコンピュータのActive Directoryオブジェクトに対する**WRITE**権限を持つことで、**昇格された権限**でのコード実行が可能になります：

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACLの悪用

侵害されたユーザーは、**ドメインオブジェクトのいくつかに対して興味深い権限**を持っている可能性があり、それにより**横移動**や**権限の昇格**が可能になります。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### プリンタースプーラーサービスの悪用

ドメイン内で**スプールサービスがリッスンしている**ことを発見することは、**新しい資格情報を取得**し、**権限を昇格**させるために**悪用**される可能性があります。

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 第三者セッションの悪用

**他のユーザー**が**侵害された**マシンに**アクセス**すると、メモリから**資格情報を収集**し、彼らのプロセスに**ビーコンを注入**して彼らを偽装することが可能です。\
通常、ユーザーはRDPを介してシステムにアクセスするため、ここでは第三者のRDPセッションに対していくつかの攻撃を実行する方法を示します：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**は、ドメインに参加しているコンピュータ上の**ローカル管理者パスワード**を管理するためのシステムを提供し、それが**ランダム化**され、ユニークで、頻繁に**変更**されることを保証します。これらのパスワードはActive Directoryに保存され、アクセスはACLを通じて認可されたユーザーのみに制御されます。これらのパスワードにアクセスするための十分な権限があれば、他のコンピュータにピボットすることが可能になります。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 証明書の盗難

**侵害されたマシンから証明書を収集**することは、環境内で権限を昇格させる方法となる可能性があります：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 証明書テンプレートの悪用

**脆弱なテンプレート**が構成されている場合、それを悪用して権限を昇格させることが可能です：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 高権限アカウントによるポストエクスプロイト

### ドメイン資格情報のダンプ

**ドメイン管理者**またはさらに良い**エンタープライズ管理者**の権限を取得すると、**ドメインデータベース**を**ダンプ**できます：_ntds.dit_。

[**DCSync攻撃に関する詳細情報はここにあります**](dcsync.md)。

[**NTDS.ditを盗む方法に関する詳細情報はここにあります**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 権限昇格としての持続性

前述のいくつかの技術は持続性に使用できます。\
例えば、次のことができます：

*   ユーザーを[**Kerberoast**](kerberoast.md)に対して脆弱にする

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   ユーザーを[**ASREPRoast**](asreproast.md)に対して脆弱にする

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   ユーザーに[**DCSync**](./#dcsync)権限を付与する

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### シルバーチケット

**シルバーチケット攻撃**は、特定のサービスのために**正当なチケット授与サービス（TGS）チケット**を**NTLMハッシュ**を使用して作成します（例えば、**PCアカウントのハッシュ**）。この方法は、**サービス権限にアクセス**するために使用されます。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### ゴールデンチケット

**ゴールデンチケット攻撃**は、攻撃者がActive Directory（AD）環境内の**krbtgtアカウントのNTLMハッシュ**にアクセスすることを含みます。このアカウントは特別で、すべての**チケット授与チケット（TGT）**に署名するために使用され、ADネットワーク内での認証に不可欠です。

攻撃者がこのハッシュを取得すると、任意のアカウントのために**TGT**を作成することができます（シルバーチケット攻撃）。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### ダイヤモンドチケット

これらは、**一般的なゴールデンチケット検出メカニズムを回避する方法で偽造されたゴールデンチケット**のようなものです。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **証明書アカウントの持続性**

**アカウントの証明書を持っているか、要求できること**は、ユーザーアカウントに持続するための非常に良い方法です（たとえ彼がパスワードを変更しても）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **証明書ドメインの持続性**

**証明書を使用することは、ドメイン内で高い権限を持続することも可能です：**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolderグループ

Active Directoryの**AdminSDHolder**オブジェクトは、**特権グループ**（ドメイン管理者やエンタープライズ管理者など）のセキュリティを確保するために、これらのグループ全体に標準の**アクセス制御リスト（ACL）**を適用し、無許可の変更を防ぎます。しかし、この機能は悪用される可能性があります。攻撃者がAdminSDHolderのACLを変更して通常のユーザーに完全なアクセスを与えると、そのユーザーはすべての特権グループに対して広範な制御を得ることになります。このセキュリティ対策は保護を目的としていますが、厳重に監視されない限り、不当なアクセスを許すことになります。

[**AdminDSHolderグループに関する詳細情報はここにあります。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM資格情報

すべての**ドメインコントローラー（DC）**内には、**ローカル管理者**アカウントが存在します。このようなマシンで管理者権限を取得することで、**mimikatz**を使用してローカル管理者ハッシュを抽出できます。その後、このパスワードを**使用できるようにするためのレジストリ変更**が必要で、ローカル管理者アカウントへのリモートアクセスを可能にします。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL持続性

特定のドメインオブジェクトに対して**ユーザーに特別な権限**を**与える**ことで、そのユーザーが将来的に**権限を昇格**させることができるようになります。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### セキュリティ記述子

**セキュリティ記述子**は、**オブジェクト**が**オブジェクト**に対して持つ**権限**を**保存**するために使用されます。オブジェクトの**セキュリティ記述子**に**少しの変更**を加えることができれば、そのオブジェクトに対して特権グループのメンバーである必要なく、非常に興味深い権限を取得できます。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### スケルトンキー

**LSASS**をメモリ内で変更して、すべてのドメインアカウントにアクセスを許可する**ユニバーサルパスワード**を確立します。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### カスタムSSP

[SSP（セキュリティサポートプロバイダー）とは何かをここで学びます。](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
自分の**SSP**を作成して、マシンにアクセスするために使用される**資格情報**を**平文**で**キャプチャ**することができます。\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

ADに**新しいドメインコントローラー**を登録し、指定されたオブジェクトに**属性**（SIDHistory、SPNsなど）を**プッシュ**するために使用しますが、**変更**に関する**ログ**を残さずに行います。**DA**権限が必要で、**ルートドメイン**内にいる必要があります。\
間違ったデータを使用すると、非常に醜いログが表示されることに注意してください。

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS持続性

以前に、**LAPSパスワードを読み取るための十分な権限がある場合に権限を昇格させる方法**について説明しました。しかし、これらのパスワードは**持続性を維持するためにも使用**できます。\
確認してください：

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## フォレスト権限昇格 - ドメイン信頼

Microsoftは**フォレスト**をセキュリティ境界と見なしています。これは、**単一のドメインを侵害することが、フォレスト全体の侵害につながる可能性がある**ことを意味します。

### 基本情報

[**ドメイン信頼**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx)は、ある**ドメイン**のユーザーが別の**ドメイン**のリソースにアクセスできるようにするセキュリティメカニズムです。これは、2つのドメインの認証システム間にリンクを作成し、認証確認がシームレスに流れることを可能にします。ドメインが信頼を設定すると、特定の**キー**を**ドメインコントローラー（DC）**内で交換し保持します。これは信頼の整合性にとって重要です。

典型的なシナリオでは、ユーザーが**信頼されたドメイン**のサービスにアクセスしようとする場合、まず自分のドメインのDCから**インターレルムTGT**と呼ばれる特別なチケットを要求する必要があります。このTGTは、両方のドメインが合意した共有**キー**で暗号化されています。ユーザーはこのTGTを**信頼されたドメインのDC**に提示してサービスチケット（**TGS**）を取得します。信頼されたドメインのDCによってインターレルムTGTが正常に検証されると、TGSが発行され、ユーザーはサービスにアクセスできるようになります。

**手順**：

1. **ドメイン1**の**クライアントコンピュータ**が、**ドメインコントローラー（DC1）**から**チケット授与チケット（TGT）**を要求するプロセスを開始します。
2. クライアントが正常に認証されると、DC1は新しいTGTを発行します。
3. クライアントは、**ドメイン2**のリソースにアクセスするために必要な**インターレルムTGT**をDC1に要求します。
4. インターレルムTGTは、DC1とDC2の間で共有された**信頼キー**で暗号化されています。
5. クライアントはインターレルムTGTを**ドメイン2のドメインコントローラー（DC2）**に持っていきます。
6. DC2は、共有された信頼キーを使用してインターレルムTGTを検証し、有効な場合、クライアントがアクセスしたいドメイン2のサーバーのための**チケット授与サービス（TGS）**を発行します。
7. 最後に、クライアントはこのTGSをサーバーに提示し、サーバーのアカウントハッシュで暗号化されているため、ドメイン2のサービスにアクセスします。

### 異なる信頼

**信頼は1方向または2方向**であることに注意することが重要です。2方向のオプションでは、両方のドメインが互いに信頼しますが、**1方向**の信頼関係では、一方のドメインが**信頼された**ドメインで、もう一方が**信頼する**ドメインになります。この場合、**信頼されたドメインから信頼するドメイン内のリソースにのみアクセスできる**ことになります。

ドメインAがドメインBを信頼している場合、Aは信頼するドメインで、Bは信頼されたドメインです。さらに、**ドメインA**では、これは**アウトバウンド信頼**となり、**ドメインB**では、これは**インバウンド信頼**となります。

**異なる信頼関係**

* **親子信頼**：これは、同じフォレスト内で一般的な設定であり、子ドメインは自動的に親ドメインとの双方向の推移的信頼を持ちます。基本的に、これは認証要求が親と子の間でシームレスに流れることを意味します。
* **クロスリンク信頼**：これは「ショートカット信頼」と呼ばれ、子ドメイン間で確立され、参照プロセスを迅速化します。複雑なフォレストでは、認証参照は通常、フォレストのルートまで上昇し、ターゲットドメインまで下降する必要があります。クロスリンクを作成することで、旅が短縮され、特に地理的に分散した環境で有益です。
* **外部信頼**：これは異なる無関係なドメイン間で設定され、非推移的です。Microsoftの文書によると、外部信頼は、現在のフォレスト外のドメインのリソースにアクセスするために役立ちます。これは、フォレスト信頼によって接続されていないドメインです。外部信頼では、SIDフィルタリングを通じてセキュリティが強化されます。
* **ツリーのルート信頼**：これらの信頼は、フォレストのルートドメインと新しく追加されたツリーのルート間で自動的に確立されます。一般的には遭遇しませんが、ツリーのルート信頼は、フォレストに新しいドメインツリーを追加するために重要であり、ユニークなドメイン名を維持し、双方向の推移性を確保します。詳細情報はMicrosoftのガイドで確認できます。
* **フォレスト信頼**：このタイプの信頼は、2つのフォレストルートドメイン間の双方向推移的信頼であり、セキュリティ対策を強化するためにSIDフィルタリングを強制します。
* **MIT信頼**：これらの信頼は、非WindowsのRFC4120準拠のKerberosドメインとの間で確立されます。MIT信頼は、Windowsエコシステムの外部でKerberosベースのシステムとの統合を必要とする環境に特化しています。

#### **信頼関係の他の違い**

* 信頼関係は**推移的**（AがBを信頼し、BがCを信頼する場合、AはCを信頼する）または**非推移的**であることがあります。
* 信頼関係は**双方向信頼**（両方が互いに信頼する）または**一方向信頼**（一方だけが他方を信頼する）として設定できます。

### 攻撃パス

1. **信頼関係を列挙**する
2. どの**セキュリティプリンシパル**（ユーザー/グループ/コンピュータ）が**他のドメインのリソースにアクセス**できるかを確認します。ACEエントリや他のドメインのグループにいることによって。**ドメイン間の関係**を探します（このために信頼が作成された可能性があります）。
1. この場合、kerberoastが別のオプションになる可能性があります。
3. **アカウントを侵害**し、ドメインを**ピボット**することができます。

攻撃者は、他のドメインのリソースにアクセスするために、主に3つのメカニズムを使用できます：

* **ローカルグループメンバーシップ**：プリンシパルは、サーバーの「Administrators」グループなど、マシンのローカルグループに追加されることがあり、そのマシンに対して重要な制御を与えます。
* **外国ドメイングループメンバーシップ**：プリンシパルは、外国ドメイン内のグループのメンバーでもあります。ただし、この方法の効果は、信頼の性質とグループの範囲に依存します。
* **アクセス制御リスト（ACL）**：プリンシパルは、特定のリソースへのアクセスを提供する**ACL**、特に**DACL**内の**ACE**のエンティティとして指定されることがあります。ACL、DACL、およびACEのメカニズムに深く入りたい方には、ホワイトペーパー「[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)」が貴重なリソースです。

### 子から親へのフォレスト権限昇格
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
**2つの信頼されたキー**があります。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
現在のドメインで使用されているものを次のコマンドで確認できます：
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

エンタープライズ管理者として、SID-Historyインジェクションを悪用して子/親ドメインに昇格します：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 書き込み可能な構成NCの悪用

構成命名コンテキスト（NC）がどのように悪用されるかを理解することは重要です。構成NCは、Active Directory（AD）環境内のフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべてのドメインコントローラー（DC）に複製され、書き込み可能なDCは構成NCの書き込み可能なコピーを保持します。これを悪用するには、**DC上でSYSTEM権限を持つ必要があります**。できれば子DCが望ましいです。

**GPOをルートDCサイトにリンクする**

構成NCのサイトコンテナには、ADフォレスト内のすべてのドメイン参加コンピュータのサイトに関する情報が含まれています。任意のDCでSYSTEM権限を持って操作することで、攻撃者はGPOをルートDCサイトにリンクできます。このアクションは、これらのサイトに適用されるポリシーを操作することによって、ルートドメインを危険にさらす可能性があります。

詳細情報については、[SIDフィルタリングのバイパス](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)に関する研究を探ることができます。

**フォレスト内の任意のgMSAを危険にさらす**

攻撃ベクトルは、ドメイン内の特権gMSAをターゲットにすることです。gMSAのパスワードを計算するために必要なKDSルートキーは、構成NC内に保存されています。任意のDCでSYSTEM権限を持つことで、KDSルートキーにアクセスし、フォレスト内の任意のgMSAのパスワードを計算することが可能です。

詳細な分析は、[ゴールデンgMSA信頼攻撃](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)に関する議論で見つけることができます。

**スキーマ変更攻撃**

この方法は、新しい特権ADオブジェクトの作成を待つ忍耐が必要です。SYSTEM権限を持つ攻撃者は、ADスキーマを変更して任意のユーザーにすべてのクラスに対する完全な制御を付与できます。これにより、新しく作成されたADオブジェクトへの不正アクセスと制御が可能になる可能性があります。

さらなる読み物は、[スキーマ変更信頼攻撃](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)で利用できます。

**ADCS ESC5を使用してDAからEAへ**

ADCS ESC5の脆弱性は、フォレスト内の任意のユーザーとして認証を可能にする証明書テンプレートを作成するために、公開鍵基盤（PKI）オブジェクトの制御をターゲットにしています。PKIオブジェクトは構成NCに存在するため、書き込み可能な子DCを危険にさらすことでESC5攻撃を実行できます。

これに関する詳細は、[ESC5を使用してDAからEAへ](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)で読むことができます。ADCSがないシナリオでは、攻撃者は必要なコンポーネントを設定する能力を持っており、[子ドメイン管理者からエンタープライズ管理者への昇格](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)で議論されています。

### 外部フォレストドメイン - 一方向（インバウンド）または双方向
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
このシナリオでは、**あなたのドメインが外部のドメインによって信頼されています**。これにより、**不明な権限**が与えられます。あなたは、**あなたのドメインのどのプリンシパルが外部ドメインに対してどのようなアクセス権を持っているかを見つけ**、それを悪用しようとする必要があります。

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### 外部フォレストドメイン - 一方向（アウトバウンド）
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
このシナリオでは、**あなたのドメイン**が**異なるドメイン**のプリンシパルに**特権**を**信頼**しています。

しかし、**ドメインが信頼される**と、信頼されたドメインは**予測可能な名前**の**ユーザーを作成**し、**信頼されたパスワード**を**パスワード**として使用します。これは、**信頼するドメインのユーザーにアクセスして信頼されたドメインに入る**ことが可能であり、そこから列挙してさらに特権を昇格させることができることを意味します。

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

信頼されたドメインを侵害する別の方法は、ドメイン信頼の**逆方向**に作成された[**SQL信頼リンク**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これはあまり一般的ではありません）。

信頼されたドメインを侵害する別の方法は、**信頼されたドメインのユーザーがアクセスできる**マシンで待機し、**RDP**を介してログインすることです。次に、攻撃者はRDPセッションプロセスにコードを注入し、そこから**被害者の元のドメインにアクセス**できます。\
さらに、**被害者がハードドライブをマウントしている場合**、RDPセッションプロセスから攻撃者は**ハードドライブのスタートアップフォルダーにバックドアを保存**できます。この技術は**RDPInception**と呼ばれます。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### ドメイン信頼の悪用緩和

### **SIDフィルタリング:**

* フォレスト信頼におけるSID履歴属性を利用した攻撃のリスクは、SIDフィルタリングによって軽減され、これはすべてのインターフォレスト信頼でデフォルトで有効になっています。これは、マイクロソフトの立場に従い、フォレストをセキュリティ境界と見なすことから成り立っています。
* しかし、注意点があります：SIDフィルタリングはアプリケーションやユーザーアクセスに影響を与える可能性があり、そのため時折無効にされることがあります。

### **選択的認証:**

* インターフォレスト信頼に対して、選択的認証を使用することで、2つのフォレストのユーザーが自動的に認証されないようにします。代わりに、信頼するドメインまたはフォレスト内のドメインやサーバーにアクセスするためには明示的な権限が必要です。
* これらの対策は、書き込み可能な構成名コンテキスト（NC）の悪用や信頼アカウントへの攻撃から保護するものではないことに注意が必要です。

[**ドメイン信頼に関する詳細情報はired.teamで。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一般的な防御策

[**ここで資格情報を保護する方法について詳しく学ぶ。**](../stealing-credentials/credentials-protections.md)\\

### **資格情報保護のための防御策**

* **ドメイン管理者の制限**: ドメイン管理者はドメインコントローラーにのみログインを許可し、他のホストでの使用を避けることが推奨されます。
* **サービスアカウントの特権**: サービスはセキュリティを維持するためにドメイン管理者（DA）特権で実行されるべきではありません。
* **一時的特権制限**: DA特権を必要とするタスクについては、その期間を制限するべきです。これは次のように実現できます：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **欺瞞技術の実装**

* 欺瞞を実装するには、パスワードが期限切れにならないか、委任のために信頼されているとマークされたデコイユーザーやコンピュータのような罠を設定します。詳細なアプローチには、特定の権利を持つユーザーを作成したり、高特権グループに追加したりすることが含まれます。
* 実用的な例として、次のようなツールを使用します：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* 欺瞞技術の展開に関する詳細は、[Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)で見つけることができます。

### **欺瞞の特定**

* **ユーザーオブジェクトの場合**: 疑わしい指標には、異常なObjectSID、頻繁でないログオン、作成日、低い不正パスワードカウントが含まれます。
* **一般的な指標**: 潜在的なデコイオブジェクトの属性を本物のものと比較することで不一致が明らかになることがあります。ツールのような[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)は、そのような欺瞞を特定するのに役立ちます。

### **検出システムの回避**

* **Microsoft ATA検出回避**:
* **ユーザー列挙**: ドメインコントローラーでのセッション列挙を避け、ATA検出を防ぎます。
* **チケットの偽装**: チケット作成に**aes**キーを使用することで、NTLMにダウングレードせずに検出を回避します。
* **DCSync攻撃**: ATA検出を避けるために、ドメインコントローラーから直接実行するのではなく、非ドメインコントローラーから実行することが推奨されます。

## 参考文献

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**してください 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}
