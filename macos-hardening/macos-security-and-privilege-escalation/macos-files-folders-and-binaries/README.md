# macOS ファイル、フォルダ、バイナリ＆メモリ

{% hint style="success" %}
AWSハッキングの学習と実践：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}

## ファイル階層レイアウト

* **/Applications**: インストールされたアプリはここにあります。すべてのユーザがアクセスできます。
* **/bin**: コマンドラインバイナリ
* **/cores**: 存在する場合、コアダンプを保存するために使用されます
* **/dev**: すべてがファイルとして扱われるため、ここにハードウェアデバイスが保存されていることがあります。
* **/etc**: 設定ファイル
* **/Library**: 好み、キャッシュ、ログに関連する多くのサブディレクトリとファイルがここに見つかります。ルートと各ユーザのディレクトリにLibraryフォルダが存在します。
* **/private**: 文書化されていませんが、言及されている多くのフォルダはprivateディレクトリへのシンボリックリンクです。
* **/sbin**: システムの重要なバイナリ（管理に関連する）
* **/System**: OS Xを実行するためのファイル。ここには主にApple固有のファイルのみがあります（サードパーティ製ではありません）。
* **/tmp**: ファイルは3日後に削除されます（/private/tmpへのソフトリンクです）
* **/Users**: ユーザーのホームディレクトリ。
* **/usr**: 構成とシステムバイナリ
* **/var**: ログファイル
* **/Volumes**: マウントされたドライブはここに表示されます。
* **/.vol**: `stat a.txt`を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...`のようなものが得られます。最初の数値はファイルが存在するボリュームのID番号であり、2番目の数値はinode番号です。この情報を使用して、`cat /.vol/16777223/7545753`を実行してこのファイルの内容にアクセスできます。

### アプリケーションフォルダ

* **システムアプリケーション**は`/System/Applications`にあります。
* **インストールされた**アプリケーションは通常、`/Applications`または`~/Applications`にインストールされます。
* **アプリケーションデータ**は、ルートとして実行されるアプリケーションの場合は`/Library/Application Support`、ユーザーとして実行されるアプリケーションの場合は`~/Library/Application Support`にあります。
* **ルートとして実行する必要がある**サードパーティアプリケーションの**デーモン**は通常`/Library/PrivilegedHelperTools/`にあります。
* **サンドボックス化された**アプリケーションは`~/Library/Containers`フォルダにマップされます。各アプリには、アプリケーションのバンドルIDに従って名前が付けられたフォルダがあります（`com.apple.Safari`）。
* **カーネル**は`/System/Library/Kernels/kernel`にあります。
* **Appleのカーネル拡張**は`/System/Library/Extensions`にあります。
* **サードパーティのカーネル拡張**は`/Library/Extensions`に保存されます。

### 機密情報を含むファイル

MacOSは、パスワードなどの情報をいくつかの場所に保存します：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 脆弱なpkgインストーラ

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X固有の拡張子

* **`.dmg`**: Apple Disk Imageファイルはインストーラーで非常に頻繁に使用されます。
* **`.kext`**: 特定の構造に従う必要があり、ドライバーのOS Xバージョンです（バンドルです）。
* **`.plist`**: プロパティリストとしても知られ、情報をXMLまたはバイナリ形式で保存します。
* XMLまたはバイナリになります。バイナリの場合は次のように読み取れます：
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: ディレクトリ構造に従うAppleアプリケーション（バンドル）です。
* **`.dylib`**: ダイナミックライブラリ（WindowsのDLLファイルのようなもの）
* **`.pkg`**: xar（eXtensible Archive形式）と同じです。これらのファイルの内容をインストールするには、installerコマンドを使用できます。
* **`.DS_Store`**: このファイルは各ディレクトリにあり、ディレクトリの属性とカスタマイズを保存します。
* **`.Spotlight-V100`**: このフォルダはシステムのすべてのボリュームのルートディレクトリに表示されます。
* **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlightはそのボリュームをインデックスしません。
* **`.noindex`**: この拡張子を持つファイルやフォルダはSpotlightによってインデックスされません。
* **`.sdef`**: AppleScriptからアプリケーションとのやり取りが可能であるかどうかを指定するバンドル内のファイル。

### macOSバンドル

バンドルは、Finderのオブジェクトのように見える**ディレクトリ**です（バンドルの例は`*.app`ファイルです）。

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld共有ライブラリキャッシュ（SLC）

macOS（およびiOS）では、フレームワークやdylibなどのすべてのシステム共有ライブラリが1つのファイルに結合され、**dyld共有キャッシュ**と呼ばれます。これにより、コードを高速に読み込むことができ、パフォーマンスが向上します。

これはmacOSでは`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`にあり、古いバージョンでは**共有キャッシュ**を**`/System/Library/dyld/`**に見つけることができるかもしれません。\
iOSでは、これらを**`/System/Library/Caches/com.apple.dyld/`**に見つけることができます。

dyld共有キャッシュと同様に、カーネルとカーネル拡張もカーネルキャッシュにコンパイルされ、起動時にロードされます。

単一ファイルdylib共有キャッシュからライブラリを抽出するために、以前はバイナリ[dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)を使用できましたが、現在は機能しないかもしれませんが、[**dyldextractor**](https://github.com/arandomdev/dyldextractor)を使用することもできます：

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

{% hint style="success" %}
`dyld_shared_cache_util` ツールが機能しなくても、**共有 dyld バイナリを Hopper に渡す**ことで、Hopper がすべてのライブラリを識別し、調査したいものを**選択**できます。
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

一部のエクストラクタは、dylibs がハードコードされたアドレスで prelink されているため、動作しない場合があり、そのため、未知のアドレスにジャンプする可能性があります。

{% hint style="success" %}
Xcode のエミュレータを使用して、macOS の他の \*OS デバイスの Shared Library Cache をダウンロードすることも可能です。これらは次の場所にダウンロードされます：`$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`、例：`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### SLC のマッピング

**`dyld`** は、SLC がマップされたかどうかを知るためにシスコール **`shared_region_check_np`** を使用し（アドレスを返す）、SLC をマップするために **`shared_region_map_and_slide_np`** を使用します。

SLC が最初に使用されるとスライドされていても、すべての**プロセス**が**同じコピー**を使用するため、攻撃者がシステム内でプロセスを実行できた場合、ASLR 保護が**無効化**されます。これは実際に過去に悪用され、共有リージョンページャで修正されました。

ブランチプールは、イメージマッピング間に小さなスペースを作成する小さな Mach-O dylibs であり、関数を介入不可能にします。

### SLC のオーバーライド

環境変数を使用して：

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> これにより、新しい共有ライブラリキャッシュをロードできます
* **`DYLD_SHARED_CACHE_DIR=avoid`** およびライブラリを実際のものにシンボリックリンクで置き換える（これらを抽出する必要があります）

## 特別なファイル権限

### フォルダの権限

**フォルダ**において、**読み取り**は**リスト化**を可能にし、**書き込み**は**削除**および**ファイルの書き込み**を可能にし、**実行**は**ディレクトリをトラバース**することを可能にします。したがって、たとえば、ユーザーが**実行権限を持たない**ディレクトリ内のファイルに**読み取り権限**を持っている場合、そのユーザーはファイルを**読むことができません**。

### フラグ修飾子

ファイルに設定されるいくつかのフラグがあり、ファイルの動作を異なるものにします。`ls -lO /path/directory` でディレクトリ内のファイルのフラグを確認できます。

* **`uchg`**：**uchange** フラグとして知られ、**ファイルの変更や削除を防止**します。これを設定するには：`chflags uchg file.txt`
* ルートユーザーは**フラグを削除**してファイルを変更できます
* **`restricted`**：このフラグはファイルを **SIP で保護**します（このフラグをファイルに追加することはできません）。
* **`Sticky bit`**：スティッキービットが設定されたディレクトリの場合、**ディレクトリの所有者または root のみがファイルの名前を変更したり削除したり**できます。通常、これは /tmp ディレクトリに設定され、通常のユーザーが他のユーザーのファイルを削除したり移動したりするのを防ぎます。

すべてのフラグはファイル `sys/stat.h` に見つけることができ（`mdfind stat.h | grep stat.h` を使用して検索します）、次のとおりです：

* `UF_SETTABLE` 0x0000ffff: オーナー変更可能フラグのマスク。
* `UF_NODUMP` 0x00000001: ファイルをダンプしない。
* `UF_IMMUTABLE` 0x00000002: ファイルを変更できません。
* `UF_APPEND` 0x00000004: ファイルへの書き込みは追記のみ可能です。
* `UF_OPAQUE` 0x00000008: ディレクトリは union に対して不透明です。
* `UF_COMPRESSED` 0x00000020: ファイルは圧縮されています（一部のファイルシステム）。
* `UF_TRACKED` 0x00000040: これが設定されているファイルの削除/名前変更に対する通知はありません。
* `UF_DATAVAULT` 0x00000080: 読み取りおよび書き込みには権限が必要です。
* `UF_HIDDEN` 0x00008000: このアイテムは GUI に表示されないべきであることのヒント。
* `SF_SUPPORTED` 0x009f0000: スーパーユーザーがサポートするフラグのマスク。
* `SF_SETTABLE` 0x3fff0000: スーパーユーザーが変更可能なフラグのマスク。
* `SF_SYNTHETIC` 0xc0000000: システム読み取り専用合成フラグのマスク。
* `SF_ARCHIVED` 0x00010000: ファイルがアーカイブされています。
* `SF_IMMUTABLE` 0x00020000: ファイルを変更できません。
* `SF_APPEND` 0x00040000: ファイルへの書き込みは追記のみ可能です。
* `SF_RESTRICTED` 0x00080000: 書き込みには権限が必要です。
* `SF_NOUNLINK` 0x00100000: アイテムは削除、名前変更、またはマウントできません。
* `SF_FIRMLINK` 0x00800000: ファイルは firmlink です。
* `SF_DATALESS` 0x40000000: ファイルはデータレスオブジェクトです。

### **ファイル ACL**

ファイルの **ACL** には、異なるユーザーによってより **細かい権限** が割り当てられる **ACE**（アクセス制御エントリ）が含まれています。

これらの権限をディレクトリに付与することが可能です：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
およびファイルに対して：`read`、`write`、`append`、`execute`。

ファイルに ACL が含まれている場合、**アクセス許可をリスト表示する際に** `+` が見つかります。
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
ファイルのACLを次のようにして読むことができます：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
次のコマンドを使用して、**すべてのACLを持つファイルを見つけることができます**（これは非常に遅いです）:
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 拡張属性

拡張属性には名前と任意の値があり、`ls -@`を使用して表示し、`xattr`コマンドを使用して操作できます。一般的な拡張属性には次のものがあります:

- `com.apple.resourceFork`: リソースフォークの互換性。`filename/..namedfork/rsrc`としても表示されます
- `com.apple.quarantine`: MacOS: Gatekeeperの隔離メカニズム (III/6)
- `metadata:*`: MacOS: `_backup_excludeItem`や`kMD*`などのさまざまなメタデータ
- `com.apple.lastuseddate` (#PS): 最終ファイル使用日
- `com.apple.FinderInfo`: MacOS: ファインダー情報 (例: カラータグ)
- `com.apple.TextEncoding`: ASCIIテキストファイルのテキストエンコーディングを指定します
- `com.apple.logd.metadata`: `/var/db/diagnostics`内のファイルでlogdによって使用されます
- `com.apple.genstore.*`: 世代ストレージ (`/.DocumentRevisions-V100`はファイルシステムのルートにあります)
- `com.apple.rootless`: MacOS: システムインテグリティ保護によってファイルにラベル付けされます (III/10)
- `com.apple.uuidb.boot-uuid`: ブートエポックのlogdマーキングと一意のUUID
- `com.apple.decmpfs`: MacOS: 透過的なファイル圧縮 (II/7)
- `com.apple.cprotect`: \*OS: ファイルごとの暗号化データ (III/11)
- `com.apple.installd.*`: \*OS: installdによって使用されるメタデータ、例: `installType`、`uniqueInstallID`

### リソースフォーク | macOS ADS

これは**MacOS**マシンで**Alternate Data Streams**を取得する方法です。ファイル内の**com.apple.ResourceFork**という拡張属性にコンテンツを保存することができます。保存する場合は**file/..namedfork/rsrc**に保存します。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
次のコマンドを使用して、この拡張属性を含むすべてのファイルを見つけることができます：

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

### decmpfs

拡張属性`com.apple.decmpfs`はファイルが暗号化されて保存されていることを示します。`ls -l`は**サイズが0**と報告し、圧縮されたデータはこの属性の中にあります。ファイルにアクセスするたびに、メモリ内で復号化されます。

この属性は`ls -lO`で見ることができ、圧縮されたものは`UF_COMPRESSED`フラグでタグ付けされています。圧縮されたファイルが削除されると、`chflags nocompressed </path/to/file>`でこのフラグを削除すると、システムはファイルが圧縮されていたことを知らなくなり、データにアクセスできなくなります（実際には空であると思います）。

ツール`afscexpand`を使用してファイルを強制的に展開することができます。

## **Universal binaries &** Mach-o Format

Mac OSのバイナリは通常、**universal binaries**としてコンパイルされます。**Universal binary**は**同じファイル内で複数のアーキテクチャをサポート**できます。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS プロセスメモリ

## macOS メモリダンピング

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## リスクカテゴリファイル Mac OS

ディレクトリ`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`には、異なるファイル拡張子に関連する**リスクに関する情報**が格納されています。このディレクトリはファイルをさまざまなリスクレベルに分類し、Safariがこれらのファイルをダウンロード後にどのように処理するかに影響を与えます。カテゴリは次のとおりです：

* **LSRiskCategorySafe**：このカテゴリのファイルは**完全に安全**と見なされます。Safariはこれらのファイルを自動的にダウンロード後に開きます。
* **LSRiskCategoryNeutral**：これらのファイルには警告がなく、Safariによって**自動的に開かれません**。
* **LSRiskCategoryUnsafeExecutable**：このカテゴリのファイルは、そのファイルがアプリケーションであることを示す**警告をトリガー**します。これはユーザーに警告するセキュリティ対策となります。
* **LSRiskCategoryMayContainUnsafeExecutable**：このカテゴリは、アーカイブなどの実行可能ファイルを含む可能性があるファイル用です。Safariは、すべての内容が安全または中立であることを検証できない限り、**警告をトリガー**します。

## ログファイル

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：ダウンロードされたファイルに関する情報が含まれています。ダウンロード元のURLなどが含まれます。
* **`/var/log/system.log`**：OSXシステムのメインログ。com.apple.syslogd.plistはsysloggingの実行を担当しています（`launchctl list`で"com.apple.syslogd"を検索して無効になっていないか確認できます）。
* **`/private/var/log/asl/*.asl`**：これらはApple System Logsで、興味深い情報が含まれている可能性があります。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：最近アクセスしたファイルやFinderを介してアクセスしたアプリケーションが格納されています。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：システム起動時に起動するアイテムが格納されています。
* **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility Appのログファイル（USBを含むドライブに関する情報が含まれています）。
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：ワイヤレスアクセスポイントに関するデータ。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：無効になっているデーモンのリスト。

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**または**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローしてください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}
