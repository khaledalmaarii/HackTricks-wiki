# AppArmor

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由**暗网**支持的搜索引擎，提供**免费**功能，用于检查公司或其客户是否受到**窃取恶意软件**的**侵害**。

WhiteIntel的主要目标是打击由窃取信息恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

---

## 基本信息

AppArmor是一个**内核增强程序，旨在通过每个程序的配置文件限制程序可用的资源**，有效地实现强制访问控制（MAC），将访问控制属性直接绑定到程序而不是用户。该系统通过**将配置文件加载到内核中**来运行，通常在启动时进行，这些配置文件规定了程序可以访问的资源，例如网络连接、原始套接字访问和文件权限。

AppArmor配置文件有两种操作模式：

- **强制模式**：该模式积极执行配置文件中定义的策略，阻止违反这些策略的操作，并通过诸如syslog或auditd等系统记录任何试图违反这些策略的尝试。
- **投诉模式**：与强制模式不同，投诉模式不会阻止违反配置文件策略的操作。相反，它将这些尝试记录为策略违规，而不强制执行限制。

### AppArmor组件

- **内核模块**：负责执行策略。
- **策略**：指定程序行为和资源访问的规则和限制。
- **解析器**：将策略加载到内核以执行或报告。
- **实用程序**：这些是用户模式程序，提供与AppArmor交互和管理的接口。

### 配置文件路径

AppArmor配置文件通常保存在_**/etc/apparmor.d/**_中\
使用`sudo aa-status`命令，您将能够列出受某个配置文件限制的二进制文件。如果您可以将每个列出的二进制文件的路径中的斜杠“/”更改为一个点，您将获得所提到文件夹中AppArmor配置文件的名称。

例如，_usr/bin/man_的**apparmor**配置文件将位于_/etc/apparmor.d/usr.bin.man_中

### 命令
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## 创建一个配置文件

* 为了指定受影响的可执行文件，允许使用**绝对路径和通配符**（用于文件通配）来指定文件。
* 为了指示二进制文件将对**文件**具有的访问权限，可以使用以下**访问控制**：
* **r**（读取）
* **w**（写入）
* **m**（内存映射为可执行文件）
* **k**（文件锁定）
* **l**（创建硬链接）
* **ix**（使用新程序继承策略执行另一个程序）
* **Px**（在清理环境后在另一个配置文件下执行）
* **Cx**（在清理环境后在子配置文件下执行）
* **Ux**（在清理环境后执行无限制操作）
* **变量**可以在配置文件中定义，并且可以从配置文件外部进行操作。例如：@{PROC} 和 @{HOME}（在配置文件中添加 #include \<tunables/global>）
* **拒绝规则支持覆盖允许规则**。

### aa-genprof

为了轻松开始创建一个配置文件，apparmor 可以帮助您。可以让**apparmor 检查二进制文件执行的操作，然后让您决定要允许还是拒绝哪些操作**。\
只需要运行：
```bash
sudo aa-genprof /path/to/binary
```
然后，在另一个控制台执行二进制文件通常会执行的所有操作：
```bash
/path/to/binary -a dosomething
```
然后，在第一个控制台中按下 "**s**"，然后在记录的操作中指示您想要忽略、允许或其他操作。完成后按下 "**f**"，新配置文件将被创建在 _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
使用箭头键，您可以选择要允许/拒绝/其他的内容
{% endhint %}

### aa-easyprof

您还可以使用以下命令创建二进制文件的AppArmor配置文件模板：
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
请注意，默认情况下，在创建的配置文件中，什么都不允许，因此一切都被拒绝。您需要添加类似 `/etc/passwd r,` 这样的行来允许例如二进制文件读取 `/etc/passwd`。
{% endhint %}

然后，您可以使用以下命令**强制执行**新配置文件：
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### 从日志修改配置文件

以下工具将读取日志，并询问用户是否要允许一些检测到的禁止操作：
```bash
sudo aa-logprof
```
{% hint style="info" %}
使用箭头键可以选择您想要允许/拒绝/其他操作的内容
{% endhint %}

### 管理配置文件
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## 日志

来自 _/var/log/audit/audit.log_ 的 **AUDIT** 和 **DENIED** 日志示例，针对可执行文件 **`service_bin`**：
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
您也可以使用以下方式获取此信息：
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Docker中的Apparmor

请注意，默认情况下加载了docker的配置文件**docker-profile**：
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
默认情况下，**Apparmor docker-default profile** 是从 [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) 生成的。

**docker-default profile 摘要**：

- 允许访问所有**网络**
- 没有定义**任何权限**（但是，一些权限将来自于包含基本基础规则，即 #include \<abstractions/base>）
- **不允许**写入任何 **/proc** 文件
- 其他 /**proc** 和 /**sys** 的**子目录**/**文件** **拒绝**读取/写入/锁定/链接/执行访问
- **不允许**挂载
- **Ptrace** 只能在由**相同的 apparmor profile** 限制的进程上运行

一旦您**运行一个 docker 容器**，您应该看到以下输出：
```bash
1 processes are in enforce mode.
docker-default (825)
```
请注意，**apparmor 默认会阻止容器被授予的 capabilities 权限**。例如，即使授予了 SYS_ADMIN capability，它也可以**阻止在 /proc 目录内写入的权限**，因为默认情况下 docker apparmor profile 拒绝了这种访问：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
您需要**禁用AppArmor**以绕过其限制：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
请注意，默认情况下**AppArmor**也会**禁止容器从内部挂载**文件夹，即使具有SYS_ADMIN权限也是如此。

请注意，您可以向docker容器**添加/删除****权限**（这仍将受到诸如**AppArmor**和**Seccomp**之类的保护方法的限制）：

- `--cap-add=SYS_ADMIN` 给予`SYS_ADMIN`权限
- `--cap-add=ALL` 给予所有权限
- `--cap-drop=ALL --cap-add=SYS_PTRACE` 撤销所有权限，仅给予`SYS_PTRACE`权限

{% hint style="info" %}
通常，当您**发现**在**docker**容器**内**有**特权权限**可用，但某些**利用**的部分**无法正常工作**时，这是因为docker的**apparmor会阻止**它。
{% endhint %}

### 示例

（示例来自[**这里**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)）

为了说明AppArmor的功能，我创建了一个名为“mydocker”的新Docker配置文件，并添加了以下行：
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
要激活该配置文件，我们需要执行以下操作：
```
sudo apparmor_parser -r -W mydocker
```
要列出配置文件，我们可以执行以下命令。下面的命令正在列出我的新AppArmor配置文件。
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
如下所示，在尝试更改“/etc/”时，由于AppArmor配置文件阻止对“/etc”的写访问，因此会出现错误。
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

您可以使用以下命令查找运行容器的 **AppArmor配置文件**：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
然后，您可以运行以下命令来**查找正在使用的确切配置文件**：
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmor是基于路径的**，这意味着即使它可能会**保护**目录内的文件，比如**`/proc`**，如果你能**配置容器的运行方式**，你可以将主机的proc目录挂载到**`/host/proc`**，这样它就**不再受AppArmor保护**。

### AppArmor Shebang Bypass

在[**这个漏洞**](https://bugs.launchpad.net/apparmor/+bug/1911431)中，你可以看到一个例子，即使你正在阻止perl使用某些资源运行，如果你只是创建一个shell脚本，在第一行**指定**`#!/usr/bin/perl`，然后**直接执行该文件**，你就可以执行任何你想要的东西。例如：
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由**暗网**推动的搜索引擎，提供**免费**功能，用于检查公司或其客户是否受到**窃取恶意软件**的**侵害**。

WhiteIntel的主要目标是打击由窃取信息恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
