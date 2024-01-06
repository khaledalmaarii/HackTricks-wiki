<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 基本信息

**AppArmor** 是一种内核增强功能，用于将**程序**限制在具有**每个程序配置文件**的**有限**资源集中。配置文件可以**允许**诸如网络访问、原始套接字访问以及在匹配路径上读取、写入或执行文件的**能力**。

它是一种强制访问控制或**MAC**，将**访问控制**属性**绑定到程序而不是用户**。\
AppArmor限制是通过加载到内核中的**配置文件**提供的，通常在启动时。\
AppArmor配置文件可以处于**两种模式**之一：

* **执行**：以执行模式加载的配置文件将导致**执行配置文件中定义的策略**以及**报告**策略违规尝试（通过syslog或auditd）。
* **投诉**：投诉模式下的配置文件**不会执行策略**，而是**报告**策略**违规**尝试。

AppArmor与Linux上的一些其他MAC系统不同：它是**基于路径的**，允许混合执行和投诉模式配置文件，它使用包含文件来简化开发，并且它的入门门槛远低于其他流行的MAC系统。

## AppArmor的组成部分

* **内核模块**：执行实际工作
* **策略**：定义行为和限制
* **解析器**：将策略加载到内核
* **工具**：用户模式程序与apparmor交互

## 配置文件路径

Apparmor配置文件通常保存在 _**/etc/apparmor.d/**_\
使用`sudo aa-status`，您将能够列出受某些配置文件限制的二进制文件。如果您能将每个列出的二进制文件的路径中的字符“/”更改为点，您将获得在上述文件夹中的apparmor配置文件的名称。

例如，针对 _/usr/bin/man_ 的**apparmor**配置文件将位于 _/etc/apparmor.d/usr.bin.man_

## 命令
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
# 创建配置文件

* 为了指示受影响的可执行文件，允许使用**绝对路径和通配符**（用于文件匹配）来指定文件。
* 为了指示二进制文件将对**文件**拥有的访问权限，可以使用以下**访问控制**：
* **r**（读取）
* **w**（写入）
* **m**（将内存映射为可执行文件）
* **k**（文件锁定）
* **l**（创建硬链接）
* **ix**（执行另一个程序，新程序继承策略）
* **Px**（在清理环境后，根据另一个配置文件执行）
* **Cx**（在清理环境后，根据子配置文件执行）
* **Ux**（在清理环境后，无限制执行）
* **变量**可以在配置文件中定义，并且可以从配置文件外部操作。例如：@{PROC} 和 @{HOME}（在配置文件中添加#include \<tunables/global>）
* **支持拒绝规则以覆盖允许规则**。

## aa-genprof

为了轻松开始创建配置文件，apparmor 可以帮助您。它可以让 **apparmor 检查二进制文件执行的操作，然后让您决定想要允许或拒绝哪些操作**。\
您只需要运行：
```bash
sudo aa-genprof /path/to/binary
```
然后，在不同的控制台执行二进制文件通常会执行的所有操作：
```bash
/path/to/binary -a dosomething
```
然后，在第一个控制台按下“**s**”，然后在记录的操作中指示您想要忽略、允许或其他操作。完成后按下“**f**”，新的配置文件将在 _/etc/apparmor.d/path.to.binary_ 中创建

{% hint style="info" %}
使用箭头键可以选择您想要允许/拒绝/其他操作
{% endhint %}

## aa-easyprof

您还可以使用以下命令为二进制文件创建一个apparmor配置文件模板：
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
请注意，默认情况下，在创建的配置文件中不允许任何操作，因此一切都将被拒绝。您需要添加像 `/etc/passwd r,` 这样的行来允许二进制文件读取 `/etc/passwd`，例如。
{% endhint %}

然后，您可以使用以下命令**强制执行**新的配置文件
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
## 从日志修改配置文件

以下工具将读取日志，并询问用户是否想要允许一些检测到的禁止操作：
```bash
sudo aa-logprof
```
{% hint style="info" %}
使用箭头键，您可以选择要允许/拒绝/其他操作的内容。
{% endhint %}

## 管理配置文件
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
# 日志

以下是来自 _/var/log/audit/audit.log_ 中可执行文件 **`service_bin`** 的 **AUDIT** 和 **DENIED** 日志示例：
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
您也可以使用以下方法获取这些信息：
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
# Docker 中的 Apparmor

注意默认情况下如何加载 docker 的 **docker-profile** 配置文件：
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

**docker-default profile 概要**：

* 对所有**网络**的**访问**
* **没有定义能力**（然而，一些能力将来自包含基本基础规则，即 #include \<abstractions/base>）
* **不允许**向任何**/proc** 文件**写入**
* /**proc** 和 /**sys** 的其他**子目录**/**文件**被**拒绝**读/写/锁定/链接/执行访问
* **不允许**使用**挂载**
* **Ptrace** 只能在被**相同 apparmor profile**限制的进程上运行

一旦你**运行一个 docker 容器**，你应该看到以下输出：
```bash
1 processes are in enforce mode.
docker-default (825)
```
请注意，**apparmor 甚至会默认阻止授予容器的 capabilities 权限**。例如，即使授予了 SYS_ADMIN 能力，它也能够**阻止写入 /proc 的权限**，因为默认情况下 docker apparmor 配置文件拒绝此访问权限：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
你需要**禁用 apparmor** 来绕过它的限制：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
请注意，默认情况下，**AppArmor** 也会**禁止容器从内部挂载**文件夹，即使具有 SYS_ADMIN 能力。

请注意，您可以**添加/删除**对 docker 容器的**能力**（这仍将受到像 **AppArmor** 和 **Seccomp** 这样的保护方法的限制）：

* `--cap-add=SYS_ADMIN` _赋予_ `SYS_ADMIN` 能力
* `--cap-add=ALL` _赋予_ 所有能力
* `--cap-drop=ALL --cap-add=SYS_PTRACE` 删除所有能力，只赋予 `SYS_PTRACE`

{% hint style="info" %}
通常，当您**发现**在 **docker** 容器**内部**有一个**特权能力**可用**但是**部分**利用不起作用**时，这将是因为 docker **apparmor 将阻止它**。
{% endhint %}

## AppArmor Docker breakout

您可以使用以下方法找出哪个**apparmor 配置文件正在运行容器**：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
```markdown
然后，您可以运行以下命令来**找到正在使用的确切配置文件**：
```
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
在这种奇怪的情况下，你可以**修改 apparmor docker 配置文件并重新加载它。** 你可以移除限制并“绕过”它们。

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks 中看到你的公司广告** 或者 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧。

</details>
