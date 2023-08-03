<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 基本信息

**AppArmor**是一种内核增强技术，用于将**程序**限制在一组**有限资源**和**每个程序配置文件**中。配置文件可以**允许**网络访问、原始套接字访问以及在匹配路径上读取、写入或执行文件的权限。

它是一种强制访问控制（**MAC**），将**访问控制属性**与**程序而不是用户**绑定。\
AppArmor通过**加载到内核中的配置文件**提供限制。\
AppArmor配置文件可以处于以下**两种模式**之一：

* **强制模式**：加载到强制模式的配置文件将导致**执行配置文件中定义的策略**，并报告策略违规尝试（通过syslog或auditd）。
* **投诉模式**：投诉模式下的配置文件**不会执行策略**，而是**报告**策略**违规**尝试。

AppArmor与Linux上的其他一些MAC系统不同：它是**基于路径**的，允许混合使用强制模式和投诉模式配置文件，使用包含文件简化开发，并且比其他流行的MAC系统具有更低的入门门槛。

## AppArmor的组成部分

* **内核模块**：执行实际工作
* **策略**：定义行为和限制
* **解析器**：将策略加载到内核中
* **实用程序**：与apparmor交互的用户模式程序

## 配置文件路径

AppArmor配置文件通常保存在_**/etc/apparmor.d/**_目录中\
使用`sudo aa-status`命令，您将能够列出受某个配置文件限制的二进制文件。如果您可以将每个列出的二进制文件的路径中的字符“/”更改为点，您将获得所提到文件夹中apparmor配置文件的名称。

例如，_usr/bin/man_的**apparmor**配置文件将位于_**/etc/apparmor.d/usr.bin.man**_中。

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
# 创建一个配置文件

* 为了指定受影响的可执行文件，可以使用**绝对路径和通配符**（用于文件匹配）来指定文件。
* 为了指示二进制文件对**文件**的访问权限，可以使用以下**访问控制**：
* **r**（读取）
* **w**（写入）
* **m**（内存映射为可执行文件）
* **k**（文件锁定）
* **l**（创建硬链接）
* **ix**（使用新程序执行另一个程序，继承策略）
* **Px**（在清理环境后，在另一个配置文件下执行）
* **Cx**（在清理环境后，在子配置文件下执行）
* **Ux**（在清理环境后，执行不受限制的程序）
* **变量**可以在配置文件中定义，并且可以从配置文件外部进行操作。例如：@{PROC} 和 @{HOME}（在配置文件中添加 #include \<tunables/global>）
* **拒绝规则支持覆盖允许规则**。

## aa-genprof

为了方便地开始创建一个配置文件，可以使用 apparmor。它可以**检查二进制文件执行的操作，然后让您决定要允许还是拒绝哪些操作**。\
只需运行以下命令：
```bash
sudo aa-genprof /path/to/binary
```
然后，在另一个控制台上执行二进制文件通常会执行的所有操作：
```bash
/path/to/binary -a dosomething
```
然后，在第一个控制台中按下“**s**”，然后在记录的操作中指示您想要忽略、允许或其他操作。完成后按下“**f**”，新的配置文件将被创建在_/etc/apparmor.d/path.to.binary_中。

{% hint style="info" %}
使用箭头键可以选择您想要允许/拒绝/其他的内容
{% endhint %}

## aa-easyprof

您还可以使用以下命令创建一个二进制文件的apparmor配置文件模板：
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
请注意，默认情况下，在创建的配置文件中，没有任何权限被允许，因此一切都被拒绝。您需要添加类似于 `/etc/passwd r,` 的行，以允许例如读取 `/etc/passwd` 的二进制文件。
{% endhint %}

然后，您可以使用以下命令**强制执行**新配置文件：
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
## 从日志中修改配置文件

以下工具将读取日志，并询问用户是否允许执行一些被检测到的禁止操作：
```bash
sudo aa-logprof
```
{% hint style="info" %}
使用箭头键可以选择您想要允许/拒绝/其他的内容
{% endhint %}

## 管理配置文件

To manage a profile, you can use the `apparmor_parser` command. Here are some useful commands:

- To load a profile: `sudo apparmor_parser -r -W /path/to/profile`
- To unload a profile: `sudo apparmor_parser -R /path/to/profile`
- To check the status of a profile: `sudo apparmor_parser -Q /path/to/profile`

You can also use the `aa-status` command to view the status of all loaded profiles.

## Enforcing and Complaining Modes

AppArmor profiles can be in two modes: enforcing and complaining.

- **Enforcing mode**: In this mode, AppArmor enforces the rules defined in the profile. If a process violates any of the rules, it will be blocked or restricted.
- **Complaining mode**: In this mode, AppArmor logs violations but does not enforce them. It is useful for testing and debugging profiles.

To change the mode of a profile, you can use the `aa-enforce` and `aa-complain` commands:

- To enforce a profile: `sudo aa-enforce /path/to/profile`
- To set a profile to complain mode: `sudo aa-complain /path/to/profile`

## Editing a Profile

To edit a profile, you can use a text editor to modify the profile file located in `/etc/apparmor.d/`. Make sure to follow the syntax and rules defined in the AppArmor documentation.

After making changes to a profile, you need to reload it using the `apparmor_parser` command:

```bash
sudo apparmor_parser -r -W /path/to/profile
```

## Creating a New Profile

To create a new profile, you can use the `aa-genprof` command. This command will guide you through the process of creating a profile for a specific application.

```bash
sudo aa-genprof /path/to/application
```

Follow the prompts and provide the necessary information to generate the profile.

## Conclusion

Managing and configuring AppArmor profiles is an essential part of securing a Linux system. By understanding how to manage, enforce, and edit profiles, you can effectively control the access and permissions of processes, reducing the risk of privilege escalation and unauthorized access.
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
# 日志

以下是来自可执行文件 **`service_bin`** 的 _/var/log/audit/audit.log_ 中的 **AUDIT** 和 **DENIED** 日志示例：
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
您还可以使用以下方法获取此信息：
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
# Docker中的Apparmor

注意，默认情况下加载了Docker的配置文件**docker-profile**：
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
默认情况下，**Apparmor docker-default配置文件**是从[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)生成的。

**docker-default配置文件摘要**：

* 允许访问所有的**网络**
* 没有定义**特权**（但是，一些特权将来自于包含基本基础规则，即#include \<abstractions/base>）
* 不允许**写入**任何**/proc**文件
* 其他/**proc**和/**sys**的**子目录**/**文件**被**拒绝**读取/写入/锁定/链接/执行访问
* 不允许**挂载**
* 只能在由**相同的apparmor配置文件**限制的进程上运行**Ptrace**

一旦你**运行一个docker容器**，你应该看到以下输出：
```bash
1 processes are in enforce mode.
docker-default (825)
```
请注意，默认情况下，**apparmor甚至会阻止容器被授予的特权权限**。例如，即使授予了SYS_ADMIN特权，它也可以**阻止在/proc目录下写入的权限**，因为默认的Docker apparmor配置文件拒绝了此访问权限：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
你需要**禁用 apparmor**来绕过其限制：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
请注意，默认情况下，**AppArmor** 也会禁止容器从内部挂载文件夹，即使具有 SYS_ADMIN 权限。

请注意，您可以向 Docker 容器**添加/删除**权限（这仍然受到像 **AppArmor** 和 **Seccomp** 这样的保护方法的限制）：

- `--cap-add=SYS_ADMIN`_ _授予_ _`SYS_ADMIN` 权限
- `--cap-add=ALL`_ _授予_ _所有权限
- `--cap-drop=ALL --cap-add=SYS_PTRACE`_ _删除所有权限，仅授予 `SYS_PTRACE` 权限

{% hint style="info" %}
通常，当您**发现**在**docker**容器**内部**有一个**特权权限**可用，但某些部分的**利用无法正常工作**时，这是因为 docker **apparmor 阻止了它**。
{% endhint %}

## AppArmor Docker 逃逸

您可以使用以下命令找到正在运行容器的**apparmor配置文件**：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
然后，您可以运行以下命令来**查找正在使用的确切配置文件**：
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
在奇怪的情况下，你可以**修改apparmor docker配置文件并重新加载它**。你可以移除限制并"绕过"它们。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
