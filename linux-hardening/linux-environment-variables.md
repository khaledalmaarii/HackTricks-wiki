# Linux环境变量

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 全局变量

全局变量**将被**子进程继承。

你可以通过以下方式为当前会话创建一个全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
这个变量将可以被当前会话及其子进程访问。

您可以通过以下方式**删除**一个变量：
```bash
unset MYGLOBAL
```
## 本地变量

**本地变量**只能被**当前的shell脚本**访问。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 列出当前变量

To list the current environment variables in Linux, you can use the `env` command. This command will display a list of all the variables and their values.

```bash
$ env
```

You can also use the `printenv` command to achieve the same result:

```bash
$ printenv
```

Both commands will output the variables in the format `variable=value`.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## 持久环境变量

#### 影响每个用户行为的文件：

* _**/etc/bash.bashrc**_：每次启动交互式shell（普通终端）时都会读取此文件，并执行其中的所有命令。
* _**/etc/profile和/etc/profile.d/\***_**：**每次用户登录时都会读取此文件。因此，此处执行的所有命令仅在用户登录时执行一次。
*   **示例：**

`/etc/profile.d/somescript.sh`

```bash
#!/bin/bash
TEST=$(cat /var/somefile)
export $TEST
```

#### 仅影响特定用户行为的文件：

* _**\~/.bashrc**_：此文件的工作方式与 _/etc/bash.bashrc_ 文件相同，但仅对特定用户执行。如果要为自己创建环境，请修改或在您的主目录中创建此文件。
* _**\~/.profile, \~/.bash\_profile, \~/.bash\_login**_**：**这些文件与 _/etc/profile_ 相同。区别在于执行方式。仅当用户在其主目录中存在此文件时，才会执行此文件。

**摘自：**[**此处**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **和** [**此处**](https://www.gnu.org/software/bash/manual/html\_node/Bash-Startup-Files.html)

## 常见变量

来自：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
* **EDITOR** – 用户首选的文本编辑器。
* **HISTFILESIZE** – 历史记录文件中包含的最大行数。
* **HISTSIZE** - 用户会话结束时添加到历史记录文件中的行数
* **HOME** – 您的主目录。
* **HOSTNAME** – 计算机的主机名。
* **LANG** – 当前语言。
* **MAIL** – 用户邮件存储位置。通常为 **/var/spool/mail/USER**。
* **MANPATH** – 手册页搜索的目录列表。
* **OSTYPE** – 操作系统类型。
* **PS1** – bash 中的默认提示符。
* **PATH** - 存储所有目录的路径，这些目录包含您想要通过指定文件名而不是相对或绝对路径来执行的二进制文件。
* **PWD** – 当前工作目录。
* **SHELL** – 当前命令shell的路径（例如，**/bin/bash**）。
* **TERM** – 当前终端类型（例如，**xterm**）。
* **TZ** – 您的时区。
* **USER** – 您当前的用户名。

## 用于黑客攻击的有趣变量

### **HISTFILESIZE**

将此变量的值更改为0，这样当您**结束会话**时，**历史记录文件**（\~/.bash\_history）将被删除。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的值更改为0，这样当您结束会话时，任何命令都不会被添加到历史文件（\~/.bash\_history）。
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

进程将使用在此处声明的**代理**通过**http或https**连接到互联网。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

进程将信任**这些环境变量**中指定的证书。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

更改提示符的外观。

我创建了[**这个**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)（基于另一个，请阅读代码）。

Root用户：

![](<../.gitbook/assets/image (87).png>)

普通用户：

![](<../.gitbook/assets/image (88).png>)

一个、两个和三个后台作业：

![](<../.gitbook/assets/image (89).png>)

一个后台作业，一个停止的作业和最后一个命令未正确完成：

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
