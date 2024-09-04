# Linux 环境变量

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

## 全局变量

全局变量 **将被** 子进程 **继承**。

您可以通过以下方式为当前会话创建全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
这个变量将可以被您当前的会话及其子进程访问。

您可以通过以下方式**删除**一个变量：
```bash
unset MYGLOBAL
```
## Local variables

**局部变量**只能被**当前的 shell/脚本**访问。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 列出当前变量
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，这意味着当前计算机上的第一个显示器。
* **EDITOR** – 用户首选的文本编辑器。
* **HISTFILESIZE** – 历史文件中包含的最大行数。
* **HISTSIZE** – 用户完成会话时添加到历史文件的行数。
* **HOME** – 你的主目录。
* **HOSTNAME** – 计算机的主机名。
* **LANG** – 你当前的语言。
* **MAIL** – 用户邮件存储的位置。通常是 **/var/spool/mail/USER**。
* **MANPATH** – 搜索手册页的目录列表。
* **OSTYPE** – 操作系统的类型。
* **PS1** – bash 中的默认提示符。
* **PATH** – 存储所有目录的路径，这些目录包含你想通过指定文件名而不是相对或绝对路径执行的二进制文件。
* **PWD** – 当前工作目录。
* **SHELL** – 当前命令 shell 的路径（例如，**/bin/bash**）。
* **TERM** – 当前终端类型（例如，**xterm**）。
* **TZ** – 你的时区。
* **USER** – 你当前的用户名。

## Interesting variables for hacking

### **HISTFILESIZE**

将 **此变量的值更改为 0**，这样当你 **结束会话** 时，**历史文件**（\~/.bash\_history）**将被删除**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的**值更改为 0**，这样当您**结束会话**时，任何命令都将被添加到**历史文件**（\~/.bash\_history）中。
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

进程将使用此处声明的 **proxy** 通过 **http 或 https** 连接到互联网。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

进程将信任**这些环境变量**中指示的证书。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

更改提示的外观。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

普通用户:

![](<../.gitbook/assets/image (740).png>)

一个、两个和三个后台作业:

![](<../.gitbook/assets/image (145).png>)

一个后台作业，一个已停止，最后一个命令未正确完成:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
学习和实践 AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
