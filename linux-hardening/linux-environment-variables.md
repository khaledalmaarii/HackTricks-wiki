# Linux环境变量

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## 全局变量

全局变量**将会**被**子进程**继承。

您可以通过以下方式为当前会话创建一个全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
这个变量将可以被当前会话及其子进程访问。

您可以通过以下方式**移除**一个变量：
```bash
unset MYGLOBAL
```
## 本地变量

**本地变量** 只能被 **当前的 shell/script** 访问。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 列出当前变量

```bash
printenv
```
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## 常见变量

来源：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** 使用的显示器。该变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
* **EDITOR** – 用户首选的文本编辑器。
* **HISTFILESIZE** – 历史文件中包含的最大行数。
* **HISTSIZE** – 用户结束会话时添加到历史文件中的行数。
* **HOME** – 您的主目录。
* **HOSTNAME** – 计算机的主机名。
* **LANG** – 您当前的语言。
* **MAIL** – 用户邮件存储位置。通常为 **/var/spool/mail/USER**。
* **MANPATH** – 用于搜索手册页的目录列表。
* **OSTYPE** – 操作系统类型。
* **PS1** – bash 中的默认提示符。
* **PATH** – 存储所有目录的路径，这些目录包含您希望通过指定文件名而不是相对或绝对路径来执行的二进制文件。
* **PWD** – 当前工作目录。
* **SHELL** – 当前命令 shell 的路径（例如，**/bin/bash**）。
* **TERM** – 当前终端类型（例如，**xterm**）。
* **TZ** – 您的时区。
* **USER** – 您当前的用户名。

## 用于黑客的有趣变量

### **HISTFILESIZE**

将此变量的值更改为 **0**，这样当您 **结束会话** 时，历史文件（\~/.bash\_history）将被删除。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的值更改为0，这样当您结束会话时，任何命令都不会被添加到历史文件（\~/.bash\_history）中。
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

进程将使用在此处声明的 **代理** 通过 **http 或 https** 连接到互联网。
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

更改您的提示符外观。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Regular user:

![](<../.gitbook/assets/image (88).png>)

一个、两个和三个后台作业:

![](<../.gitbook/assets/image (89).png>)

一个后台作业，一个停止和最后一个命令未正确完成:

![](<../.gitbook/assets/image (90).png>)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式:

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
