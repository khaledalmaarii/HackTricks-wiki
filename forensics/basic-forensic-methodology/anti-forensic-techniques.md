```markdown
# Timestamps

एक हमलावर फाइलों के **timestamps को बदलने** में रुचि रख सकता है ताकि पकड़ा न जाए।\
MFT में `$STANDARD_INFORMATION` __ और __ `$FILE_NAME` गुणों के अंदर timestamps पाए जा सकते हैं।

दोनों गुणों में 4 timestamps होते हैं: **Modification**, **access**, **creation**, और **MFT registry modification** (MACE या MACB)।

**Windows explorer** और अन्य उपकरण **`$STANDARD_INFORMATION`** से जानकारी दिखाते हैं।

## TimeStomp - Anti-forensic Tool

यह उपकरण **`$STANDARD_INFORMATION`** के अंदर की timestamp जानकारी को **संशोधित** करता है **लेकिन** **`$FILE_NAME`** के अंदर की जानकारी को **नहीं**। इसलिए, **संदिग्ध** **गतिविधि** की **पहचान** करना संभव है।

## Usnjrnl

**USN Journal** (Update Sequence Number Journal), या Change Journal, Windows NT फाइल सिस्टम (NTFS) की एक विशेषता है जो **वॉल्यूम में किए गए परिवर्तनों का रिकॉर्ड रखती है**।\
[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) उपकरण का उपयोग करके इस रिकॉर्ड में संशोधनों की खोज की जा सकती है।

![](<../../.gitbook/assets/image (449).png>)

ऊपर की छवि में **उपकरण** द्वारा दिखाया गया **आउटपुट** है जहां देखा जा सकता है कि फाइल में कुछ **परिवर्तन किए गए थे**।

## $LogFile

फाइल सिस्टम में सभी मेटाडेटा परिवर्तनों को लॉग किया जाता है ताकि सिस्टम क्रैश के बाद महत्वपूर्ण फाइल सिस्टम संरचनाओं की सुसंगत रिकवरी सुनिश्चित की जा सके। इसे [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) कहा जाता है।\
लॉग किया गया मेटाडेटा “**$LogFile**” नामक फाइल में संग्रहीत होता है, जो NTFS फाइल सिस्टम की रूट डायरेक्टरी में पाया जाता है।\
[LogFileParser](https://github.com/jschicht/LogFileParser) जैसे उपकरणों का उपयोग करके इस फाइल को पार्स करना और परिवर्तनों को खोजना संभव है।

![](<../../.gitbook/assets/image (450).png>)

फिर से, उपकरण के आउटपुट में देखा जा सकता है कि **कुछ परिवर्तन किए गए थे**।

उसी उपकरण का उपयोग करके यह पहचानना संभव है कि **किस समय timestamps को संशोधित किया गया था**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: फाइल का निर्माण समय
* ATIME: फाइल का संशोधन समय
* MTIME: फाइल का MFT रजिस्ट्री संशोधन
* RTIME: फाइल का एक्सेस समय

## `$STANDARD_INFORMATION` और `$FILE_NAME` तुलना

संशोधित की गई संदिग्ध फाइलों की पहचान करने का एक और तरीका दोनों गुणों में समय की **असमानता** की तलाश करना होगा।

## Nanoseconds

**NTFS** timestamps की **सटीकता** **100 नैनोसेकंड** की होती है। इसलिए, 2010-10-10 10:10:**00.000:0000 जैसे timestamps वाली फाइलें बहुत संदिग्ध होती हैं।

## SetMace - Anti-forensic Tool

यह उपकरण दोनों गुण `$STARNDAR_INFORMATION` और `$FILE_NAME` को संशोधित कर सकता है। हालांकि, Windows Vista से, इस जानकारी को संशोधित करने के लिए एक लाइव OS की आवश्यकता होती है।

# Data Hiding

NFTS एक क्लस्टर का उपयोग करता है और न्यूनतम जानकारी का आकार होता है। इसका मतलब है कि अगर एक फाइल एक क्लस्टर और आधा का उपयोग करती है, तो **बचा हुआ आधा कभी भी उपयोग में नहीं आएगा** जब तक कि फाइल को हटाया नहीं जाता। इसलिए, इस खाली जगह में **डेटा छिपाना** संभव है।

slacker जैसे उपकरण हैं जो इस "छिपी" जगह में डेटा छिपाने की अनुमति देते हैं। हालांकि, `$logfile` और `$usnjrnl` का विश्लेषण यह दिखा सकता है कि कुछ डेटा जोड़ा गया था:

![](<../../.gitbook/assets/image (452).png>)

इसके बाद, FTK Imager जैसे उपकरणों का उपयोग करके खाली जगह को पुनः प्राप्त करना संभव है। ध्यान दें कि इस प्रकार का उपकरण सामग्री को छिपाकर या यहां तक कि एन्क्रिप्टेड भी सेव कर सकता है।

# UsbKill

यह एक उपकरण है जो **कंप्यूटर को बंद कर देगा अगर USB** पोर्ट्स में कोई परिवर्तन पता चलता है।\
इसका पता लगाने का एक तरीका चल रही प्रक्रियाओं की जांच करना और **प्रत्येक पायथन स्क्रिप्ट की समीक्षा करना** होगा।

# Live Linux Distributions

ये डिस्ट्रोस **RAM** मेमोरी के अंदर **निष्पादित** किए जाते हैं। इन्हें पता लगाने का एकमात्र तरीका है **अगर NTFS फाइल-सिस्टम को लिखने की अनुमति के साथ माउंट किया गया हो**। अगर यह केवल पढ़ने की अनुमति के साथ माउंट किया गया हो तो घुसपैठ का पता लगाना संभव नहीं होगा।

# Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows Configuration

कई Windows लॉगिंग विधियों को अक्षम करके फोरेंसिक जांच को बहुत कठिन बनाना संभव है।

## Disable Timestamps - UserAssist

यह एक रजिस्ट्री कुंजी है जो उपयोगकर्ता द्वारा प्रत्येक निष्पादन योग्य को चलाए जाने के समय और घंटे को बनाए रखती है।

UserAssist को अक्षम करने के लिए दो चरणों की आवश्यकता होती है:

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` और `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` दोनों रजिस्ट्री कुंजियों को शून्य पर सेट करें ताकि संकेत मिले कि हम UserAssist को अक्षम करना चाहते हैं।
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` की तरह दिखने वाले अपने रजिस्ट्री सबट्रीज को साफ करें।

## Disable Timestamps - Prefetch

यह Windows सिस्टम के प्रदर्शन को सुधारने के उद्देश्य से निष्पादित अनुप्रयोगों के बारे में जानकारी सहेजेगा। हालांकि, यह फोरेंसिक प्रथाओं के लिए भी उपयोगी हो सकता है।

* `regedit` निष्पादित करें
* फाइल पथ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` का चयन करें
* `EnablePrefetcher` और `EnableSuperfetch` दोनों पर राइट-क्लिक करें
* इनमें से प्रत्येक पर Modify का चयन करें और मान को 1 (या 3) से 0 में बदलें
* पुनः आरंभ करें

## Disable Timestamps - Last Access Time

जब भी Windows NT सर्वर पर NTFS वॉल्यूम से कोई फोल्डर खोला जाता है, सिस्टम प्रत्येक सूचीबद्ध फोल्डर पर एक timestamp फील्ड को अपडेट करने का समय लेता है, जिसे अंतिम पहुंच समय कहा जाता है। एक भारी उपयोग वाले NTFS वॉल्यूम पर, यह प्रदर्शन को प्रभावित कर सकता है।

1. रजिस्ट्री एडिटर (Regedit.exe) खोलें।
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` पर ब्राउज़ करें।
3. `NtfsDisableLastAccessUpdate` की तलाश करें। अगर यह मौजूद नहीं है, तो इस DWORD को जोड़ें और इसका मान 1 पर स
