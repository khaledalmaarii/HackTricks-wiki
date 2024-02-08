# macOS .Net Applications Injection

<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos पर PRs सबमिट करके।

</details>

**यह [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) पोस्ट का सारांश है। अधिक विवरण के लिए इसे देखें!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **डीबगिंग सत्र स्थापित करना** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET में डीबगर और डीबगी के बीच संचार का प्रबंधन [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) द्वारा प्रबंधित किया जाता है। यह घटक प्रति .NET प्रक्रिया के लिए दो नेम्ड पाइप सेट करता है जैसा कि [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) में देखा जा सकता है, जो [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) के माध्यम से प्रारंभ किए जाते हैं। ये पाइप **`-in`** और **`-out`** के साथ समाप्त होते हैं।

उपयोगकर्ता के **`$TMPDIR`** पर जाकर कोई भी .Net एप्लिकेशन को डीबग करने के लिए उपलब्ध डीबगिंग FIFOs मिल सकते हैं।

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) डीबगर से संचार प्रबंधित करने के लिए जिम्मेदार है। एक नई डीबगिंग सत्र प्रारंभ करने के लिए, एक डीबगर को एक `MessageHeader` संरचना के साथ `out` पाइप के माध्यम से एक संदेश भेजना होगा, जो .NET स्रोत कोड में विस्तार से वर्णित है:
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
एक नए सत्र का अनुरोध करने के लिए, यह स्ट्रक्ट निम्नलिखित रूप में पूरा किया जाता है, संदेश प्रकार को `MT_SessionRequest` और प्रोटोकॉल संस्करण को वर्तमान संस्करण पर सेट करके:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
यह हेडर फिर `write` सिसकॉल का उपयोग करके लक्ष्य को भेजा जाता है, जिसके बाद `sessionRequestData` स्ट्रक्ट भेजी जाती है जिसमें सत्र के लिए एक GUID होता है:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
एक `out` पाइप पर पढ़ने की क्रिया डीबगिंग सत्र स्थापना की सफलता या असफलता की पुष्टि करती है:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## मेमोरी पढ़ना
एक डीबगिंग सत्र स्थापित होने के बाद, [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) संदेश प्रकार का उपयोग करके मेमोरी पढ़ी जा सकती है। फ़ंक्शन readMemory विस्तार से विवरणित है, आवश्यक कदमों को करने के लिए एक पढ़ने का अनुरोध भेजने और प्रतिक्रिया प्राप्त करने के लिए।
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
पूर्ण सिद्धांत (POC) यहाँ उपलब्ध है [यहाँ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## मेमोरी लिखना

उसी तरह, `writeMemory` फ़ंक्शन का उपयोग करके मेमोरी लिखी जा सकती है। इस प्रक्रिया में संदेश प्रकार को `MT_WriteMemory` पर सेट करना शामिल है, डेटा के पते और लंबाई को निर्दिष्ट करना है, और फिर डेटा भेजना है:
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
जुड़ा हुआ POC यहाँ उपलब्ध है [यहाँ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core कोड निष्पादन <a href="#net-core-code-execution" id="net-core-code-execution"></a>

कोड निष्पादित करने के लिए, किसी कोड क्षेत्र की पहचान करनी होगी जिसमें rwx अनुमतियाँ हो, जो vmmap -pages का उपयोग करके किया जा सकता है:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
एक स्थान का पता लगाना जहाँ फ़ंक्शन पॉइंटर को ओवरराइट किया जा सकता है, यह आवश्यक है, और .NET Core में, यह **डायनामिक फ़ंक्शन टेबल (DFT)** को लक्षित करके किया जा सकता है। यह टेबल, [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) में विस्तार से वर्णित है, जो JIT संकलन सहायक फ़ंक्शनों के लिए रनटाइम द्वारा उपयोग किया जाता है।

x64 सिस्टमों के लिए, सिग्नेचर हंटिंग का उपयोग किया जा सकता है ताकि `libcorclr.dll` में `_hlpDynamicFuncTable` प्रतीक का संदर्भ मिल सके।

`MT_GetDCB` डीबगर फ़ंक्शन महत्वपूर्ण जानकारी प्रदान करता है, जिसमें एक हेल्पर फ़ंक्शन, `m_helperRemoteStartAddr`, का पता चलता है, जो `libcorclr.dll` के स्थान का प्रकाशन मेमोरी में है। इस पते का उपयोग फिर DFT के लिए खोज शुरू करने और एक फ़ंक्शन पॉइंटर को शेलकोड के पते से ओवरराइट करने के लिए किया जाता है।

PowerShell में इंजेक्शन के लिए पूरा POC कोड [यहाँ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) उपलब्ध है।

## संदर्भ

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
