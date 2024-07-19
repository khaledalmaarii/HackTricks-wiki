# macOS .Net Applications Injection

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

**यह [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) पोस्ट का सारांश है। आगे की जानकारी के लिए इसे देखें!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **डिबगिंग सत्र स्थापित करना** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET में डिबगर और डिबगी के बीच संचार का प्रबंधन [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) द्वारा किया जाता है। यह घटक प्रत्येक .NET प्रक्रिया के लिए दो नामित पाइप स्थापित करता है, जैसा कि [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) में देखा गया है, जो [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) के माध्यम से आरंभ होते हैं। इन पाइपों के अंत में **`-in`** और **`-out`** जोड़ा जाता है।

उपयोगकर्ता के **`$TMPDIR`** पर जाकर, .Net अनुप्रयोगों के लिए उपलब्ध डिबगिंग FIFOs पाए जा सकते हैं।

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) संचार प्रबंधन के लिए जिम्मेदार है। एक नया डिबगिंग सत्र शुरू करने के लिए, एक डिबगर को `out` पाइप के माध्यम से एक संदेश भेजना चाहिए जो `MessageHeader` संरचना से शुरू होता है, जो .NET स्रोत कोड में विस्तृत है:
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
नए सत्र का अनुरोध करने के लिए, इस संरचना को इस प्रकार भरा जाता है, संदेश प्रकार को `MT_SessionRequest` और प्रोटोकॉल संस्करण को वर्तमान संस्करण पर सेट किया जाता है:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
यह हेडर फिर `write` syscall का उपयोग करके लक्ष्य पर भेजा जाता है, इसके बाद `sessionRequestData` संरचना होती है जिसमें सत्र के लिए एक GUID होता है:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` पाइप पर एक पढ़ने का ऑपरेशन डिबगिंग सत्र की स्थापना की सफलता या विफलता की पुष्टि करता है:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## मेमोरी पढ़ना
एक डिबगिंग सत्र स्थापित होने के बाद, मेमोरी को [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) संदेश प्रकार का उपयोग करके पढ़ा जा सकता है। फ़ंक्शन readMemory विस्तृत है, पढ़ने के अनुरोध को भेजने और प्रतिक्रिया प्राप्त करने के लिए आवश्यक कदम उठाता है:
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
पूर्ण प्रमाण अवधारणा (POC) [यहाँ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) उपलब्ध है।

## मेमोरी लिखना

इसी तरह, `writeMemory` फ़ंक्शन का उपयोग करके मेमोरी लिखी जा सकती है। प्रक्रिया में संदेश प्रकार को `MT_WriteMemory` पर सेट करना, डेटा का पता और लंबाई निर्दिष्ट करना, और फिर डेटा भेजना शामिल है:
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
संबंधित POC [यहाँ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) उपलब्ध है।

## .NET Core कोड निष्पादन <a href="#net-core-code-execution" id="net-core-code-execution"></a>

कोड निष्पादित करने के लिए, एक को मेमोरी क्षेत्र की पहचान करनी होती है जिसमें rwx अनुमतियाँ होती हैं, जिसे vmmap -pages: का उपयोग करके किया जा सकता है।
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
एक फ़ंक्शन पॉइंटर को ओवरराइट करने के लिए स्थान ढूंढना आवश्यक है, और .NET Core में, यह **डायनामिक फ़ंक्शन टेबल (DFT)** को लक्षित करके किया जा सकता है। यह तालिका, जो [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) में विस्तृत है, रनटाइम द्वारा JIT संकलन सहायक फ़ंक्शनों के लिए उपयोग की जाती है।

x64 सिस्टम के लिए, सिग्नेचर हंटिंग का उपयोग `libcorclr.dll` में प्रतीक `_hlpDynamicFuncTable` के संदर्भ को खोजने के लिए किया जा सकता है।

`MT_GetDCB` डिबगर फ़ंक्शन उपयोगी जानकारी प्रदान करता है, जिसमें एक सहायक फ़ंक्शन का पता, `m_helperRemoteStartAddr`, शामिल है, जो प्रक्रिया मेमोरी में `libcorclr.dll` के स्थान को इंगित करता है। इस पते का उपयोग DFT के लिए खोज शुरू करने और फ़ंक्शन पॉइंटर को शेलकोड के पते के साथ ओवरराइट करने के लिए किया जाता है।

PowerShell में इंजेक्शन के लिए पूरा POC कोड [यहाँ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) उपलब्ध है।

## संदर्भ

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

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
