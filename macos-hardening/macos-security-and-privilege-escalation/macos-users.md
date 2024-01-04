# macOS उपयोगकर्ता

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें PRs जमा करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में.

</details>

### सामान्य उपयोगकर्ता

*   **Daemon**: सिस्टम डेमन्स के लिए आरक्षित उपयोगकर्ता। डिफ़ॉल्ट डेमन खाते के नाम आमतौर पर "\_" से शुरू होते हैं:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```
* **Guest**: अतिथियों के लिए खाता जिसमें बहुत सख्त अनुमतियां होती हैं

{% code overflow="wrap" %}
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
{% endcode %}

* **Nobody**: जब न्यूनतम अनुमतियों की आवश्यकता होती है तो प्रक्रियाएं इस उपयोगकर्ता के साथ निष्पादित की जाती हैं
* **Root**

### उपयोगकर्ता विशेषाधिकार

* **स्टैंडर्ड उपयोगकर्ता:** सबसे बुनियादी उपयोगकर्ता। इस उपयोगकर्ता को सॉफ्टवेयर स्थापित करने या अन्य उन्नत कार्य करने के प्रयास में एक व्यवस्थापक उपयोगकर्ता से अनुमतियां प्रदान की जानी चाहिए। वे अपने आप से यह नहीं कर सकते।
* **व्यवस्थापक उपयोगकर्ता**: एक उपयोगकर्ता जो अधिकतर समय स्टैंडर्ड उपयोगकर्ता के रूप में काम करता है लेकिन उसे सॉफ्टवेयर स्थापित करने और अन्य प्रशासनिक कार्य करने जैसे रूट क्रियाएं करने की भी अनुमति है। व्यवस्थापक समूह के सभी उपयोगकर्ताओं को **sudoers फ़ाइल के माध्यम से रूट तक पहुँच प्रदान की जाती है**।
* **Root**: रूट एक उपयोगकर्ता है जिसे लगभग किसी भी क्रिया को करने की अनुमति है (सिस्टम अखंडता सुरक्षा जैसी सुरक्षाओं द्वारा लगाए गए प्रतिबंध हैं)।
* उदाहरण के लिए रूट `/System` के अंदर एक फ़ाइल नहीं रख पाएगा

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) के साथ शून्य से हीरो तक AWS हैकिंग सीखें</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें** तो [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
