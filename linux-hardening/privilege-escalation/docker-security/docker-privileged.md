# Docker --privileged

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

## What Affects

जब आप एक कंटेनर को विशेषाधिकार प्राप्त के रूप में चलाते हैं, तो ये सुरक्षा उपाय हैं जिन्हें आप निष्क्रिय कर रहे हैं:

### Mount /dev

एक विशेषाधिकार प्राप्त कंटेनर में, सभी **डिवाइस `/dev/` में पहुंचा जा सकता है**। इसलिए आप **माउंटिंग** करके होस्ट के डिस्क से **भाग सकते हैं**।

{% tabs %}
{% tab title="Inside default container" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="विशेषाधिकार प्राप्त कंटेनर के अंदर" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
{% endtab %}
{% endtabs %}

### केवल-पढ़ने योग्य कर्नेल फ़ाइल सिस्टम

कर्नेल फ़ाइल सिस्टम एक प्रक्रिया को कर्नेल के व्यवहार को संशोधित करने का तंत्र प्रदान करते हैं। हालाँकि, जब कंटेनर प्रक्रियाओं की बात आती है, तो हम उन्हें कर्नेल में कोई परिवर्तन करने से रोकना चाहते हैं। इसलिए, हम कर्नेल फ़ाइल सिस्टम को कंटेनर के भीतर **केवल-पढ़ने योग्य** के रूप में माउंट करते हैं, यह सुनिश्चित करते हुए कि कंटेनर प्रक्रियाएँ कर्नेल को संशोधित नहीं कर सकतीं।

{% tabs %}
{% tab title="डिफ़ॉल्ट कंटेनर के अंदर" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="विशिष्ट कंटेनर के अंदर" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### कर्नेल फ़ाइल सिस्टम पर मास्किंग

**/proc** फ़ाइल प्रणाली चयनात्मक रूप से लिखने योग्य है लेकिन सुरक्षा के लिए, कुछ भागों को **tmpfs** के साथ ओवरले करके लिखने और पढ़ने की पहुंच से ढक दिया गया है, यह सुनिश्चित करते हुए कि कंटेनर प्रक्रियाएँ संवेदनशील क्षेत्रों तक नहीं पहुँच सकतीं।

{% hint style="info" %}
**tmpfs** एक फ़ाइल प्रणाली है जो सभी फ़ाइलों को वर्चुअल मेमोरी में संग्रहीत करती है। tmpfs आपके हार्ड ड्राइव पर कोई फ़ाइलें नहीं बनाती। इसलिए यदि आप एक tmpfs फ़ाइल प्रणाली को अनमाउंट करते हैं, तो इसमें मौजूद सभी फ़ाइलें हमेशा के लिए खो जाती हैं।
{% endhint %}

{% tabs %}
{% tab title="डिफ़ॉल्ट कंटेनर के अंदर" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="विशिष्ट कंटेनर के अंदर" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux क्षमताएँ

कंटेनर इंजन कंटेनरों को **सीमित संख्या में क्षमताओं** के साथ लॉन्च करते हैं ताकि डिफ़ॉल्ट रूप से कंटेनर के अंदर क्या होता है, उसे नियंत्रित किया जा सके। **विशेषाधिकार प्राप्त** वाले सभी **क्षमताओं** तक पहुँच रखते हैं। क्षमताओं के बारे में जानने के लिए पढ़ें:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="डिफ़ॉल्ट कंटेनर के अंदर" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="विशेषाधिकार प्राप्त कंटेनर के अंदर" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

आप `--privileged` मोड में चलाए बिना कंटेनर के लिए उपलब्ध क्षमताओं को `--cap-add` और `--cap-drop` ध्वजों का उपयोग करके हेरफेर कर सकते हैं।

### Seccomp

**Seccomp** एक कंटेनर द्वारा कॉल किए जा सकने वाले **syscalls** को **सीमित** करने के लिए उपयोगी है। डॉकर कंटेनरों को चलाते समय एक डिफ़ॉल्ट सेकंप प्रोफ़ाइल डिफ़ॉल्ट रूप से सक्षम होती है, लेकिन विशेषाधिकार मोड में यह अक्षम होती है। Seccomp के बारे में अधिक जानें यहाँ:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Inside default container" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="विशेषाधिकार प्राप्त कंटेनर के अंदर" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Also, note that when Docker (or other CRIs) are used in a **Kubernetes** cluster, the **seccomp filter is disabled by default**

### AppArmor

**AppArmor** एक कर्नेल संवर्धन है जो **कंटेनरों** को **सीमित** संसाधनों के सेट में **प्रति-कार्यक्रम प्रोफाइल** के साथ सीमित करता है। जब आप `--privileged` ध्वज के साथ चलाते हैं, तो यह सुरक्षा अक्षम हो जाती है।

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged` ध्वज के साथ कंटेनर चलाने से **SELinux लेबल** अक्षम हो जाते हैं, जिससे यह कंटेनर इंजन का लेबल विरासत में लेता है, आमतौर पर `unconfined`, जो कंटेनर इंजन के समान पूर्ण पहुंच प्रदान करता है। रूटलेस मोड में, यह `container_runtime_t` का उपयोग करता है, जबकि रूट मोड में, `spc_t` लागू होता है।

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## क्या प्रभावित नहीं करता

### नामस्थान

Namespaces **प्रभावित नहीं होते** `--privileged` ध्वज द्वारा। भले ही उनके पास सुरक्षा प्रतिबंध सक्षम नहीं हैं, वे **सिस्टम या होस्ट नेटवर्क पर सभी प्रक्रियाओं को नहीं देखते, उदाहरण के लिए**। उपयोगकर्ता **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** कंटेनर इंजन ध्वजों का उपयोग करके व्यक्तिगत नामस्थान को अक्षम कर सकते हैं।

{% tabs %}
{% tab title="डिफ़ॉल्ट विशेषाधिकार प्राप्त कंटेनर के अंदर" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="अंदर --pid=host कंटेनर" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### उपयोगकर्ता नामस्थान

**डिफ़ॉल्ट रूप से, कंटेनर इंजन उपयोगकर्ता नामस्थान का उपयोग नहीं करते हैं, सिवाय रूटलेस कंटेनरों के**, जिन्हें फ़ाइल सिस्टम माउंटिंग और कई UID का उपयोग करने के लिए इसकी आवश्यकता होती है। उपयोगकर्ता नामस्थान, जो रूटलेस कंटेनरों के लिए अनिवार्य हैं, को बंद नहीं किया जा सकता है और यह विशेषाधिकारों को सीमित करके सुरक्षा को महत्वपूर्ण रूप से बढ़ाते हैं।

## संदर्भ

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

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
