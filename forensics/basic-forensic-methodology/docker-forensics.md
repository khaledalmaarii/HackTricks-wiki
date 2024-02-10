# Docker Forensics

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Container modification

There are suspicions that some docker container was compromised:

<details>

<summary><strong>qaStaHvIS Docker container vItlhutlh</strong></summary>
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
**tlhIngan Hol:**

**ghItlh:** *'ejwI'ghom* **container** *vItlhutlh* **modifications** *ghaH* **image** *DajatlhlaH** *vaj* **jImej** *ghItlh* **find** *lajvam** *jatlhlaH**:

**English:**

You can easily **find the modifications done to this container with regards to the image** with:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
In the previous command **C** means **Changed** and **A,** **Added**.\
If you find that some interesting file like `/etc/shadow` was modified you can download it from the container to check for malicious activity with:

**C** means **Qap** and **A,** **Qav**.\
If you find that some interesting file like `/etc/shadow` was modified you can download it from the container to check for malicious activity with:
```bash
docker cp wordpress:/etc/shadow.
```
**ghItlhvam** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **vItlhutlh** **vaj** **
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**ghItlhvam** **QaQ** **file** **vItlhutlh** **'e'** **Duj** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vItlhutlh** **'e'** **'ej** **vIt
```bash
docker exec -it wordpress bash
```
## Images modifications

When you are given an exported docker image (probably in `.tar` format) you can use [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) to **extract a summary of the modifications**:

---

## Images modifications

ghItlhvam Docker image (ghItlhvam `.tar` format) vItlhutlh [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) vItlhutlh **ghItlhvam modifications** vItlhutlh:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
**ghItlh** 'e' **decompress** **image** 'ej **access the blobs** **search** **suspicious files** **may have found** **changes history**:

```bash
ghItlh
```

**ghItlh** 'e' **decompress** **image** 'ej **access the blobs** **search** **suspicious files** **may have found** **changes history**:

```bash
ghItlh
```
```bash
tar -xf image.tar
```
### tlhIngan Hol

**mIw** jImej **mIw** vItlhutlh **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw** **mIw
```bash
docker inspect <image>
```
**tlhIngan Hol Translation:**

jImej **vetlh** qetlhDaq **chel** vItlhutlh.
```bash
docker history --no-trunc <image>
```
**Dockerfile** jImej **image** laH **generate** **Dockerfile** jatlh:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

**Dive** (download it from [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) (ghItlh releases) utility vItlhutlh can be used to find added/modified files in docker images:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
**tlhIngan Hol:**

**Qap** vItlhutlh **docker images** blobs **ghItlh** je **chelwI'**. **SuD** vItlhutlh 'ej **Sutlh** vItlhutlh. **tab** vItlhutlh **qaStaHvIS** **vItlhutlh** **space** vItlhutlh **qImHa'**/**qoH**.

**die** vItlhutlh **ghItlh** **image** stages content **ghItlh** **access**. **ghItlh** **decompress** **layer** **access** **need**.\
**image** **layer** **decompress** **all** **directory** **image** **decompress** **execute** **vItlhutlh**:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials from memory

Note that when you run a docker container inside a host **you can see the processes running on the container from the host** just running `ps -ef`

Therefore (as root) you can **dump the memory of the processes** from the host and search for **credentials** just [**like in the following example**](../../linux-hardening/privilege-escalation/#process-memory).

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
