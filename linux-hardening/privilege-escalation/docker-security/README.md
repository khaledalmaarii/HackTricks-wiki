# Docker Security

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Basic Docker Engine Security**

The **Docker engine** employs the Linux kernel's **Namespaces** and **Cgroups** to isolate containers, offering a basic layer of security. Additional protection is provided through **Capabilities dropping**, **Seccomp**, and **SELinux/AppArmor**, enhancing container isolation. An **auth plugin** can further restrict user actions.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Secure Access to Docker Engine

The Docker engine can be accessed either locally via a Unix socket or remotely using HTTP. For remote access, it's essential to employ HTTPS and **TLS** to ensure confidentiality, integrity, and authentication.

The Docker engine, by default, listens on the Unix socket at `unix:///var/run/docker.sock`. On Ubuntu systems, Docker's startup options are defined in `/etc/default/docker`. To enable remote access to the Docker API and client, expose the Docker daemon over an HTTP socket by adding the following settings:

---

# Docker Security

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Basic Docker Engine Security**

The **Docker engine** employs the Linux kernel's **Namespaces** and **Cgroups** to isolate containers, offering a basic layer of security. Additional protection is provided through **Capabilities dropping**, **Seccomp**, and **SELinux/AppArmor**, enhancing container isolation. An **auth plugin** can further restrict user actions.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Secure Access to Docker Engine

The Docker engine can be accessed either locally via a Unix socket or remotely using HTTP. For remote access, it's essential to employ HTTPS and **TLS** to ensure confidentiality, integrity, and authentication.

The Docker engine, by default, listens on the Unix socket at `unix:///var/run/docker.sock`. On Ubuntu systems, Docker's startup options are defined in `/etc/default/docker`. To enable remote access to the Docker API and client, expose the Docker daemon over an HTTP socket by adding the following settings:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
However, exposing the Docker daemon over HTTP is not recommended due to security concerns. It's advisable to secure connections using HTTPS. There are two main approaches to securing the connection:
1. The client verifies the server's identity.
2. Both the client and server mutually authenticate each other's identity.

Certificates are utilized to confirm a server's identity. For detailed examples of both methods, refer to [**this guide**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Security of Container Images

Container images can be stored in either private or public repositories. Docker offers several storage options for container images:

* **[Docker Hub](https://hub.docker.com)**: A public registry service from Docker.
* **[Docker Registry](https://github.com/docker/distribution)**: An open-source project allowing users to host their own registry.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Docker's commercial registry offering, featuring role-based user authentication and integration with LDAP directory services.

### Image Scanning

Containers can have **security vulnerabilities** either because of the base image or because of the software installed on top of the base image. Docker is working on a project called **Nautilus** that does security scan of Containers and lists the vulnerabilities. Nautilus works by comparing the each Container image layer with vulnerability repository to identify security holes.

For more [**information read this**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

The **`docker scan`** command allows you to scan existing Docker images using the image name or ID. For example, run the following command to scan the hello-world image:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker Image Signing

Docker image signing ensures the security and integrity of images used in containers. Here's a condensed explanation:

- **Docker Content Trust** utilizes the Notary project, based on The Update Framework (TUF), to manage image signing. For more info, see [Notary](https://github.com/docker/notary) and [TUF](https://theupdateframework.github.io).
- To activate Docker content trust, set `export DOCKER_CONTENT_TRUST=1`. This feature is off by default in Docker version 1.10 and later.
- With this feature enabled, only signed images can be downloaded. Initial image push requires setting passphrases for the root and tagging keys, with Docker also supporting Yubikey for enhanced security. More details can be found [here](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Attempting to pull an unsigned image with content trust enabled results in a "No trust data for latest" error.
- For image pushes after the first, Docker asks for the repository key's passphrase to sign the image.

To back up your private keys, use the command:

```
docker trust key backup
```
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Docker hosts jImejDaq 'e'elDI'pu' 'ej repository keys jImejDaq 'e'elDI'pu' 'e' vItlhutlh. 

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vItlhutlh 'ej **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Containers Security Features

<details>

<summary>Summary of Container Security Features</summary>

### Main Process Isolation Features

In containerized environments, isolating projects and their processes is paramount for security and resource management. Here's a simplified explanation of key concepts:

#### **Namespaces**
- **Purpose**: Ensure isolation of resources like processes, network, and filesystems. Particularly in Docker, namespaces keep a container's processes separate from the host and other containers.
- **Usage of `unshare`**: The `unshare` command (or the underlying syscall) is utilized to create new namespaces, providing an added layer of isolation. However, while Kubernetes doesn't inherently block this, Docker does.
- **Limitation**: Creating new namespaces doesn't allow a process to revert to the host's default namespaces. To penetrate the host namespaces, one would typically require access to the host's `/proc` directory, using `nsenter` for entry.

#### **Control Groups (CGroups)**
- **Function**: Primarily used for allocating resources among processes.
- **Security Aspect**: CGroups themselves don't offer isolation security, except for the `release_agent` feature, which, if misconfigured, could potentially be exploited for unauthorized access.

#### **Capability Drop**
- **Importance**: It's a crucial security feature for process isolation.
- **Functionality**: It restricts the actions a root process can perform by dropping certain capabilities. Even if a process runs with root privileges, lacking the necessary capabilities prevents it from executing privileged actions, as the syscalls will fail due to insufficient permissions.

These are the **remaining capabilities** after the process drop the others:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Docker jenbogh Seccomp. QaStaHvIS syscalls process call.\
Docker Seccomp profile [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) Daq yIqaw.

**AppArmor**

Docker template [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) Daq yIqaw.

</details>

### Namespaces

**Namespaces** Linux kernel feature 'ej partitions kernel resources. 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej 'oH 'ej 'ej
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
To get the cgroup of a container you can do:

```
docker inspect --format='{{.State.Pid}}' <container_id>
```

This will return the process ID (PID) of the container.
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
For more information check:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilities allow **finer control for the capabilities that can be allowed** for root user. Docker uses the Linux kernel capability feature to **limit the operations that can be done inside a Container** irrespective of the type of user.

When a docker container is run, the **process drops sensitive capabilities that the proccess could use to escape from the isolation**. This try to assure that the proccess won't be able to perform sensitive actions and escape:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp in Docker

This is a security feature that allows Docker to **limit the syscalls** that can be used inside the container:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor in Docker

**AppArmor** is a kernel enhancement to confine **containers** to a **limited** set of **resources** with **per-program profiles**.:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux in Docker

- **Labeling System**: SELinux assigns a unique label to every process and filesystem object.
- **Policy Enforcement**: It enforces security policies that define what actions a process label can perform on other labels within the system.
- **Container Process Labels**: When container engines initiate container processes, they are typically assigned a confined SELinux label, commonly `container_t`.
- **File Labeling within Containers**: Files within the container are usually labeled as `container_file_t`.
- **Policy Rules**: The SELinux policy primarily ensures that processes with the `container_t` label can only interact (read, write, execute) with files labeled as `container_file_t`.

This mechanism ensures that even if a process within a container is compromised, it's confined to interacting only with objects that have the corresponding labels, significantly limiting the potential damage from such compromises.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

In Docker, an authorization plugin plays a crucial role in security by deciding whether to allow or block requests to the Docker daemon. This decision is made by examining two key contexts:

- **Authentication Context**: This includes comprehensive information about the user, such as who they are and how they've authenticated themselves.
- **Command Context**: This comprises all pertinent data related to the request being made.

These contexts help ensure that only legitimate requests from authenticated users are processed, enhancing the security of Docker operations.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS from a container

If you are not properly limiting the resources a container can use, a compromised container could DoS the host where it's running.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
# *Bandwidth DoS*

## Description

A Bandwidth Denial of Service (DoS) attack is a type of attack that aims to consume the available bandwidth of a network or a specific target, rendering it inaccessible to legitimate users. This type of attack can be highly disruptive and can effectively bring down a network or a specific service.

## How it Works

In a Bandwidth DoS attack, the attacker floods the target network or service with a large volume of traffic, overwhelming its capacity to handle the incoming requests. This can be achieved by sending a high number of requests or by exploiting vulnerabilities in network protocols or applications.

The attack can be launched from a single source or from multiple sources, making it difficult to trace the origin of the attack. The attacker may use botnets or compromised devices to amplify the attack and increase its impact.

## Impact

The impact of a Bandwidth DoS attack can be severe. By consuming all available bandwidth, the attack can effectively render a network or service inaccessible to legitimate users. This can result in financial losses, reputational damage, and disruption of critical services.

## Mitigation

To mitigate the risk of a Bandwidth DoS attack, it is important to implement proper network security measures. This can include:

- Implementing traffic filtering and rate limiting mechanisms to detect and block malicious traffic.
- Monitoring network traffic for anomalies and suspicious patterns.
- Regularly updating and patching network devices and applications to address vulnerabilities.
- Implementing network segmentation to limit the impact of an attack.
- Deploying intrusion detection and prevention systems to detect and block malicious activity.

By implementing these measures, organizations can reduce the risk of a Bandwidth DoS attack and ensure the availability and integrity of their network and services.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## QaStaHvIS Docker Flags

### --privileged Qa'

**'--privileged' flag** **nuqneH** **jImej** **'e' vItlhutlh**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

**container Hoch** **low privilege user** **ghaH** **ghItlh** **'e'** **Suid binary** **vItlhutlh** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### lo'laHbe' 

Docker is a popular containerization platform that allows you to run applications in isolated environments called containers. While Docker provides many security features out of the box, it is still important to harden your Docker environment to prevent unauthorized access and potential privilege escalation.

Here are some best practices for securing your Docker environment:

1. **Use Official Images**: Always use official Docker images from trusted sources. These images are regularly updated and maintained, reducing the risk of vulnerabilities.

2. **Update Regularly**: Keep your Docker installation and images up to date with the latest security patches. This helps protect against known vulnerabilities.

3. **Enable Content Trust**: Enable Docker Content Trust to ensure the integrity and authenticity of your images. This prevents the use of tampered or malicious images.

4. **Limit Privileges**: Avoid running containers with root privileges. Instead, use non-root users with restricted permissions whenever possible.

5. **Isolate Containers**: Use Docker's network and storage isolation features to prevent containers from accessing sensitive resources or data.

6. **Secure Docker Daemon**: Restrict access to the Docker daemon by using strong authentication mechanisms, such as TLS certificates or token-based authentication.

7. **Monitor Container Activity**: Regularly monitor container activity and log files for any suspicious behavior or unauthorized access attempts.

8. **Implement Network Segmentation**: Use network segmentation to isolate Docker containers from other critical systems and services.

9. **Implement Resource Limits**: Set resource limits for containers to prevent resource exhaustion attacks and ensure fair resource allocation.

10. **Regularly Audit and Remove Unused Images**: Regularly audit your Docker environment for unused or unnecessary images and containers. Remove them to reduce the attack surface.

By following these best practices, you can enhance the security of your Docker environment and minimize the risk of privilege escalation or unauthorized access.
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
**`--security-opt`** options check: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Other Security Considerations

### Managing Secrets: Best Practices

It's crucial to avoid embedding secrets directly in Docker images or using environment variables, as these methods expose your sensitive information to anyone with access to the container through commands like `docker inspect` or `exec`.

**Docker volumes** are a safer alternative, recommended for accessing sensitive information. They can be utilized as a temporary filesystem in memory, mitigating the risks associated with `docker inspect` and logging. However, root users and those with `exec` access to the container might still access the secrets.

**Docker secrets** offer an even more secure method for handling sensitive information. For instances requiring secrets during the image build phase, **BuildKit** presents an efficient solution with support for build-time secrets, enhancing build speed and providing additional features.

To leverage BuildKit, it can be activated in three ways:

1. Through an environment variable: `export DOCKER_BUILDKIT=1`
2. By prefixing commands: `DOCKER_BUILDKIT=1 docker build .`
3. By enabling it by default in the Docker configuration: `{ "features": { "buildkit": true } }`, followed by a Docker restart.

BuildKit allows for the use of build-time secrets with the `--secret` option, ensuring these secrets are not included in the image build cache or the final image, using a command like:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
For secrets needed in a running container, **Docker Compose and Kubernetes** offer robust solutions. Docker Compose utilizes a `secrets` key in the service definition for specifying secret files, as shown in a `docker-compose.yml` example:

---

**Klingon Translation:**

DaH jImejDaq containers vItlhutlh **Docker Compose je Kubernetes** Hoch. Docker Compose, `secrets` key vIlo'laHbe'chugh service definition vItlhutlh secret files jatlh, 'ej 'ejay' `docker-compose.yml` example:

---
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
**tlhIngan Hol:**

**Docker Compose** jatlhlaHbe'chugh **secrets** lo'laHbe'chugh **services** jatlhlaHbe'.

Kubernetes qay'be'wI'pu' **secrets** native vItlhutlh. [Helm-Secrets](https://github.com/futuresimple/helm-secrets) vItlhutlhlaHbe'chugh **tools** vItlhutlhlaHbe'. Kubernetes' Role Based Access Controls (RBAC) **secret management security** vItlhutlhlaHbe'chugh, Docker Enterprise vItlhutlhlaHbe'.

### gVisor

**gVisor** Go vItlhutlhlaHbe'chugh **application kernel** vItlhutlhlaHbe'. **Linux system surface** vItlhutlhlaHbe'. **Open Container Initiative (OCI)** runtime **runsc** vItlhutlhlaHbe' **isolation boundary** **application** 'ej **host kernel** vItlhutlhlaHbe'. **runsc** runtime Docker 'ej Kubernetes vItlhutlhlaHbe' **sandboxed containers** vItlhutlhlaHbe'.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** **open source community** vItlhutlhlaHbe'chugh **secure container runtime** vItlhutlhlaHbe'. **lightweight virtual machines** vItlhutlhlaHbe'chugh **stronger workload isolation** vItlhutlhlaHbe'chugh **hardware virtualization** technology vItlhutlhlaHbe'chugh **second layer of defense** vItlhutlhlaHbe'.

{% embed url="https://katacontainers.io/" %}

### Summary Tips

* **--privileged** flag **Docker socket** **mount** **Do not use**. Docker socket vItlhutlhlaHbe'chugh containers **spawn** vItlhutlhlaHbe', 'ej **host** **full control** **take** **easy way** vItlhutlhlaHbe', **another container** **--privileged** flag vItlhutlhlaHbe'.
* **root** **container** **run** **Do not**. **Different user** 'ej **user namespaces** vItlhutlhlaHbe'. root container vItlhutlhlaHbe'chugh host vItlhutlhlaHbe' **same** **remapped** user namespaces vItlhutlhlaHbe'. Linux namespaces, capabilities, 'ej cgroups vItlhutlhlaHbe'chugh **lightly restricted**.
* **Drop all capabilities** **(--cap-drop=all)** **enable** **required**. **workloads** **capabilities** vItlhutlhlaHbe'chugh **need** **adding** **increase** **potential attack**.
* **no-new-privileges** **security option** **Use** **prevent** **processes** **gaining** **privileges**. **suid binaries** vItlhutlhlaHbe'chugh **example** **through** **attacks**.
* **Limit resources** **container** **available**. Resource limits vItlhutlhlaHbe'chugh **machine** **denial of service attacks**.
* **seccomp**, **AppArmor** (or SELinux) profiles vItlhutlhlaHbe'chugh **restrict** **actions** **syscalls** **container** **minimum required**.
* **official docker images** **Use** **require signatures** **build** **based**. **backdoored** images vItlhutlhlaHbe'chugh **inherit** **use**. root keys, passphrase vItlhutlhlaHbe'chugh **safe place**. Docker vItlhutlhlaHbe'chugh **manage keys** UCP.
* **Regularly rebuild** **images** **apply security patches** **host an images**.
* **secrets wisely** **Manage** **difficult** **attacker** **access**.
* **exposes** **docker daemon** **HTTPS** **client & server authentication**.
* Dockerfile vItlhutlhlaHbe'chugh **COPY** **ADD** **favor**. ADD vItlhutlhlaHbe'chugh **automatically extracts** **zipped files** 'ej **copy files** **URLs**. COPY vItlhutlhlaHbe'chugh **capabilities**. ADD vItlhutlhlaHbe'chugh **susceptible** **attacks** **remote URLs** **Zip files**.
* **separate containers** **micro-services**
* **Don't put ssh** **container**, "docker exec" vItlhutlhlaHbe'chugh **ssh** **Container**.
* **smaller** **container images**

## Docker Breakout / Privilege Escalation

**Docker container** vItlhutlhlaHbe'chugh **inside** **access** **docker group user** vItlhutlhlaHbe'chugh **escape** 'ej **escalate privileges** **try**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker Authentication Plugin Bypass

**docker socket** **access** **docker group user** vItlhutlhlaHbe'chugh **docker auth plugin** **actions** **limited** **check** **bypass** **can**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Hardening Docker

* **docker-bench-security** **tool** vItlhutlhlaHbe'chugh **dozens of common best-practices** **deploying Docker containers** **production**. Tests vItlhutlhlaHbe'chugh **automated**, 'ej **CIS Docker Benchmark v1.3.1** vItlhutlhlaHbe'chugh **based**.\
**README** **run** **tool** **host running docker** **container** **enough privileges** **Find out** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## References

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker
**HackTricks**'a yIbuS:

* **HackTricks** **yIghItlhvam** 'ej **HackTricks PDF** **ghItlhvam** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **chaw'}'a'**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **ghItlhvam**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **ghItlhvam** **NFTs** [**opensea.io**](https://opensea.io/collection/the-peass-family) **ghItlhvam**
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **joq** **telegram group**](https://t.me/peass) **'ej** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **HackTricks** **'ej** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **ghItlhvam** **Hacking tricks** **ghItlhvam** **submit** **PRs** **ghItlhvam**.
