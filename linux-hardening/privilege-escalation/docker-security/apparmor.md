# AppArmor

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basic Information

AppArmor is a **kernel enhancement designed to restrict the resources available to programs through per-program profiles**, effectively implementing Mandatory Access Control (MAC) by tying access control attributes directly to programs instead of users. This system operates by **loading profiles into the kernel**, usually during boot, and these profiles dictate what resources a program can access, such as network connections, raw socket access, and file permissions.

There are two operational modes for AppArmor profiles:

- **Enforcement Mode**: This mode actively enforces the policies defined within the profile, blocking actions that violate these policies and logging any attempts to breach them through systems like syslog or auditd.
- **Complain Mode**: Unlike enforcement mode, complain mode does not block actions that go against the profile's policies. Instead, it logs these attempts as policy violations without enforcing restrictions.

### Components of AppArmor

- **Kernel Module**: Responsible for the enforcement of policies.
- **Policies**: Specify the rules and restrictions for program behavior and resource access.
- **Parser**: Loads policies into the kernel for enforcement or reporting.
- **Utilities**: These are user-mode programs that provide an interface for interacting with and managing AppArmor.

### Profiles path

Apparmor profiles are usually saved in _**/etc/apparmor.d/**_\
With `sudo aa-status` you will be able to list the binaries that are restricted by some profile. If you can change the char "/" for a dot of the path of each listed binary and you will obtain the name of the apparmor profile inside the mentioned folder.

For example, a **apparmor** profile for _/usr/bin/man_ will be located in _/etc/apparmor.d/usr.bin.man_

### Commands
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## tlhegh

* **tlheghmey** (absolute paths and wildcards) **ghaH** **ghItlh** (file globbing) **ghaH** **tlheghmey** **ghaH** **ghItlh** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **ghaH** **gha
```bash
sudo aa-genprof /path/to/binary
```
DaH, vItlhutlh. vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh v
```bash
/path/to/binary -a dosomething
```
DaH, cha'logh vItlhutlh "**s**" 'ej vItlhutlh recorded actions vItlhutlh 'e' vItlhutlh, 'ej vItlhutlh "**f**" 'ej _/etc/apparmor.d/path.to.binary_ created profile new will be. 

{% hint style="info" %}
arrow keys vItlhutlh allow/deny/whatever vItlhutlh 'e' vItlhutlh
{% endhint %}

### aa-easyprof

You can also create a template of an apparmor profile of a binary with:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
ghItlhvam, 'e' vItlhutlh. 'e' vItlhutlh, 'ej 'e' vItlhutlh. 'e' vItlhutlh, `/etc/passwd r,` vItlhutlh `/etc/passwd` binary read.
{% endhint %}

ghItlhvam, **ghItlh** vItlhutlh.
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### logs vItlhutlh

logmey tool vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhut
```bash
sudo aa-logprof
```
{% hint style="info" %}
Qa'vIn 'ej qeylIS qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS 'ej qeylIS
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Example of **AUDIT** and **DENIED** logs from _/var/log/audit/audit.log_ of the executable **`service_bin`**:

```
## Logs

Example of **AUDIT** and **DENIED** logs from _/var/log/audit/audit.log_ of the executable **`service_bin`**:
```
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
bI'vam vItlhutlh.:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id> | grep "AppArmorProfile"
```

DaH jImej:

```
docker inspect <container_id
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

**docker-profile**-n profile **docker**-Daq yIlo'laHbe'chugh:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
By default **Apparmor docker-default profile** is generated from [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profile Summary**:

* **Access** to all **networking**
* **No capability** is defined (However, some capabilities will come from including basic base rules i.e. #include \<abstractions/base> )
* **Writing** to any **/proc** file is **not allowed**
* Other **subdirectories**/**files** of /**proc** and /**sys** are **denied** read/write/lock/link/execute access
* **Mount** is **not allowed**
* **Ptrace** can only be run on a process that is confined by **same apparmor profile**

Once you **run a docker container** you should see the following output:
```bash
1 processes are in enforce mode.
docker-default (825)
```
**apparmor vItlhutlh** **container**-Daq **capabilities privileges** **block**. **jatlh**, **SYS\_ADMIN capability** **ghaH** **/proc** **ghItlh** **write permission** **block** **Docker apparmor profile** **ghItlh** **access** **deny** **vItlhutlh**.
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
**apparmor** jatlh **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qaybta'** **qayb
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Qapla'! **AppArmor** jatlhlaH **container** qachDaq **mount** **forbid** **default** **SYS\_ADMIN capability** vaj.

Qapla'! **capabilities** **add/remove** **Docker container** (ghaH **AppArmor** **Seccomp** protection methods **restricted**):

* `--cap-add=SYS_ADMIN` **SYS_ADMIN** cap **ghoD**
* `--cap-add=ALL` **all caps** **ghoD**
* `--cap-drop=ALL --cap-add=SYS_PTRACE` **all caps** **drop** **SYS_PTRACE** **ghoD**

{% hint style="info" %}
**usually**, **find** **privileged capability** **available** **inside** **docker** container **but** **exploit isn't working**, **docker apparmor** **preventing**.
{% endhint %}

### Example

(Example from [**here**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

**AppArmor** functionality **illustrate** **Example** **created** **Docker profile** "mydocker" **following line** **added**:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
To activate the profile, we need to do the following:

```
1. Open the terminal and navigate to the directory where the AppArmor profile is located.
2. Use the `apparmor_parser` command to load the profile into the kernel. For example:
   ```
   sudo apparmor_parser -r -W /path/to/profile
   ```
   Replace `/path/to/profile` with the actual path to the profile file.
3. Verify that the profile is loaded by running the `apparmor_status` command. You should see the profile listed under the "profiles" section.
4. Restart the Docker daemon to apply the changes:
   ```
   sudo systemctl restart docker
   ```
   Note: This step is necessary for the changes to take effect.
5. Test the profile by running the Docker container that is associated with the profile. If the profile is properly configured, it should enforce the specified restrictions and prevent any unauthorized actions.
```
```
sudo apparmor_parser -r -W mydocker
```
To list the profiles, we can do the following command. The command below is listing my new AppArmor profile.

```
$ sudo apparmor_status
```

The output should include the name of the profile you created.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
**AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor** **AppArmor**
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

**apparmor profile jImej** **container** **running** **vetlh** **apparmor profile** **Docker** **bIyajbe'** **jImej** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile** **running** **container** **vetlh** **ghItlh** **Docker** **bIyajbe'** **apparmor profile**
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
**DaH, bIquvmoH** **ghItlh** **profile** **ghaH** **Dajatlh** **DIvI'** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DIvI'** **ghaH** **Dajatlh** **DI
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmor jup path based**, jup means that even if it might be **protecting** files inside a directory like **`/proc`** if you can **configure how the container is going to be run**, you could **mount** the proc directory of the host inside **`/host/proc`** and it **won't be protected by AppArmor anymore**.

### AppArmor Shebang Bypass

In [**this bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) you can see an example of how **even if you are preventing perl to be run with certain resources**, if you just create a a shell script **specifying** in the first line **`#!/usr/bin/perl`** and you **execute the file directly**, you will be able to execute whatever you want. E.g.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
