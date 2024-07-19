# CGroup Namespace

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

## Basic Information

Cgroup namespace je funkcija Linux kernela koja pruža **izolaciju cgroup hijerarhija za procese koji se izvršavaju unutar namespace-a**. Cgroups, skraćeno za **kontrolne grupe**, su funkcija kernela koja omogućava organizovanje procesa u hijerarhijske grupe radi upravljanja i sprovođenja **ograničenja na sistemske resurse** kao što su CPU, memorija i I/O.

Iako cgroup namespace-i nisu poseban tip namespace-a kao što su drugi koje smo ranije diskutovali (PID, mount, network, itd.), oni su povezani sa konceptom izolacije namespace-a. **Cgroup namespace-i virtualizuju pogled na cgroup hijerarhiju**, tako da procesi koji se izvršavaju unutar cgroup namespace-a imaju drugačiji pogled na hijerarhiju u poređenju sa procesima koji se izvršavaju na hostu ili u drugim namespace-ima.

### How it works:

1. Kada se kreira novi cgroup namespace, **on počinje sa pogledom na cgroup hijerarhiju zasnovanom na cgroup-u procesa koji ga kreira**. To znači da će procesi koji se izvršavaju u novom cgroup namespace-u videti samo podskup cele cgroup hijerarhije, ograničen na cgroup podstablo koje se oslanja na cgroup procesa koji ga kreira.
2. Procesi unutar cgroup namespace-a će **videti svoju vlastitu cgroup kao koren hijerarhije**. To znači da, iz perspektive procesa unutar namespace-a, njihova vlastita cgroup se pojavljuje kao koren, i ne mogu videti ili pristupiti cgroup-ima van svog podstabla.
3. Cgroup namespace-i ne pružaju direktno izolaciju resursa; **oni samo pružaju izolaciju pogleda na cgroup hijerarhiju**. **Kontrola i izolacija resursa se i dalje sprovode od strane cgroup** pod sistema (npr., cpu, memorija, itd.) sami.

Za više informacija o CGroups proverite:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **tačnu i izolovanu sliku informacija o procesima specifičnim za tu imensku oblast**.

<details>

<summary>Greška: bash: fork: Ne može da dodeli memoriju</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Objašnjenje problema**:
- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Posledica**:
- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Rešenje**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Proverite u kojem je namespace vaš proces
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Pronađite sve CGroup imenske prostore

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Uđite unutar CGroup imenskog prostora
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u drugi procesni prostor imena samo ako ste root**. I **ne možete** **ući** u drugo ime prostora **bez deskriptora** koji na njega ukazuje (kao što je `/proc/self/ns/cgroup`).

## Reference
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
