<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# SELinux katika Kontena

[Utangulizi na mfano kutoka kwenye nyaraka za redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) ni **mfumo wa lebo**. Kila **mchakato** na kila **faili** kwenye mfumo una **lebo**. Sera za SELinux hutoa sheria juu ya kile **lebo ya mchakato inaruhusiwa kufanya na lebo zingine zote** kwenye mfumo.

Injini za kontena huzindua **mchakato wa kontena na lebo moja iliyozuiwa ya SELinux**, kawaida `container_t`, na kisha kuweka kontena ndani ya kontena kuwa na lebo `container_file_t`. Sheria za sera za SELinux kimsingi zinasema kuwa **mchakato wa `container_t` unaweza tu kusoma/kuandika/kutekeleza faili zenye lebo `container_file_t`**. Ikiwa mchakato wa kontena unafanikiwa kutoroka kutoka kwenye kontena na kujaribu kuandika kwenye yaliyomo kwenye mwenyeji, kernel ya Linux inakataa ufikiaji na inaruhusu mchakato wa kontena kuandika tu kwenye yaliyomo yenye lebo `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Watumiaji wa SELinux

Kuna watumiaji wa SELinux mbali na watumiaji wa kawaida wa Linux. Watumiaji wa SELinux ni sehemu ya sera ya SELinux. Kila mtumiaji wa Linux ameunganishwa na mtumiaji wa SELinux kama sehemu ya sera. Hii inaruhusu watumiaji wa Linux kuurithi vizuizi na sheria za usalama zilizowekwa kwa watumiaji wa SELinux.
