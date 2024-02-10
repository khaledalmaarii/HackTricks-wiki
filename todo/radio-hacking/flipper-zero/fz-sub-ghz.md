# FZ - Sub-GHz

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>tlhIngan Hol</strong></a><strong>!</strong></summary>

HackTricks yuQjIjDI' 'e' vItlhutlh.:
* **tlhIngan Hol** 'ej **HackTricks** PDF **ghItlh** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) qaStaHvIS.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) ghom.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) 'ej [**NFTs**](https://opensea.io/collection/the-peass-family) ghom.
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) 'ej [**telegram group**](https://t.me/peass) 'ej **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) 'ej [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

vItlhutlh 'e' vItlhutlh. Intruder vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhutlh, vItlhut
### Supported Sub-GHz vendors

Check the list in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Supported Frequencies by region

Check the list in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Get dBms of the saved frequencies
{% endhint %}

## Reference

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
