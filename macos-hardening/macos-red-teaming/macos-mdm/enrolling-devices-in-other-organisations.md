# qo'noSghaj

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>DaH jImej</strong></a><strong>!</strong></summary>

HackTricks ni qaparHa'lu'chugh, qatlh je 'oH **tlhInganpu'** **HackTricks** 'e' vItlhutlh. **SUBSCRIPTION PLANS** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **yIlo'!**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) yIghItlh
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) yIlo'lu' [**NFTs**](https://opensea.io/collection/the-peass-family) 'e' vItlhutlh
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Intro

[**previously commented**](./#what-is-mdm-mobile-device-management)**,** 'oH 'e' vItlhutlh **Serial Number** 'e' vItlhutlh **Organization** 'e' vItlhutlh **device** 'e' vItlhutlh **enrol**. **device** 'e' vItlhutlh **enrolled**, **organizations** **sensitive data** 'e' vItlhutlh **device**: **certificates**, **applications**, **WiFi passwords**, **VPN configurations** [**so on**](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
**attackers** 'e' vItlhutlh **enrolment process** **correctly protected** 'e' vItlhutlh **dangerous entrypoint**.

**The following is a summary of the research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Check it for further technical details!**

## Overview of DEP and MDM Binary Analysis

**`mdmclient`**: **MDM servers** 'e' vItlhutlh **DEP check-ins** **macOS versions** 10.13.4 **before** **triggers** **communicates**.
**`profiles`**: **Configuration Profiles** 'e' vItlhutlh **DEP check-ins** **macOS versions** 10.13.4 **later** **manages**.
**`cloudconfigurationd`**: **DEP API communications** 'e' vItlhutlh **manages** **retrieves Device Enrollment profiles**.

**DEP check-ins** **`CPFetchActivationRecord`** **`CPGetActivationRecord`** **functions** **Configuration Profiles framework** **fetch** **Activation Record**, **`CPFetchActivationRecord`** **`cloudconfigurationd`** **XPC** **coordinating**.

## Tesla Protocol and Absinthe Scheme Reverse Engineering

**DEP check-in** **`cloudconfigurationd`** **encrypted**, **signed JSON payload** **_iprofiles.apple.com/macProfile_** **sending**. **payload** **device's serial number** **action "RequestProfileConfiguration"** **includes**. **encryption scheme** **"Absinthe"** **referred** **complex** **numerous steps**, **exploring alternative methods** **inserting arbitrary serial numbers** **Activation Record request**.

## Proxying DEP Requests

**DEP requests** **_iprofiles.apple.com_** **intercept** **modify** **tools** **Charles Proxy** **hindered** **payload encryption** **SSL/TLS security measures**. **`MCCloudConfigAcceptAnyHTTPSCertificate`** **configuration** **bypassing** **server certificate validation** **enabling**, **payload's encrypted nature** **modification** **serial number** **decryption key**.

## Instrumenting System Binaries Interacting with DEP

**`cloudconfigurationd`** **system binaries** **instrumenting** **SIP** **disabling System Integrity Protection** **macOS**. **SIP disabled**, **LLDB** **attach** **system processes** **modify** **serial number** **DEP API interactions**. **method** **preferable** **avoids** **complexities** **entitlements** **code signing**.

**Exploiting Binary Instrumentation:**
**DEP request payload** **JSON serialization** **`cloudconfigurationd`** **proved effective**. **process**:

1. **LLDB** **`cloudconfigurationd`** **attaching**.
2. **system serial number** **fetched** **point** **Locating**.
3. **payload** **encrypted** **sent** **memory** **arbitrary serial number** **Injecting**.

**method** **allowed** **retrieving complete DEP profiles** **arbitrary serial numbers**, **demonstrating** **potential vulnerability**.

### Automating Instrumentation with Python

**exploitation process** **automated** **Python** **LLDB API** **feasible** **programmatically inject** **arbitrary serial numbers** **retrieve** **DEP profiles**.

### Potential Impacts of DEP and MDM Vulnerabilities

**research** **highlighted** **significant security concerns**:

1. **Information Disclosure**: **DEP-registered serial number** **providing**, **sensitive organizational information** **DEP profile** **retrieved**.
2. **Rogue DEP Enrollment**: **proper authentication**, **DEP-registered serial number** **attacker** **rogue device** **organization's MDM server** **enroll**, **gaining access** **sensitive data** **network resources**.

**conclusion**, **DEP and MDM** **provide powerful tools** **managing Apple devices** **enterprise environments**, **present potential attack vectors** **need to be secured and monitored**.



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>DaH jImej</strong></a><strong>!</strong></summary>

HackTricks ni qaparHa'lu'chugh, qatlh je 'oH **tlhInganpu'** **HackTricks** 'e' vItlhutlh. **SUBSCRIPTION PLANS** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **yIlo'!**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) yIghItlh
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) yIlo'lu' [**NFTs**](https://opensea.io/collection/the-peass-family) 'e' vItlhutlh
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
