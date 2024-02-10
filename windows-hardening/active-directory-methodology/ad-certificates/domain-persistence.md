# AD CS Domain Persistence

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

It can be determined that a certificate is a CA certificate if several conditions are met:

- The certificate is stored on the CA server, with its private key secured by the machine's DPAPI, or by hardware such as a TPM/HSM if the operating system supports it.
- Both the Issuer and Subject fields of the certificate match the distinguished name of the CA.
- A "CA Version" extension is present in the CA certificates exclusively.
- The certificate lacks Extended Key Usage (EKU) fields.

To extract the private key of this certificate, the `certsrv.msc` tool on the CA server is the supported method via the built-in GUI. Nonetheless, this certificate does not differ from others stored within the system; thus, methods such as the [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) can be applied for extraction.

The certificate and private key can also be obtained using Certipy with the following command:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
**DaH jImej** `.pfx` **format**-Daq **CA certificate** je **private key**-vam **ghItlh**. [ForgeCert](https://github.com/GhostPack/ForgeCert) **ghItlh** **tools**-vam **valid certificates** **luq**.
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Qa'pla'! Certificate forgery laHlIj Daq 'e' vItlhutlh Active Directory authentication 'e' vItlhutlh. krbtgt vItlhutlh 'e' vItlhutlh certificate forgery 'e' vItlhutlh.
{% endhint %}

**valid** certificate 'e' vItlhutlh 'ej **root CA certificate valid** (5 to **10+ cha'logh**) vItlhutlh. **machines** vItlhutlh, **S4U2Self** vIleghlaHbe'chugh, attacker **maintain persistence on any domain machine** vItlhutlh.\
**certificates generated** 'e' vItlhutlh **cannot be revoked** vaj CA 'e' vItlhutlh.

## Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` object **CA certificates** vItlhutlh 'e' vItlhutlh 'ej Active Directory (AD) vItlhutlh. verification process **domain controller** involves checking `NTAuthCertificates` object **CA specified** Issuer field 'e' vItlhutlh **certificate**. match vItlhutlh authentication proceeds.

Self-signed CA certificate 'e' vItlhutlh 'ej `NTAuthCertificates` object 'e' attacker vItlhutlh, AD object vItlhutlh control vItlhutlh. normally, **Enterprise Admin** group members, **Domain Admins** 'ej **Administrators** **forest root’s domain** permission modify vItlhutlh. `NTAuthCertificates` object 'e' `certutil.exe` vIleghlaHbe'chugh `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` command, [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) vIleghlaHbe'chugh.

capability relevant 'e' vItlhutlh ForgeCert vItlhutlh dynamically generate certificates.

## Malicious Misconfiguration - DPERSIST3

**persistence** 'e' vItlhutlh **security descriptor modifications of AD CS** components. modifications 'e' vItlhutlh "[Domain Escalation](domain-escalation.md)" section 'e' vItlhutlh attacker vItlhutlh elevated access. includes "control rights" (WriteOwner/WriteDACL/etc.) sensitive components vItlhutlh:

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- **descendant AD object or container** **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (Certificate Templates container, Certification Authorities container, NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** default 'ej organization (Cert Publishers group 'ej members)

malicious implementation example vItlhutlh attacker, elevated permissions domain, **`WriteOwner`** permission **`User`** certificate template vItlhutlh, attacker principal vItlhutlh. exploit vItlhutlh, attacker **ownership** **`User`** template vItlhutlh. following, **`mspki-certificate-name-flag`** vItlhutlh **1** template 'ej **`ENROLLEE_SUPPLIES_SUBJECT`** vItlhutlh, user Subject Alternative Name provide vItlhutlh. subsequently, attacker **enroll** **template**, domain administrator name alternative name vItlhutlh, acquired certificate authentication DA vItlhutlh.


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
