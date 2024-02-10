# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vItlhutlh 'ej **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Access Control List (ACL)**

ghItlhvam Access Control List (ACL) consists of an ordered set of Access Control Entries (ACEs) that dictate the protections for an object and its properties. In essence, an ACL defines which actions by which security principals (users or groups) are permitted or denied on a given object.

Duj lo'laHbe'chugh ACLmey:

- **Discretionary Access Control List (DACL):** Specifies which users and groups have or do not have access to an object.
- **System Access Control List (SACL):** Governs the auditing of access attempts to an object.

The process of accessing a file involves the system checking the object's security descriptor against the user's access token to determine if access should be granted and the extent of that access, based on the ACEs.

### **Key Components**

- **DACL:** Contains ACEs that grant or deny access permissions to users and groups for an object. It's essentially the main ACL that dictates access rights.

- **SACL:** Used for auditing access to objects, where ACEs define the types of access to be logged in the Security Event Log. This can be invaluable for detecting unauthorized access attempts or troubleshooting access issues.

### **System Interaction with ACLs**

Each user session is associated with an access token that contains security information relevant to that session, including user, group identities, and privileges. This token also includes a logon SID that uniquely identifies the session.

The Local Security Authority (LSASS) processes access requests to objects by examining the DACL for ACEs that match the security principal attempting access. Access is immediately granted if no relevant ACEs are found. Otherwise, LSASS compares the ACEs against the security principal's SID in the access token to determine access eligibility.

### **Summarized Process**

- **ACLs:** Define access permissions through DACLs and audit rules through SACLs.
- **Access Token:** Contains user, group, and privilege information for a session.
- **Access Decision:** Made by comparing DACL ACEs with the access token; SACLs are used for auditing.


### ACEs

There arey **three main types of Access Control Entries (ACEs)**:

- **Access Denied ACE**: This ACE explicitly denies access to an object for specified users or groups (in a DACL).
- **Access Allowed ACE**: This ACE explicitly grants access to an object for specified users or groups (in a DACL).
- **System Audit ACE**: Positioned within a System Access Control List (SACL), this ACE is responsible for generating audit logs upon access attempts to an object by users or groups. It documents whether access was allowed or denied and the nature of the access.

Each ACE has **four critical components**:

1. The **Security Identifier (SID)** of the user or group (or their principal name in a graphical representation).
2. A **flag** that identifies the ACE type (access denied, allowed, or system audit).
3. **Inheritance flags** that determine if child objects can inherit the ACE from their parent.
4. An **[access mask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, a 32-bit value specifying the object's granted rights.

Access determination is conducted by sequentially examining each ACE until:

- An **Access-Denied ACE** explicitly denies the requested rights to a trustee identified in the access token.
- **Access-Allowed ACE(s)** explicitly grant all requested rights to a trustee in the access token.
- Upon checking all ACEs, if any requested right has **not been explicitly allowed**, access is implicitly **denied**.


### Order of ACEs

The way **ACEs** (rules that say who can or cannot access something) are put in a list called **DACL** is very important. This is because once the system gives or denies access based on these rules, it stops looking at the rest.

There is a best way to organize these ACEs, and it is called **"canonical order."** This method helps make sure everything works smoothly and fairly. Here is how it goes for systems like **Windows 2000** and **Windows Server 2003**:

- First, put all the rules that are made **specifically for this item** before the ones that come from somewhere else, like a parent folder.
- In those specific rules, put the ones that say **"no" (deny)** before the ones that say **"yes" (allow)**.
- For the rules that come from somewhere else, start with the ones from the **closest source**, like the parent, and then go back from there. Again, put **"no"** before **"yes."**

This setup helps in two big ways:

* It makes sure that if there is a specific **"no,"** it is respected, no matter what other **"yes"** rules are there.
* It lets the owner of an item have the **final say** on who gets in, before any rules from parent folders or further back come into play.

By doing things this way, the owner of a file or folder can be very precise about who gets access, making sure the right people can get in and the wrong ones can't.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

So, this **"canonical order"** is all about making sure the access rules are clear and work well, putting specific rules first and organizing everything in a smart way.


<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vItlhutlh 'ej **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### GUI Example

**[Example from here](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

**QaQ** vItlhutlhla' **ghItlh** pagh **Advanced button** vItlhutlh:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

'ej **Security Principal** chelwI' vItlhutlh:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

'ej **SACL** Auditing pagh:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Access Control jatlh

ghItlh resources, 'ej folder, jatlhmeH lists 'ej rules, 'ej Access Control Lists (ACLs) 'ej Access Control Entries (ACEs) jatlh. cha'logh vItlhutlh vay' Data vay' vItlhutlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatlhmeH jatl
