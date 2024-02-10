# macOS Keychain

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Main Keychains

* The **User Keychain** (`~/Library/Keychains/login.keycahin-db`), which is used to store **user-specific credentials** like application passwords, internet passwords, user-generated certificates, network passwords, and user-generated public/private keys.
* The **System Keychain** (`/Library/Keychains/System.keychain`), which stores **system-wide credentials** such as WiFi passwords, system root certificates, system private keys, and system application passwords.

### Password Keychain Access

These files, while they do not have inherent protection and can be **downloaded**, are encrypted and require the **user's plaintext password to be decrypted**. A tool like [**Chainbreaker**](https://github.com/n0fate/chainbreaker) could be used for decryption.

## Keychain Entries Protections

### ACLs

Each entry in the keychain is governed by **Access Control Lists (ACLs)** which dictate who can perform various actions on the keychain entry, including:

* **ACLAuhtorizationExportClear**: Allows the holder to get the clear text of the secret.
* **ACLAuhtorizationExportWrapped**: Allows the holder to get the clear text encrypted with another provided password.
* **ACLAuhtorizationAny**: Allows the holder to perform any action.

The ACLs are further accompanied by a **list of trusted applications** that can perform these actions without prompting. This could be:

* &#x20;**N`il`** (no authorization required, **everyone is trusted**)
* An **empty** list (**nobody** is trusted)
* **List** of specific **applications**.

Also the entry might contain the key **`ACLAuthorizationPartitionID`,** which is use to identify the **teamid, apple,** and **cdhash.**

* If the **teamid** is specified, then in order to **access the entry** value **withuot** a **prompt** the used application must have the **same teamid**.
* If the **apple** is specified, then the app needs to be **signed** by **Apple**.
* If the **cdhash** is indicated, then **app** must have the specific **cdhash**.

### Creating a Keychain Entry

When a **new** **entry** is created using **`Keychain Access.app`**, the following rules apply:

* All apps can encrypt.
* **No apps** can export/decrypt (without prompting the user).
* All apps can see the integrity check.
* No apps can change ACLs.
* The **partitionID** is set to **`apple`**.

When an **application creates an entry in the keychain**, the rules are slightly different:

* All apps can encrypt.
* Only the **creating application** (or any other apps explicitly added) can export/decrypt (without prompting the user).
* All apps can see the integrity check.
* No apps can change the ACLs.
* The **partitionID** is set to **`teamid:[teamID here]`**.

## Accessing the Keychain

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
**LockSmith** (https://github.com/its-a-feature/LockSmith) **ghItlh** **keychain enumeration and dumping** **won't generate a prompt** **secrets** **'ej** **vItlhutlh**.
{% endhint %}

**keychain entry** **info** **list** **'ej** **jImej**:

* **`SecItemCopyMatching`** **API** **entry** **info** **ghItlh** **attributes** **vItlhutlh**:
* **`kSecReturnData`**: **true** **ghItlh** **data** **decrypt** **jatlh** (potential pop-ups **chIm** **false** **set**)
* **`kSecReturnRef`**: **keychain item** **reference** **ghItlh** **jImej** **(pop-up** **chIm** **decrypt** **jatlh** **jatlh** **true** **set**)
* **`kSecReturnAttributes`**: **entries** **metadata** **ghItlh** **jImej**
* **`kSecMatchLimit`**: **results** **jImej**
* **`kSecClass`**: **keychain entry** **kind**

**entry ACLs** **jImej** **'ej** **jImej**:

* **`SecAccessCopyACLList`** **API** **keychain item** **ACL** **ghItlh** **list** **jImej** **(ACLAuhtorizationExportClear** **'ej** **ghItlh** **list**) **'ej** **list** **jImej** **jImej**:
* **Description**
* **Trusted Application List**: **app**: /Applications/Slack.app, **binary**: /usr/libexec/airportd, **group**: group://AirPort

**data** **export**:

* **`SecKeychainItemCopyContent`** **API** **plaintext** **ghItlh**
* **`SecItemExport`** **API** **keys** **certificates** **export** **jImej** **content** **encrypted** **ghItlh** **passwords** **set** **jImej**

**requirements** **export** **secret** **prompt** **chIm**:

* **1+ trusted** **apps** **listed**:
* **appropriate authorizations** **chIm** (**`Nil`**, **allowed** **list** **apps** **authorization** **access** **secret info** **part** **be**)
* **code signature** **PartitionID** **match** **chIm**
* **code signature** **trusted app** **match** **chIm** **(right KeychainAccessGroup** **member** **be**)
* **all applications trusted** **chIm**:
* **appropriate authorizations** **chIm**
* **code signature** **PartitionID** **match** **chIm**
* **PartitionID** **chIm**, **chIm** **needed**

{% hint style="danger" %}
**1 application listed** **chIm**, **code** **inject** **application** **chIm** **need**.

**apple** **PartitionID** **chIm**, **`osascript`** **access** **chIm** **apple** **partitionID** **trust** **applications** **anything**. **`Python`** **chIm** **be**.
{% endhint %}

### **Two additional attributes**

* **Invisible**: **entry** **UI** **Keychain app** **hide** **boolean flag**
* **General**: **metadata** **store** **chIm** (NOT ENCRYPTED)
* **Microsoft** **refresh tokens** **access** **sensitive endpoint** **plain text** **store**.

## References

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
