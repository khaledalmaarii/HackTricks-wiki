# macOS Dirty NIB

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qa'vIn AWS hacking jatlh</strong></a><strong>!</strong></summary>

HackTricks vItlhutlh:

* **HackTricks vItlhutlh** vaj **HackTricks PDF** laH **tlhIngan Hol** **company advertise** 'ej **SUBSCRIPTION PLANS** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **check**!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **exclusive** **collection** **our**
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **or the** [**telegram group**](https://t.me/peass) **or** **follow** **us on** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **and** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>

**[https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) **original post** **the technique** **about detail further For** **the** **Check**.

NIB files, Apple's development ecosystem, **UI elements** **defining** **for intended** **are files NIB**. They serialized objects such as windows and buttons, and are loaded at runtime. Apple now advocates for Storyboards for more comprehensive UI flow visualization.

### Security Concerns with NIB Files
**NIB files can be a security risk** **to note that**. They have the potential to **execute arbitrary commands**, and alterations to NIB files within an app don't hinder Gatekeeper from executing the app, posing a significant threat.

### Dirty NIB Injection Process
#### Creating and Setting Up a NIB File
1. **Initial Setup**:
- Create a new NIB file using XCode.
- Add an Object to the interface, setting its class to `NSAppleScript`.
- Configure the initial `source` property via User Defined Runtime Attributes.

2. **Code Execution Gadget**:
- The setup facilitates running AppleScript on demand.
- Integrate a button to activate the `Apple Script` object, specifically triggering the `executeAndReturnError:` selector.

3. **Testing**:
- A simple Apple Script for testing purposes:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- Test by running in the XCode debugger and clicking the button.

#### Targeting an Application (Example: Pages)
1. **Preparation**:
- Copy the target app (e.g., Pages) into a separate directory (e.g., `/tmp/`).
- Initiate the app to sidestep Gatekeeper issues and cache it.

2. **Overwriting NIB File**:
- Replace an existing NIB file (e.g., About Panel NIB) with the crafted DirtyNIB file.

3. **Execution**:
- Trigger the execution by interacting with the app (e.g., selecting the `About` menu item).

#### Proof of Concept: Accessing User Data
- Modify the AppleScript to access and extract user data, such as photos, without user consent.

### Code Sample: Malicious .xib File
- Access and review a [**sample of a malicious .xib file**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) that demonstrates executing arbitrary code.

### Addressing Launch Constraints
- Launch Constraints hinder app execution from unexpected locations (e.g., `/tmp`).
- It's possible to identify apps not protected by Launch Constraints and target them for NIB file injection.

### Additional macOS Protections
From macOS Sonoma onwards, modifications inside App bundles are restricted. However, earlier methods involved:
1. Copying the app to a different location (e.g., `/tmp/`).
2. Renaming directories within the app bundle to bypass initial protections.
3. After running the app to register with Gatekeeper, modifying the app bundle (e.g., replacing MainMenu.nib with Dirty.nib).
4. Renaming directories back and rerunning the app to execute the injected NIB file.

**Note**: Recent macOS updates have mitigated this exploit by preventing file modifications within app bundles post Gatekeeper caching, rendering the exploit ineffective.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qa'vIn AWS hacking jatlh</strong></a><strong>!</strong></summary>

HackTricks vItlhutlh:

* **HackTricks vItlhutlh** vaj **HackTricks PDF** laH **tlhIngan Hol** **company advertise** 'ej **SUBSCRIPTION PLANS** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **check**!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **exclusive** **collection** **our**
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **or the** [**telegram group**](https://t.me/peass) **or** **follow** **us on** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **and** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
