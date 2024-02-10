# macOS Serial Number

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qa'vIn AWS hacking vItlhutlh</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* **HackTricks vItlhutlh** pe'vIl **company advertised** 'ej **HackTricks PDF download** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **qaStaHvIS**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **ghItlh**.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **ghItlh** [**NFTs**](https://opensea.io/collection/the-peass-family) **ghItlh**.
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **join** 'ej [**telegram group**](https://t.me/peass) **join** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking tricks** **submit PRs** [**HackTricks**](https://github.com/carlospolop/hacktricks) 'ej [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **Share**.

</details>


## Basic Information

Apple devices post-2010 have serial numbers consisting of **12 alphanumeric characters**, each segment conveying specific information:

- **First 3 Characters**: **manufacturing location** **Indicate**.
- **Characters 4 & 5**: **year and week of manufacture** **Denote**.
- **Characters 6 to 8**: **unique identifier** **Serve**.
- **Last 4 Characters**: **model number** **Specify**.

For instance, the serial number **C02L13ECF8J2** follows this structure.

### **Manufacturing Locations (First 3 Characters)**
Certain codes represent specific factories:
- **FC, F, XA/XB/QP/G8**: **Various locations in the USA**.
- **RN**: **Mexico**.
- **CK**: **Cork, Ireland**.
- **VM**: **Foxconn, Czech Republic**.
- **SG/E**: **Singapore**.
- **MB**: **Malaysia**.
- **PT/CY**: **Korea**.
- **EE/QT/UV**: **Taiwan**.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: **Different locations in China**.
- **C0, C3, C7**: **Specific cities in China**.
- **RM**: **Refurbished devices**.

### **Year of Manufacturing (4th Character)**
This character varies from 'C' (representing the first half of 2010) to 'Z' (second half of 2019), with different letters indicating different half-year periods.

### **Week of Manufacturing (5th Character)**
Digits 1-9 correspond to weeks 1-9. Letters C-Y (excluding vowels and 'S') represent weeks 10-27. For the second half of the year, 26 is added to this number.

### **Unique Identifier (Characters 6 to 8)**
These three digits ensure each device, even of the same model and batch, has a distinct serial number.

### **Model Number (Last 4 Characters)**
These digits identify the specific model of the device.

### Reference

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qa'vIn AWS hacking vItlhutlh</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* **HackTricks vItlhutlh** pe'vIl **company advertised** 'ej **HackTricks PDF download** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **qaStaHvIS**.
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **ghItlh**.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **ghItlh** [**NFTs**](https://opensea.io/collection/the-peass-family) **ghItlh**.
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **join** 'ej [**telegram group**](https://t.me/peass) **join** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking tricks** **submit PRs** [**HackTricks**](https://github.com/carlospolop/hacktricks) 'ej [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **Share**.

</details>
