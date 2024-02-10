<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


For a phishing assessment sometimes it might be useful to completely **clone a website**.

Note that you can add also some payloads to the cloned website like a BeEF hook to "control" the tab of the user.

There are different tools you can use for this purpose:

## wget
```text
wget -mk -nH
```
## goclone

### Description

The `goclone` tool is a powerful utility that allows you to clone a website for phishing purposes. It is designed to make the process of creating a replica of a target website as simple as possible.

### Installation

To install `goclone`, follow these steps:

1. Clone the `goclone` repository from GitHub:

   ```
   git clone https://github.com/hacker/goclone.git
   ```

2. Change into the `goclone` directory:

   ```
   cd goclone
   ```

3. Install the required dependencies:

   ```
   go get -d ./...
   ```

4. Build the `goclone` binary:

   ```
   go build
   ```

### Usage

To use `goclone`, follow these steps:

1. Run the `goclone` binary:

   ```
   ./goclone
   ```

2. Enter the URL of the target website you want to clone.

3. Specify the output directory where the cloned website will be saved.

4. Customize the cloned website by modifying the HTML, CSS, and JavaScript files in the output directory.

5. Start a web server to serve the cloned website:

   ```
   python -m SimpleHTTPServer 8000
   ```

6. Send the cloned website URL to the target users and wait for them to enter their credentials.

7. Retrieve the credentials from the server logs or any other method of your choice.

### Conclusion

With `goclone`, you can easily create a replica of a website for phishing purposes. However, it is important to note that phishing is illegal and unethical. This tool should only be used for educational purposes or with proper authorization.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolkit (SET)

The Social Engineering Toolkit (SET) is a powerful open-source tool that allows hackers to perform various social engineering attacks. It is specifically designed to automate and streamline the process of phishing, credential harvesting, and other social engineering techniques.

SET provides a wide range of attack vectors, including email spoofing, website cloning, and malicious file generation. In this section, we will focus on the website cloning feature of SET, which allows hackers to create identical copies of legitimate websites for phishing purposes.

### Cloning a Website

Website cloning is a technique used by hackers to create a replica of a legitimate website. The cloned website looks and functions exactly like the original, but it is hosted on a different domain or server controlled by the attacker.

To clone a website using SET, follow these steps:

1. Launch SET by running the following command in the terminal:

   ```
   setoolkit
   ```

2. Select the "Website Attack Vectors" option from the main menu.

3. Choose the "Credential Harvester Attack Method" option.

4. Select the "Site Cloner" option.

5. Enter the URL of the website you want to clone.

6. Specify the IP address or domain name where the cloned website will be hosted.

7. SET will automatically clone the website and generate a phishing page.

8. Share the phishing page with the target victims through email, social media, or other communication channels.

9. When the victims visit the phishing page and enter their credentials, SET will capture the information and store it for further analysis.

It is important to note that website cloning is an illegal activity and should only be performed for educational or authorized penetration testing purposes. Unauthorized use of this technique can lead to severe legal consequences.

### Conclusion

Website cloning is a powerful technique that allows hackers to create convincing phishing pages. By using the Social Engineering Toolkit (SET), hackers can automate the process of cloning websites and launching phishing attacks. However, it is crucial to use these tools responsibly and ethically, ensuring that they are only used for legitimate purposes.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
