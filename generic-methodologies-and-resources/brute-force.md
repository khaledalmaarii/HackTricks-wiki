# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) lo'laHbe'chugh **automate workflows** powered by the world's **most advanced** community tools.\
Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Default Credentials

**Search in google** for default credentials of the technology that is being used, or **try these links**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Create your own Dictionaries**

Find as much information about the target as you can and generate a custom dictionary. Tools that may help:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

#### tlhIngan Hol

### Cewl

#### tlhIngan Hol
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Generate passwords based on your knowledge of the victim (names, dates...)

### [CUPP](https://github.com/Mebus/cupp)

vItlhutlh passwords vItlhutlh victim (nganpu', jaj...) Daq vItlhutlh.
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

ghItlhDI' wIvDI'wI' vItlhutlh, 'ej vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI'wI' vItlhutlhDI
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Wordlists

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Services

Ordered alphabetically by service name.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for communication between the web server and the application server.

#### Brute Forcing AJP

To brute force an AJP service, you can use tools like `ajpfuzzer` or `ajp-buster`. These tools allow you to send multiple requests with different usernames and passwords to the AJP service in order to guess the correct credentials.

Here is an example of how to use `ajpfuzzer` to brute force an AJP service:

```
ajpfuzzer -u http://target.com/ -p 8009 -U usernames.txt -P passwords.txt
```

In this example, `ajpfuzzer` is being used to send requests to the AJP service running on port 8009 of the target website. The tool will iterate through the usernames and passwords provided in the `usernames.txt` and `passwords.txt` files, respectively.

It is important to note that brute forcing is a time-consuming process and may be detected by intrusion detection systems (IDS) or web application firewalls (WAF). Therefore, it is recommended to use techniques like rate limiting and account lockouts to protect against brute force attacks.

#### Mitigations

To protect against brute force attacks on AJP services, consider implementing the following mitigations:

- Use strong and complex passwords for AJP service accounts.
- Implement account lockouts after a certain number of failed login attempts.
- Implement rate limiting to restrict the number of login attempts per unit of time.
- Monitor AJP service logs for suspicious activity and failed login attempts.
- Regularly update and patch the AJP service software to fix any security vulnerabilities.

By following these mitigations, you can significantly reduce the risk of successful brute force attacks on your AJP services.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)

### Brute Force

Brute force is a common technique used to gain unauthorized access to AMQP servers. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on an AMQP server, you can use tools like Hydra or Medusa. These tools allow you to specify a list of usernames and passwords, and they will automatically try each combination until a successful login is achieved.

When attempting a brute force attack, it is important to use a strong password list and to set a reasonable delay between each login attempt. This helps to avoid detection and prevents the server from becoming overwhelmed with login requests.

It is also worth noting that some AMQP servers may have built-in protections against brute force attacks, such as account lockouts or rate limiting. Therefore, it is important to be aware of these protections and adjust your attack accordingly.

### Dictionary Attack

A dictionary attack is a variation of the brute force technique that uses a pre-generated list of commonly used passwords, known as a dictionary. Instead of trying all possible combinations, a dictionary attack only tries the passwords in the dictionary.

To perform a dictionary attack on an AMQP server, you can use tools like Hydra or Medusa. These tools allow you to specify a dictionary file containing a list of passwords, and they will automatically try each password until a successful login is achieved.

It is important to note that dictionary attacks are generally less effective than brute force attacks, as they rely on the assumption that the correct password is in the dictionary. However, they can still be useful if the target is using a weak or commonly used password.

### Credential Stuffing

Credential stuffing is another technique that can be used to gain unauthorized access to AMQP servers. It involves using a list of previously leaked usernames and passwords, obtained from other data breaches, and trying them on different services.

To perform a credential stuffing attack on an AMQP server, you can use tools like Sentry MBA or STORM. These tools allow you to specify a list of usernames and passwords, and they will automatically try each combination on the target server.

Credential stuffing attacks can be highly effective, as many users reuse the same passwords across multiple services. Therefore, if a user's credentials have been leaked in one data breach, they may be vulnerable to credential stuffing attacks on other services, including AMQP servers.

To protect against credential stuffing attacks, it is important to use unique and strong passwords for each service, and to enable multi-factor authentication whenever possible. Additionally, organizations can implement account lockouts or rate limiting to detect and prevent credential stuffing attacks.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra is a highly scalable and distributed NoSQL database that is commonly used in big data applications. It is designed to handle large amounts of data across multiple commodity servers, providing high availability and fault tolerance.

#### Brute Forcing Cassandra

Brute forcing is a technique used to gain unauthorized access to a system by systematically trying all possible combinations of usernames and passwords until the correct one is found. While brute forcing is generally not recommended, it can be used as a last resort when all other methods of gaining access to a Cassandra database have failed.

To brute force a Cassandra database, you can use tools like Hydra or Medusa, which are popular password cracking tools. These tools allow you to automate the process of trying different combinations of usernames and passwords against the Cassandra login page.

Before attempting to brute force a Cassandra database, it is important to gather as much information as possible about the target system. This includes identifying the version of Cassandra being used, as well as any default usernames and passwords that may be in use.

Once you have gathered this information, you can use the password cracking tool to launch a brute force attack against the Cassandra login page. The tool will systematically try different combinations of usernames and passwords until the correct one is found.

It is important to note that brute forcing is a time-consuming process and can take a significant amount of time to complete, especially if the target system has strong security measures in place. Additionally, brute forcing is an illegal activity and should only be performed with proper authorization and legal consent.

#### Mitigating Brute Force Attacks

To protect against brute force attacks on a Cassandra database, it is important to implement strong security measures. This includes using complex and unique passwords for all user accounts, as well as implementing account lockout policies that temporarily lock an account after a certain number of failed login attempts.

Additionally, it is recommended to monitor the Cassandra logs for any suspicious activity, such as repeated failed login attempts from the same IP address. This can help identify and mitigate brute force attacks in real-time.

In conclusion, while brute forcing can be used as a last resort to gain unauthorized access to a Cassandra database, it is generally not recommended due to its time-consuming nature and legal implications. It is important to implement strong security measures and monitor for any suspicious activity to protect against brute force attacks.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB is a NoSQL database that can be targeted for brute force attacks. Brute forcing is a technique where an attacker tries all possible combinations of usernames and passwords until the correct one is found.

To perform a brute force attack on CouchDB, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different combinations of usernames and passwords.

Before attempting a brute force attack, it is important to gather information about the target CouchDB instance. This includes identifying the CouchDB version, checking for default credentials, and looking for any known vulnerabilities.

Once you have gathered the necessary information, you can start the brute force attack by specifying the target IP address or hostname, the port number, and the list of usernames and passwords to try. It is also possible to use a wordlist file that contains a large number of potential passwords.

During the brute force attack, it is important to monitor the progress and adjust the attack parameters if necessary. This includes adjusting the number of concurrent connections, the delay between requests, and the timeout value.

It is worth noting that brute forcing can be a time-consuming process, especially if the target has implemented security measures such as account lockouts or rate limiting. Therefore, it is important to be patient and persistent during the attack.

If successful, a brute force attack on CouchDB can provide unauthorized access to the database, allowing the attacker to view, modify, or delete data. To prevent brute force attacks, it is recommended to use strong and unique passwords, implement account lockouts, and regularly update CouchDB to patch any known vulnerabilities.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

A Docker registry is a storage and distribution system for Docker images. It allows you to store and manage your Docker images in a central location, making it easier to share and deploy them across different environments.

#### Brute-Forcing Docker Registry Credentials

Brute-forcing is a common technique used to guess or crack passwords by systematically trying all possible combinations. In the context of Docker registry credentials, brute-forcing can be used to guess the username and password combination required to access a private Docker registry.

To perform a brute-force attack on Docker registry credentials, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations until a valid one is found.

Here is an example command using Hydra to brute-force Docker registry credentials:

```
hydra -L usernames.txt -P passwords.txt <target_ip> docker-registry
```

In this command, `usernames.txt` and `passwords.txt` are files containing a list of possible usernames and passwords, respectively. `<target_ip>` is the IP address of the Docker registry you want to attack.

It's important to note that brute-forcing is an aggressive and time-consuming technique. It can generate a large number of requests, potentially causing network congestion or triggering security measures like account lockouts. Therefore, it's crucial to obtain proper authorization and permission before attempting any brute-force attacks.

#### Mitigating Brute-Force Attacks

To protect your Docker registry from brute-force attacks, you can implement the following security measures:

1. **Strong Passwords**: Use complex and unique passwords for your Docker registry credentials. Avoid using common or easily guessable passwords.

2. **Account Lockouts**: Implement account lockout policies that temporarily lock user accounts after a certain number of failed login attempts. This can help prevent brute-force attacks by slowing down the attacker's progress.

3. **Rate Limiting**: Implement rate limiting mechanisms to restrict the number of login attempts from a single IP address within a specific time frame. This can help mitigate the impact of brute-force attacks by limiting the number of requests an attacker can make.

4. **Multi-Factor Authentication**: Enable multi-factor authentication (MFA) for your Docker registry. MFA adds an extra layer of security by requiring users to provide additional verification, such as a one-time password or biometric authentication, in addition to their username and password.

By implementing these security measures, you can significantly reduce the risk of successful brute-force attacks on your Docker registry.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch is a distributed, RESTful search and analytics engine built on top of Apache Lucene. It is commonly used for log and event data analysis, full-text search, and real-time analytics. Elasticsearch uses a JSON-based query language called Query DSL to perform searches and aggregations on data.

#### Brute-Forcing Elasticsearch

Brute-forcing Elasticsearch involves attempting to guess the correct username and password combination to gain unauthorized access to the Elasticsearch cluster. This can be done by systematically trying different combinations of usernames and passwords until the correct one is found.

To brute-force Elasticsearch, you can use tools like Hydra or Burp Suite Intruder. These tools allow you to automate the process of trying different username and password combinations against the Elasticsearch login page.

Before attempting a brute-force attack, it is important to gather information about the target Elasticsearch cluster, such as the default username and password, if any. This information can often be found in the Elasticsearch documentation or by searching online.

Once you have the necessary information, you can start the brute-force attack by specifying a list of usernames and passwords to try. It is recommended to use a strong password list and to avoid common usernames like "admin" or "root".

During the brute-force attack, it is important to monitor the Elasticsearch logs for any signs of suspicious activity. This can help you identify successful login attempts or any other unauthorized access attempts.

To protect against brute-force attacks, it is recommended to implement strong authentication mechanisms, such as multi-factor authentication, and to regularly update and rotate passwords. Additionally, you can configure Elasticsearch to limit the number of login attempts allowed within a certain time period.

Remember that brute-forcing Elasticsearch or any other system without proper authorization is illegal and unethical. Always ensure you have the necessary permissions and legal authorization before attempting any hacking activities.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

#### Brute Force

Brute force is a common method used to gain unauthorized access to FTP servers. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on an FTP server, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations.

Before attempting a brute force attack, it is important to gather information about the target FTP server. This includes identifying the FTP server software, as different software may have different vulnerabilities or default credentials.

Once you have gathered the necessary information, you can start the brute force attack by specifying the target FTP server, the username list, and the password list. The tool will then systematically try each combination until it finds the correct credentials.

To increase the chances of success, it is recommended to use a large password list that includes common passwords, as well as custom password lists that are specific to the target organization or individual.

It is important to note that brute force attacks can be time-consuming and resource-intensive. They can also be easily detected by intrusion detection systems (IDS) or by the target organization's security team. Therefore, it is important to use caution and consider the potential consequences before attempting a brute force attack.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Generic Brute

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic Auth

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

#### Description

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for authentication purposes.

#### Brute Force Attack

A brute force attack against an NTLM-protected HTTP service involves attempting all possible combinations of usernames and passwords until the correct credentials are found. This attack can be performed using various tools and scripts.

#### Tools and Techniques

- Hydra: A popular command-line tool for performing brute force attacks. It supports NTLM authentication and can be used to automate the process.
- Medusa: Another command-line tool that supports NTLM authentication and can be used for brute forcing.
- Ncrack: A high-speed network authentication cracking tool that supports NTLM authentication.
- Custom Scripts: You can also write custom scripts using programming languages like Python or Ruby to perform brute force attacks against NTLM-protected HTTP services.

#### Countermeasures

To protect against brute force attacks targeting NTLM-protected HTTP services, consider implementing the following countermeasures:

- Account Lockout Policies: Implement account lockout policies that temporarily lock user accounts after a certain number of failed login attempts.
- Strong Password Policies: Enforce strong password policies that require users to choose complex and unique passwords.
- Rate Limiting: Implement rate limiting mechanisms to restrict the number of login attempts per unit of time.
- Intrusion Detection Systems (IDS): Deploy IDS systems to detect and block suspicious login attempts.
- Multi-Factor Authentication (MFA): Implement MFA to add an extra layer of security to the authentication process.

#### References

- [NTLM Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)

#### Additional Resources

- [Hydra GitHub Repository](https://github.com/vanhauser-thc/thc-hydra)
- [Medusa GitHub Repository](https://github.com/jmk-foofus/medusa)
- [Ncrack GitHub Repository](https://github.com/nmap/ncrack)
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

#### Brute Force

Brute force is a technique used to crack passwords or guess sensitive information by systematically trying all possible combinations until the correct one is found. In the context of HTTP post forms, brute force can be used to automate the process of submitting different values for form fields in order to find valid credentials or exploit vulnerabilities.

#### Methodology

1. Identify the target: Determine the target website or application that has a login form or any other form that accepts user input.

2. Gather information: Collect as much information as possible about the target, such as the form fields, expected input formats, and any error messages that may be displayed.

3. Create a wordlist: Generate a wordlist containing potential usernames, passwords, or other values that could be used to brute force the form.

4. Automate the process: Use a tool or script to automate the submission of the form with different values from the wordlist. This can be done by sending HTTP POST requests to the target URL with the appropriate form data.

5. Analyze responses: Monitor the responses received from the target server. Look for any indications of success, such as a redirect to a different page or a specific error message indicating a failed login attempt.

6. Refine the wordlist: Based on the responses received, refine the wordlist by removing unsuccessful values and focusing on those that show potential.

7. Adjust the attack: Modify the attack parameters, such as the rate of requests or the number of concurrent connections, to avoid detection or improve efficiency.

8. Exploit vulnerabilities: If successful, use the obtained credentials or exploit any vulnerabilities discovered through the brute force process.

#### Tools

There are several tools available that can assist in automating the brute force process for HTTP post forms. Some popular ones include:

- Hydra: A powerful command-line tool for password cracking and brute forcing various protocols, including HTTP post forms.
- Burp Suite: A comprehensive web application security testing tool that includes a feature for automating form submissions and analyzing responses.
- WFuzz: A flexible web application brute forcer that can be used to test the security of HTTP post forms.
- Medusa: A speedy, parallel, and modular login brute-forcer for various protocols, including HTTP post forms.

#### Mitigation

To protect against brute force attacks on HTTP post forms, consider implementing the following mitigation techniques:

- Account lockout: Implement a mechanism that locks user accounts after a certain number of failed login attempts, preventing further brute force attempts.
- CAPTCHA: Use CAPTCHA or similar techniques to differentiate between human and automated form submissions.
- Rate limiting: Implement rate limiting to restrict the number of requests that can be made within a specific time frame, making brute force attacks less feasible.
- Strong passwords: Encourage users to choose strong, unique passwords that are resistant to brute force attacks.
- Two-factor authentication: Implement two-factor authentication to add an extra layer of security, making it more difficult for attackers to gain unauthorized access.

Remember that brute forcing is an aggressive technique that can be illegal and unethical if used without proper authorization. Always ensure that you have the necessary permissions and legal rights before attempting any brute force attacks.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
For http**s** you have to change from "http-post-form" to "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

#### Brute Force

Brute force is a common method used to gain unauthorized access to IMAP accounts. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on an IMAP server, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations.

Before attempting a brute force attack, it is important to gather information about the target, such as the email domain and common usernames. This information can be obtained through reconnaissance techniques like OSINT (Open Source Intelligence) or social engineering.

Once you have the necessary information, you can start the brute force attack by specifying the target's IP address or domain, the IMAP port (usually 143 or 993 for SSL/TLS), and the list of usernames and passwords to try.

It is important to note that brute force attacks can be time-consuming and resource-intensive. To increase the chances of success, you can use wordlists that contain commonly used passwords or customize the wordlists based on the target's characteristics.

To mitigate the risk of brute force attacks, it is recommended to implement strong password policies, enable account lockouts after a certain number of failed login attempts, and monitor for suspicious login activity.

#### Translation:

### IMAP

#### Brute Force

Brute Force vItlhutlhla' 'e' vItlhutlhla' 'e' IMAP accounts vItlhutlh. 'Iv involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

IMAP server vItlhutlh attack brute force, tools like Hydra or Medusa vItlhutlh. vItlhutlh 'e' vItlhutlhutlh username 'ej password combinations process automate tools vItlhutlh.

vItlhutlh attack brute force vItlhutlh, target information gather important, email domain 'ej common usernames. vItlhutlh 'e' vItlhutlhutlh techniques reconnaissance OSINT (Open Source Intelligence) 'ej social engineering vItlhutlh.

vItlhutlh information vItlhutlh, vItlhutlh attack brute force vItlhutlh, target IP address 'ej domain, IMAP port (usually 143 or 993 for SSL/TLS), 'ej username 'ej password list vItlhutlh.

vItlhutlh 'e' vItlhutlhutlh attack brute force vItlhutlh, vItlhutlh 'e' vItlhutlhutlh time-consuming 'ej resource-intensive. vItlhutlh 'e' vItlhutlhutlh success, commonly used passwords wordlists vItlhutlh or customize wordlists target characteristics vItlhutlh.

vItlhutlh attack brute force risk mitigate, strong password policies implement recommended, account lockouts enable after a certain number of failed login attempts, 'ej suspicious login activity monitor.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat) is a protocol used for real-time communication over the internet. It allows users to chat in channels or privately with other users. IRC servers host these channels and users connect to them using IRC clients.

#### Brute-Forcing IRC

Brute-forcing is a technique used to gain unauthorized access to IRC accounts by systematically trying different combinations of usernames and passwords until the correct one is found. This method relies on the assumption that the target user has chosen a weak or easily guessable password.

To perform a brute-force attack on an IRC account, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations against the target server.

Before attempting a brute-force attack, it is important to gather information about the target, such as the IRC server address, port number, and the target username (if known). This information can be obtained through reconnaissance techniques like OSINT (Open Source Intelligence) or by using tools like Nmap.

Once you have the necessary information, you can configure the brute-forcing tool to start the attack. It is recommended to use a wordlist containing common passwords or custom wordlists based on the target's personal information (e.g., name, date of birth, etc.).

Keep in mind that brute-forcing is an aggressive technique and can be easily detected by the target server's security measures. To minimize the risk of detection, you can use techniques like rate limiting, which limits the number of login attempts per unit of time, or rotating IP addresses to avoid being blocked.

It is important to note that brute-forcing is illegal unless you have explicit permission from the target to perform such an attack. Always ensure you are conducting ethical hacking activities within the boundaries of the law.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

ISCSI is a protocol that allows the transmission of SCSI commands over a TCP/IP network. It is commonly used for accessing storage devices over a network, providing a way to connect to remote storage resources as if they were local.

#### Brute-Forcing ISCSI Targets

Brute-forcing ISCSI targets involves attempting to guess the authentication credentials required to access a specific ISCSI target. This can be done by systematically trying different combinations of usernames and passwords until the correct credentials are found.

To brute-force ISCSI targets, you can use tools like Hydra or Medusa, which are capable of automating the process of trying different combinations of credentials. These tools can be configured to use a wordlist containing potential usernames and passwords, or they can generate combinations based on specific patterns.

It is important to note that brute-forcing ISCSI targets is a time-consuming process, as there are typically a large number of possible combinations to try. Additionally, many ISCSI implementations have built-in protections against brute-force attacks, such as account lockouts or rate limiting.

#### Mitigating Brute-Force Attacks

To protect against brute-force attacks on ISCSI targets, it is recommended to implement strong authentication mechanisms, such as using complex passwords or implementing two-factor authentication. Additionally, monitoring and logging can help detect and respond to brute-force attempts in real-time.

Regularly reviewing logs and monitoring for unusual activity can help identify potential brute-force attacks and allow for timely response and mitigation. It is also important to keep ISCSI software and firmware up to date, as vendors often release security patches and updates to address vulnerabilities that could be exploited in brute-force attacks.

By implementing these measures, organizations can significantly reduce the risk of successful brute-force attacks on their ISCSI targets.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

#### Introduction

JSON Web Tokens (JWTs) are a popular method for securely transmitting information between parties as a JSON object. They consist of three parts: a header, a payload, and a signature. The header and payload are Base64Url encoded JSON strings, while the signature is used to verify the integrity of the token.

#### Brute Forcing JWTs

Brute forcing JWTs involves attempting to guess the secret key used to sign the token. This can be done by trying different combinations of characters until a valid signature is found. Brute forcing JWTs can be a time-consuming process, especially if the secret key is long and complex.

#### Tools for Brute Forcing JWTs

There are several tools available for brute forcing JWTs, such as:

- **jwt-cracker**: A Python script that can be used to brute force JWTs by trying different secret keys.
- **jwt_tool**: A toolkit for testing, tweaking, and cracking JWTs.
- **Hashcat**: A popular password cracking tool that can be used for brute forcing JWTs.

#### Best Practices to Prevent Brute Forcing

To prevent brute forcing attacks on JWTs, it is important to follow these best practices:

- Use a strong secret key: Choose a secret key that is long, complex, and difficult to guess.
- Implement rate limiting: Limit the number of requests that can be made within a certain time period to prevent automated brute forcing.
- Use JWT libraries with built-in protections: Some JWT libraries have built-in protections against brute forcing attacks, such as rate limiting and IP blocking.

#### Conclusion

Brute forcing JWTs can be a challenging task, but with the right tools and best practices in place, it is possible to prevent unauthorized access to sensitive information. By following the recommended guidelines, you can enhance the security of your JWT-based authentication systems.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) is a protocol used to access and manage directory information. It is commonly used for authentication and authorization purposes in various systems.

#### Brute-Force Attack

A brute-force attack is a method used to gain unauthorized access to a system by systematically trying all possible combinations of usernames and passwords until the correct one is found. This attack can be used against LDAP servers to attempt to guess valid credentials and gain access to the directory.

#### Tools for Brute-Force Attacks against LDAP

There are several tools available that can be used to perform brute-force attacks against LDAP servers. Some popular ones include:

- **Hydra**: A powerful online password cracking tool that supports various protocols, including LDAP.
- **Patator**: A multi-purpose brute-forcing tool that can be used against various protocols, including LDAP.
- **Medusa**: A speedy, parallelized brute-forcing tool that supports LDAP among other protocols.
- **Ncrack**: A high-speed network authentication cracking tool that can be used against LDAP servers.

#### Best Practices to Prevent Brute-Force Attacks

To protect against brute-force attacks on LDAP servers, it is important to follow these best practices:

- Implement account lockout policies: Set up a mechanism that locks user accounts after a certain number of failed login attempts.
- Use strong passwords: Encourage users to choose complex passwords that are difficult to guess.
- Enable two-factor authentication: Implement an additional layer of security by requiring users to provide a second form of authentication, such as a code sent to their mobile device.
- Monitor and log failed login attempts: Regularly review logs to identify any suspicious activity or patterns of failed login attempts.
- Limit access to LDAP servers: Restrict access to LDAP servers to only authorized users and IP addresses.
- Keep software up to date: Regularly update LDAP server software to ensure any known vulnerabilities are patched.

By following these best practices, you can significantly reduce the risk of successful brute-force attacks against your LDAP servers.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) is a lightweight messaging protocol commonly used in IoT (Internet of Things) applications. It is designed to be simple and efficient, making it ideal for resource-constrained devices and low-bandwidth networks.

#### Brute-Forcing MQTT Credentials

Brute-forcing MQTT credentials involves systematically trying different combinations of usernames and passwords until the correct credentials are found. This can be done using various tools and techniques, such as:

- **Dictionary Attacks**: Using a list of commonly used usernames and passwords to guess the credentials.
- **Credential Stuffing**: Trying previously leaked credentials from other sources to gain unauthorized access.
- **Rainbow Tables**: Precomputed tables of password hashes that can be used to quickly find the plaintext password corresponding to a given hash.
- **Hybrid Attacks**: Combining dictionary attacks with variations of usernames and passwords, such as adding numbers or special characters.

To perform a brute-force attack on MQTT credentials, you can use tools like `mqtt-brute` or `mosquito-crack`. These tools automate the process of trying different combinations of credentials and can significantly speed up the attack.

It is important to note that brute-forcing MQTT credentials is considered unethical and illegal unless you have explicit permission to do so. Always ensure you are conducting any hacking activities within the boundaries of the law and with proper authorization.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a Mongo database. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on a Mongo database, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different combinations of usernames and passwords.

Before attempting a brute force attack, it is important to gather as much information as possible about the target database. This includes identifying the version of Mongo being used, as well as any known usernames or passwords.

Once you have gathered this information, you can start the brute force attack by specifying the target IP address, port number, and the list of usernames and passwords to try. The tool will then systematically try each combination until it finds the correct credentials.

To increase the chances of success, it is recommended to use a large wordlist containing common passwords and usernames. You can also customize the tool to try different variations of passwords, such as adding numbers or special characters.

It is important to note that brute force attacks can be time-consuming and resource-intensive. They can also be easily detected by intrusion detection systems. Therefore, it is advisable to use other techniques, such as password cracking or exploiting vulnerabilities, if available.

Remember to always obtain proper authorization before attempting any hacking activities. Unauthorized access to computer systems is illegal and can result in severe consequences.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

#### Brute Force

Brute force is a common technique used to gain unauthorized access to MSSQL databases by systematically trying all possible combinations of usernames and passwords until the correct one is found.

##### Tools

- **Hydra**: A popular command-line tool used for brute forcing various protocols, including MSSQL. It supports both username and password lists.

##### Methodology

1. Identify the target MSSQL server and its associated port (default is 1433).
2. Gather information about the target, such as valid usernames and password policies.
3. Create a list of potential usernames and passwords to use for the brute force attack.
4. Use Hydra to launch the brute force attack, specifying the target IP address, port, username list, and password list.
5. Monitor the progress of the attack and wait for a successful login attempt.
6. Once the correct username and password combination is found, use it to gain unauthorized access to the MSSQL database.

##### Tips and Recommendations

- Use a strong and diverse list of potential usernames and passwords to increase the chances of success.
- Consider using a password cracking tool, such as John the Ripper, to generate a list of common passwords to include in the attack.
- Implement account lockout policies on the target MSSQL server to prevent brute force attacks.
- Monitor the server logs for any suspicious login attempts and take appropriate action to mitigate the risk.

##### Example Command

```
hydra -L usernames.txt -P passwords.txt mssql://target_ip:1433
```

Replace `usernames.txt` and `passwords.txt` with the respective lists of usernames and passwords to use for the brute force attack. Replace `target_ip` with the IP address of the target MSSQL server.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

#### Brute Force

Brute force is a common technique used to gain unauthorized access to MySQL databases. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on a MySQL database, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different combinations of usernames and passwords.

Before attempting a brute force attack, it is important to gather information about the target MySQL database. This includes identifying the version of MySQL being used, as well as any known usernames or passwords that may be associated with the database.

Once you have gathered this information, you can use a tool like Hydra to launch the brute force attack. Hydra supports various protocols, including MySQL, and allows you to specify a list of usernames and passwords to try.

When launching a brute force attack, it is important to use a strong password list that includes a wide range of possible passwords. This can include common passwords, dictionary words, and variations of known passwords.

It is also important to use a slow and steady approach when performing a brute force attack. Rapidly trying multiple combinations can trigger security measures, such as account lockouts or IP blocking.

To mitigate the risk of a brute force attack, it is recommended to implement strong password policies, such as enforcing complex passwords and implementing account lockout policies after a certain number of failed login attempts.

Remember, brute forcing a MySQL database without proper authorization is illegal and unethical. Always ensure you have the necessary permissions and legal authorization before attempting any hacking activities.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

OracleSQL is a powerful relational database management system that is commonly used in enterprise environments. It provides a wide range of features and functionalities for managing and manipulating data.

#### Brute-Force Attack

A brute-force attack is a common method used by hackers to gain unauthorized access to OracleSQL databases. This attack involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

#### Brute-Force Tools

There are several tools available that can automate the brute-force attack process for OracleSQL databases. These tools typically use a list of common usernames and passwords, as well as various techniques to speed up the attack.

#### Prevention Techniques

To protect against brute-force attacks on OracleSQL databases, it is important to implement strong security measures. This includes using complex and unique passwords, enforcing account lockouts after a certain number of failed login attempts, and regularly monitoring and reviewing access logs for any suspicious activity.

#### Conclusion

Brute-force attacks can pose a significant threat to the security of OracleSQL databases. By implementing proper security measures and regularly updating passwords, organizations can greatly reduce the risk of unauthorized access to their databases.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
**oracle_login**-'eS **patator**-vam **vaj** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **vaj** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI'** **tlhIngan Hol** **ghItlh** **DIvI
```bash
pip3 install cx_Oracle --upgrade
```
[Offline OracleSQL hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):

[Offline OracleSQL hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

The Post Office Protocol (POP) is an application-layer protocol used for retrieving email from a remote server. It is commonly used by email clients to download messages from a mail server. 

POP operates over TCP/IP and typically uses port 110. The protocol allows users to access their email by connecting to the mail server and authenticating with their username and password. Once authenticated, the client can retrieve and manage their email messages.

Brute-forcing a POP server involves systematically attempting different combinations of usernames and passwords until a successful login is achieved. This technique can be used to gain unauthorized access to email accounts or to test the security of a POP server.

To perform a brute-force attack on a POP server, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations, making it easier to find weak credentials.

It is important to note that brute-forcing a POP server without proper authorization is illegal and unethical. It is recommended to only perform brute-force attacks on systems that you have permission to test, such as during a penetration testing engagement.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a PostgreSQL database by systematically trying all possible combinations of usernames and passwords until the correct one is found.

##### Tools

- **Hydra**: A popular tool for performing brute force attacks. It supports various protocols, including PostgreSQL.

##### Methodology

1. Identify the target: Determine the IP address or hostname of the PostgreSQL server you want to attack.

2. Enumerate usernames: Use tools like **Metasploit** or **Nmap** to identify valid usernames on the target server.

3. Generate password list: Create a list of potential passwords to try during the brute force attack. This can be done using tools like **Cupp** or **Crunch**.

4. Configure Hydra: Set up Hydra with the target IP address, port number (default is 5432 for PostgreSQL), and the username and password lists.

5. Launch the attack: Run Hydra with the appropriate options to start the brute force attack. Monitor the progress and wait for a successful login.

6. Post-exploitation: Once access is gained, perform further actions like data exfiltration or privilege escalation.

##### Prevention

To protect against brute force attacks on your PostgreSQL database, consider implementing the following measures:

- Use strong and complex passwords for all database accounts.
- Implement account lockout policies to temporarily lock accounts after a certain number of failed login attempts.
- Enable logging and monitoring to detect and respond to suspicious login activity.
- Regularly update and patch your PostgreSQL server to address any security vulnerabilities.

> Note: Brute force attacks are illegal and should only be performed with proper authorization and for legitimate purposes, such as penetration testing.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

You can download the `.deb` package to install from [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft that allows users to remotely access and control a computer over a network. It is commonly used for remote administration and troubleshooting purposes.

#### Brute-Force Attacks on RDP

Brute-force attacks on RDP involve systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This is done by using automated tools that can rapidly attempt multiple login attempts.

To perform a brute-force attack on RDP, you can use tools like Hydra, Crowbar, or RDPY. These tools allow you to specify a list of usernames and passwords, and they will automatically try each combination until a successful login is achieved.

It is important to note that brute-force attacks are highly resource-intensive and time-consuming. They can also be easily detected by intrusion detection systems (IDS) and can result in the attacker being blocked or banned.

To mitigate the risk of brute-force attacks on RDP, it is recommended to:

- Use strong and complex passwords that are not easily guessable.
- Implement account lockout policies that temporarily lock an account after a certain number of failed login attempts.
- Enable network-level authentication (NLA) for RDP, which requires users to authenticate before establishing a remote desktop session.
- Use a virtual private network (VPN) to secure RDP connections and restrict access to trusted IP addresses.

By following these best practices, you can significantly reduce the risk of successful brute-force attacks on RDP.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis is an open-source, in-memory data structure store that can be used as a database, cache, and message broker. It supports various data structures such as strings, hashes, lists, sets, and sorted sets. Redis also provides built-in replication, Lua scripting, and support for transactions.

#### Brute Forcing Redis

Brute forcing is a technique used to guess passwords or keys by systematically trying all possible combinations until the correct one is found. In the context of Redis, brute forcing can be used to guess the password of a Redis server or to guess the keys of a Redis database.

##### Brute Forcing Redis Password

To brute force the password of a Redis server, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different passwords against a target Redis server. You can provide a list of passwords and the tool will try each one until it finds the correct password.

Here is an example command using Hydra to brute force a Redis server:

```
hydra -L usernames.txt -P passwords.txt redis://target-ip
```

In this command, `usernames.txt` is a file containing a list of usernames, `passwords.txt` is a file containing a list of passwords, and `target-ip` is the IP address of the Redis server.

##### Brute Forcing Redis Keys

To brute force the keys of a Redis database, you can use tools like Redis-cli or a custom script. These tools allow you to iterate through all possible key names and check if they exist in the Redis database.

Here is an example command using Redis-cli to brute force Redis keys:

```
redis-cli -h target-ip -p target-port --scan --pattern "*"
```

In this command, `target-ip` is the IP address of the Redis server and `target-port` is the port number of the Redis server.

It is important to note that brute forcing is a time-consuming process and may be detected by security systems. It is recommended to use brute forcing techniques responsibly and with proper authorization.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec is a remote execution service that allows users to execute commands on a remote system. It is commonly used in network administration and troubleshooting scenarios. Rexec works by establishing a connection between the client and the server, and then sending the command to be executed on the server.

#### Brute Forcing Rexec

Brute forcing is a common technique used to gain unauthorized access to systems by systematically trying all possible combinations of usernames and passwords. In the case of Rexec, brute forcing can be used to try different username and password combinations until a successful login is achieved.

To brute force Rexec, you can use tools like Hydra or Medusa, which are popular password cracking tools. These tools allow you to specify a list of usernames and passwords, and then systematically try each combination until a successful login is found.

It is important to note that brute forcing is an aggressive technique and can be detected by intrusion detection systems (IDS) or other security measures. Therefore, it is recommended to use brute forcing techniques responsibly and with proper authorization.

#### Mitigating Rexec Brute Force Attacks

To protect against Rexec brute force attacks, it is recommended to implement strong authentication mechanisms, such as using complex passwords and enforcing account lockouts after a certain number of failed login attempts. Additionally, monitoring and analyzing log files can help detect and respond to brute force attacks in a timely manner.

Regularly updating and patching the Rexec service can also help mitigate the risk of brute force attacks, as vulnerabilities in the service can be exploited by attackers. It is important to stay informed about the latest security updates and apply them promptly.

By following these best practices, you can enhance the security of your Rexec service and reduce the risk of unauthorized access through brute force attacks.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems. Rlogin uses the TCP port 513.

#### Brute Forcing Rlogin

To brute force Rlogin, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations until you find the correct one.

Here is an example command using Hydra:

```plaintext
hydra -l <username> -P <password_list> rlogin://<target_ip>
```

Replace `<username>` with the target username, `<password_list>` with the path to a file containing a list of passwords, and `<target_ip>` with the IP address of the target system.

#### Countermeasures

To protect against brute force attacks on Rlogin, you can implement the following countermeasures:

- Use strong and complex passwords that are not easily guessable.
- Implement account lockout policies that temporarily lock an account after a certain number of failed login attempts.
- Monitor and analyze logs for any suspicious login activity.
- Disable Rlogin if it is not necessary for your system.

Remember to always obtain proper authorization before attempting any brute force attacks.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. However, due to its lack of security features, it is considered insecure and is rarely used in modern environments.

#### Brute Forcing Rsh

Brute forcing Rsh involves attempting to guess the username and password combination to gain unauthorized access to a remote system. This can be done by systematically trying different combinations until the correct one is found.

To brute force Rsh, you can use tools like Hydra or Medusa, which are capable of automating the process. These tools allow you to specify a list of usernames and passwords to try, as well as configure the number of simultaneous connections and the delay between attempts.

It is important to note that brute forcing Rsh is illegal and unethical unless you have explicit permission from the system owner to perform such actions. Always ensure you are conducting penetration testing or security assessments within the boundaries of the law and with proper authorization.

#### Mitigating Rsh Brute Force Attacks

To protect against Rsh brute force attacks, it is recommended to disable or block Rsh access altogether. This can be done by removing or commenting out the rsh line in the /etc/inetd.conf file on Unix-like systems.

Additionally, enforcing strong password policies and implementing account lockout mechanisms can help mitigate the risk of successful brute force attacks. Regularly monitoring system logs for suspicious activity and promptly addressing any detected anomalies is also crucial for maintaining a secure environment.

Remember, the best defense against brute force attacks is a combination of strong security practices, regular vulnerability assessments, and proactive monitoring.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync is a utility commonly used for file synchronization and transfer. It allows for efficient copying and updating of files between different systems. Rsync can be particularly useful during a penetration test for transferring files to and from compromised systems. It can also be used to synchronize files between different machines, making it a valuable tool for managing backups or mirroring data. Rsync operates over the SSH protocol by default, providing secure file transfers.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real-Time Streaming Protocol) is a network protocol used for controlling the streaming of media data over a network. It is commonly used for streaming audio and video content. RTSP operates on top of the TCP/IP protocol suite and uses port 554 by default.

#### Brute-Force Attacks against RTSP

Brute-force attacks can be used to gain unauthorized access to RTSP servers by systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This type of attack can be automated using tools like Hydra or Medusa.

To perform a brute-force attack against an RTSP server, you need a wordlist containing possible usernames and passwords. The wordlist can be created manually or obtained from various sources, such as leaked password databases or common password lists.

Once you have a wordlist, you can use a brute-force tool to automate the attack. The tool will iterate through each combination of usernames and passwords, sending login requests to the RTSP server. If the correct credentials are found, the tool will notify you, allowing you to gain unauthorized access to the server.

It is important to note that brute-force attacks are time-consuming and resource-intensive. They can also be easily detected by intrusion detection systems (IDS) or rate-limiting mechanisms implemented by the server. Therefore, it is recommended to use other attack vectors or techniques before resorting to brute-force attacks.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) is a secure method for transferring files over a network. It provides a secure channel for data transfer and uses encryption to protect the confidentiality and integrity of the data.

#### Brute-Force Attacks against SFTP

Brute-force attacks are a common method used to gain unauthorized access to SFTP servers. In a brute-force attack, an attacker systematically tries all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute-force attack against an SFTP server, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations, making it easier and faster for the attacker to find the correct credentials.

To protect against brute-force attacks, it is important to use strong and unique passwords for SFTP accounts. Additionally, you can implement account lockout policies that temporarily lock an account after a certain number of failed login attempts.

#### Mitigating Brute-Force Attacks

There are several measures you can take to mitigate the risk of brute-force attacks against SFTP servers:

1. **Strong Passwords**: Encourage users to use strong and unique passwords that are difficult to guess. Passwords should be at least 12 characters long and include a combination of uppercase and lowercase letters, numbers, and special characters.

2. **Account Lockout Policies**: Implement account lockout policies that temporarily lock an account after a certain number of failed login attempts. This can help prevent brute-force attacks by slowing down the attacker's progress.

3. **Two-Factor Authentication**: Enable two-factor authentication (2FA) for SFTP accounts. This adds an extra layer of security by requiring users to provide a second form of authentication, such as a code sent to their mobile device, in addition to their username and password.

4. **IP Whitelisting**: Restrict access to the SFTP server by whitelisting specific IP addresses or IP ranges. This can help prevent unauthorized access from unknown or suspicious sources.

5. **Monitoring and Alerting**: Implement monitoring and alerting systems to detect and respond to suspicious activity, such as multiple failed login attempts or unusual login patterns.

By implementing these measures, you can significantly reduce the risk of successful brute-force attacks against your SFTP server.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) is a widely used protocol for managing and monitoring network devices. It allows network administrators to collect information about the devices on their network, such as their status, performance, and configuration.

SNMP operates on the concept of managed objects, which are organized in a hierarchical structure called the Management Information Base (MIB). Each managed object has a unique identifier called an Object Identifier (OID), which is used to retrieve or set its value.

SNMP uses a client-server model, where the SNMP manager (client) sends requests to the SNMP agent (server) running on the network device. The agent responds to these requests by providing the requested information or performing the requested action.

One common use of SNMP is to monitor the health and performance of network devices. SNMP managers can periodically poll the devices to collect data such as CPU usage, memory usage, network traffic, and interface status. This data can be used to identify and troubleshoot issues, as well as to plan for capacity upgrades.

Another use of SNMP is for device configuration and management. SNMP managers can use SNMP to remotely configure settings on network devices, such as enabling or disabling interfaces, changing routing tables, or updating firmware.

SNMP has several versions, with SNMPv3 being the most secure and feature-rich. It provides authentication, encryption, and access control mechanisms to protect the confidentiality and integrity of SNMP communications.

In summary, SNMP is a powerful protocol for managing and monitoring network devices. It allows network administrators to collect information, monitor performance, and configure devices remotely.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

#### Brute Force

Brute force is a common technique used to gain unauthorized access to SMB (Server Message Block) services. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on an SMB service, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations against the target SMB server.

When attempting a brute force attack, it is important to use a wordlist that contains commonly used passwords, as well as variations and combinations of them. This increases the chances of finding the correct credentials.

It is also recommended to use a tool that supports multi-threading, as this can significantly speed up the brute force process. Additionally, you can try limiting the number of login attempts per minute to avoid triggering account lockouts or detection by intrusion detection systems.

Keep in mind that brute forcing is a time-consuming process and may not always be successful. It is important to consider other attack vectors and techniques in combination with brute forcing to increase the chances of a successful compromise.

#### Mitigation

To protect against brute force attacks on SMB services, there are several measures that can be taken:

1. Implement account lockout policies: Set a maximum number of failed login attempts before locking out an account. This can help prevent brute force attacks by temporarily locking out an account after a certain number of failed attempts.

2. Use strong and complex passwords: Encourage users to choose passwords that are difficult to guess and contain a combination of uppercase and lowercase letters, numbers, and special characters.

3. Enable two-factor authentication (2FA): Implementing 2FA adds an extra layer of security by requiring users to provide a second form of authentication, such as a code sent to their mobile device, in addition to their password.

4. Monitor and analyze logs: Regularly review logs for any suspicious activity, such as multiple failed login attempts from the same IP address or unusual patterns of login attempts.

5. Limit access to SMB services: Restrict access to SMB services only to authorized users and devices. This can be done by implementing firewall rules or using network segmentation.

By implementing these measures, you can significantly reduce the risk of successful brute force attacks on your SMB services.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) is a communication protocol used for sending email messages between servers. It is widely used for email transmission over the internet.

#### Brute Forcing SMTP Credentials

Brute forcing SMTP credentials involves systematically trying different combinations of usernames and passwords until the correct credentials are found. This technique can be used to gain unauthorized access to an email account or to test the strength of SMTP credentials.

To perform a brute force attack on SMTP credentials, you can use tools like Hydra or Medusa. These tools automate the process of trying different combinations of usernames and passwords against an SMTP server.

It is important to note that brute forcing SMTP credentials is illegal and unethical unless you have explicit permission from the owner of the email account or the server you are testing. Always ensure you have proper authorization before attempting any brute force attacks.

#### Protecting Against Brute Force Attacks

To protect against brute force attacks on SMTP credentials, it is important to follow best practices for password security. This includes using strong, unique passwords for each account and enabling multi-factor authentication whenever possible.

Additionally, implementing account lockout policies can help prevent brute force attacks. These policies lock an account after a certain number of failed login attempts, making it more difficult for an attacker to guess the correct credentials.

Regularly monitoring and analyzing log files can also help detect and mitigate brute force attacks. By monitoring for unusual login patterns or a high number of failed login attempts, you can take proactive measures to protect your SMTP credentials.

#### Conclusion

Brute forcing SMTP credentials is a common technique used by attackers to gain unauthorized access to email accounts. By following best practices for password security and implementing account lockout policies, you can protect against these types of attacks. Regular monitoring and analysis of log files can also help detect and mitigate brute force attacks.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

#### Description

SOCKS is a protocol that allows a client to establish a TCP connection through a proxy server. It is commonly used for bypassing network restrictions and anonymizing internet traffic.

#### Brute-Forcing SOCKS Credentials

To brute-force SOCKS credentials, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations until the correct credentials are found.

Here is an example command using Hydra to brute-force SOCKS credentials:

```plaintext
hydra -L usernames.txt -P passwords.txt socks5://target_ip:target_port
```

Replace `usernames.txt` with a file containing a list of possible usernames and `passwords.txt` with a file containing a list of possible passwords. `target_ip` and `target_port` should be replaced with the IP address and port of the SOCKS proxy server you want to brute-force.

#### Brute-Forcing SOCKS Proxy

If you have a list of potential SOCKS proxy servers and want to find valid ones, you can use tools like Nmap or Masscan to scan for open SOCKS ports. Once you have a list of open ports, you can use tools like Proxychains or Proxychains-ng to test the proxies and see if they are working.

Here is an example command using Nmap to scan for open SOCKS ports:

```plaintext
nmap -p 1080 --open -sV target_ip_range
```

Replace `target_ip_range` with the range of IP addresses you want to scan. This command will scan for open ports on port 1080 and display the version information of any services running on those ports.

#### Conclusion

SOCKS can be a useful protocol for bypassing network restrictions and anonymizing internet traffic. However, it is important to use it responsibly and not engage in any illegal activities.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a SQL Server by systematically trying all possible combinations of usernames and passwords until the correct one is found. This method relies on the assumption that the correct credentials are weak or easily guessable.

To perform a brute force attack on a SQL Server, you can use tools like Hydra or Medusa, which are capable of automating the process. These tools allow you to specify a list of usernames and passwords to try, as well as the target SQL Server's IP address or hostname.

It is important to note that brute force attacks can be time-consuming and resource-intensive, especially if the target SQL Server has implemented measures to prevent such attacks, such as account lockouts or rate limiting. Additionally, brute force attacks are illegal and unethical unless performed with proper authorization and consent.

To protect against brute force attacks, it is recommended to use strong and unique passwords for all SQL Server accounts. Additionally, implementing account lockouts or rate limiting can help mitigate the risk of successful brute force attacks.

#### Dictionary Attacks

Dictionary attacks are a variation of brute force attacks that rely on a predefined list of commonly used passwords, known as a dictionary. Instead of trying all possible combinations, dictionary attacks only try the passwords in the dictionary, significantly reducing the time and resources required.

To defend against dictionary attacks, it is important to use strong and unique passwords that are not easily guessable. Additionally, regularly updating passwords and implementing account lockouts or rate limiting can help protect against dictionary attacks.

#### Credential Stuffing

Credential stuffing is another technique used to gain unauthorized access to a SQL Server. It involves using a list of stolen usernames and passwords, typically obtained from data breaches or leaks, to try to gain access to other systems or services where the same credentials may have been reused.

To protect against credential stuffing attacks, it is important to use unique passwords for each system or service. Implementing multi-factor authentication (MFA) can also add an extra layer of security by requiring additional verification beyond just a username and password.

#### Conclusion

Brute force attacks, dictionary attacks, and credential stuffing are all techniques used to gain unauthorized access to a SQL Server. It is important to implement strong security measures, such as using strong and unique passwords, regularly updating passwords, and implementing account lockouts or rate limiting, to protect against these types of attacks. Additionally, it is crucial to stay informed about the latest security vulnerabilities and patches to ensure the SQL Server is protected against known exploits.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) is a cryptographic network protocol that allows secure remote login and command execution over an insecure network. It provides a secure channel over an unsecured network by encrypting the connection between the client and the server.

SSH can be used for various purposes, such as remote administration, file transfer, and tunneling. It is widely used in the field of cybersecurity for secure remote access to servers and devices.

#### Brute-Force Attacks on SSH

Brute-force attacks on SSH involve systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This method is often used by attackers to gain unauthorized access to SSH servers.

To perform a brute-force attack on SSH, attackers use automated tools that generate and test a large number of username and password combinations. These tools can be configured to use different techniques, such as dictionary attacks (using a list of commonly used passwords) or brute-force attacks (trying all possible combinations).

To protect against brute-force attacks on SSH, it is important to use strong and unique passwords, implement account lockout policies, and monitor SSH logs for suspicious activity. Additionally, using key-based authentication instead of password-based authentication can provide an extra layer of security.

#### Countermeasures

To protect against brute-force attacks on SSH, consider implementing the following countermeasures:

- **Strong Passwords**: Use strong and unique passwords for SSH accounts. Avoid using common passwords or easily guessable combinations.

- **Account Lockout Policies**: Implement account lockout policies that temporarily lock user accounts after a certain number of failed login attempts. This can help prevent brute-force attacks by slowing down the attacker's progress.

- **SSH Keys**: Consider using key-based authentication instead of password-based authentication. SSH keys provide a more secure method of authentication and are not susceptible to brute-force attacks.

- **Monitoring and Logging**: Regularly monitor SSH logs for any suspicious activity, such as multiple failed login attempts from the same IP address. This can help identify and mitigate brute-force attacks in real-time.

- **Firewall Rules**: Configure firewall rules to limit SSH access to trusted IP addresses only. This can help prevent unauthorized access to SSH servers from unknown sources.

By implementing these countermeasures, you can significantly reduce the risk of successful brute-force attacks on SSH servers.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### qatlh SSH keys / Debian predictable PRNG

Some systems have known flaws in the random seed used to generate cryptographic material. This can result in a dramatically reduced keyspace which can be bruteforced with tools such as [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Pre-generated sets of weak keys are also available such as [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ and OpenMQ)

The STOMP text protocol is a widely used messaging protocol that **allows seamless communication and interaction with popular message queueing services** such as RabbitMQ, ActiveMQ, HornetQ, and OpenMQ. It provides a standardized and efficient approach to exchange messages and perform various messaging operations.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet is a protocol used to establish a remote connection to a device over a network. It allows users to access and manage devices remotely by providing a command-line interface. Telnet is commonly used for administrative tasks, such as configuring routers and switches.

Telnet can be vulnerable to brute-force attacks, where an attacker attempts to gain unauthorized access by systematically trying different combinations of usernames and passwords. Brute-forcing Telnet can be done using tools like Hydra or Medusa, which automate the process of trying multiple login credentials.

To perform a Telnet brute-force attack, the attacker needs a list of possible usernames and passwords. This can be obtained through various methods, such as using common default credentials, searching for leaked password databases, or using social engineering techniques to gather information about potential targets.

Once the attacker has the list of credentials, they can use a brute-force tool to systematically try each combination until a successful login is achieved. It is important to note that brute-forcing is a time-consuming process and may take a significant amount of time depending on the complexity of the passwords and the security measures in place.

To protect against Telnet brute-force attacks, it is recommended to use strong, unique passwords and implement account lockout policies that temporarily lock an account after a certain number of failed login attempts. Additionally, disabling Telnet and using more secure protocols like SSH is highly recommended.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) is a graphical desktop sharing system that allows you to remotely control another computer. It is commonly used for remote administration and support purposes.

#### Brute-Forcing VNC Passwords

Brute-forcing VNC passwords involves systematically trying all possible combinations of characters until the correct password is found. This can be done using tools like Hydra or Medusa.

To brute-force VNC passwords, you need to know the IP address or hostname of the target machine and the VNC port number (usually 5900). Additionally, you may need to specify the VNC protocol version and the username (if required).

Here is an example command to brute-force VNC passwords using Hydra:

```
hydra -L users.txt -P passwords.txt <target_ip> vnc -V
```

In this command, `users.txt` and `passwords.txt` are files containing a list of usernames and passwords, respectively. `<target_ip>` should be replaced with the IP address of the target machine.

#### Mitigating VNC Brute-Force Attacks

To protect against brute-force attacks on VNC, you can implement the following measures:

1. Use strong passwords: Ensure that your VNC passwords are long, complex, and unique. Avoid using common or easily guessable passwords.

2. Limit access: Restrict VNC access to trusted IP addresses or networks. This can be done by configuring firewall rules or using a VPN.

3. Enable account lockout: Implement account lockout policies that temporarily lock user accounts after a certain number of failed login attempts.

4. Monitor logs: Regularly review VNC server logs for any suspicious activity or repeated failed login attempts.

By following these best practices, you can significantly reduce the risk of successful brute-force attacks on your VNC server.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm is a protocol used for remote management of Windows systems. It allows administrators to execute commands, access files, and perform various administrative tasks on remote Windows machines.

#### Brute-Forcing Winrm

Brute-forcing is a common technique used to gain unauthorized access to a system by systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This technique can also be applied to Winrm to attempt to guess the login credentials and gain access to a remote Windows machine.

To brute-force Winrm, you can use tools like Hydra or Medusa, which are popular password-cracking tools. These tools allow you to specify a list of usernames and passwords, and they will systematically try each combination until a successful login is achieved.

It is important to note that brute-forcing is a time-consuming process and can be easily detected by intrusion detection systems (IDS) or account lockout policies. Therefore, it is recommended to use this technique only when other methods of gaining access to the system have failed.

#### Mitigating Brute-Force Attacks

To protect against brute-force attacks on Winrm, it is recommended to implement the following security measures:

1. **Strong Passwords**: Ensure that strong passwords are used for all user accounts on the system. A strong password should be at least 12 characters long and include a combination of uppercase and lowercase letters, numbers, and special characters.

2. **Account Lockout Policies**: Implement account lockout policies that lock user accounts after a certain number of failed login attempts. This helps to prevent brute-force attacks by temporarily disabling the account after a specified number of unsuccessful login attempts.

3. **IP Whitelisting**: Restrict Winrm access to specific IP addresses or IP ranges. By whitelisting only trusted IP addresses, you can limit the exposure to brute-force attacks from unknown sources.

4. **Monitoring and Logging**: Implement monitoring and logging mechanisms to detect and track suspicious login attempts. This can help identify brute-force attacks and provide valuable information for incident response.

By implementing these security measures, you can significantly reduce the risk of successful brute-force attacks on Winrm and enhance the overall security of your Windows systems.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vItlhutlh 'ej **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Local

### Online cracking databases

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 with/without ESS/SSP and with any challenge's value)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2 captures, and archives MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes and file hashes)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Check this out before trying to brute force a Hash.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### qarDaq zip tIq attack

**zip tIq** (zip file) **Daq** (inside) **jImej** (plaintext) **(yIghoS)** **jImej** (part of the plaintext) **Dajatlh** (need to know). **zip tIq** (zip file) **Daq** (inside) **jImej** (files) **ghItlh** (filenames) **'ej** (and) **jImej** (size) **(yIghoS)** **jImej** (files) **Dajatlh** (need to know). **encrypted.zip** **chay'** (run) **`7z l encrypted.zip`** **(yIghoS)**.

**[bkcrack](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)** **ghItlh** (download) **(yIghoS)**.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

#### Description

7z is a file compression format and software application used for compressing and decompressing files. It provides high compression ratios and supports various compression algorithms, including LZMA and LZMA2. The 7z format is commonly used for creating and distributing archives.

#### Brute-Force Attack

A brute-force attack is a method used to crack passwords or encryption keys by systematically trying all possible combinations until the correct one is found. In the context of 7z files, a brute-force attack can be used to guess the password used to encrypt the file.

To perform a brute-force attack on a 7z file, you can use tools like `7z2john` and `john` to extract the hash from the file and then use `john` or `hashcat` to crack the password. These tools utilize various techniques, such as dictionary attacks and rule-based attacks, to speed up the cracking process.

It's important to note that brute-forcing a password can be a time-consuming process, especially if the password is long and complex. Additionally, the success of a brute-force attack depends on factors such as the strength of the password and the computing power available.

#### Prevention and Mitigation

To protect your 7z files from brute-force attacks, it's essential to use strong and unique passwords. Avoid using common words or easily guessable patterns. Instead, opt for long and complex passwords that include a combination of uppercase and lowercase letters, numbers, and special characters.

Additionally, you can increase the security of your 7z files by using a key derivation function (KDF) to generate the encryption key. A KDF applies a one-way function to the password, making it more difficult for an attacker to guess the original password.

Regularly updating your passwords and monitoring for any unauthorized access to your files can also help mitigate the risk of brute-force attacks.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

#### Brute Force

Brute force is a common technique used in hacking to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. This method relies on the assumption that the password is weak and can be easily guessed.

To perform a brute force attack, hackers use automated tools that generate and test a large number of password combinations in a short period of time. These tools can be customized to target specific systems or accounts, increasing the chances of success.

Brute force attacks can be time-consuming and resource-intensive, especially if the password is long and complex. However, they can be effective against weak passwords or poorly implemented security measures.

To protect against brute force attacks, it is important to use strong and unique passwords that are not easily guessable. Additionally, implementing account lockouts or rate limiting can help prevent multiple login attempts within a short period of time.

#### Klingon Translation

#### PDF

#### Brute Force

Brute force jatlhHa' vItlhutlhlaHbe'chugh, jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhlaHbe'chugh 'ej jatlhHa' vItlhutlhla
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Owner Password

To crack a PDF Owner password check this: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM qo'qish

NTLM qo'qish, Windows tizimlarida foydalaniladigan bir autentifikatsiya protokolining bir xususiyatidir. Bu protokol, parolni hash qilish uchun NTLM hash algoritmini ishlatadi. NTLM hash, parolni o'z ichiga oladi va uni ma'lumotlar bazasida saqlash uchun ishlatiladi.

NTLM qo'qishni qo'llash orqali, hakerlar parolni hash qilish uchun har bir imkoniyatli parolni sinab ko'rishlari mumkin. Bu sinovlar, parolni topish uchun barcha imkoniyatlarni tekshirishga yordam beradi. Hakerlar, parolni topish uchun har bir imkoniyatli kombinatsiyani tekshirish uchun avtomatlashtirilgan vositalardan foydalanishadi.

NTLM qo'qishning bir nechta usullari mavjud, masalan, slovar seriyalari, kombinatorik seriyalari va boshqa usullar. Hakerlar, parolni topish uchun eng samarali usulni tanlashadi va uning orqali NTLM hashlarini qo'qishni boshlaydi.

NTLM qo'qishning muvaffaqiyatli bo'lishi uchun, hakerlar parolni topish uchun yuqori darajadagi kombinatsiyalarni sinab ko'rishlari kerak. Bu, hakerlarga tez va samarali parolni topish imkonini beradi.

NTLM qo'qish, hakerlarga parolni topish uchun samarali usulni taqdim etadi. Bu usul, hakerlarga NTLM hashlarini qo'qish orqali parolni topish imkonini beradi.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

#### Description

Keepass is a popular open-source password manager that allows users to securely store and manage their passwords. It uses strong encryption algorithms to protect the stored passwords and provides a user-friendly interface for easy access.

#### Brute-Force Attack

A brute-force attack is a common method used to crack passwords in Keepass. In this attack, the hacker systematically tries all possible combinations of characters until the correct password is found. This method can be time-consuming and resource-intensive, especially for complex passwords.

#### Prevention

To protect against brute-force attacks in Keepass, it is important to use strong and unique passwords. Avoid using common words or easily guessable patterns. Additionally, enabling the option to lock the database after a certain number of failed login attempts can help prevent unauthorized access.

#### Conclusion

While Keepass is a secure password manager, it is still vulnerable to brute-force attacks. By following best practices for password creation and enabling security features, users can enhance the security of their Keepass database and protect their sensitive information.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
#### Keberoasting

Keberoasting is a technique used to extract and crack service account passwords from Active Directory (AD) environments. It takes advantage of the way Kerberos authentication works in AD.

When a user authenticates to a service using Kerberos, a Ticket Granting Ticket (TGT) is issued. This TGT can be used to request service tickets for various services within the AD environment. However, some services do not require the user to provide their password when requesting a service ticket. Instead, the service retrieves the user's TGT from the AD and uses it to request a service ticket on behalf of the user.

Keberoasting exploits this behavior by requesting service tickets for accounts that have Kerberos pre-authentication disabled. These accounts include service accounts, which are often privileged and have weak or easily guessable passwords.

To perform Keberoasting, an attacker first identifies service accounts with Kerberos pre-authentication disabled. This can be done by querying the AD for accounts with the "Do not require Kerberos preauthentication" flag set. Once the vulnerable accounts are identified, the attacker requests service tickets for these accounts using their TGTs.

The attacker then extracts the encrypted service tickets and offline cracks them using brute-force techniques. Since the service tickets are encrypted with the account's password hash, the attacker can attempt to crack the password offline without triggering any account lockouts or alerts.

Keberoasting can be a powerful technique for compromising AD environments, as it allows an attacker to target privileged service accounts that often have weak passwords. To defend against Keberoasting, organizations should enforce strong password policies for service accounts and regularly rotate their passwords. Additionally, enabling Kerberos pre-authentication for all accounts can help mitigate the risk of Keberoasting attacks.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks chel

#### Method 1

Install: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Qa'Hom 2

---

##### Brute Force

###### Definition

Brute force is a method used in hacking to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. It is a time-consuming technique but can be effective if the password is weak or easily guessable.

###### Steps

1. Identify the target: Determine the system or account you want to gain access to.

2. Gather information: Collect as much information as possible about the target, such as usernames, email addresses, or any other relevant details.

3. Choose a tool: Select a suitable brute force tool that can automate the process of trying different password combinations.

4. Configure the tool: Set up the tool with the necessary parameters, such as the target system or account, the password list, and any additional options.

5. Start the brute force attack: Initiate the attack by running the tool and allowing it to systematically try different password combinations.

6. Monitor the progress: Keep an eye on the tool's output to track the progress of the brute force attack.

7. Analyze the results: Once the attack is complete, analyze the results to determine if the correct password was found.

8. Take appropriate action: If successful, take the necessary steps to secure the system or account. If unsuccessful, consider other hacking techniques or approaches.

###### Tips

- Use a strong and diverse password list to increase the chances of success.

- Implement rate limiting or account lockout mechanisms to prevent or mitigate brute force attacks.

- Regularly update passwords and use strong, unique passwords for each account.

- Consider using multi-factor authentication to add an extra layer of security.

---

##### Qa'Hom 2

###### Brute Force

###### Qap

Qa'Hom jatlhlaHbe'chugh, 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlhlaHbe'chugh, 'ej 'e' vItlhutlh
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Another Luks BF tutorial: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Qa'Hom key

The PGP/GPG private key is a crucial component in asymmetric encryption. It is used to decrypt messages that have been encrypted with the corresponding public key. The private key must be kept secure and should never be shared with anyone.

To generate a PGP/GPG private key, you can use tools like GnuPG (GPG) or Pretty Good Privacy (PGP). These tools provide a command-line interface for key generation and management.

When generating a private key, you will be prompted to provide a passphrase. This passphrase is used to protect the private key and should be strong and unique. It is important to remember this passphrase, as it will be required to decrypt messages encrypted with your public key.

Once you have generated your private key, it is recommended to back it up in a secure location. Losing your private key can result in permanent data loss, as encrypted messages cannot be decrypted without the corresponding private key.

Remember to always keep your private key secure and never share it with anyone.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Use [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) and then john

### Open Office Pwd Protected Column

If you have an xlsx file with a column protected by a password you can unprotect it:

* **Upload it to google drive** and the password will be automatically removed
* To **remove** it **manually**:

---

### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Use [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) and then john

### Open Office Pwd Protected Column

If you have an xlsx file with a column protected by a password you can unprotect it:

* **Upload it to google drive** and the password will be automatically removed
* To **remove** it **manually**:

---
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX Certificates

#### Description

PFX (Personal Information Exchange) certificates are a type of digital certificate that is used to securely store and transport private keys, public keys, and other sensitive information. PFX certificates are commonly used in various security protocols, such as SSL/TLS, to authenticate and encrypt communication between parties.

#### Brute-Forcing PFX Passwords

Brute-forcing PFX passwords involves attempting to guess the password used to protect a PFX certificate. This can be done using various techniques, such as dictionary attacks, where a list of commonly used passwords is systematically tested, or brute-force attacks, where all possible combinations of characters are tried.

To perform a brute-force attack on a PFX certificate password, you can use tools like `openssl` or `John the Ripper`. These tools allow you to automate the process of trying different passwords until the correct one is found.

It is important to note that brute-forcing PFX passwords can be a time-consuming process, especially if the password is complex and has a high entropy. Additionally, it is considered unethical and illegal to brute-force passwords without proper authorization.

#### Mitigating Brute-Force Attacks

To mitigate brute-force attacks on PFX certificates, it is recommended to use strong and unique passwords that are not easily guessable. Additionally, enabling account lockouts or rate limiting can help prevent multiple failed login attempts.

Furthermore, implementing multi-factor authentication (MFA) can add an extra layer of security to PFX certificates. MFA requires users to provide additional verification, such as a one-time password or biometric authentication, in addition to the password.

Regularly updating and rotating PFX certificate passwords is also important to minimize the risk of brute-force attacks. This ensures that even if a password is compromised, it will only be valid for a limited period of time.

#### Conclusion

PFX certificates are a widely used method for securely storing and transporting sensitive information. However, it is crucial to protect these certificates with strong passwords and implement additional security measures to mitigate the risk of brute-force attacks.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) **ghItlh** **automate workflows** **Dujmey** **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Tools

**Hash examples:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Wordlists

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Wordlist Generation Tools**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Advanced keyboard-walk generator with configurable base chars, keymap and routes.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John mutlh

**_etc/john/john.conf_** qar'a' 'e' yIlo' je 'oH.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat attacks

* **Wordlist attack** (`-a 0`) with rules

**Hashcat** **ghItlh** **rules** **ghItlh** **folder** **Daj** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'**
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Wordlist combinator** attack

**Hashcat** jupwI'pu' **2 wordlists** **1**-Daq **combine** vItlhutlh.\
vItlhutlh 1 **"hello"** vItlhutlh 2 **"world"** je **"earth"** vItlhutlh. `helloworld` je `helloearth` vItlhutlh.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Mask attack** (`-a 3`)

* **Qa'Hom attack** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* **Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) attack**

  Klingon Translation:
  
  * **Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) jang**
  
  ---
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat qo'noS

Hashcat jatlhlaHbe'chugh, 'ej hashcat jatlhlaHbe'chugh qo'noS. Hashcat jatlhlaHbe'chugh qo'noS 'oH 'ej hashcat jatlhlaHbe'chugh qo'noS 'oH. 

#### Brute-force mode

#### QaDHa'wI' jatlhlaHbe'chugh

In brute-force mode, Hashcat tries all possible combinations of characters to crack a password. This mode is useful when the password is not known and there are no specific hints or patterns to guess it. However, brute-force attacks can be time-consuming and resource-intensive, especially for longer and more complex passwords. 

QaDHa'wI' jatlhlaHbe'chughDaq, Hashcat password crack laH 'e' vItlhutlh. 'Iv password vItlhutlh 'ej 'oH vItlhutlh hints patterns ghap vItlhutlh. 'ach, QaDHa'wI' jatlhlaHbe'chughDaq, password vItlhutlh 'ej password vItlhutlh 'e' vItlhutlh. 

#### Rule-based mode

#### Rule-based jatlhlaHbe'chugh

In rule-based mode, Hashcat applies a set of predefined rules to modify the passwords before attempting to crack them. These rules can include adding or removing characters, changing case, or applying specific transformations. Rule-based attacks can be more efficient than brute-force attacks as they take advantage of common password patterns and variations. 

Rule-based jatlhlaHbe'chughDaq, Hashcat password vItlhutlh 'e' vItlhutlh. 'Iv password vItlhutlh 'ej 'oH vItlhutlh hints patterns ghap vItlhutlh. 'ach, Rule-based jatlhlaHbe'chughDaq, password vItlhutlh 'ej password vItlhutlh 'e' vItlhutlh. 

#### Hybrid attack mode

#### Hybrid attack jatlhlaHbe'chugh

In hybrid attack mode, Hashcat combines the brute-force and rule-based approaches to crack passwords. It first applies the rule-based transformations to the passwords and then tries all possible combinations using the modified passwords. This mode can be effective in cracking complex passwords that include common patterns or variations. 

Hybrid attack jatlhlaHbe'chughDaq, Hashcat password vItlhutlh 'e' vItlhutlh. 'Iv password vItlhutlh 'ej 'oH vItlhutlh hints patterns ghap vItlhutlh. 'ach, Hybrid attack jatlhlaHbe'chughDaq, password vItlhutlh 'ej password vItlhutlh 'e' vItlhutlh.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Cracking Linux Hashes - /etc/shadow file

## Introduction

In Linux systems, user passwords are stored in the `/etc/shadow` file. This file contains hashed representations of the passwords, making it difficult to retrieve the original passwords. However, with the help of brute-force techniques, it is possible to crack these hashes and obtain the plaintext passwords.

## Brute-Force Attack

A brute-force attack involves systematically trying all possible combinations of characters until the correct password is found. In the case of cracking Linux hashes, this means generating different passwords, hashing them, and comparing the resulting hash with the target hash from the `/etc/shadow` file.

## Tools for Brute-Forcing Linux Hashes

There are several tools available for brute-forcing Linux hashes. Some popular ones include:

- **John the Ripper**: A powerful password cracking tool that supports various hash types, including the ones used in Linux systems.
- **Hashcat**: Another popular password cracking tool that supports a wide range of hash types, including Linux hashes.
- **Hydra**: A versatile network login cracker that can also be used for cracking Linux hashes.

## Wordlists

To perform a successful brute-force attack, it is essential to have a good wordlist. A wordlist is a file containing a list of potential passwords that will be tested during the attack. There are various wordlists available online, including general-purpose ones and specialized ones for specific purposes.

## Tips for Brute-Forcing Linux Hashes

Here are some tips to improve the efficiency and success rate of brute-forcing Linux hashes:

1. **Use a good wordlist**: Choose a wordlist that includes commonly used passwords, as well as variations and combinations of words.
2. **Leverage rules**: Some password cracking tools allow the use of rules to modify the wordlist on-the-fly. These rules can apply transformations such as capitalization, appending numbers, or replacing characters with symbols.
3. **Combine multiple techniques**: Try different techniques, such as dictionary attacks, mask attacks, and hybrid attacks, to increase the chances of cracking the hash.
4. **Leverage GPU power**: If available, use a powerful GPU for password cracking, as it can significantly speed up the process.

## Conclusion

Cracking Linux hashes from the `/etc/shadow` file can be a challenging task. However, with the right tools, wordlists, and techniques, it is possible to crack these hashes and obtain the plaintext passwords. Remember to always perform these activities within the legal boundaries and with proper authorization.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Cracking Windows Hashes

## Introduction

In this section, we will discuss the process of cracking Windows hashes. Hash cracking is a common technique used in password cracking, where the goal is to recover the original plaintext password from its hashed representation.

## Types of Windows Hashes

Windows operating systems use different types of hashes to store user passwords. The most common types are:

- **LM Hash**: This is an older and weaker hash algorithm used in older versions of Windows. It is no longer used in modern Windows systems.
- **NTLM Hash**: This is the default hash algorithm used in Windows NT-based systems, including Windows XP, Windows 7, and Windows 10.
- **NTLMv2 Hash**: This is an improved version of the NTLM hash algorithm, used in newer Windows systems.

## Cracking Windows Hashes

To crack Windows hashes, we can use various tools and techniques. Here are some common methods:

1. **Brute-Force Attack**: This method involves trying all possible combinations of characters until the correct password is found. It is a time-consuming process but can be effective if the password is weak.
2. **Dictionary Attack**: In this method, a pre-generated list of commonly used passwords, known as a dictionary, is used to crack the hash. This method is faster than brute-force but relies on the password being present in the dictionary.
3. **Rainbow Table Attack**: A rainbow table is a precomputed table of hash values for all possible passwords. By comparing the hash to the values in the table, the original password can be recovered. This method is faster than brute-force and dictionary attacks but requires a large amount of storage.

## Tools for Cracking Windows Hashes

There are several tools available for cracking Windows hashes, including:

- **John the Ripper**: A popular password cracking tool that supports various hash types, including Windows hashes.
- **Hashcat**: A powerful password cracking tool that can crack a wide range of hash types, including Windows hashes.
- **Cain and Abel**: A versatile tool that can be used for password cracking, including Windows hashes.

## Conclusion

Cracking Windows hashes can be a challenging task, but with the right tools and techniques, it is possible to recover the original plaintext password. It is important to note that hash cracking should only be performed with proper authorization and for legitimate purposes, such as penetration testing or password recovery.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Cracking Common Application Hashes

## Introduction

In this section, we will discuss the process of cracking common application hashes. Hash cracking is a technique used to recover plaintext passwords from their hashed representations. By cracking the hashes, we can gain unauthorized access to various applications and systems.

## Methodology

The process of cracking common application hashes typically involves the following steps:

1. **Hash Identification**: Identify the type of hash used by the application. Common hash types include MD5, SHA1, SHA256, etc.

2. **Wordlist Generation**: Create a wordlist containing potential passwords. This can be done by using tools like `Crunch` or by downloading pre-generated wordlists from online sources.

3. **Hash Cracking**: Use a hash cracking tool such as `John the Ripper` or `Hashcat` to crack the hashes. These tools utilize the wordlist generated in the previous step to attempt to find a match for the hashed passwords.

4. **Brute Force Attack**: If the hash cracking process fails, a brute force attack can be attempted. This involves systematically trying all possible combinations of characters until the correct password is found.

5. **Rainbow Tables**: In some cases, rainbow tables can be used to speed up the hash cracking process. Rainbow tables are precomputed tables that contain a large number of hash-to-plaintext mappings.

## Resources

There are several resources available that can aid in the process of cracking common application hashes. Some of these include:

- **Wordlists**: Online sources such as `SecLists` or `CrackStation` provide extensive wordlists that can be used for hash cracking.

- **Hash Cracking Tools**: Tools like `John the Ripper` and `Hashcat` are widely used for hash cracking and support a variety of hash types.

- **Rainbow Tables**: Websites like `Project RainbowCrack` offer precomputed rainbow tables that can be used to crack hashes more efficiently.

## Conclusion

Cracking common application hashes is a crucial skill for hackers and penetration testers. By understanding the methodology and utilizing the available resources, one can successfully crack hashed passwords and gain unauthorized access to various applications and systems. However, it is important to note that hash cracking should only be performed on systems with proper authorization and consent.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>qaStaHvIS AWS hacking vItlh</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) vItlh **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
