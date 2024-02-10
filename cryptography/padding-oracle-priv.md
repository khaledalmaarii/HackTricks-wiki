<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# CBC - Cipher Block Chaining

In CBC mode the **previous encrypted block is used as IV** to XOR with the next block:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

To decrypt CBC the **opposite** **operations** are done:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Notice how it's needed to use an **encryption** **key** and an **IV**.

# Message Padding

As the encryption is performed in **fixed** **size** **blocks**, **padding** is usually needed in the **last** **block** to complete its length.\
Usually **PKCS7** is used, which generates a padding **repeating** the **number** of **bytes** **needed** to **complete** the block. For example, if the last block is missing 3 bytes, the padding will be `\x03\x03\x03`.

Let's look at more examples with a **2 blocks of length 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note how in the last example the **last block was full so another one was generated only with padding**.

# Padding Oracle

When an application decrypts encrypted data, it will first decrypt the data; then it will remove the padding. During the cleanup of the padding, if an **invalid padding triggers a detectable behaviour**, you have a **padding oracle vulnerability**. The detectable behaviour can be an **error**, a **lack of results**, or a **slower response**.

If you detect this behaviour, you can **decrypt the encrypted data** and even **encrypt any cleartext**.

## How to exploit

You could use [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) to exploit this kind of vulnerability or just do
```
sudo apt-get install padbuster
```
DaH jImej 'ej cookie vItlhutlh vulnerable 'e' vItlhutlh. vaj 'oH: 

```plaintext
1. Intercept the request containing the cookie using a proxy tool like Burp Suite.
2. Modify the cookie by removing the padding or changing its value.
3. Forward the modified request to the server and observe the response.
4. If the server returns a different response or an error message indicating invalid padding, it is likely that the site is vulnerable to a padding oracle attack.
```

This technique allows you to determine if a site is susceptible to a padding oracle attack by manipulating the cookie and analyzing the server's response.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** means that **base64** is used (but others are available, check the help menu).

You could also **abuse this vulnerability to encrypt new data. For example, imagine that the content of the cookie is "**_**user=MyUsername**_**", then you may change it to "\_user=administrator\_" and escalate privileges inside the application. You could also do it using `paduster`specifying the -plaintext** parameter:

**Encoding 0** **base64** **'oH** **(ghItlhv, **'ej **'oH **vItlhutlh **'e' vItlhutlh **, **'ej **'oH **vItlhutlh **'e' vItlhutlh **'e' **-** **paduster** **-plaintext** **parameter:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
**ghItlh** padbuster **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error** parameter **-vIqtaHvIS** **padbuster** **-error
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## ghItlh

**tlhIngan Hol** vItlhutlhlaHchugh, **encrypted data** vItlhutlhlaHchugh **correct values** vItlhutlhlaHchugh **different paddings** vItlhutlhlaHchugh **guessing** vItlhutlhlaHchugh **decrypt** vItlhutlhlaHchugh **start** vItlhutlhlaHchugh **padding oracle attack** vItlhutlhlaHchugh **decrypting bytes** vItlhutlhlaHchugh **end** vItlhutlhlaHchugh **start** vItlhutlhlaHchugh **guessing** vItlhutlhlaHchugh **correct value** vItlhutlhlaHchugh **creates a padding of 1, 2, 3, etc** vItlhutlhlaHchugh.

![](<../.gitbook/assets/image (629) (1) (1).png>)

**encrypted text** vItlhutlhlaHchugh **2 blocks** vItlhutlhlaHchugh **bytes** vItlhutlhlaHchugh **E0 to E15** vItlhutlhlaHchugh.\
**decrypt** vItlhutlhlaHchugh **last** **block** vItlhutlhlaHchugh **E8** vItlhutlhlaHchugh **E15**, **whole block** vItlhutlhlaHchugh **"block cipher decryption"** vItlhutlhlaHchugh **intermediary bytes I0 to I15** vItlhutlhlaHchugh.\
**intermediary byte** vItlhutlhlaHchugh **XORed** vItlhutlhlaHchugh **previous encrypted bytes** vItlhutlhlaHchugh **E0 to E7**. So:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

vItlhutlhlaHchugh, **modify `E7`** vItlhutlhlaHchugh **C15** vItlhutlhlaHchugh `0x01` vItlhutlhlaHchugh, **correct padding** vItlhutlhlaHchugh. vItlhutlhlaHchugh: `\x01 = I15 ^ E'7`

vItlhutlhlaHchugh **E'7** vItlhutlhlaHchugh **find**, **calculate I15**: `I15 = 0x01 ^ E'7`

vItlhutlhlaHchugh **calculate C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15** vItlhutlhlaHchugh, **calculate C14** vItlhutlhlaHchugh, **brute-forcing** vItlhutlhlaHchugh **padding** `\x02\x02`.

**BF** vItlhutlhlaHchugh **complex** vItlhutlhlaHchugh **previous one** vItlhutlhlaHchugh **calculate the the `E''15`** vItlhutlhlaHchugh **value** `0x02`: `E''7 = \x02 ^ I15`, **find** **`E'14`** vItlhutlhlaHchugh **`C14` equals to `0x02`**.\
vItlhutlhlaHchugh, **steps** vItlhutlhlaHchugh **decrypt C14**: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Follow** vItlhutlhlaHchugh **chain** vItlhutlhlaHchugh **decrypt** vItlhutlhlaHchugh **whole encrypted text**.

## Detection of the vulnerability

**Register** vItlhutlhlaHchugh **account** vItlhutlhlaHchugh **log in** vItlhutlhlaHchugh **account** .\
**log in many times** vItlhutlhlaHchugh **same cookie** vItlhutlhlaHchugh, **something** vItlhutlhlaHchugh **wrong** vItlhutlhlaHchugh **application**. **cookie sent back** vItlhutlhlaHchugh **unique** vItlhutlhlaHchugh **time** **log in**. **cookie** vItlhutlhlaHchugh **always** vItlhutlhlaHchugh **same**, **probably** vItlhutlhlaHchugh **always** vItlhutlhlaHchugh **valid** vItlhutlhlaHchugh **way to invalidate i**t.

vItlhutlhlaHchugh, **modify** vItlhutlhlaHchugh **cookie**, **error** vItlhutlhlaHchugh **application**.\
vItlhutlhlaHchugh **BF** vItlhutlhlaHchugh **padding** (padbuster vItlhutlhlaHchugh), **manage** vItlhutlhlaHchugh **cookie** vItlhutlhlaHchugh **valid** vItlhutlhlaHchugh **different user**. **scenario** vItlhutlhlaHchugh **highly probably vulnerable to padbuster**.

## References

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
