# Learning from Data Breaches in the real world

## Learning from mistakes
- When something goes wrong with systems - many companies ty to keep it inbound and not say it publicly
- ^this is not necessarily good
- no tradition for public interest
  
- accidents : there is a traditions in other fields that has a big public interest when something goes wrong
- if we say it alound we can all learn from it, and be better prepared for similar situations

- proceedual factors (e.g. if one system assumes something and one do another then it might cause an accident)

### Project note
- look at the event
- come up with how to prevent

## Project cases

### DigiNotar (2011)
- Tysk pki - official national certificate auth
- some guy could create digital auth signed by them (maybe got their private key)
- main thing is to make sure that you are the only one that can sign

### Sony pictures entertainment (2014)
- sony is hacker popular
- 1 TB
- Raw material of movies databreach

### Target (2015)
- got in through the aircon system
- sypplyline attack
- got onto cash regiteres, read creditcard data
- first example of a CEO had to resign bc. of a hacking

### Stuxnet (2010)
- lot of material

### **Mariot Hotel chain (2018)**
- got public in 2018, but got in in 2014
- got customer data (credit card, passport) -> identity theft
- in 2022 something else happened - not relevant

#### Notes
```txt
may have affected up to 339 million guests
...
Information Commissioner's Office (ICO) said names, contact information, and passport details may all have been compromised in a cyber-attack.
...
The first part of the cyber-attack happened in 2014, affecting the Starwood Hotels group, which was acquired by Marriott two years later.
...
But until 2018, when the problem was first noticed, the attacker continued to have access to all affected systems, including:
names
email addresses
phone numbers
passport numbers
arrival and departure information
VIP status
loyalty programme numbers
``` - BBC (30 October 2020) <https://www.bbc.com/news/technology-54748843>


```txt
The hack was caused by an unknown attacker
who obtained access to Starwood hotels' systems in 2014, who then
merged with Marriott in 2015.
...
The United Kingdom's Information
Commissioner's Office (ICO) fined Marriott £18.4 million for the
breach, citing General Data Protection Regulation article 32,
which specifies that organizations servicing EU residents must
take necessary measures to secure personal data.
...
On September 8, 2018, Marriott International [...] discovered that cybercriminals had breached its guest reservation system.
...
[...], stories in the New York Times and the
Washington Post in December 2018, citing anonymous sources
in the U.S. government, pointed a finger in an entirely other
direction: at hackers employed by Chinese intelligence services.
The Post's and Times's sources had access to more
information on the hack than had been made public, and they
say the code and attack patterns utilized match up with approaches used by state-sponsored Chinese hackers; for example, the attackers used a cloud-hosting space frequently
used by Chinese hackers.
...
Another indication that this breach was carried out by the government rather than by cybercriminals is that none of the millions of valuable records were sold on the dark web;
...
According
to government sources, it was part of a larger Chinese operation to collect enormous amounts of data on American government employees and intelligence officers; Marriott is the largest hotel provider to the US government and military. Stolen passport numbers, in instance, might be used to track people's movements all over the world. The breach of the Office of Personnel Management's networks, which also resulted in millions of people's data being taken but none of it winding up on the dark web or being used for fraud, was most likely part of the same campaign.
...
In February 2020, the U.S. Department of Justice formally charged four members of the Chinese military with the 2017 Equifax attack, which resulted in the theft of personally identifiable information from millions of people; the Equifax attack was explicitly linked to the Marriott and OPM breaches as part of the same larger operation in the announcement of the indictment. This was an extremely rare step — the US rarely accuses foreign intelligence officials in order to avoid retaliation against American operatives — that demonstrated how seriously the U.S. government considered the attack.
...
An attacker got physical access to a machine on the Starwood network on July 29, 2014, and deployed a web shell. The machine was connected to the internet and had administrative privileges since it was running a service that allowed employees to make changes to the Starwood website. The attacker installed a Remote Access Trojan (RAT) along with MimiKatz (post-exploitation tool that dumps passwords from memory, as well as hashes, PINs and Kerberos tickets) on the system through the web shell, giving the attacker access to a shell with root-level privileges on the impacted machine and network-adjacent machines. 
...
Simply described, a RAT is a malicious computer program that allows the perpetrator to gain unauthorized administrative access over their victim's technology. A multitude of digital vulnerabilities at Starwood's properties could have aided the cyber-criminals' RAT's success. These properties, in particular, were running outdated versions of Windows Server on their computer systems and remote access via Telnet and Remote Desktop Protocol (RDP) ports were left open to the internet.
...
Furthermore, Marriott was unaware that
Starwood had been targeted by separate attackers in an unrelated incident in 2015, leaving its workplace devices with malware.
...
In addition, Marriott began migrating data from multiple databases stored within Starwood's guest reservation system. This information included a variety of customers’ personal details—such as names, addresses, phone numbers, email addresses, passport numbers and credit card numbers.
...
While the data in these databases was encrypted, cybercriminals were finally able to find their related decryption keys and subsequently unlock the information. The cybercriminals then began exfiltrating the information. After transporting this information, the cybercriminals then re-encrypted it in an effort to remain undetected within the system.
...
Marriott discovered the vulnerability September 8 2018,
over two years after the acquisition, thanks to a system security
alert.
...
As a result [of the attack], Marriott's stock dropped by 5% nearly immediately after the company disclosed the details of the hack. Furthermore, the company is projected to have lost over $1 billion in revenue due to diminished customer loyalty following the incident.
...
The ICO's (Information Commissioner’s Office) ruling contains four important findings at a high level:
1. Insufficient monitoring of privileged accounts:
There was a failure to implement continuous network
and user activity monitoring. According to the ICO,
Marriott should have been aware of the requirement for
additional layers of security.
2. Database monitoring is insufficient
3. Failure to implement server hardening:
The server's vulnerability could have been mitigated, for
example, through whitelisting
4. Lack of encryption:
For example, passport information was not encrypted.
...
By considering the ICO’s findings, following are several
tools and techniques that could be used to enforce security of
data and traffic in relation to the Marriott data breach:
1. Anomaly detection: It might be tough to discover
anomalies in an organization's network if they don't
have a baseline understanding of how it should work.
Anomaly detection engines (ADE) allow them to
evaluate their network so that when breaches occur,
they are notified quickly enough to respond.
2. Data loss prevention (DLP): The human factor is
frequently the weakest link in network security. DLP
technology and policies serve to prevent employees
and other users from misusing and potentially
compromising sensitive data, or from allowing
sensitive data to leave the network.
3. Security information and event management
(SIEM): Getting the proper information from so many
various tools and resources can be tough at times,
especially when the time is short. SIEM technologies
and software provide responders with the information
they need to act quickly.
4. Virtual private network (VPN): VPN security tools
enable secure networks and endpoint devices to
communicate with one another. Remote-access VPNs
typically employ IPsec or Secure Sockets Layer (SSL)
for authentication, resulting in an encrypted line that
prevents eavesdropping by third parties.
5. Network Segmentation: By segmenting the network, it
can be ensured that sensitive data is kept separate from
the rest of the network, making it more difficult for
attackers to access the data.
6. Vulnerability Scanning: Vulnerability scanning can be
used to identify potential vulnerabilities in the IT
infrastructure. This could be done using commercial or
open-source vulnerability scanning tools.
7. Monitoring and Logging: Monitoring and logging can
be used to detect any unusual activity on the network
and to provide a record of events that can be used for
forensic analysis in the event of a security breach.
8. Intrusion Detection and Prevention Systems (IDPS):
IDPS can be used to detect and prevent unauthorized
access to the network. This could include firewalls,
network intrusion detection systems (NIDS), and
host-based intrusion detection systems (HIDS).
9. Access Control: Access control systems can be put in
place to ensure that only authorized individuals have
access to sensitive data. This could include biometric
authentication, smart cards, and multi-factor
authentication.
...
The Marriott data breach in 2018 raised several ethical issues
related to data privacy and security. Some of these issues
include:
1. Responsibility of the organization: Marriott
International was responsible for protecting its
customers' personal and sensitive information.
However, the data breach showed that the organization
failed to adequately secure its systems, which raises
questions about their level of responsibility and ethical
obligation towards their customers.
2. Impact on customers: The data breach resulted in the
exposure of personal and sensitive information of 300
million customers, including passport numbers, credit
card details, and other sensitive data. This breach of
privacy had a significant impact on the customers, who
were now at risk of identity theft and financial fraud.
3. Lack of transparency: Marriott International initially
failed to provide sufficient information about the
breach, which made it difficult for customers to take
the necessary steps to protect themselves. This lack of
transparency is considered unethical, as it places the
customers at a disadvantage and undermines their trust
in the organization.
4. Responsibility for third-party vendors: Marriott
International outsourced its IT services to a third-party
vendor, and it is still unclear who was responsible for
the breach. This raises questions about the ethical
responsibilities of organizations to ensure that their
third-party vendors are following appropriate security
protocols to protect sensitive data
...
Recommendations
...
1. Implement a robust incident response plan:
2. Strengthen data security measures:
3. Enhance employee training and awareness:
4. Conduct regular risk assessments:
```

### Carbanak (2015)
- hacker group - singapore banks ~1 bilion

### Kaspersky Labs (2015)
- security company
- got hit by malware
- would say recident in memory
- when other connected it spread - but when they turned of it whent away

### Equifax (2017)
- data breach
- class action suit - with huge settlement

### Hacking team (2015)
- italian company
- made pen tools for law ppl and military

### Wannacry (2017)
- us nsa internal blue hacking sweep - that was stolen and published
- vulnabilities that was discovered
- ransomeware 
- attacking hospitals

### NotPetya (bl.a. Mærsk) (2017)
- lot of logistics companies

...

### Colonial pipeline attack (2021)
- ransomeware
- they did pay the ransome - but got the money back
- might be russian hackers

### Log4 (2021)
- anything taht logged something using log4j could be taken over
- could take over minecraft servers
- vm ware was vulnarable

...

### Facebook
- databreach or scraping of public data

### LinkedIn (2012)
- passwords database was breached

### Conti
- russian hacker group
- good at initial pen
- sell the entry/access that could then write the code
- conti then oversaw the attack
- conti then did the ransome and pay the others in the process
- hit irish healthcare

### Kyivstar dec 2023
- biggest mobile operator in ukrane
- 24 million ppl lost their services
- also in alarm systems
- tell evidence of who did it - make sure to have evidence for it - have to prove

## Data breach examination
- what was the motive and what was the target
- what was the tecnical stuff that made this possible
- that was the data and protocols that got used , what was the place they got in
- that can be learned from this

## Report
- is from the standpoint of the assignments