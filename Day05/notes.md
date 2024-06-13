# Web Security

## Threat Landscape
- Vulnabilities
  - only gets worse
  - Phishing (high)
- Most important business risks
  - we are more cloudbased

## External Recon
- when you do testing/hacking 
  - nmap and showdan
- steps
  - what things are running
  - are there any known vulnabilities
  - what versions
  - any remote access stuff
  - send phising mail to sales or marketing

## Internal Recon
- Active Directory (AD)
- endpoint detection will catch BloodHound if you just run it
  - a way to figure out how ppl are connected
- also native microsoft tools to get an overview
- Scanning
  - Burpsuit (best for web)
    - web 
    - has a passive scanner 
    - get an overview of vulnabilities by browsing
    - attack proxy
    - proxy all the traffic through it
    - look at the code and manipulate
  - temmable io
  - Nessus (best for servers)
    - normal scanning
  - openvas
- best on servers
- problems with scanner is that it only looks at headers - a lot of false positives - always have to verify
  - get headers
  - go in - check what versions they are running 
  - go in through a shell 
  - use nmap
- browser extensions
  - tamper data (plugin to firefox)
  - info of versions of a webside [WILL COME BACK TO WHAT IT IS CALLED]

## Exploitation
### sql injection
  - trick to give data from the database
  - if the site doesn't have input validation or segregation
  - or prepared statements
  - most frameworks protects againts this
  - inject sql statements in inputs
  - e.g. in the url
  - send in a pling(?) and it will give an error
  - tools
    - SQL Map
      - finding and exploiting sql injections
### Cross-site scripting (XXS)
  -  2 different
  -  send a link with embedded code or stored xxs (put it in a block until next user accesses it)
  -  you attacking the users on the site and not the company
  -  stealing cookies - guiding them to other sites etc
  -  normaly with javascript
  -  to stop : validate input ; no reason to validate scripts or let it be executable
-  Cross sit request forgery (CSRF)
   -  get the victim to click on a link
   -  i can change something on your site

### Exploiting known vulnabilities
- vulnability numbers
- elsa db
- attack called pass the hash

### Web shells
- if you have something where you can upload will give you access to the web server

### Citrix Bleed
- from last year
- can bypass multifactor
- get the session
- get privileges as the user logged in

## Maintain Access
- get a user and browse arround 
- but we want to escalate

### Kerberoasting Service Principle Name (spn)
- microsoft feature
- Service accounts has a lot of access
- Tool : Rubeus (will be endpoint detectable)
  - can get hashes or somethig

### Network poisining
- if the network allows legacy protocols a user will communicate 
- Look it up
- Tools : **Hashcat**, caneandable, scantheriver(?)
- Tool : ENview or (python tool) responder

### Certificate Misconfiguration - ESC
- 8 different
- you cannot patch it, you have to configure it
- any user can ask for another users certificate - problemm : attacker can now (if they have an account) they can now get the domain admin certificate
- tool: Certify
- with the certificate (of any user), you can get the password (hashed)

### Defender Bypass
- (Microsoft) Defender uses AMSI to scan memory
- there are ways to disable amsi, so that you can run stuff without defender seeing it
- if you have a program coded in c, you can do "reflection"
  - first do bypass
  - then reflection
  - then you can do something
- featur in defender
  - rn : you can do subprocesses and it will not be detected by defender
  - running malware in a subprocess will be detected , but the malware will stilll run
  - e.g. through Apache Solar (has known vulnabilities)