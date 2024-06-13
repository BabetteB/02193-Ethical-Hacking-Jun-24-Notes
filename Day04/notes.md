# Active Reconenssaince
**READ UP ON THE TERMS IN THIS LECTURE**

## Vulnability management
- assets are the target : can have value
- Risks : there are always a risk
  - not every system has a big risk
- can have vulnabilities : can include counter measures
  - e.g. adding a firewall

- vulnability db: nist and mitre

Examples to look into:
- heartbleed
- petya ransomeware
  - exploit linked to External blue

- SANS paper : Maturity Model
  - vulnability management

## Tooling

### A quick note on firewalls
LOOK UP FIREWALLS AND NEXT GENERATION FIREWALL

### Wireshark
- package sniffer
  - usefor for monotoring trafic
  - a ui
  - any app using a network you can use wireshark on the network
Wireshark is a network packet analyzer. A network packet analyzer will try to capture network packets and display them in as much detail as possible. Think of it as a measuring device used to examine what's going on inside a network cable, similar to how a voltmeter is used by an electrician to examine what's happening inside an electric cable.

#### Key Features of Wireshark
- **Live Packet Capture**: Wireshark can capture network traffic from a live network connection or read from a previously saved capture file.
- **Offline Analysis**: Wireshark can analyze network traffic that was captured previously and saved to a file.
- Deep Inspection: It can deeply inspect hundreds of protocols at various network layers.
- **Rich GUI**: Wireshark's graphical user interface makes it easy to browse through captured network data.
- **Filters**: Powerful filters allow users to view only the traffic of interest.
- **Colorization**: Packets can be colorized based on various criteria to make them easier to distinguish.
- **Extensibility**: Wireshark supports plugins and custom scripts for extended functionality.

#### How Wireshark Works
Wireshark captures data packets flowing through the network interface. It operates by putting the network interface into promiscuous mode, which allows it to capture all packets on the network, not just those addressed to the capturing machine.

#### Components of Wireshark
- **Capture Engine**: This is responsible for capturing live data from the network interface.
- **Dissector:** This interprets the data and breaks it down according to the protocol layers.
- **Display Filter**: Filters packets based on user-defined criteria.
- **Coloring Rules**: Color-coding to make it easier to identify different types of traffic.
- **Statistics:** Provides various statistical views of captured data, such as protocol hierarchy and conversations.

#### Basic Operations in Wireshark
1. Starting a Capture
   - Select the network interface to capture from.
   - Click on the "Start" button to begin capturing packets.
2. stopping a capture
3. Applying filters
   - Display filters are used to view specific packets. For example, to filter HTTP traffic, you can use: `http`
   - Capture filters are used to limit the packets captured. For example, to capture only TCP traffic: `tcp`
4. Analysing Packets'
   - Packets are displayed in a list with detailed information available for each packet.
   - Clicking on a packet will show its details in the packet details pane and the raw data in the packet bytes pane.

#### Advanced Features
1. Follow TCP/UDP Stream
   - Allows you to reconstruct a full conversation between two endpoints.
   - Useful for debugging application-level protocols.
2. Exporting Data
   - Captured data can be exported to various file formats, including pcap, CSV, and plain text.
3. Packet Reassembly
   - Wireshark can reassemble fragmented packets, such as IP fragments and TCP segments.
4. Packet Decryption
   - Wireshark supports decryption for protocols like SSL/TLS, WEP, and WPA/WPA2, provided the necessary keys are available.

#### User Interface
The Wireshark user interface is divided into several key components:
- **Menu Bar**: Contains various menus like File, Edit, View, Capture, Analyze, Statistics, Telephony, and Help. These menus provide access to all the features and functionalities of Wireshark.
- **Toolbar**: Provides quick access to commonly used functions, such as starting and stopping packet captures, opening and saving capture files, and applying filters.
- **Packet List Pane**: Displays a summary of all captured packets in a tabular format. Each row represents a single packet, and columns display information such as the packet number, time, source, destination, protocol, length, and a brief info description.
- **Packet List Detail Pane**: Displays the details of the selected packet. This pane shows a hierarchical breakdown of the packet's protocols and layers, allowing for in-depth inspection of each field within the packet.
- **Packet Byte Pane**: Displays the raw data of the selected packet in hexadecimal and ASCII formats. This pane shows the actual bytes that make up the packet.

#### Packet Capture Engine
Wireshark's packet capture engine is responsible for capturing network traffic. It uses the following components:
- **Capture Interfaces** : Wireshark can capture traffic from various network interfaces, including Ethernet, Wi-Fi, Bluetooth, and virtual interfaces. Users can select which interface to capture from.
- **Capture Filters** : Applied before the capture starts to limit the packets that are captured based on specified criteria. For example, capturing only TCP traffic: `tcp`
- **Libpcap/tcpdump (on Unix-like systems) or WinPcap/Npcap (on Windows)**: These libraries provide the low-level packet capture and filtering capabilities.

#### Capture Filters
- combine AND and OR for long strings of filters
Capture filters limit the packets that Wireshark captures from the network. They use a syntax based on the Berkeley Packet Filter (BPF) language.

**Syntax and Examples**:
- Filter by IP Address
  - Host: Capture traffic to or from a specific IP address.
  ```bash
  host 192.168.1.1
  ```
  - Source: Capture traffic from a specific IP address
  ```bash
  src host 192.168.1.1
  ```
  - Destination: Capture traffic to a specific IP address.
  ```bash
  dst host 192.168.1.1
  ```
- Filter by Network
  - Network: Capture traffic from a specific subnet.
  ```bash
  net 192.168.1.0/24
  ```
- Filter by Protocol
  - TCP: Capture only TCP traffic.
  ```bash
  tcp
  ```
  - UDP: Capture only UDP traffic.
  ```bash
  udp
  ```
  - ICMP: Capture only ICMP traffic.
  ```bash
  icmp
  ```
- Filter by Port
  - Port: Capture traffic to or from a specific port
  ```bash
  port 80
  ```
  - Source Port: Capture traffic from a specific port.
  ```bash
  src port 80
  ```
  - Destination Port: Capture traffic to a specific port
  ```bash
  dst port 80
  ```
- Combining filters
  - AND: `and`
  - OR: `or`
  - NOT: `not`

#### Display Filters
Display filters allow you to filter the captured packets displayed in Wireshark's user interface. They use a more powerful and flexible syntax compared to capture filters.
- Filter by IP Address
  - Host: Capture traffic to or from a specific IP address.
  ```bash
  ip.addr == 192.168.1.1
  ```
  - Source: Capture traffic from a specific IP address
  ```bash
  ip.src == 192.168.1.1
  ```
  - Destination: Capture traffic to a specific IP address.
  ```bash
  ip.dst == 192.168.1.1
  ```
- Filter by Network
  - Network: Capture traffic from a specific subnet.
  ```bash
  ip.addr == 192.168.1.0/24
  ```
- Filter by Protocol (the same as with Capture Filters)
  ```
- Filter by Port
  - Port: Capture traffic to or from a specific port
  ```bash
  tcp.port == 80
  ```
  - Source Port: Capture traffic from a specific port.
  ```bash
  tcp.srcport == 80
  ```
  - Destination Port: Capture traffic to a specific port
  ```bash
  tcp.dstport == 80
  ```
- Filter by MAC Address
 - Ethernet Address: Display traffic to or from a specific MAC address
  ```bash
  eth.addr == 00:11:22:33:44:55
  ```
  - Source: Display traffic from a specific MAC address
  ```bash
  eth.src == 00:11:22:33:44:55
  ```
  - Destination: Display traffic to a specific MAC address
  ```bash
  eth.dst == 00:11:22:33:44:55
  ```
- Filter by Application Layer Protocol (`http`, `dns` and `ftp`)
- Combining Filters (the same as with Capture Filters)
- Filter by Packet Content
  - String Matching: Display packets containing a specific string.
  ```bash
  frame contains "string"
  ```

### Common and Interesting Protocols

| Protocol  | Port(s)       | Description |
|-----------|---------------|-------------|
| **HTTP**  | 80            | **HyperText Transfer Protocol**: Used for transmitting web pages over the Internet. |
| **HTTPS** | 443           | **HTTP Secure**: Secure version of HTTP, uses SSL/TLS to encrypt data. |
| **FTP**   | 20, 21        | **File Transfer Protocol**: Used for transferring files between client and server. Port 21 for control commands and port 20 for data transfer. |
| **FTPS**  | 989, 990      | **FTP Secure**: Secure version of FTP using SSL/TLS for encryption. |
| **SFTP**  | 22            | **SSH File Transfer Protocol**: Secure file transfer over SSH. |
| **SMTP**  | 25, 465, 587  | **Simple Mail Transfer Protocol**: Used for sending emails. Port 25 is standard, 465 for SMTPS, and 587 for submission. |
| **POP3**  | 110, 995      | **Post Office Protocol 3**: Used by email clients to retrieve emails from a server. Port 995 for POP3 over SSL. |
| **IMAP**  | 143, 993      | **Internet Message Access Protocol**: Used by email clients to retrieve emails. Port 993 for IMAP over SSL. |
| **DNS**   | 53            | **Domain Name System**: Translates domain names to IP addresses. |
| **DHCP**  | 67, 68        | **Dynamic Host Configuration Protocol**: Used to dynamically assign IP addresses to devices on a network. |
| **SNMP**  | 161, 162      | **Simple Network Management Protocol**: Used for network management and monitoring. Port 162 for SNMP traps. |
| **NTP**   | 123           | **Network Time Protocol**: Used to synchronize the clocks of computer systems. |
| **SSH**   | 22            | **Secure Shell**: Used for secure remote login and other secure network services. |
| **Telnet**| 23            | Unencrypted text communications protocol for remote login. |
| **RDP**   | 3389          | **Remote Desktop Protocol**: Used for remote desktop access. |
| **LDAP**  | 389, 636      | **Lightweight Directory Access Protocol**: Used for accessing and maintaining distributed directory information services. Port 636 for LDAP over SSL (LDAPS). |
| **SMB**   | 445           | **Server Message Block**: Used for providing shared access to files, printers, and serial ports. |
| **SQL**   | Varies (e.g., 1433 for MSSQL, 3306 for MySQL, 5432 for PostgreSQL) | **Structured Query Language**: Used for managing and querying relational databases. |
| **TFTP**  | 69            | **Trivial File Transfer Protocol**: Simple, unsecured file transfer protocol. |
| **HTTPS** | 443           | **HTTP Secure**: Encrypted version of HTTP using SSL/TLS. |
| **ICMP**  | N/A           | **Internet Control Message Protocol**: Used for sending error messages and operational information. Commonly used by tools like `ping`. |
| **BGP**   | 179           | **Border Gateway Protocol**: Used to exchange routing information between autonomous systems on the Internet. |
| **IRC**   | 194           | **Internet Relay Chat**: Used for real-time text communication. |
| **NNTP**  | 119           | **Network News Transfer Protocol**: Used for reading and posting Usenet articles. |
| **Syslog**| 514           | **System Logging Protocol**: Used for system logging. |
| **RTP**   | Varies        | **Real-time Transport Protocol**: Used for delivering audio and video over IP networks. |
| **SIP**   | 5060, 5061    | **Session Initiation Protocol**: Used for signaling and controlling multimedia communication sessions. |
| **HTTPS** | 443           | **HTTP Secure**: Secure version of HTTP, uses SSL/TLS to encrypt data. |
| **NFS**   | 2049          | **Network File System**: Used for distributed file systems, allowing a user to access files over a network. |
| **MQTT**  | 1883, 8883    | **Message Queuing Telemetry Transport**: Lightweight messaging protocol for small sensors and mobile devices, optimized for high-latency or unreliable networks. Port 8883 for MQTT over SSL. |
| **CoAP**  | 5683          | **Constrained Application Protocol**: Designed for use in simple electronics like sensors, and designed to easily translate to HTTP for integration with the web. |
| **WebSocket** | 80 (ws), 443 (wss) | **WebSocket Protocol**: Provides full-duplex communication channels over a single TCP connection. |


### Common and Interesting Ports

| Port Number | Protocol | Description |
|-------------|----------|-------------|
| **20**      | TCP      | **FTP (File Transfer Protocol) Data Transfer**: Used for transferring files between client and server. |
| **21**      | TCP      | **FTP Control (Command)**: Used for controlling the FTP session. |
| **22**      | TCP      | **SSH (Secure Shell)**: Used for secure logins, file transfers (scp, sftp), and port forwarding. |
| **23**      | TCP      | **Telnet**: Unencrypted text communications. |
| **25**      | TCP      | **SMTP (Simple Mail Transfer Protocol)**: Used for sending emails. |
| **53**      | TCP/UDP  | **DNS (Domain Name System)**: Used for translating domain names to IP addresses. |
| **67**      | UDP      | **DHCP (Dynamic Host Configuration Protocol) Server**: Used for distributing IP addresses to clients. |
| **68**      | UDP      | **DHCP Client**: Used by clients to receive IP addresses from the DHCP server. |
| **80**      | TCP      | **HTTP (HyperText Transfer Protocol)**: Used for web traffic. |
| **110**     | TCP      | **POP3 (Post Office Protocol 3)**: Used by email clients to retrieve emails from a server. |
| **119**     | TCP      | **NNTP (Network News Transfer Protocol)**: Used for Usenet articles. |
| **123**     | UDP      | **NTP (Network Time Protocol)**: Used for clock synchronization between computer systems. |
| **143**     | TCP      | **IMAP (Internet Message Access Protocol)**: Used by email clients to retrieve emails. |
| **161**     | UDP      | **SNMP (Simple Network Management Protocol)**: Used for network management and monitoring. |
| **162**     | UDP      | **SNMP Trap**: Used to send alerts and notifications. |
| **179**     | TCP      | **BGP (Border Gateway Protocol)**: Used for routing information exchange between autonomous systems on the internet. |
| **194**     | TCP      | **IRC (Internet Relay Chat)**: Used for real-time chat. |
| **389**     | TCP/UDP  | **LDAP (Lightweight Directory Access Protocol)**: Used for directory services. |
| **443**     | TCP      | **HTTPS (HTTP Secure)**: Used for secure web traffic. |
| **445**     | TCP      | **SMB (Server Message Block)**: Used for file sharing and printer services. |
| **465**     | TCP      | **SMTPS (SMTP over SSL)**: Used for secure email transmission. |
| **514**     | UDP      | **Syslog**: Used for system logging. |
| **636**     | TCP      | **LDAPS (LDAP over SSL)**: Used for secure directory services. |
| **873**     | TCP      | **rsync**: Used for file synchronization and transfer. |
| **989**     | TCP/UDP  | **FTPS (FTP Secure) Data**: Used for secure file transfer. |
| **990**     | TCP      | **FTPS Control**: Used for secure FTP control. |
| **993**     | TCP      | **IMAPS (IMAP over SSL)**: Used for secure email retrieval. |
| **995**     | TCP      | **POP3S (POP3 over SSL)**: Used for secure email retrieval. |
| **1080**    | TCP      | **SOCKS Proxy**: Used for proxy servers. |
| **1433**    | TCP      | **MSSQL**: Microsoft SQL Server database management. |
| **1434**    | UDP      | **MSSQL Monitor**: Microsoft SQL Server monitoring. |
| **1521**    | TCP      | **Oracle Database**: Oracle database service. |
| **2049**    | TCP/UDP  | **NFS (Network File System)**: Used for file sharing. |
| **2082**    | TCP      | **cPanel**: Web hosting control panel. |
| **2083**    | TCP      | **cPanel (Secure)**: Secure web hosting control panel. |
| **3128**    | TCP      | **Squid Proxy**: Web proxy cache. |
| **3306**    | TCP      | **MySQL**: MySQL database system. |
| **3389**    | TCP      | **RDP (Remote Desktop Protocol)**: Used for remote desktop access. |
| **5432**    | TCP      | **PostgreSQL**: PostgreSQL database system. |
| **5900**    | TCP      | **VNC (Virtual Network Computing)**: Used for remote desktop access. |
| **8080**    | TCP      | **HTTP Proxy**: Alternative HTTP port, often used for proxy servers. |
| **8443**    | TCP      | **HTTPS Alt**: Alternative port for HTTPS. |
| **10000**   | TCP      | **Webmin**: Web-based system administration tool. |


### NMap
- port scanner
- network security scanner
- tcp illustrated - book
Nmap is designed to scan large networks, though it can also be used to scan single hosts. It can determine what hosts are available on a network, what services those hosts are offering, what operating systems they are running, what type of packet filters/firewalls are in use, and other characteristics.

#### Key Features of Nmap
- Host Discovery: Identifies live hosts on a network.
- Port Scanning: Enumerates open ports on a host to identify services.
- Service Version Detection: Determines the version of services running on open ports.
- OS Detection: Identifies the operating system and hardware characteristics of network devices.
- Scriptable Interaction with the Target: Nmap Scripting Engine (NSE) allows users to write scripts for advanced detection, vulnerability scanning, and more.
- Network Inventory: Useful for auditing network device configurations and identifying unauthorized devices.

#### Nmap Scan Types
- **Ping Scan (-sn)**: Determines which hosts are up and running.
  - **Purpose**: To discover live hosts on a network.
  - **How it works**: Sends ICMP echo requests, TCP SYN to port 443, or TCP ACK packets to determine if hosts are up.
  - **Use case**: Quickly identify which IP addresses are active without scanning ports.
- **SYN Scan (-sS)**: Commonly known as half-open scanning, it sends SYN packets and waits for a response, providing an efficient way to scan without completing the TCP handshake.
  - **Purpose**: To scan for open ports efficiently and stealthily.
  - **How it works**: Sends a SYN packet and waits for a response. If a SYN/ACK is received, the port is open. If an RST is received, the port is closed. The connection is not completed, hence it's called a half-open scan.
  - **Use case**: Commonly used for its speed and stealth, as it doesn’t complete the TCP handshake.
- **TCP Connect Scan (-sT)**: Completes the TCP handshake, often used when SYN scan is not an option.
  - **Purpose**: To scan for open ports when SYN scan isn't possible.
  - **How it works**: Completes the full TCP handshake (SYN, SYN/ACK, ACK). If the handshake completes, the port is open.
  - **Use case**: Useful when SYN scan cannot be used, typically due to lack of permissions or access requirements.
- **UDP Scan (-sU)**: Scans for open UDP ports, which can be trickier and slower than TCP scanning.
  - **Purpose**: To discover open UDP ports.
  - **How it works**: Sends UDP packets to the target ports. If no response or ICMP port unreachable (type 3, code 3) is received, the port is likely open. Other ICMP unreachable messages can indicate filtered or closed ports.
  - **Use case**: Used to find services running on UDP, though it’s slower and more difficult due to the stateless nature of UDP.
- **FIN Scan (-sF), Xmas Scan (-sX), and Null Scan (-sN)**: Used to bypass certain types of firewall and IDS systems by sending non-standard TCP packets.
  - **Purpose**: To bypass firewalls and packet filters that detect standard scans.
  - **How they work**:
    - **FIN Scan (-sF)**: Sends a FIN packet. Closed ports respond with an RST, open ports ignore it.
    - **Xmas Scan (-sX)**: Sends a packet with FIN, URG, and PSH flags set. Closed ports respond with RST.
    - **Null Scan (-sN)**: Sends a packet with no flags set. Closed ports respond with RST.
  - **Use case**: Useful for evading some firewalls and IDS that are configured to log and detect SYN scans.
- **ACK Scan (-sA)**: Used to map firewall rulesets, determining whether packets can pass through.
  - **Purpose**: To map out firewall rules and determine if ports are filtered.
  - **How it works**: Sends an ACK packet. The response indicates whether the port is filtered (no response or ICMP unreachable) or unfiltered (RST response).
  - **Use case**: Used to infer firewall rules and determine whether traffic can pass through a firewall.
- **Window Scan (-sW)**: Analyzes TCP window sizes to infer the state of a port.
  - **Purpose**: To determine the open or closed state of ports by analyzing TCP window size.
  - **How it works**: Sends packets with various flags and analyzes the window size in responses. Differing window sizes can indicate port status.
  - **Use case**: Useful in environments where SYN scan is not effective or allowed.
- **Maimon Scan (-sM)**
  - **Purpose**: Similar to FIN, Xmas, and Null scans but sends a FIN/ACK packet.
  - **How it works**: Closed ports typically respond with RST. Open ports usually ignore the packet.
  - **Use case**: Another stealth scan type to bypass certain firewall configurations.
- **Idle Scan (-sI)**: A stealth scan method that exploits IP ID idle hosts.
  - Purpose: A stealth scan method that uses a third-party zombie host to send packets, hiding the attacker's identity.

#### Nmap Scripting Engine (NSE)
NSE provides powerful scripting capabilities to extend Nmap’s functionality. Scripts are written in Lua and can be used for:

- Vulnerability Detection: Identifying known vulnerabilities.
- Advanced Service Detection: Detailed interrogation of services.
- Network Discovery: More granular control over network discovery processes.
- Brute Force Attacks: Attempting to guess passwords for various protocols.

#### Practical Uses of Nmap
- Network Inventory: Keeping track of devices and services on a network.
- Security Auditing: Identifying vulnerable systems and services.
- Firewall Testing: Ensuring firewall rules are functioning correctly.
- Service Upgrade Scheduling: Identifying outdated software versions for upgrade.
- Compliance Auditing: Ensuring network devices comply with security policies.

#### Basic Nmap Commands
- Scan a single IP:     `nmap 192.168.1.1`
- Scan a range of IPs:  `nmap 192.168.1.1-255`
- Scan a subnet:        `nmap 192.168.1.0/24`
- Ping scan:            `nmap -sn 192.168.1.0/24`
- Service version detection: `nmap -sV 192.168.1.1`
- OS detection:         `nmap -O 192.168.1.1`
- Script scan:          `nmap --script=vuln 192.168.1.1`

#### Nmap Output Options
Nmap provides various output formats for different needs:

- Normal output:    `nmap -oN output.txt 192.168.1.1`
- XML output:       `nmap -oX output.xml 192.168.1.1`
- Grepable output:  `nmap -oG output.gnmap 192.168.1.1`
- All formats:      `nmap -oA output 192.168.1.1`

#### Best Practices
- Permission: Always ensure you have permission to scan a network.
- Stealth: Use stealth scans (like SYN scan) to minimize detection.
- Combination: Combine various Nmap options for comprehensive scans.
- Update: Keep Nmap updated to benefit from the latest features and scripts.

### Openvas
OpenVAS (Open Vulnerability Assessment System) is a comprehensive open-source suite of tools used for vulnerability scanning and vulnerability management. It is designed to identify security issues in systems, applications, and network devices by performing thorough scans and producing detailed reports. OpenVAS is part of the Greenbone Vulnerability Management (GVM) suite, which includes a set of services and tools offering vulnerability scanning and management capabilities.

#### Key Components of OpenVAS
- **OpenVAS Scanner**: The core component that performs the actual network vulnerability tests.
- **OpenVAS Manager**: Manages scan configurations, schedules, user management, and stores scan results.
- **Greenbone Security Assistant (GSA)**: A web-based interface for managing and viewing scan results.
- **Greenbone Security Feed (GSF)**: Provides regular updates with new vulnerability tests and enhancements.
- **OpenVAS CLI**: A command-line interface for interacting with OpenVAS services.

#### Features of OpenVAS
- **Vulnerability Scanning**: Capable of scanning various network devices, servers, web applications, databases, and more.
- **Extensive Vulnerability Tests**: Supports thousands of Network Vulnerability Tests (NVTs) to identify known vulnerabilities.
- **Compliance Auditing**: Can be used to check compliance with various security standards and policies.
- **Report Generation**: Generates detailed reports in various formats, including PDF, HTML, XML, and CSV.
- **Customizable Scans**: Allows users to create and customize scan configurations to meet specific needs.
- **User Management**: Supports multi-user environments with role-based access controls.
- **Scheduling**: Enables scheduling of scans to run automatically at specified times.

#### Using OpenVAS
**Configuring a Scan**
- Log in to the Web Interface: Navigate to https://<your-server-ip>:9392.
- Create a Target: Define the IP address or range to be scanned.
- Create a Task: Set up a scan task that specifies the target, scan configurations, and schedules.
- Run the Scan: Execute the scan task and monitor its progress through the interface.
**Viewing Results**
- Reports: After the scan completes, detailed reports are available, highlighting the discovered vulnerabilities, their severity, and recommendations for remediation.
- Filtering: Use filters to focus on specific vulnerabilities, hosts, or severity levels.
- Exporting Reports: Reports can be exported in multiple formats for further analysis or compliance documentation.


### BloodHound
BloodHound is a powerful tool used for analyzing Active Directory (AD) environments. It is primarily used by penetration testers and red teams to identify potential attack paths within AD domains. BloodHound utilizes graph theory to reveal the relationships and permissions within AD, making it easier to discover hidden or complex attack vectors.

- **Purpose**: To map out Active Directory environments and identify potential security weaknesses and attack paths.
- **Core Technology**: Uses graph databases (Neo4j) to represent and query AD relationships.

#### Key Features

1. **Graph-Based Analysis**: Uses graph theory to visually represent AD relationships and permissions.
2. **Query Language**: Customizable queries using Cypher, the query language for Neo4j, to find specific relationships and attack paths.
3. **Data Collection**: Multiple methods to gather AD data, including SharpHound (the primary data collector).
4. **Visualization**: Provides a graphical interface to explore and analyze AD relationships.
5. **Attack Path Discovery**: Identifies potential attack paths to high-value targets, such as Domain Admin accounts.

#### Components

- **BloodHound Interface**: A web-based interface for visualizing and querying the AD data.
- **Neo4j Database**: Stores the collected AD data in a graph format.
- **SharpHound**: The primary data collector written in C# for gathering information from AD environments.

#### Data collection with SharpHound

SharpHound is the data collector used to gather information from AD. It can be run from any domain-joined machine.

1. **Collect Data**:

    ```bash
    SharpHound.exe -c All
    ```

    This command collects all relevant AD data and saves it as JSON files.

2. **Import Data**: Upload the collected JSON files into BloodHound using the interface or the following command:

    ```bash
    ./BloodHound --no-sandbox -import /path/to/json/files
    ```

#### Querying and Analysis

BloodHound provides a set of built-in queries to identify common attack paths, such as:

- **Find Shortest Paths to Domain Admins**: Identifies the shortest path to Domain Admin accounts.
- **Find Shortest Paths to High-Value Targets**: Targets specific high-value accounts or groups.
- **Enumerate Local Admin Rights**: Lists users with local admin rights on machines.

##### Custom Queries

You can write custom Cypher queries to find specific relationships or permissions. For example:

```cypher
MATCH (n:User)-[r:AdminTo]->(m)
RETURN n.name, type(r), m.name
```
This query finds users with administrative rights to any machine.

### Metasploit
Metasploit is a widely used penetration testing framework that helps security professionals find, exploit, and validate vulnerabilities. It provides a suite of tools for testing, exploiting, and developing exploit code against a variety of systems and platforms.

- **Purpose**: To aid penetration testers in identifying and exploiting vulnerabilities in systems, applications, and networks.
- **Components**: Metasploit Framework, Metasploit Pro, Metasploit Community, and Metasploit Express.

#### Key Features

1. **Exploits**: A vast library of exploits for different platforms and applications.
2. **Payloads**: Various payloads that can be delivered to a target after exploiting a vulnerability.
3. **Encoders**: Tools to obfuscate payloads to avoid detection.
4. **NOPS**: No-operation instructions to pad payloads.
5. **Post-Exploitation**: Modules for further exploitation after gaining access.
6. **Auxiliary Modules**: Tools for scanning, fuzzing, and other tasks.
7. **Meterpreter**: An advanced payload that provides an interactive shell and more functionalities.

#### Core Components

##### Exploits

Exploits are the core modules used to take advantage of vulnerabilities in systems. They are classified based on the target platform and type of vulnerability.

- **Types of Exploits**:
  - **Remote Exploits**: Target vulnerabilities over the network.
  - **Local Exploits**: Require prior access to the target system.
  - **Client-Side Exploits**: Exploit vulnerabilities in client applications.

##### Payloads

Payloads are the code that runs on the target system after exploiting a vulnerability. They can range from simple command execution to complex, multi-stage payloads.

- **Types of Payloads**:
  - **Singles**: Self-contained payloads that execute a single command.
  - **Stagers**: Payloads that establish a network connection and download additional stages.
  - **Stages**: Additional payload components delivered by stagers.

##### Auxiliary Modules

Auxiliary modules are used for tasks other than exploitation, such as scanning, fuzzing, and information gathering.

- **Common Auxiliary Modules**:
  - **Scanners**: Network and port scanners to identify potential targets.
  - **Fuzzers**: Tools to test the robustness of applications.
  - **DoS Modules**: Tools to perform denial-of-service attacks.

##### Encoders

Encoders are used to obfuscate payloads to avoid detection by antivirus and intrusion detection systems.

##### NOP Generators

NOP generators create sequences of "No Operation" instructions to pad shellcode, helping to evade detection and maintain alignment in memory.

#### Workflow

1. **Information Gathering**: Use auxiliary modules and other tools to collect information about the target.
2. **Vulnerability Identification**: Identify vulnerabilities using scanners and manual analysis.
3. **Exploit Selection**: Choose an appropriate exploit from the Metasploit database.
4. **Payload Configuration**: Select and configure a payload to be delivered by the exploit.
5. **Exploit Execution**: Run the exploit to gain access to the target system.
6. **Post-Exploitation**: Perform further actions such as privilege escalation, data extraction, and maintaining access.

#### Metasploit Interfaces

Metasploit provides several interfaces to interact with the framework:

1. **msfconsole**: The most popular and powerful command-line interface.
2. **msfcli**: A command-line interface for executing individual commands and scripting.
3. **Armitage**: A graphical user interface (GUI) for Metasploit, providing a user-friendly way to manage sessions and exploits.
4. **Metasploit Community and Pro**: Web-based interfaces with additional features for enterprise use, such as automated exploitation and reporting.

#### Common Commands

##### msfconsole Commands

- **search**: Find modules in the database.
  ```bash
  search windows
  ```
- use: Select a module to use.
  ```bash
  use exploit/windows/smb/ms08_067_netapi
  ```
- show options: Display module options.
  ```bash
  show options
  ```
- set: Set module options.
  ```bash
  set RHOST 192.168.1.10
  ```
- run: Execute the selected module.
  ```bash
  run
  ```
- sessions: Manage active sessions.
  ```bash
  sessions -l  # List sessions
  sessions -i 1  # Interact with session 1
  ```

#### Post-Exploitation Commands
- **hashdump**: Dump password hashes from the target system.
- **keyscan_start**: Start capturing keystrokes on the target system.
- **keyscan_dump**: Display captured keystrokes.


### Impacket
Impacket is a collection of Python classes for working with network protocols. It provides low-level programmatic access to several network protocols, making it a powerful tool for penetration testers and security researchers. Developed by SecureAuth, Impacket allows the crafting and parsing of network packets, enabling various network-related tasks such as remote code execution, authentication, and more.
- **Purpose**: To provide a suite of tools and libraries for network protocol manipulation.
- **Programming Language**: Python.

#### Key Features

1. **Network Protocol Support**: Impacket supports a wide range of network protocols including SMB, MSRPC, NetBIOS, DCERPC, LDAP, and more.
2. **Packet Crafting and Parsing**: Allows detailed crafting and parsing of network packets for custom applications and analysis.
3. **Authentication**: Supports various authentication protocols, including NTLM and Kerberos.
4. **Built-in Tools**: Comes with several pre-built scripts for common tasks such as dumping credentials, querying domain information, and executing commands on remote systems.
5. **Interoperability**: Can interact with both Windows and Unix-like systems.

#### Key Components

##### Protocols Supported

- **SMB (Server Message Block)**: Protocol for file sharing and other network operations.
- **MSRPC (Microsoft Remote Procedure Call)**: Used for communication between client and server processes.
- **NetBIOS**: Provides services related to the network layer in the OSI model.
- **DCERPC (Distributed Computing Environment / Remote Procedure Calls)**: A remote procedure call system.
- **LDAP (Lightweight Directory Access Protocol)**: Used for accessing and maintaining distributed directory information services.
- **Kerberos**: Network authentication protocol designed to provide strong authentication for client/server applications.

##### Commonly Used Tools
- `psexec.py`: Allows the execution of commands on remote Windows systems using SMB/RPC.
  ```bash
  psexec.py <domain>/<username>:<password>@<target-ip>
  ```
- `wmiexec.py`: Executes commands on remote Windows systems using WMI (Windows Management Instrumentation).
  ```bash
  wmiexec.py <domain>/<username>:<password>@<target-ip>
  ```
- `smbexec.py`: Similar to psexec.py, but uses a semi-interactive shell over SMB.
  ```bash
  smbexec.py <domain>/<username>:<password>@<target-ip>
  ```
- `secretsdump.py`: Extracts credentials from a Windows system, including hashes, domain cached credentials, and more.
  ```bash
  secretsdump.py <domain>/<username>:<password>@<target-ip>
  ```
- `getTGT.py`: Requests a Kerberos TGT (Ticket Granting Ticket) from a Kerberos KDC (Key Distribution Center).
  ```bash
  getTGT.py <domain>/<username>:<password>
  ```
- `ticketer.py`: Creates Kerberos tickets for various purposes, including Pass-the-Ticket attacks.
  ```bash
  ticketer.py -nthash <hash> -domain-sid <sid> <username>
  ```
- `lookupsid.py`: Performs SID (Security Identifier) lookups to enumerate domain users and groups.
  ```bash
  lookupsid.py <domain>/<username>:<password>@<target-ip>
  ```
- `rpcdump.py`: Dumps information from DCE/RPC services.
  ```bash
  rpcdump.py <target-ip>
  ```



### Certipy
Certipy is a tool designed to interact with and exploit Active Directory Certificate Services (AD CS). It is commonly used by penetration testers and red teams to identify misconfigurations, enumerate certificate templates, request certificates, and perform various attacks within AD CS environments.
- **Purpose**: To facilitate the enumeration and exploitation of Active Directory Certificate Services.

#### Key Features

1. **Enumeration**: Enumerates certificate templates, Certificate Authorities (CAs), and certificate objects.
2. **Certificate Requesting**: Requests certificates based on identified templates.
3. **Exploitation**: Identifies and exploits misconfigurations in AD CS to escalate privileges and persist within environments.
4. **Various Attacks**: Supports different attack vectors such as ESC1, ESC2, and certificate abuse techniques.
5. **Credential Dumping**: Extracts credentials and private keys from requested certificates.
6. **Interoperability**: Works with other tools and frameworks to enhance attack capabilities.

#### Key Components

##### Enumeration

Certipy provides detailed enumeration capabilities to identify all elements within AD CS:

- **Certificate Authorities (CAs)**: Lists all CAs within the domain.
- **Certificate Templates**: Lists all certificate templates and their configurations.
- **Certificates**: Lists issued certificates and their details.

##### Certificate Requesting

Allows users to request certificates using identified templates. These certificates can then be used for authentication and other purposes.

##### Exploitation

Certipy identifies and exploits various misconfigurations in AD CS, such as:

- **ESC1 (Vulnerable Certificate Templates)**: Identifies templates that allow arbitrary certificate requests.
- **ESC2 (Misconfigured DACLs)**: Finds Discretionary Access Control List (DACL) misconfigurations that can be exploited.
- **Certificate Abuse**: Abuses certificates for persistence and privilege escalation.

##### Credential Dumping

Extracts credentials from requested certificates, including NTLM hashes and private keys.

#### Examples

- Enumerate Certificate Authorities: This command lists all Certificate Authorities within the specified target domain.
  ```bash
  certipy ca -target <target-domain>
  ```
- Enumerate Certificate Templates: This command lists all certificate templates and their configurations within the specified target domain.
  ```bash
  certipy template -target <target-domain>
  ```
- Request a Certificate: This command requests a certificate using the specified template and credentials.
  ```bash
  certipy request -template <template-name> -target <target-domain> -username <username> -password <password>
  ```
- Perform ESC1 Exploitation: This command exploits a vulnerable certificate template to request a certificate.
  ```bash
  certipy esc1 -target <target-domain> -template <template-name> -username <username> -password <password>
  ```
- Extract Credentials from a Certificate: This command extracts credentials from the specified certificate and key files.
  ```bash
  certipy dump -cert <certificate-file> -key <key-file>
  ```

### PowerSploit

### PowerUpSQL

### BurpSuite

## OWASP Security Testing Guide

# Shell trail

## Assesment workflow steps before hacking
- customer and authorization - needs something to be tested
- scoping : what and how are we gonna test it
  - risks : they see e.g. medical app, risks that some personal info leaks
  - goals : find as many vulnabilities as possible
  - price : have to discuss this
- hacking for a week or two
- reporting + debreefing meeting
  - maybe security training

## Web assesment - tooling
- browser 
- intercepting proxy e.g. burpsuite
- path discovery e.g. ffuf, gobuster (headers and stuff)
- various extensions
  - java extensions for java apps 
  - node etc
- wordlist (e.g. params, usernames etc)
  - seclist (different lists for different purposes)

### metholodgy
- web security testing guide (OWASP) <-- LOOKUP --> 
- based on customer risk
- broad vs. deep
- complex functionality - are easy to target
  - e.g. fileuploads, pdf generators (e.g. pdf signup where they include name)
- find affected backend systems
- authen & authorize
  - check that you cannot bypass and sign in 
  - cant access other orgs data
- Chaining 
  - identify types (if you find two vulnabilities, combining them might give damage)
- lack the creativity needed, but a good start

### Infrastructure tooling
- Port scanners (nmap, massscan - fast but not thorough)
- metasploit (mainly for databases)
- intercepting proxy (burpsuite)

### Active directory testing
- BloodHound
  - internal testing (not red team - makes noise)
- impacket
  - use for e.g. executing code on other systems
- PowerSploit / sharpspoloit
- PowerUpSql
  - used on sql databases
  - privelege escalation
- certipy
- cmloot.py
  - good for attacking sscm 
  - the new black
  - credentials

### Internal testing 
#### methodlogy
- discover hosts
- port scans of hosts
- investigate interesting ports
  - find ports like web or uses remote access
- always find default credentials
- Internal webapps are less secure

#### active directory
- escalate privolege
- targets : hosts used by sysadmins, systems they should not be logged into
- common to have sql misconfig
- there migh tbe issues with certificates - look like you are another user
- sometimes passwords in files 
- sccm : alot of security issues
- password spraying

## Red team pentest
- be sneaky
- simulate real world attack
- often you dont have initial access

## Example
- initial access : scan alot of stuff
- one had a vulnability - but it didn't work (SSRF)
- what applications do we have on the internal systems
- used SSRF as a port scanner to get access to systems that were not supposed to be accessable by the internet
- systems had default credentials 
- see slides