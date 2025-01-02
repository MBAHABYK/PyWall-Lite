Absolutely! Here's an English-language guide on how to use PyWall Lite, covering all its features and functionalities:

PyWall Lite: A Simple and Customizable Firewall - User Guide

PyWall Lite is an open-source, customizable firewall application designed for those looking to learn and implement basic network security. Built with Python, this project allows you to understand fundamental network security concepts and apply them practically. PyWall Lite can be managed through both a web interface and a command-line interface (CLI).

Key Features:

IP Address Blocking:

Blocks all connections originating from specified IP addresses.

Easily add or remove IP addresses via the web interface or CLI.

Port Blocking:

Blocks all connections made to specified ports.

Easily add or remove port numbers via the web interface or CLI.

Protocol Blocking:

Blocks all connections using specified network protocols such as TCP or UDP.

Easily add or remove protocols via the web interface or CLI.

Rule Management:

Allows you to define more complex and custom blocking rules.

Enables flexible matching for IP addresses using regular expressions (regex).

Add and remove rules via the web interface or CLI.

Real-time Log Monitoring:

Provides live tracking of network activities and blockages in the web interface.

Logs are displayed in an auto-updating box that always shows the latest entries.

Basic DoS/DDoS Protection:

Automatically blocks an IP address if it makes too many connection attempts within a specified time.

This protection mechanism helps prevent basic denial-of-service attacks.

Logging:

Records all network activity and blocking decisions in a file named pywall.log.

Log entries include timestamps, event levels, and extra details such as IP, port, and protocol.

Command-Line Interface (CLI) Support:

Offers the ability to manage IP, port, protocol, and rule settings directly from the command line.

Allows viewing blocked lists and log files through the command line.

Open Source: The code is publicly available for anyone to review, modify, and contribute to.

Ease of Use: Provides a simple and user-friendly interface that's easy to manage.

Customizable: Due to its open-source nature, it can be customized according to your own specific needs.

Technical Details:

Programming Language: Python

Network Communication: socket and asyncio libraries

Web Interface: Flask framework

Command-Line Interface: argparse library

Regex Support: re library used to define complex rules using regular expressions.

Why Use PyWall Lite?

Educational: It's an ideal project for learning about network security, firewalls, and network programming.

Simple and Effective: Provides a basic level of protection that meets most basic security requirements.

Customizable: Open-source architecture allows you to adapt and enhance the project based on your needs.

Flexible Management: It can be easily managed through both a web interface and a command-line interface.

Limitations:

Basic Blocking: Only provides basic blocking functionalities. Lacks features such as stateful inspection or deep packet inspection.

No Outbound Control: Doesn't control outbound connections.

No Application Layer Protection: Can't inspect or filter application layer protocols like HTTP/HTTPS.

Basic DDoS Protection: Only offers basic DoS protection and may not be effective against sophisticated DDoS attacks.

Not a Complete Solution: For serious security situations, it's necessary to use more comprehensive solutions.

Getting Started:

Download and Installation:

Ensure you have Python installed on your system.

Clone or download the project files to a local directory.

Web Interface Management:

Navigate to the project directory using your terminal or command prompt.

Run python web_app.py to start both the web application and the PyWall Lite server.

Open a web browser and go to http://localhost:5000 or http://192.168.1.70:5000 (or whatever your IP address is).

Command Line Management:

Navigate to the project directory using your terminal or command prompt.

Use the following commands to manage PyWall Lite:

To see help use: python pywall_lite.py -h

To block an IP address use: python pywall_lite.py block_ip <ip_address>

To unblock an IP address use: python pywall_lite.py unblock_ip <ip_address>

To block a port use: python pywall_lite.py block_port <port_number>

To unblock a port use: python pywall_lite.py unblock_port <port_number>

To block a protocol use: python pywall_lite.py block_protocol <protocol>

To unblock a protocol use: python pywall_lite.py unblock_protocol <protocol>

To add a new rule use: python pywall_lite.py block_rule --ip "<ip_regex>" --port <port_number> --protocol <protocol>

To remove a rule use: python pywall_lite.py unblock_rule --ip "<ip_regex>" --port <port_number> --protocol <protocol>

To see the current blocked list use: python pywall_lite.py list

To view logs use: python pywall_lite.py logs

Testing and Verification:

To verify blocking rules, try accessing a blocked IP address or port through telnet, netcat, or a web browser.

Check the pywall.log file to track all network activities.

Verify settings you've made from the web interface or the command line appear in the log.

Important Notes:

Remember that this application will only protect traffic that is intended for the machine it's installed on.

PyWall Lite is a great learning project, but should not be considered a fully production-ready firewall solution.

Use PyWall Lite in conjunction with a fully supported OS firewall or professional firewall solution.

Conclusion:

PyWall Lite is an excellent educational and basic security tool that provides a flexible way to control network traffic. It can be managed through a user-friendly web interface or the command line. This tool can be used to understand fundamental network concepts and to gain practical experience with firewalls.

If you have any further questions or need more assistance, feel free to ask!
