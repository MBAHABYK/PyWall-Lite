# PyWall-Lite
Firewall software with Python.

PyWall Lite: Simple and Customizable Network Security Solution

PyWall Lite is a simple, customizable and open source firewall application developed for those who want to learn and implement network security. Created using the Python programming language, this project allows you to understand and experience basic network security concepts in a practical way. PyWall Lite can be managed with both the web interface and the command line interface (CLI).

Key Features:

IP ​​Address Blocking:

Blocks all connections from specific IP addresses.

You can easily add or remove IP addresses via the web interface or CLI.

Port Blocking:

Blocks all connections to specific ports.

You can easily add or remove port numbers via the web interface or CLI.

Protocol Blocking:

Blocks all connections using specific network protocols such as TCP and UDP.

You can easily add or remove protocols via the web interface or CLI.

Rule Management:

Allows you to define more complex and customized blocking rules.

You can make more flexible matches for IP addresses using Regex.

You can add or remove rules via web interface or CLI.

Real-time Log Monitoring:

Allows you to monitor network activities and blockings in real time in the web interface.

Logs are displayed in an automatically updated box and always scroll to the latest record.

DoS/DDoS Protection:

Automatically blocks when there are too many connection attempts from a specific IP address within a certain period of time.

This simple DoS/DDoS protection tries to prevent overload.

Logging:

Records all network activities and blocking decisions in a file called pywall.log.

Log records include timestamps, event levels and additional information (IP, port, protocol).

Command Line (CLI) Support

Allows you to add or remove IP, port, protocol and rules from the command line, see the blocked list and view log files.

Open Source: Allows everyone to develop and contribute by publishing codes on platforms like GitHub.

Easy to Use: Thanks to its simple and user-friendly interface, you can easily use and manage PyWall Lite.

Customizable: Thanks to its open source structure, you can easily customize it according to your own needs.

Technical Details:

Programming Language: Python

Network Communication: socket and asyncio libraries

Web Interface: Flask framework

Command Line Interface: argparse library

Regex Support: Create more flexible rules with the re library

Why PyWall Lite?

For Learning Purposes: It is an ideal project to learn topics such as network security, firewalls and network programming.

Simple and Effective: Despite its simplicity, it provides a level of protection that will meet your basic security needs.

Customizable: Thanks to its open source structure, you can customize and develop it according to your needs.

Flexible Management: It can be easily managed with both the web interface and the command line.

Limitations:

Basic Blocking: Only has basic blocking capabilities. It does not have the features that more advanced firewalls have.

Does Not Check Outgoing Connections: Does not check outgoing connections.

No Application Layer Protection: Cannot inspect application layer protocols such as HTTP/HTTPS.

Basic DDoS Protection: Only protects against simple DoS attacks.

Not Enough Alone: ​​Must be used in conjunction with more comprehensive solutions for real security.

Conclusion:

PyWall Lite is a great starting point for anyone who wants to learn basic network security concepts and implement a simple security solution. You can control network traffic and increase your security either via the web interface or the command line. The open source nature of the project allows you to adapt and develop the project according to your own needs.

I hope this introductory article clarified all the features and potential of the PyWall Lite project. If you have any further questions or requests, please feel free to ask.
