# Secure-Communication---Cryptography-Project

Introduction : The assignment addresses the critical challenge of preserving privacy in communication channels, aiming to maintain the confidentiality and integrity of transmitted data. In an era of digital communication dominance, ensuring security is crucial, given the exposure of data to threats like eavesdropping and tampering. There's a pressing need for robust mechanisms to safeguard communication privacy, protecting data integrity and confidentiality.

Importance of the Problem: Ensuring privacy in communication is vital, considering the reliance on digital platforms for personal, professional, and governmental interactions. Breaches of privacy can lead to financial loss, reputational damage, and compromise national security. Existing solutions focus on encryption and hashing techniques to secure communication channels, but challenges remain in efficiently detecting and thwarting tampering attempts, necessitating innovation in privacy-preserving communication methodologies.

Here is the project design : https://github.com/priyanka644851/Secure-Communication---Cryptography-Project/blob/main/Project%20Architecture.pdf

Steps to run:

First run hacker code using : gcc hacker.c -o h -lpcap sudo ./h
Then run client1 code (receiver side): gcc client1.c -o c1 ./c1
Now run client2 code (senders side): gcc client2.c -o c2 ./c2
Then whenever client2 sends some message to client1, hacker can listen to conversation and can insert malicious message also in the name of c1.


