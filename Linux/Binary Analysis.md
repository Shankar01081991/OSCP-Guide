
## **Binary Analysis**


strings
=======

Search for printable strings of characters in binaries:

 

    strings /path/to/binary
    strings /path/to/binary | awk 'length($0) > 10'
    -To find typical usernames (e.g., alphanumeric strings), you might use:
    strings /path/to/binary | grep -E '[a-zA-Z0-9._-]{3,}'
    
    -Passwords can vary widely, but a common pattern might include:
    strings /path/to/binary | grep -E '[a-zA-Z0-9!@#$%^&*()_+-=]{6,}'
    
    -Keys often have a specific format, such as hexadecimal or base64. Here are examples for each:
    strings /path/to/binary | grep -E '[a-fA-F0-9]{32,}'
    This regex matches strings that are at least 32 characters long and consist of hexadecimal characters.

    -Base64 Keys
    strings /path/to/binary | grep -E '[A-Za-z0-9+/=]{20,}'
    This regex matches strings that are at least 20 characters long and consist of base64 characters.


 ![image](https://github.com/user-attachments/assets/76f4513c-fc6d-4a04-9576-98d6dec0acef)


strace
======
When you run this command, strace will output a detailed log of all the system calls made by the binary, along with their arguments and return values. This can be useful for debugging, performance analysis, or understanding the behavior of the binary.
Trace system calls and signals in a process:

 

    strace ./path/to/binary --argument arg



ltrace
======

Trace library calls in a process:

 

    ltrace ./path/to/binary --argument arg
