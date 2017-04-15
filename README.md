# About
Qencrypt is a small gui program which helps you encrypt small files.  
It uses nacl's 'secretbox' for encryption and https://github.com/andlabs/ui for the ui.  
[Download](https://github.com/chin123/qencrypt/releases/)

# Screenshots
![Main Interface of qencrypt linux](screenshots/main.png)  

![Main Interface of qencrypt windows](screenshots/windowsscreen.png)

# Building
1. Make sure you have all the dependencies needed for building https://github.com/andlabs/ui  
2. Assuming you have go installed and have set your GOPATH, run:    
`go get github.com/chin123/qencrypt`  
3. Run `go build github.com/chin123/qencrypt`  

# Usage

1. Open a file which you want to encrypt or decrypt using the 'Open' button.
2. Type in a password in the password field which you want to use to encrypt or decrypt the file.
3. Choose whether you want to encrypt or decrypt the file by clicking the 'Encrypt' or 'Decrypt' buttons.

Thats it!

# License
GPLv3. For more information, please see the LICENSE file.
