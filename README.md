# All In One TryHackMe Automation
This Python script is designed to assist you in automating the steps required to solve the All In One CTF on TryHackMe. It will lead you through the stages of the attack, from initial reconnaissance to finally capturing user.txt and root.txt.

The script aims to:

- Automate enumeration tasks

- Assist with vulnerability identification

- Execute exploits to escalate privileges

- Finally, print the contents of user.txt and root.txt


# Usage

First Launch the instance of the machine in TryHackMe
![image](https://github.com/user-attachments/assets/72af56f9-776f-4dfc-9ba6-0638e8ee2a77)

Make sure you have Nmap and Wpscan installed.
```
sudo apt install nmap
```
```
sudo gem install wpscan
```

Run the python script
```
python All_In_One_Automation.py
```

End of the script should look like:
![image](https://github.com/user-attachments/assets/45414aa2-c29b-4a40-b2eb-6d78329d0e76)

