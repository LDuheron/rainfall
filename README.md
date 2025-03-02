## About the project

**Rainfall** is an ISO challenge from the **42Network** curriculum. It is designed to develop skills in binary exploitation, assembly analysis, and low-level debugging. It consists of **10 levels** and **4 bonus challenges**.

Each level is documented in its corresponding directory, with a detailed explanation of the approach and reasoning used to solve it.

## Table of contents

- [About the Project](https://www.notion.so/Leaffliction-11bd775f41e6809986ace63e12d25d2e?pvs=21)
- [Getting Started](https://www.notion.so/Leaffliction-11bd775f41e6809986ace63e12d25d2e?pvs=21)
- [Usage](https://www.notion.so/Leaffliction-11bd775f41e6809986ace63e12d25d2e?pvs=21)

## Getting Started

1. Create a virtual machine using the ISO file provided by 42. Ensure that the VM's network is set to **Host-Only Adapter**.
2. Find the IP address of your VM by running:

```
ifconfig
```

3. Connect via SSH on port 4242 replacing X with the level you want to access and <VM_IP_ADDRESS> with your VM’s actual IP.

```python
ssh -p 4242 levelX@<VM_IP_ADDRESS>
```

## Usage

1. **Log in to level00** using the default credentials:

```bash
ssh -p 4242 level0@<VM_IP_ADDRESS>
#password: level0
```

1. **Find the password for the next level.** 

After logging in, the goal is to locate and read the **".pass"** file belonging to the next level's user account (**levelX**, where **X** is the next level number). This file is stored in the home directory of each user, except for **level0**.

1. **Switch level**

Use the `su` command to switch to the next level after obtaining the password. Upon reaching **level9**, progression continues towards the **bonus0** user.

```bash
su levelX
su bonusX
```

## Ressources
