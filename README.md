

## **Overview**

This project is a **Linux-based Network Monitor** written in C++.  
It continuously captures live network packets using **raw sockets**, dissects them layer by layer (Ethernet, IPv4, IPv6, TCP, and UDP), and manages them through custom **stack** and **queue** implementations.  

The main goal of this assignment was to apply data structure concepts like **stacks** and **queues** in a real-world system-level problem. The program also demonstrates **packet filtering**, **replay functionality**, and **multi-threaded processing** with proper error handling.

---

## **Features**

- Continuous real-time packet capture using **raw sockets**  
- Layer dissection for **Ethernet**, **IPv4**, **IPv6**, **TCP**, and **UDP**  
- Custom **LIFO stack** (`LifoParse`) for parsing packet layers  
- Queue implemented using `std::deque` for packet management  
- IP-based filtering (source and destination)  
- Replay functionality with up to **2 retries**  
- Backup mechanism for failed replay attempts  
- Thread-safe handling using mutex and condition variables  
- Runs for **1 minute continuously**, showing live updates  

---

## **Requirements**

Before running, make sure your environment meets these conditions:

- **Operating System:** Linux (Ubuntu, Debian, or Fedora recommended)  
- **Compiler:** g++ with support for **C++17 or later**  
- **Privileges:** Root access is required to open and use **raw sockets**  

---

## **Files Included**

| File | Description |
|------|--------------|
| `main.cpp` | Main C++ source file for the Network Monitor |
| `README.md` | Setup and usage guide (this file) |


---

## **How to Compile**

Open your terminal in the project directory and run the following command:

```bash
g++ -std=c++17 -pthread main.cpp.cpp -o network_monitor
```

If it compiles successfully, an executable named **network_monitor** will be generated in the same folder.

---

## **How to Run**

Since raw sockets require root privileges, you must run the program as **sudo**:

```bash
sudo ./network_monitor
```

### Once the program starts:
- It will begin capturing packets from your default network interface.  
- Each packet will be **stored**, **parsed**, and **filtered** based on IP addresses.  
- Matching packets are sent for **replay**, with up to **2 retry attempts** on failure.  
- Failed packets are moved to a **backup queue**.  
- The program will run **continuously for 1 minute** and then display a final summary.  

---


## **Troubleshooting**

If something doesn’t work as expected:

- **Permission Denied:**  
  Make sure to run the program with `sudo`.

- **No Packets Captured:**  
  Try generating some network traffic (open a browser, ping a website, etc.).

- **Interface Issues:**  
  If you’re not using the default interface, modify the code to capture from `eth0`, `wlan0`, or your specific interface name.

- **Compilation Errors:**  
  Ensure your g++ version supports **C++17** and that all headers (`<netinet/ip.h>`, `<arpa/inet.h>`, etc.) are available.

---

## **Assumptions**

- The program assumes it is running as **root** to access raw sockets.  
- It captures traffic from a **single active network interface**.  
- Packet size beyond **1500 bytes** may be skipped based on the threshold logic.  
- Replay attempts are capped at **2 retries per packet** as defined in the assignment.  

---

## **Demonstration Summary**

- Runs continuously for **1 minute**.  
- Captures packets and pushes them to the queue.  
- Dissects packets layer by layer using stack operations.  
- Filters packets by IP addresses.  
- Replays filtered packets and retries failures.  
- Moves permanently failed packets to a backup queue.  
- Displays all captured, processed, retried, and failed packet summaries at the end.  

---


