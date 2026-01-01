# Security Policy



## Reporting a Vulnerability

If you find a security vulnerability in FauxSSH, please open a standard GitHub Issue or use the repository's security reporting feature if available.

## Risk Warning & Disclaimer

> [!WARNING]
> **Running a honeypot is inherently risky.** By design, this software attracts malicious traffic and interacts with attackers. You are inviting diverse threat actors to connect to your infrastructure.

### 1. Infrastructure Risks
*   **Lateral Movement & Breakouts**: If FauxSSH is not properly isolated (e.g., usually containerized or in a dedicated VM), a sophisticated attacker could exploit a vulnerability in the Python runtime, the OS kernel, or the `paramiko` library to escape the application sandbox and compromise your host machine. From there, they could pivot to your internal network.
*   **Resource Exhaustion (DoS)**: Attackers may flood the service with connections, potentially consuming all available CPU, RAM, or file descriptors, causing the host system to become unresponsive.
*   **Fingerprinting**: Advanced attackers may identify this as a honeypot. Once identified, they might use it to feed false data to your threat intelligence or launch specific exploits targeting honeypot software.

### 2. LLM & API Risks
*   **API Quota Exhaustion ($$$)**: High-volume attacks or scripted bots can trigger thousands of LLM requests in a short time. If you do not set quotas on your Google Cloud Console, this could lead to **significant financial costs**.
*   **Prompt Injection & Jailbreaks**: Attackers may try to manipulate the LLM into generating harmful, offensive, or illegal content. While Gemini has safety filters, no model is 100% immune to sophisticated jailbreaks.
*   **ToS Violation**: If attackers use your honeypot to generate abusive content, you (the API key holder) are technically the one sending these requests to Google. This could theoretically lead to API suspension.

### 3. Data & Legal Risks
*   **Privacy & Logging**: FauxSSH logs IP addresses and full session transcripts. Ensure you comply with local laws (e.g., GDPR, CCPA) regarding the collection and storage of data associated with potential human actors.
*   **Liability**: In extremely rare cases, if your honeypot is compromised and used to attack third parties (e.g., part of a botnet), you could face liability. Strict outbound network blocking is essential to prevent this.

### 4. Operational Recommendations
*   **Strict Isolation**: **NEVER** run this on your personal laptop, workstation, or a server containing sensitive data. Use a throwaway VPS or a dedicated isolated VLAN.
*   **Network Limits**: Use firewall rules (e.g., `ufw`, `iptables`, AWS Security Groups) to strictly **BLOCK ALL OUTBOUND TRAFFIC** from the honeypot machine, except for the specific Google API endpoints needed for the LLM.
*   **Cost Controls**: Configure strict budget alerts and quotas in your Google Cloud Console to prevent billing shocks.

