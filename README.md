# ScamShield AI: Fake Offer and Phishing Inspector

A full-stack, enterprise-grade cybersecurity web application designed to detect, analyze, and neutralize employment scams, counterfeit cashier check schemes, and sophisticated phishing campaigns before victims lose money or compromise their identities.

Powered by Google Gemini 2.5 Flash on an Express backend proxy to ensure API keys are never exposed to client browsers.

---

## Key Features

- **Gemini AI Threat Intelligence Engine**: Real-time evaluation of linguistic manipulation, premature hiring, artificial urgency, and financial red flags.
- **Scam Threat Index (0–100) & Risk Scoring**: Mathematical fraud scoring categorized into 5 discrete risk tiers: `SAFE`, `LOW`, `MODERATE`, `HIGH`, and `CRITICAL`.
- **In-Context Suspicious Phrase Highlighting**: Interactive visual highlighting of fraudulent patterns directly in the source text, with categorized explanations (e.g., Advance-Fee Scheme, Off-Platform Channels, Coercive Language).
- **Domain & Recruiter Email Verification**: Cross-checks recruiter email addresses and attached URLs against corporate identity best practices, detecting free webmail domains (`@gmail.com`), deceptive subdomains, and malicious TLDs.
- **"What Should I Do Now?" Security Action Plan**:
  - Interactive immediate containment checklist (trackable in the UI).
  - Safe verification protocol (how to independently contact corporate HR without alerting the scammer).
  - Critical prohibitions (what never to do).
  - Direct links to official incident reporting portals (FTC, FBI IC3, APWG).
- **Downloadable Threat Audit Reports**:
  - **HTML Audit Document**: Printable, beautifully styled standalone document ready for PDF export or employer compliance submission.
  - **Markdown Document**: Technical audit breakdown for IT helpdesks and ticketing systems.
  - **One-Click Clipboard Copy**: Formatted summary ready to paste into security incident channels.
- **Realistic Scenario Presets**: Instant one-click test cases including Fake Equipment Check Scams, WhatsApp/Telegram Recruiter Traps, Corporate Payroll Phishing, and Legitimate Corporate Offers.

---

## Architecture & Security

```
Browser Client (React + Tailwind + Lucide)
   │
   │  POST /api/scan-threats (Private payload)
   ▼
Express Node Server (server.ts)
   │
   ├─► Server-Side GEMINI_API_KEY (Hidden from browser)
   │     │
   │     ▼
   │   Google GenAI SDK (gemini-3.8-flash)
   │     │
   │     ▼
   │   Strict Structured JSON Threat Analysis
   │
   └─► Resilience Fallback Engine (Heuristic analyzer if offline/timeout)
```

- **Zero Client-Side Key Leakage**: The Google Gemini API key resides solely on the backend container environment (`process.env.GEMINI_API_KEY`).
- **Resilient Fallback Engine**: If an external network timeout or API rate limit occurs, a heuristic fallback rule engine steps in automatically so the user is never left stranded.

---

## Local Development Setup

### Prerequisites
- Node.js 20+
- A Google Gemini API Key from [Google AI Studio](https://aistudio.google.com/)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/scamshield-ai.git
   cd scamshield-ai
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Add your Gemini API Key:
   ```env
   GEMINI_API_KEY="your-gemini-api-key-here"
   ```

4. **Start the Development Server:**
   ```bash
   npm run dev
   ```
   The application will start on `http://localhost:3000`.

---

## Production Build & Deployment

### Build Command
```bash
npm run build
```
This compiles the Vite frontend into `dist/` and bundles `server.ts` into a self-contained CommonJS backend at `dist/server.cjs`.

### Start Command
```bash
npm run start
```
Starts the production server on port 3000.

### Cloud Run / Docker Deployment
The project is container-ready. Bind port 3000 and ensure the environment variable `GEMINI_API_KEY` is provided via secrets management.

---

## License
Apache-2.0
