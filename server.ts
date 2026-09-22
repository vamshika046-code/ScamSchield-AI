import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "5mb" }));

// Lazy initialization of Gemini client
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

// Heuristic fallback analyzer for when API key is missing or network failure occurs
function performHeuristicAnalysis(
  messageText: string,
  urlOrDomain?: string,
  recruiterEmail?: string
) {
  const lowerText = messageText.toLowerCase();
  const lowerUrl = (urlOrDomain || "").toLowerCase();
  const lowerEmail = (recruiterEmail || "").toLowerCase();

  let threatScore = 15;
  const indicators: Array<{ indicator: string; present: boolean; scoreImpact: number; observation: string }> = [];
  const highlightedPhrases: Array<{ phrase: string; category: string; severity: 'high' | 'medium' | 'low'; explanation: string }> = [];

  // 1. Advance fee / equipment check check
  const checkPatterns = [
    { p: "check to purchase equipment", text: "check to purchase equipment", cat: "Financial / Check Scam", sev: "high" as const, exp: "Legitimate employers never send checks to candidates to buy equipment from specified vendors." },
    { p: "send you a check", text: "send you a check", cat: "Financial Scam", sev: "high" as const, exp: "Counterfeit check scams involve sending money that bounces after you forward funds to a 'vendor'." },
    { p: "home office supplies", text: "home office supplies", cat: "Equipment Scam", sev: "medium" as const, exp: "Often combined with fake checks to order from an unauthorized third-party site." },
    { p: "cashiers check", text: "cashier's check", cat: "Financial Scam", sev: "high" as const, exp: "Cashier's checks are a hallmark of overpayment frauds." },
    { p: "cashier's check", text: "cashier's check", cat: "Advance-Fee Check Scheme", sev: "high" as const, exp: "Counterfeit cashier checks bounce days after deposit, leaving the victim liable for all funds sent to fake vendors." },
    { p: "cashier check", text: "cashier check", cat: "Advance-Fee Check Scheme", sev: "high" as const, exp: "Fake employer cashier checks are a classic hallmark of equipment advance-fee employment fraud." },
    { p: "home equipment", text: "home equipment", cat: "Equipment Purchasing Scam", sev: "high" as const, exp: "Requiring new hires to buy hardware or software from designated vendors using an upfront check is fraudulent." },
    { p: "remote data entry", text: "remote data entry", cat: "High-Frequency Scam Title", sev: "medium" as const, exp: "Remote data entry is the most commonly impersonated job title by international phishing and check-cashing syndicates." },
    { p: "wire transfer", text: "wire transfer", cat: "Irreversible Payment", sev: "high" as const, exp: "Demanding wire transfers makes funds unrecoverable once sent." },
    { p: "crypto", text: "crypto", cat: "Cryptocurrency", sev: "high" as const, exp: "Legitimate recruiters and corporate HR never transact in cryptocurrency." },
    { p: "gift card", text: "gift card", cat: "Payment Red Flag", sev: "high" as const, exp: "No legitimate employer or business requests payments via gift cards." }
  ];

  for (const item of checkPatterns) {
    if (lowerText.includes(item.p)) {
      threatScore += 25;
      highlightedPhrases.push({
        phrase: item.text,
        category: item.cat,
        severity: item.sev,
        explanation: item.exp
      });
      indicators.push({
        indicator: item.cat,
        present: true,
        scoreImpact: 25,
        observation: `Detected phrase: "${item.text}". ${item.exp}`
      });
    }
  }

  // 2. Off-platform interview communication
  const commsPatterns = [
    { p: "telegram", text: "Telegram", cat: "Off-Platform Channel", sev: "high" as const, exp: "Interviews conducted solely over Telegram or Signal allow scammers to remain anonymous." },
    { p: "whatsapp", text: "WhatsApp", cat: "Off-Platform Channel", sev: "medium" as const, exp: "Recruiting cold messages on WhatsApp frequently originate from task and fake job syndicates." },
    { p: "signal", text: "Signal", cat: "Off-Platform Channel", sev: "high" as const, exp: "Anonymous messaging apps bypass standard corporate recruitment protocols." }
  ];

  for (const item of commsPatterns) {
    if (lowerText.includes(item.p)) {
      threatScore += 20;
      highlightedPhrases.push({
        phrase: item.text,
        category: item.cat,
        severity: item.sev,
        explanation: item.exp
      });
      indicators.push({
        indicator: "Anonymous Communication App",
        present: true,
        scoreImpact: 20,
        observation: `Applicant redirected to ${item.text}, avoiding corporate email or official portals.`
      });
    }
  }

  // 3. Urgency and pressure tactics
  const urgencyPatterns = [
    { p: "urgent response required", text: "urgent response required", cat: "Urgency Pressure", sev: "medium" as const, exp: "Artificial urgency prevents victims from cross-referencing company details." },
    { p: "within 24 hours", text: "within 24 hours", cat: "Time Pressure", sev: "medium" as const, exp: "Tight deadlines force rushed decisions before verification can occur." },
    { p: "immediate start", text: "immediate start", cat: "Hiring Anomaly", sev: "low" as const, exp: "Skipping formal vetting, interviews, and reference checks is a high risk indicator." },
    { p: "no interview required", text: "no interview required", cat: "Unrealistic Hiring", sev: "high" as const, exp: "Legitimate competitive roles require formal live evaluation." }
  ];

  for (const item of urgencyPatterns) {
    if (lowerText.includes(item.p)) {
      threatScore += 15;
      highlightedPhrases.push({
        phrase: item.text,
        category: item.cat,
        severity: item.sev,
        explanation: item.exp
      });
      indicators.push({
        indicator: item.cat,
        present: true,
        scoreImpact: 15,
        observation: `High pressure tactic detected: "${item.text}".`
      });
    }
  }

  // 4. PII requests
  const piiPatterns = [
    { p: "social security", text: "social security", cat: "Sensitive PII Solicitation", sev: "high" as const, exp: "SSNs should never be provided over unencrypted chat or before verified job contracts." },
    { p: "bank details", text: "bank details", cat: "Banking Info Solicitation", sev: "high" as const, exp: "Direct deposit info is only collected after signed onboarding on verified HR portals." },
    { p: "front and back of your id", text: "front and back of your ID", cat: "Identity Theft Risk", sev: "high" as const, exp: "Government IDs requested on informal channels are harvested for identity fraud." }
  ];

  for (const item of piiPatterns) {
    if (lowerText.includes(item.p)) {
      threatScore += 20;
      highlightedPhrases.push({
        phrase: item.text,
        category: item.cat,
        severity: item.sev,
        explanation: item.exp
      });
      indicators.push({
        indicator: "Premature PII Solicitation",
        present: true,
        scoreImpact: 20,
        observation: `Requested sensitive identity or banking details before verified employment verification.`
      });
    }
  }

  // URL analysis
  let urlVerdict: 'safe' | 'suspicious' | 'malicious' | 'unverified' | 'none' = 'none';
  let urlAnalysis = 'No external URL provided or identified.';
  const urlDetails: string[] = [];

  if (urlOrDomain || lowerText.match(/https?:\/\/[^\s]+/i)) {
    const rawUrl = urlOrDomain || (lowerText.match(/https?:\/\/[^\s]+/i)?.[0] || '');
    const lowUrl = rawUrl.toLowerCase();
    
    if (lowUrl.includes('.ru') || lowUrl.includes('.xyz') || lowUrl.includes('.top') || lowUrl.includes('.tk') || lowUrl.includes('bit.ly') || lowUrl.includes('tinyurl')) {
      urlVerdict = 'suspicious';
      urlAnalysis = `URL uses a high-risk TLD or shortening service (${rawUrl}) often leveraged to obscure destination phishing sites.`;
      urlDetails.push('Uses URL shortener or generic high-abuse top level domain (.xyz, .top, etc.).');
      urlDetails.push('Domain registration details and redirect destinations cannot be verified without sandboxing.');
      threatScore += 25;
    } else if (lowUrl.includes('forms.gle') || lowUrl.includes('docs.google.com/forms')) {
      urlVerdict = 'suspicious';
      urlAnalysis = 'Company is using a generic Google Form for job application or sensitive data collection instead of an official ATS (Greenhouse, Lever, Workday).';
      urlDetails.push('Free form hosting prevents employer domain validation.');
      threatScore += 15;
    } else {
      urlVerdict = 'unverified';
      urlAnalysis = `URL detected: ${rawUrl}. Verify that this matches the exact corporate domain of the employer and does not contain subtle typos (e.g. typosquatting).`;
      urlDetails.push('Check the root domain against official company registry.');
      threatScore += 5;
    }
  }

  // Email analysis
  let emailVerdict: 'safe' | 'suspicious' | 'spoofed' | 'unverified' | 'none' = 'none';
  let emailAnalysis = 'No recruiter email provided.';
  const emailDetails: string[] = [];

  if (recruiterEmail || lowerText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i)) {
    const rawEmail = recruiterEmail || (lowerText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i)?.[0] || '');
    const lowEmail = rawEmail.toLowerCase();

    if (lowEmail.endsWith('@gmail.com') || lowEmail.endsWith('@yahoo.com') || lowEmail.endsWith('@hotmail.com') || lowEmail.endsWith('@outlook.com')) {
      emailVerdict = 'suspicious';
      emailAnalysis = `Recruiter claims to represent an organization but communicates using a free public email provider (${rawEmail}).`;
      emailDetails.push('Legitimate corporate recruiters almost exclusively communicate via registered company domains.');
      emailDetails.push('Free email accounts (@gmail.com, @outlook.com) have zero organizational verification.');
      threatScore += 30;
      highlightedPhrases.push({
        phrase: rawEmail,
        category: "Free Email Provider",
        severity: "high",
        explanation: "Corporate recruiters contacting from free email domains is one of the highest scam correlates."
      });
    } else {
      emailVerdict = 'unverified';
      emailAnalysis = `Sender address: ${rawEmail}. Verify whether this matches the verified corporate domain. Beware of hyphenated suffixes like -careers.com or -jobs.com.`;
      emailDetails.push('Verify DNS MX records and sender domain authenticity.');
      threatScore += 5;
    }
  }

  // Clamp threat score
  threatScore = Math.min(100, Math.max(5, threatScore));
  let riskLevel: 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (threatScore >= 80) riskLevel = 'CRITICAL';
  else if (threatScore >= 60) riskLevel = 'HIGH';
  else if (threatScore >= 40) riskLevel = 'MODERATE';
  else if (threatScore >= 20) riskLevel = 'LOW';
  else riskLevel = 'SAFE';

  return {
    threatIndex: threatScore,
    riskLevel,
    verdictTitle: threatScore >= 60 
      ? "High Probability Fake Offer / Phishing Scheme" 
      : threatScore >= 40 
      ? "Suspicious Communication with Warning Indicators" 
      : "Low Threat Detected — Exercise Standard Caution",
    summary: threatScore >= 60
      ? `This message exhibits multiple critical red flags common in recruitment fraud and phishing. Scammers frequently use premature job offers, unverified communication platforms, and advance-fee equipment check scams to defraud applicants.`
      : `The inspected content displays moderate to low threat markers. While obvious fraud patterns are limited, always independently cross-reference the sender and job posting on the company's verified careers portal.`,
    scamCategory: threatScore >= 60 ? "Fake Remote Job & Advance-Fee Equipment Fraud" : "Unverified Employment Communication",
    highlightedPhrases,
    urlFindings: {
      detectedUrl: urlOrDomain,
      verdict: urlVerdict,
      domainAnalysis: urlAnalysis,
      details: urlDetails
    },
    emailFindings: {
      detectedEmail: recruiterEmail,
      verdict: emailVerdict,
      domainAnalysis: emailAnalysis,
      details: emailDetails
    },
    actionPlan: {
      immediateSteps: [
        "Do NOT send any funds, gift cards, or cryptocurrency under any circumstances.",
        "Do NOT deposit checks mailed or emailed to you to buy 'workspace supplies'.",
        "Cease communication on informal apps like Telegram, WhatsApp, or Google Chat."
      ],
      safeVerificationSteps: [
        "Navigate directly to the official company website by typing their URL in a browser tab — never click links in the message.",
        "Locate their official 'Careers' page and confirm the exact job requisition ID exists.",
        "Contact the corporate HR switchboard or message the legitimate recruiter on LinkedIn to verify their outreach."
      ],
      whatNotToDo: [
        "Never share your Social Security Number, bank routing number, or passport scan prior to signed official contract via an accredited ATS.",
        "Never purchase hardware or software licenses through a 'designated vendor' portal provided by the sender."
      ],
      reportingChannels: [
        { name: "FTC Report Fraud", description: "Report recruitment and consumer fraud to the Federal Trade Commission.", url: "https://reportfraud.ftc.gov" },
        { name: "FBI Internet Crime Complaint Center (IC3)", description: "Submit reports on internet-facilitated fraud and wire schemes.", url: "https://www.ic3.gov" },
        { name: "Anti-Phishing Working Group (APWG)", description: "Global repository for phishing emails and malicious domains.", url: "https://apwg.org/reportphishing" }
      ]
    },
    indicators: indicators.length > 0 ? indicators : [
      { indicator: "General Message Tone", present: false, scoreImpact: 0, observation: "No overt scam keywords detected in general baseline scan." }
    ],
    analyzedAt: new Date().toISOString(),
    inputExcerpt: {
      textLength: messageText.length,
      hasUrl: Boolean(urlOrDomain),
      hasEmail: Boolean(recruiterEmail)
    }
  };
}

// API endpoint for threat scanning
app.post("/api/scan-threats", async (req, res) => {
  try {
    const { messageText, urlOrDomain, recruiterEmail } = req.body || {};

    if (!messageText || typeof messageText !== "string" || messageText.trim().length === 0) {
      return res.status(400).json({ error: "Please provide suspicious text, message, or offer letter to analyze." });
    }

    const ai = getGeminiClient();

    if (!ai) {
      // Fallback if API key is not configured in environment
      console.warn("GEMINI_API_KEY not configured. Running heuristic threat inspector.");
      const heuristicResult = performHeuristicAnalysis(messageText, urlOrDomain, recruiterEmail);
      return res.json(heuristicResult);
    }

    const prompt = `You are a cybersecurity expert and senior fraud investigator specializing in job scam detection, fake employment offers, spear-phishing, credential harvesting, and advance-fee schemes.

Analyze the following suspicious communication, email, offer letter, or chat transcript:

=================== SUSPICIOUS MESSAGE ===================
${messageText}
==========================================================
Optional Recruiter Email: ${recruiterEmail || "Not specified by user (check if present in message text)"}
Optional URL or Domain: ${urlOrDomain || "Not specified by user (check if present in message text)"}

Provide an exhaustive, accurate threat assessment.
Evaluate:
1. Threat Index (integer from 0 to 100, where 0 is 100% verified legitimate and safe, and 100 is a confirmed malicious phishing/fraud scam).
2. Risk Level: "SAFE" (0-19), "LOW" (20-39), "MODERATE" (40-59), "HIGH" (60-79), "CRITICAL" (80-100).
3. Verdict title: clear, punchy security judgment (e.g., "Critical Risk: Advance-Fee Fake Equipment Check Scam").
4. Summary: 2-4 sentences explaining the scam mechanism or legitimacy factors clearly.
5. Scam Category: precise category (e.g. "Fake Remote Job & Advance Fee Equipment Scam", "Credential Phishing / Account Takeover", "Crypto Task Scam", "Executive Impersonation (BEC)", "Check Overpayment Fraud", "Legitimate Employment Offer").
6. Highlighted Phrases: An array of specific suspicious phrases found verbatim in the user text. For each phrase, provide its exact quote, category (e.g. 'Financial Red Flag', 'Urgency Tactic', 'Communication Channel', 'PII Solicitation', 'Unrealistic Compensation'), severity ('high', 'medium', 'low'), and a crystal-clear explanation why it is a red flag.
7. URL Findings: evaluate any provided URL or URLs found in the text. Evaluate domain age flags, typo-squatting, free web hosting (e.g., forms.gle, typeform, free webflow), suspicious TLDs, and give actionable details.
8. Email Findings: evaluate any recruiter email provided or found. Check if they use public free mailboxes (@gmail, @yahoo, @hotmail) while claiming to represent a corporation, or lookalike domain names.
9. Action Plan: immediate steps, safe verification steps (how to check without tipping off or trusting the scammer), what NEVER to do, and relevant official reporting channels (like FTC, IC3, etc.).
10. Scam Indicators: structured breakdown of key risk factors (e.g. "Equipment Check Scheme", "Off-Platform Chat Interview", "Artificial Urgency", "Free Email Provider", "Sensitive PII Solicited") with presence boolean, score impact, and specific observation.`;

    // Wrap Gemini call in a 10-second timeout to guarantee fast responsiveness
    const geminiPromise = ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            threatIndex: { type: Type.INTEGER, description: "0 to 100 scam probability" },
            riskLevel: { type: Type.STRING, description: "SAFE, LOW, MODERATE, HIGH, CRITICAL" },
            verdictTitle: { type: Type.STRING },
            summary: { type: Type.STRING },
            scamCategory: { type: Type.STRING },
            highlightedPhrases: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  phrase: { type: Type.STRING, description: "Exact quote from text" },
                  category: { type: Type.STRING },
                  severity: { type: Type.STRING, description: "high, medium, or low" },
                  explanation: { type: Type.STRING }
                },
                required: ["phrase", "category", "severity", "explanation"]
              }
            },
            urlFindings: {
              type: Type.OBJECT,
              properties: {
                detectedUrl: { type: Type.STRING },
                verdict: { type: Type.STRING, description: "safe, suspicious, malicious, unverified, or none" },
                domainAnalysis: { type: Type.STRING },
                details: { type: Type.ARRAY, items: { type: Type.STRING } }
              },
              required: ["verdict", "domainAnalysis", "details"]
            },
            emailFindings: {
              type: Type.OBJECT,
              properties: {
                detectedEmail: { type: Type.STRING },
                verdict: { type: Type.STRING, description: "safe, suspicious, spoofed, unverified, or none" },
                domainAnalysis: { type: Type.STRING },
                details: { type: Type.ARRAY, items: { type: Type.STRING } }
              },
              required: ["verdict", "domainAnalysis", "details"]
            },
            actionPlan: {
              type: Type.OBJECT,
              properties: {
                immediateSteps: { type: Type.ARRAY, items: { type: Type.STRING } },
                safeVerificationSteps: { type: Type.ARRAY, items: { type: Type.STRING } },
                whatNotToDo: { type: Type.ARRAY, items: { type: Type.STRING } },
                reportingChannels: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      name: { type: Type.STRING },
                      description: { type: Type.STRING },
                      url: { type: Type.STRING }
                    },
                    required: ["name", "description", "url"]
                  }
                }
              },
              required: ["immediateSteps", "safeVerificationSteps", "whatNotToDo", "reportingChannels"]
            },
            indicators: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  indicator: { type: Type.STRING },
                  present: { type: Type.BOOLEAN },
                  scoreImpact: { type: Type.INTEGER },
                  observation: { type: Type.STRING }
                },
                required: ["indicator", "present", "scoreImpact", "observation"]
              }
            }
          },
          required: [
            "threatIndex",
            "riskLevel",
            "verdictTitle",
            "summary",
            "scamCategory",
            "highlightedPhrases",
            "urlFindings",
            "emailFindings",
            "actionPlan",
            "indicators"
          ]
        }
      }
    });

    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Gemini analysis timed out")), 9000)
    );

    const response: any = await Promise.race([geminiPromise, timeoutPromise]);

    const responseText = response.text;
    if (!responseText) {
      throw new Error("No response received from Gemini analysis engine.");
    }

    const parsedData = JSON.parse(responseText);

    const fullResult = {
      ...parsedData,
      analyzedAt: new Date().toISOString(),
      inputExcerpt: {
        textLength: messageText.length,
        hasUrl: Boolean(urlOrDomain),
        hasEmail: Boolean(recruiterEmail)
      }
    };

    return res.json(fullResult);
  } catch (error: any) {
    console.error("Gemini Threat Scan Error:", error);
    // If Gemini fails or times out, seamlessly return a detailed heuristic evaluation so user experience is rock solid
    const { messageText, urlOrDomain, recruiterEmail } = req.body || {};
    if (messageText) {
      const fallback = performHeuristicAnalysis(messageText, urlOrDomain, recruiterEmail);
      return res.json(fallback);
    }
    return res.status(500).json({ error: error?.message || "Failed to analyze message threats." });
  }
});

// Health check endpoint
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString()
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`ScamShield AI Server running on http://localhost:${PORT}`);
  });
}

startServer();
