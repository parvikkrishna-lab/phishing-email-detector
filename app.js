// ── Demo emails ──────────────────────────────────────────────
const DEMOS = [
  {
    sender:  "security@secure-bankofamerica-alert.com",
    subject: "URGENT: Your Account Has Been Suspended",
    body:    "Dear Valued Customer,\n\nWe have detected unusual activity on your account. Your account will be terminated within 24 hours unless you verify your credentials immediately.\n\nClick here to verify your account: http://192.168.1.54/verify\n\nPlease provide your username, password, and credit card number to confirm your identity.\n\nRegards,\nBank of America Security Team"
  },
  {
    sender:  "winner@lottery-claims.tk",
    subject: "Congratulations! You Have Won $1,000,000",
    body:    "Dear Friend,\n\nCongratulations! You have been selected as the winner of our international lottery. You have won the sum of $1,000,000. Kindly revert at the earliest to claim your prize.\n\nPlease provide your full name, address, bank account details and date of birth to process the transfer.\n\nDo the needful and respond immediately.\n\nBest Regards,\nDr. James Wilson\nLottery Commission"
  },
  {
    sender:  "newsletter@github.com",
    subject: "GitHub Digest: What's new this week",
    body:    "Hi Alex,\n\nHere's what's been happening on GitHub this week. New features include improved code search, pull request summaries, and expanded Copilot support.\n\nCheck out the changelog for details: https://github.com/changelog\n\nHappy coding!\n\nThe GitHub Team"
  }
];

// ── Detection patterns ────────────────────────────────────────
const PATTERNS = {
  urgent: [
    /\bact now\b/i,
    /\bimmediate(ly)?\b/i,
    /\burgent\b/i,
    /\bcritical\b/i,
    /\byour account (has been|will be) (suspended|closed|terminated|limited)\b/i,
    /\bverify (your|account|information) (now|immediately|within \d+)\b/i,
    /\b(last|final) (warning|notice|chance|attempt)\b/i,
    /\bwithin \d+ (hours?|days?|minutes?)\b/i,
    /\baction required\b/i
  ],
  reward: [
    /\bcongratulations\b/i,
    /\byou('ve| have) (won|been selected|been chosen)\b/i,
    /\bfree (gift|prize|reward|iphone|cash|money)\b/i,
    /\bclaim (your|the) (prize|reward|gift|money)\b/i,
    /\b\$\d[\d,]*\b/,
    /\blottery\b/i,
    /\binheritance\b/i,
    /\bmillion(s)?\b/i
  ],
  threat: [
    /\baccount (will be|has been) (suspended|terminated|closed|blocked|frozen)\b/i,
    /\bunusual (activity|sign-in|login|access)\b/i,
    /\bsuspicious (activity|login|access|transaction)\b/i,
    /\bunauthorized (access|login|transaction)\b/i,
    /\byour password (has|has been) (expired|compromised)\b/i
  ],
  cred: [
    /\b(enter|confirm|provide|update|verify) your (password|username|credentials|credit card|ssn|social security)\b/i,
    /\bclick (here|the link|below) to (verify|confirm|update|login|sign in)\b/i,
    /\bsign in to (confirm|verify|secure)\b/i,
    /\bupdate (your|billing|payment|account) (information|details|info)\b/i
  ],
  urls: [
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /https?:\/\/[^\s]*\.(tk|ml|ga|cf|gq|xyz|top|click|loan)\b/i,
    /bit\.ly|tinyurl\.com|t\.co|goo\.gl/i,
    /https?:\/\/[^\s]*-(paypal|amazon|apple|google|microsoft|netflix|facebook|bankof)[^\s]*\./i
  ],
  grammar: [
    /\bdear (valued|esteemed|beloved|respected) (customer|user|member|client|friend)\b/i,
    /\bdear (sir|madam|account holder)\b/i,
    /\bkindly (do|click|verify|update|provide)\b/i,
    /\bdo the needful\b/i,
    /\brevert (back)? (at the earliest|immediately|asap)\b/i
  ],
  spoofed: [
    /noreply@[a-z0-9-]+\.(tk|ml|ga|cf|xyz|top)\b/i,
    /(paypal|amazon|apple|google|microsoft|netflix|facebook)\.[a-z0-9-]+\.[a-z]{2,}\b/i
  ],
  attach: [
    /\.(exe|vbs|bat|cmd|scr|pif|jar|ps1)\b/i,
    /open (the )?attachment/i,
    /download (the )?(file|document|invoice)/i
  ]
};

// Rule definitions: which pattern group, label, score, and which field to scan
const RULES = [
  { key: "urgent",  label: "Urgency / pressure tactic",      score: 20, field: "full"   },
  { key: "reward",  label: "Reward / lottery lure",           score: 25, field: "full"   },
  { key: "threat",  label: "Account threat",                  score: 20, field: "full"   },
  { key: "cred",    label: "Credential / info request",       score: 30, field: "full"   },
  { key: "urls",    label: "Suspicious URL",                  score: 35, field: "full"   },
  { key: "grammar", label: "Unusual phrasing / grammar",      score: 10, field: "full"   },
  { key: "spoofed", label: "Spoofed sender domain",           score: 25, field: "sender" },
  { key: "attach",  label: "Dangerous attachment reference",  score: 30, field: "full"   }
];

// ── Helpers ───────────────────────────────────────────────────

/**
 * Returns a short snippet of surrounding text where the regex matches,
 * or null if there is no match.
 */
function getSnippet(text, regex) {
  const match = text.match(regex);
  if (!match) return null;
  const idx   = text.indexOf(match[0]);
  const start = Math.max(0, idx - 15);
  const end   = Math.min(text.length, idx + match[0].length + 15);
  return "…" + text.slice(start, end).replace(/\n/g, " ").trim() + "…";
}

/** Returns the meter-fill colour for a given risk class. */
function meterColor(cls) {
  return { high: "#E24B4A", medium: "#EF9F27", low: "#c8c800", safe: "#1D9E75" }[cls];
}

/** Returns the finding-score text colour for a given risk class. */
function scoreColor(cls) {
  return { high: "#a32d2d", medium: "#854f0b", low: "#6b6b00", safe: "#3b6d11" }[cls];
}

// ── Core analysis function ────────────────────────────────────

/**
 * Runs all detection rules against the provided email fields.
 * Returns { total, level, cls, verdict, findings }.
 */
function analyze(subject, sender, body) {
  const full     = `${subject} ${sender} ${body}`;
  const findings = [];
  let   total    = 0;

  // Pattern-based rules
  for (const rule of RULES) {
    const text = rule.field === "sender" ? sender : full;
    for (const pattern of PATTERNS[rule.key]) {
      const snippet = getSnippet(text, pattern);
      if (snippet) {
        findings.push({ category: rule.label, detail: snippet, score: rule.score });
        total += rule.score;
        break; // one hit per rule is enough
      }
    }
  }

  // Generic salutation check
  const generic = /\bdear (customer|user|member|client|account holder|valued customer)\b/i.exec(full);
  if (generic) {
    findings.push({ category: "Generic salutation", detail: generic[0], score: 10 });
    total += 10;
  }

  // ALL-CAPS subject check
  const capsRatio = [...subject].filter(c => c >= "A" && c <= "Z").length / Math.max(subject.length, 1);
  if (capsRatio > 0.5 && subject.length > 6) {
    findings.push({ category: "ALL-CAPS subject line", detail: subject.slice(0, 50), score: 10 });
    total += 10;
  }

  // Determine risk level
  let level, cls, verdict;
  if (total >= 70) {
    level   = "HIGH RISK";
    cls     = "high";
    verdict = "Very likely phishing. Do not click any links or provide information.";
  } else if (total >= 40) {
    level   = "MEDIUM RISK";
    cls     = "medium";
    verdict = "Suspicious email. Verify through official channels before acting.";
  } else if (total >= 15) {
    level   = "LOW RISK";
    cls     = "low";
    verdict = "Some suspicious elements present. Proceed carefully.";
  } else {
    level   = "SAFE";
    cls     = "safe";
    verdict = "No major phishing indicators detected.";
  }

  return { total, level, cls, verdict, findings };
}

// ── DOM rendering ─────────────────────────────────────────────

/** Renders the analysis result card into #result-area. */
function renderResult(result) {
  const pct = Math.min(100, Math.round(result.total / 1.2));
  const col = scoreColor(result.cls);

  const findingsHtml = result.findings.length
    ? result.findings.map(f => `
        <div class="finding">
          <div class="finding-score" style="color:${col}">+${f.score}</div>
          <div>
            <div class="finding-cat">${f.category}</div>
            <div class="finding-detail">${f.detail}</div>
          </div>
        </div>`
      ).join("")
    : `<p style="font-size:14px;color:var(--text-muted);padding:8px 0">
         No suspicious indicators found.
       </p>`;

  document.getElementById("result-area").innerHTML = `
    <div class="result-card ${result.cls}">

      <div class="result-header">
        <div>
          <div class="result-header-title">Analysis result</div>
          <div class="score-text">Score: <strong>${result.total}</strong> point${result.total !== 1 ? "s" : ""}</div>
        </div>
        <span class="risk-badge">${result.level}</span>
      </div>

      <div class="meter-bar">
        <div class="meter-fill" style="width:${pct}%; background:${meterColor(result.cls)}"></div>
      </div>

      <div class="verdict">${result.verdict}</div>

      <div class="findings-section">
        <div class="findings-title">FINDINGS (${result.findings.length})</div>
        ${findingsHtml}
      </div>

    </div>`;
}

// ── UI actions ────────────────────────────────────────────────

/** Loads a demo email into the form and runs analysis. */
function loadDemo(index) {
  const demo = DEMOS[index];
  document.getElementById("sender").value  = demo.sender;
  document.getElementById("subject").value = demo.subject;
  document.getElementById("body").value    = demo.body;
  runAnalysis();
}

/** Reads the form, runs analysis, and renders the result. */
function runAnalysis() {
  const sender  = document.getElementById("sender").value.trim();
  const subject = document.getElementById("subject").value.trim();
  const body    = document.getElementById("body").value.trim();

  if (!sender && !subject && !body) {
    document.getElementById("result-area").innerHTML = `
      <div class="empty">
        <i class="ti ti-inbox"></i>
        Enter email details above to scan.
      </div>`;
    return;
  }

  const result = analyze(subject, sender, body);
  renderResult(result);
}

/** Clears the form and result area. */
function clearAll() {
  ["sender", "subject", "body"].forEach(id => {
    document.getElementById(id).value = "";
  });
  document.getElementById("result-area").innerHTML = "";
}