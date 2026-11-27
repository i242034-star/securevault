// Build SecureVault presentation deck (pptxgenjs, structured: theme + layouts + sections)
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");

const SKILL = process.argv[2];
const OUT = process.argv[3];
const { applyTheme } = require(path.join(SKILL, "scripts", "apply_theme.js"));

const HEX = {
  ink: "0F172A", white: "FFFFFF", deep: "134E4A", mist: "F1F5F9",
  teal: "0D9488", amber: "F59E0B", red: "DC2626", green: "16A34A",
  slate: "64748B", night: "1E293B",
};
const THEME = {
  name: "SecureVault Ink",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: HEX.ink, lt1: HEX.white, dk2: HEX.deep, lt2: HEX.mist,
    accent1: HEX.teal, accent2: HEX.amber, accent3: HEX.red, accent4: HEX.green,
    accent5: HEX.slate, accent6: HEX.night, hlink: HEX.teal, folHlink: HEX.slate,
  },
};

async function icon(Comp, color = "#FFFFFF", size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color, size }));
  const buf = await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_16x9"; // 10 x 5.625
  pres.title = "SecureVault: CP-ABE Document Locker";
  pres.author = "Abdullah Khan, Syed Ali Zaidi, Maryam Imran";
  pres.subject = "CS-3002 Information Security - Topic 12";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  const C = pres.SchemeColor;

  // ---------------- Layouts ----------------
  pres.defineSlideMaster({
    title: "TITLE_DARK",
    background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 1.55, w: 8.8, h: 1.1, fontSize: 48, bold: true, color: C.background1, align: "left", valign: "bottom", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: 0.6, y: 2.75, w: 8.8, h: 0.9, fontSize: 20, color: C.accent1, align: "left", valign: "top", margin: 0 }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "CONTENT",
    background: { color: C.background1 },
    margin: [0.5, 0.5, 0.5, 0.5],
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.3, w: 9.0, h: 0.75, fontSize: 30, bold: true, color: C.text1, align: "left", valign: "middle", margin: 0 }, text: "" } },
      { text: { text: "SecureVault  ·  CS-3002 Topic 12", options: { x: 0.5, y: 5.2, w: 5, h: 0.3, fontSize: 10, color: C.accent5, margin: 0, isTextBox: true } } },
    ],
    slideNumber: { x: 9.0, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent5, align: "right" },
  });
  pres.defineSlideMaster({
    title: "CLOSING_DARK",
    background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.3, w: 9.0, h: 0.75, fontSize: 30, bold: true, color: C.background1, align: "left", valign: "middle", margin: 0 }, text: "" } },
    ],
    slideNumber: { x: 9.0, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent5, align: "right" },
  });

  // ---------------- Icons ----------------
  const I = {};
  const iconSpecs = {
    lock: fa.FaLock, db: fa.FaDatabase, admin: fa.FaUserSecret, users: fa.FaUsers, key: fa.FaKey,
    shield: fa.FaShieldAlt, merge: fa.FaRandom, pen: fa.FaPenFancy, bolt: fa.FaBolt, history: fa.FaHistory,
    clock: fa.FaStopwatch, userlock: fa.FaUserLock, cloud: fa.FaCloud, server: fa.FaServer,
    desktop: fa.FaDesktop, file: fa.FaFileAlt, flask: fa.FaFlask, check: fa.FaCheck, times: fa.FaTimes,
    bug: fa.FaBug, play: fa.FaPlay,
  };
  for (const [k, Comp] of Object.entries(iconSpecs)) I[k] = await icon(Comp);

  // Motif: white icon inside a filled circle
  function circleIcon(slide, img, x, y, d, fill, name) {
    slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill }, objectName: name + " circle" });
    const pad = d * 0.27;
    slide.addImage({ data: img, x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad, objectName: name + " icon", altText: name });
  }
  const card = (slide, x, y, w, h, fill, name) =>
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: { color: fill }, objectName: name });
  const T = (slide, text, opts) => slide.addText(text, Object.assign({ isTextBox: true, margin: 0, valign: "top" }, opts));

  // =========================================================
  // 1. Title
  // =========================================================
  pres.addSection({ title: "Opening" });
  let s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "Opening" });
  s.addText("SecureVault", { placeholder: "title" });
  s.addText("Fine-grained access control with Ciphertext-Policy Attribute-Based Encryption", { placeholder: "body" });
  circleIcon(s, I.lock, 0.6, 0.55, 0.85, C.accent1, "Vault");
  T(s, "Abdullah Khan  ·  Syed Ali Zaidi  ·  Maryam Imran", { x: 0.6, y: 4.3, w: 8.8, h: 0.35, fontSize: 16, color: C.background1 });
  T(s, "CS-3002 Information Security  ·  Topic 12  ·  November 2026", { x: 0.6, y: 4.7, w: 8.8, h: 0.3, fontSize: 12, color: C.accent5 });
  s.addNotes("Open with the one-line idea: in SecureVault the file itself carries its access rule, and the maths decides who can open it, not the server. Introduce the team and who will cover which part (core crypto, app/architecture, security evaluation).");

  // =========================================================
  // 2. Problem
  // =========================================================
  pres.addSection({ title: "Problem & idea" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Problem & idea" });
  s.addText("Today the server decides who reads a file", { placeholder: "title" });
  const probs = [
    [I.db, "Stolen database or backup", "Access checks live in code; the data on disk is readable by whoever holds it."],
    [I.admin, "Curious or rogue admin", "Whoever runs the server can bypass every role check."],
    [I.users, "Groups don't fit PKI", "One file for N readers means N encrypted copies or one shared key."],
  ];
  probs.forEach(([img, h, d], i) => {
    const y = 1.35 + i * 1.15;
    circleIcon(s, img, 0.5, y, 0.7, C.accent1, h);
    T(s, h, { x: 1.4, y: y - 0.02, w: 4.0, h: 0.35, fontSize: 17, bold: true, color: C.text1 });
    T(s, d, { x: 1.4, y: y + 0.36, w: 4.0, h: 0.6, fontSize: 14, color: C.accent5 });
  });
  card(s, 5.8, 1.35, 3.7, 3.4, C.text1, "Goal card");
  T(s, "OUR GOAL", { x: 6.1, y: 1.6, w: 3.1, h: 0.3, fontSize: 12, bold: true, color: C.accent2, charSpacing: 2 });
  T(s, "Encrypt each file under its access rule, so only matching credentials can decrypt it", { x: 6.1, y: 1.95, w: 3.1, h: 1.2, fontSize: 16, color: C.background1 });
  T(s, "(Role:Engineer OR Role:Manager)\nAND Clearance:Level-3", { x: 6.1, y: 3.4, w: 3.1, h: 0.9, fontSize: 14, color: C.accent1, fontFace: "Courier New", bold: true });
  s.addNotes("Explain why RBAC is not enough: it is a software check over data that is stored in a readable form. Then show the project's required policy on the right. Everything in the talk is about enforcing that one line cryptographically.");

  // =========================================================
  // 3. Policy in ciphertext, attributes in key
  // =========================================================
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Problem & idea" });
  s.addText("Policy lives in the file, attributes live in the key", { placeholder: "title" });
  // Policy tree
  const node = (x, y, w, txt, fill, fc, name) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 0.5, rectRadius: 0.08, fill: { color: fill }, line: { color: fill }, objectName: name });
    T(s, txt, { x, y, w, h: 0.5, fontSize: 14, bold: true, color: fc, align: "center", valign: "middle" });
  };
  const line = (x1, y1, x2, y2, n) => s.addShape(pres.shapes.LINE, { x: Math.min(x1, x2), y: y1, w: Math.abs(x2 - x1) || 0.001, h: y2 - y1, flipH: x2 < x1, line: { color: C.accent5, width: 1.5 }, objectName: n });
  line(2.45, 1.85, 1.45, 2.65, "edge AND-OR");
  line(2.45, 1.85, 3.55, 2.65, "edge AND-L3");
  line(1.45, 3.15, 0.95, 3.85, "edge OR-Eng");
  line(1.45, 3.15, 2.05, 3.85, "edge OR-Mgr");
  node(1.85, 1.35, 1.2, "AND", C.text1, C.background1, "AND gate");
  node(0.95, 2.65, 1.0, "OR", C.text1, C.background1, "OR gate");
  node(2.95, 2.65, 1.3, "Level-3", C.accent1, C.background1, "Leaf Level-3");
  node(0.45, 3.85, 1.05, "Engineer", C.accent1, C.background1, "Leaf Engineer");
  node(1.6, 3.85, 1.05, "Manager", C.accent1, C.background1, "Leaf Manager");
  T(s, "Access tree embedded in every ciphertext", { x: 0.45, y: 4.55, w: 4.0, h: 0.3, fontSize: 12, italic: true, color: C.accent5 });
  // Persona matrix
  const people = [
    ["Alice", "Engineer · Level-3", true],
    ["Charlie", "Manager · Level-3", true],
    ["Bob", "Student · Level-3", false],
    ["David", "Engineer · Level-2", false],
  ];
  T(s, "Each key carries its owner's attributes", { x: 5.0, y: 1.3, w: 4.5, h: 0.35, fontSize: 15, bold: true, color: C.text1 });
  people.forEach(([n, a, ok], i) => {
    const y = 1.8 + i * 0.68;
    card(s, 5.0, y, 4.5, 0.56, C.background2, n + " row");
    T(s, n, { x: 5.2, y, w: 1.0, h: 0.56, fontSize: 15, bold: true, color: C.text1, valign: "middle" });
    T(s, a, { x: 6.2, y, w: 1.9, h: 0.56, fontSize: 14, color: C.accent5, valign: "middle" });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 8.15, y: y + 0.11, w: 1.2, h: 0.34, rectRadius: 0.08, fill: { color: ok ? C.accent4 : C.accent3 }, line: { color: ok ? C.accent4 : C.accent3 }, objectName: n + " verdict" });
    T(s, ok ? "OPENS" : "DENIED", { x: 8.15, y: y + 0.11, w: 1.2, h: 0.34, fontSize: 12, bold: true, color: C.background1, align: "center", valign: "middle" });
  });
  s.addNotes("Walk the tree: AND at the root, OR over the two roles, and the clearance leaf. Then run each persona through it. Bob fails the OR branch, David fails the clearance leaf. Emphasise: the server never evaluates this tree to grant access; decryption simply fails for Bob and David.");

  // =========================================================
  // 4. BSW07
  // =========================================================
  pres.addSection({ title: "How it works" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "How it works" });
  s.addText("BSW07 CP-ABE in four algorithms", { placeholder: "title" });
  const algs = [
    ["1", "Setup", "Authority creates public key PK and master key MK", "once"],
    ["2", "KeyGen", "MK + attributes → private key, blinded by a random r", "per user"],
    ["3", "Encrypt", "PK + message + policy → ciphertext with secret shares", "per file"],
    ["4", "Decrypt", "Pairings recombine shares only if the attributes satisfy the policy", "per read"],
  ];
  algs.forEach(([n, h, d, f], i) => {
    const x = 0.5 + i * 2.32;
    card(s, x, 1.35, 2.1, 2.75, C.background2, h + " card");
    circleIcon(s, I.key, x + 0.2, 1.55, 0.55, C.accent1, h);
    T(s, n, { x: x + 1.5, y: 1.55, w: 0.45, h: 0.55, fontSize: 26, bold: true, color: C.accent1, align: "right", valign: "middle" });
    T(s, h, { x: x + 0.2, y: 2.25, w: 1.75, h: 0.4, fontSize: 18, bold: true, color: C.text1 });
    T(s, d, { x: x + 0.2, y: 2.68, w: 1.75, h: 1.1, fontSize: 14, color: C.text1 });
    T(s, f, { x: x + 0.2, y: 3.75, w: 1.75, h: 0.3, fontSize: 12, italic: true, color: C.accent5 });
  });
  card(s, 0.5, 4.3, 8.98, 0.7, C.text1, "Collusion callout");
  T(s, [
    { text: "Why users can't pool keys: ", options: { bold: true, color: C.accent2 } },
    { text: "every component of a key shares that user's random r, so pieces from two users never cancel out.", options: { color: C.background1 } },
  ], { x: 0.75, y: 4.3, w: 8.5, h: 0.7, fontSize: 14, valign: "middle" });
  s.addNotes("Implemented with Charm-Crypto's CPabe_BSW07 over the BN254 pairing curve; we did not write any primitive ourselves. Key point for Q&A: decryption computes e(g,g)^(r*s) via Lagrange interpolation; the r is unique per user, which is exactly why collusion fails. BN254 is about 100-bit security today.");

  // =========================================================
  // 5. Hybrid
  // =========================================================
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "How it works" });
  s.addText("ABE locks the key, AES-GCM locks the file", { placeholder: "title" });
  const step = (x, y, w, txt, fill, fc, n) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 0.62, rectRadius: 0.08, fill: { color: fill }, line: { color: fill }, objectName: n });
    T(s, txt, { x: x + 0.08, y, w: w - 0.16, h: 0.62, fontSize: 14, bold: true, color: fc, align: "center", valign: "middle" });
  };
  const arrow = (x, y, w, n) => s.addShape(pres.shapes.RIGHT_ARROW, { x, y, w, h: 0.3, fill: { color: C.accent5 }, line: { color: C.accent5 }, objectName: n });
  T(s, "KEY LANE", { x: 0.5, y: 1.3, w: 3, h: 0.3, fontSize: 12, bold: true, color: C.accent1, charSpacing: 2 });
  step(0.5, 1.65, 1.9, "Random element M", C.background2, C.text1, "M");
  arrow(2.5, 1.81, 0.45, "arrow1");
  step(3.05, 1.65, 2.6, "CP-ABE encrypt under policy", C.accent1, C.background1, "ABE");
  arrow(5.75, 1.81, 0.45, "arrow2");
  step(6.3, 1.65, 3.18, "Ciphertext CT (~1 KB)", C.text1, C.background1, "CT");
  T(s, "DATA LANE", { x: 0.5, y: 2.55, w: 3, h: 0.3, fontSize: 12, bold: true, color: C.accent1, charSpacing: 2 });
  step(0.5, 2.9, 1.9, "Key = SHA-256(M)", C.background2, C.text1, "K");
  arrow(2.5, 3.06, 0.45, "arrow3");
  step(3.05, 2.9, 2.6, "AES-256-GCM encrypt file", C.accent1, C.background1, "AES");
  arrow(5.75, 3.06, 0.45, "arrow4");
  step(6.3, 2.9, 3.18, "Ciphertext + nonce + 128-bit tag", C.text1, C.background1, "Blob");
  const stats = [["28 ms", "encrypt 1 MB"], ["154 ms", "authorized decrypt"], ["0", "plaintext bytes stored"]];
  stats.forEach(([v, l], i) => {
    const x = 0.5 + i * 3.05;
    T(s, v, { x, y: 3.8, w: 2.9, h: 0.75, fontSize: 36, bold: true, color: C.text1, fontFace: "Cambria" });
    T(s, l, { x, y: 4.55, w: 2.9, h: 0.35, fontSize: 13, color: C.accent5 });
  });
  s.addNotes("Pairings can only encrypt a group element, not a 5 MB PDF, so we use KEM/DEM. CP-ABE protects a random element M; its hash becomes the AES-256 key; AES-GCM encrypts the document and adds an authentication tag, so tampering is detected. Encryption time is almost flat in file size because the ABE step dominates.");

  // =========================================================
  // 6. Architecture
  // =========================================================
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "How it works" });
  s.addText("Three tiers, one trusted authority", { placeholder: "title" });
  const cols = [
    [I.desktop, "Browser", "React 19 + Vite on Vercel", ["Login, Locker, Attack Lab", "Admin and audit pages", "Guided walkthrough"], C.background2, C.text1],
    [I.server, "API + Authority", "Flask on Render (Docker)", ["BSW07 via Charm-Crypto", "AES-GCM, PBKDF2 key store", "HMAC audit chain"], C.text1, C.background1],
    [I.db, "Untrusted storage", "SQLite + encrypted blobs", ["Only ciphertext on disk", "Keys wrapped per user", "Master key wrapped too"], C.background2, C.text1],
  ];
  cols.forEach(([img, h, sub, items, fill, fc], i) => {
    const x = 0.5 + i * 3.1;
    card(s, x, 1.3, 2.8, 3.6, fill, h + " tier");
    circleIcon(s, img, x + 0.25, 1.5, 0.6, C.accent1, h);
    T(s, h, { x: x + 0.25, y: 2.2, w: 2.35, h: 0.4, fontSize: 17, bold: true, color: fc });
    T(s, sub, { x: x + 0.25, y: 2.6, w: 2.35, h: 0.35, fontSize: 12, italic: true, color: fill === C.text1 ? C.accent1 : C.accent5 });
    T(s, items.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < items.length - 1 } })),
      { x: x + 0.25, y: 3.05, w: 2.4, h: 1.7, fontSize: 14, color: fc, paraSpaceAfter: 6 });
    if (i < 2) s.addShape(pres.shapes.RIGHT_ARROW, { x: x + 2.83, y: 2.9, w: 0.24, h: 0.3, fill: { color: C.accent2 }, line: { color: C.accent2 }, objectName: "tier arrow " + i });
  });
  s.addNotes("Browser talks HTTPS + bearer token to the Flask API. The CryptoService is the Trusted Authority: it holds the master key in memory and issues user keys. Storage is treated as untrusted: steal it and you get ciphertext, password hashes and wrapped keys. Five REST blueprints: auth, documents, admin, audit, attacks.");

  // =========================================================
  // 7. Changing attributes & revocation
  // =========================================================
  pres.addSection({ title: "Key lifecycle" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Key lifecycle" });
  s.addText("Changing attributes and revoking keys", { placeholder: "title" });
  const lanes = [
    ["Attribute change", [["Admin sets David to Level-3", I.admin], ["Next login issues key v2", I.key], ["David can now decrypt", I.check]]],
    ["Revocation", [["Admin advances Epoch 1 → 2", I.history], ["Files re-encrypted with Epoch:2", I.lock], ["Old keys fail the pairing", I.times]]],
  ];
  lanes.forEach(([label, steps], li) => {
    const y = 1.3 + li * 1.9;
    T(s, label.toUpperCase(), { x: 0.5, y, w: 4, h: 0.3, fontSize: 12, bold: true, color: C.accent1, charSpacing: 2 });
    steps.forEach(([txt, img], si) => {
      const x = 0.5 + si * 3.1;
      if (si < steps.length - 1) {
        // connector between this circle and the next one only (never under text)
        s.addShape(pres.shapes.LINE, { x: x + 0.75, y: y + 0.7, w: 3.1 - 0.8, h: 0, line: { color: C.accent5, width: 1.5, dashType: "dash" }, objectName: label + " connector " + si });
      }
      circleIcon(s, img, x, y + 0.35, 0.7, si === 2 ? (li === 0 ? C.accent4 : C.accent3) : C.text1, label + " step " + si);
      T(s, txt, { x, y: y + 1.12, w: 2.8, h: 0.4, fontSize: 14, color: C.text1 });
    });
  });
  s.addNotes("Demo-friendly part of the brief: 'demonstrate how changing attributes play out'. Admins never see passwords; the user's own password wraps the new key on their next login. Revocation: Epoch is just another attribute in the policy, so advancing it and re-encrypting makes old keys mathematically useless, without regenerating the master key. Old plaintext already downloaded is out of scope.");

  // =========================================================
  // 8. Threat model
  // =========================================================
  pres.addSection({ title: "Security evaluation" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Security evaluation" });
  s.addText("Threat model: who we trust, and how far", { placeholder: "title" });
  const hdr = (t) => ({ text: t, options: { bold: true, color: HEX.white, fill: { color: HEX.ink } } });
  const rows = [
    [hdr("Party"), hdr("Trust"), hdr("Assumption")],
    ["Trusted Authority", "Full", "Issues keys honestly; holds the master key"],
    ["Server & storage", "Honest-but-curious", "Runs code correctly, may read or leak everything stored"],
    ["Admin", "Attributes only", "Never learns user passwords"],
    ["Users", "Malicious", "Collude, keep old keys, tamper with files"],
  ];
  s.addTable(rows, { x: 0.5, y: 1.3, w: 5.6, colW: [1.55, 1.5, 2.55], fontSize: 13, color: HEX.ink, border: { type: "solid", pt: 0.75, color: "CBD5E1" }, fill: { color: HEX.white }, valign: "middle", rowH: 0.55, margin: 0.06, objectName: "Trust table" });
  card(s, 6.4, 1.3, 3.1, 1.6, C.accent1, "Guarantees card");
  T(s, "GUARANTEED", { x: 6.6, y: 1.42, w: 2.7, h: 0.3, fontSize: 12, bold: true, color: C.background1, charSpacing: 2 });
  T(s, "Policy confidentiality · collusion resistance · tamper detection · revocation", { x: 6.6, y: 1.75, w: 2.75, h: 1.1, fontSize: 14, color: C.background1 });
  card(s, 6.4, 3.1, 3.1, 1.6, C.text1, "Out of scope card");
  T(s, "OUT OF SCOPE", { x: 6.6, y: 3.22, w: 2.7, h: 0.3, fontSize: 12, bold: true, color: C.accent2, charSpacing: 2 });
  T(s, "Takeover of the running authority; plaintext a user already downloaded", { x: 6.6, y: 3.55, w: 2.75, h: 1.1, fontSize: 14, color: C.background1 });
  s.addNotes("Be explicit and honest; examiners like a clear boundary. Storage compromise is covered: an attacker gets ciphertext and wrapped keys. A live compromise of the authority process is not: it holds MK in RAM, which in production would live in an HSM or KMS. Decryption is server-side, so the server sees plaintext transiently.");

  // =========================================================
  // 9. Attack Lab
  // =========================================================
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Security evaluation" });
  s.addText("Attack Lab: six real attacks, six blocked", { placeholder: "title" });
  const attacks = [
    [I.merge, "Collusion", "Bob + David merge keys", "Pairing mismatch"],
    [I.pen, "Policy tampering", "Edit policy to Role:Student", "Pairing mismatch"],
    [I.bolt, "Bit-flip", "Flip 1 bit in file or tag", "4 / 4 detected"],
    [I.history, "Revoked key", "Reuse Epoch-1 key", "Denied"],
    [I.userlock, "Brute force", "Dictionary attack on login", "Locked after 5"],
    [I.clock, "Timing leak", "Probe for valid usernames", "Gap 26 → 0.6 ms"],
  ];
  attacks.forEach(([img, h, d, r], i) => {
    const x = 0.5 + (i % 3) * 3.05, y = 1.3 + Math.floor(i / 3) * 1.85;
    card(s, x, y, 2.85, 1.65, C.background2, h + " card");
    circleIcon(s, img, x + 0.2, y + 0.2, 0.55, C.text1, h);
    T(s, h, { x: x + 0.9, y: y + 0.2, w: 1.85, h: 0.55, fontSize: 16, bold: true, color: C.text1, valign: "middle" });
    T(s, d, { x: x + 0.2, y: y + 0.85, w: 2.5, h: 0.35, fontSize: 14, color: C.accent5 });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + 0.2, y: y + 1.2, w: 2.45, h: 0.32, rectRadius: 0.08, fill: { color: C.accent4 }, line: { color: C.accent4 }, objectName: h + " result" });
    T(s, "BLOCKED · " + r, { x: x + 0.2, y: y + 1.2, w: 2.45, h: 0.32, fontSize: 12, bold: true, color: C.background1, align: "center", valign: "middle" });
  });
  s.addNotes("Live in the app under Attack Lab, any user can press Run all. Every attack runs real Charm/AES/PBKDF2 code against a throw-away sandbox authority, so no real keys are touched, and each run is logged in the audit chain. Collusion is the ABE-specific one to explain: the merged key has the right labels but the wrong randomness.");

  // =========================================================
  // 10. Found & fixed
  // =========================================================
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Security evaluation" });
  s.addText("What our own security review caught", { placeholder: "title" });
  T(s, "BEFORE", { x: 1.15, y: 1.25, w: 3.6, h: 0.3, fontSize: 12, bold: true, color: C.accent3, charSpacing: 2 });
  T(s, "AFTER", { x: 5.45, y: 1.25, w: 4.0, h: 0.3, fontSize: 12, bold: true, color: C.accent4, charSpacing: 2 });
  const fixes = [
    ["Anyone could self-register as admin with Level-3", "Only the authority enrols users"],
    ["Forged key crashed decrypt with HTTP 500", "Classified and returned as 403 Access Denied"],
    ["Unlimited login guesses", "Lockout after 5 failures, HTTP 429"],
    ["Unknown usernames answered 26 ms faster", "Same PBKDF2 work on every path"],
  ];
  fixes.forEach(([b, a], i) => {
    const y = 1.62 + i * 0.85;
    circleIcon(s, I.bug, 0.5, y + 0.06, 0.5, C.accent3, "Issue " + i);
    card(s, 1.15, y, 3.9, 0.66, C.background2, "Before " + i);
    T(s, b, { x: 1.3, y, w: 3.65, h: 0.66, fontSize: 14, color: C.text1, valign: "middle" });
    s.addShape(pres.shapes.RIGHT_ARROW, { x: 5.1, y: y + 0.18, w: 0.3, h: 0.3, fill: { color: C.accent5 }, line: { color: C.accent5 }, objectName: "fix arrow " + i });
    card(s, 5.45, y, 4.05, 0.66, C.text1, "After " + i);
    T(s, a, { x: 5.6, y, w: 3.8, h: 0.66, fontSize: 14, color: C.background1, valign: "middle" });
  });
  s.addNotes("The first one is the most important: open sign-up let a user pick their own attributes, which makes the whole policy meaningless. An attribute authority must vet attributes. The second we found while building the collusion attack: Charm 0.63 throws InvalidCiphertext for forged keys and our code didn't catch it.");

  // =========================================================
  // 11. Performance & trade-offs
  // =========================================================
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Security evaluation" });
  s.addText("Security costs milliseconds, not seconds", { placeholder: "title" });
  s.addChart(pres.charts.BAR, [{
    name: "Latency (ms)",
    labels: ["Denied decrypt", "KeyGen (2 attrs)", "PBKDF2 key unwrap", "Encrypt 1 MB", "Authorized decrypt"],
    values: [2.4, 5.0, 13.0, 28.5, 154.4],
  }], {
    x: 0.5, y: 1.25, w: 5.4, h: 3.75, barDir: "bar",
    chartColors: [HEX.teal], showValue: true, dataLabelPosition: "outEnd", dataLabelColor: HEX.ink, dataLabelFontSize: 11, dataLabelFontFace: "+mn-lt",
    showTitle: true, title: "Measured latency (ms, mean of 5)", titleFontSize: 13, titleColor: HEX.ink, titleFontFace: "+mn-lt",
    catAxisLabelColor: HEX.slate, catAxisLabelFontSize: 11, catAxisLabelFontFace: "+mn-lt",
    valAxisLabelColor: HEX.slate, valAxisLabelFontSize: 10, valAxisLabelFontFace: "+mn-lt", valAxisMaxVal: 180,
    valGridLine: { color: "E2E8F0", size: 0.5 }, catGridLine: { style: "none" }, showLegend: false, objectName: "Latency chart",
  });
  const tradeoffs = [
    ["PBKDF2 100k", "6× more iterations = 6× harder cracking, +65 ms per login"],
    ["Richer policies", "Decrypt time grows with every attribute leaf"],
    ["Real revocation", "Re-encrypt each file (~0.2 s) and reissue keys"],
  ];
  tradeoffs.forEach(([h, d], i) => {
    const y = 1.3 + i * 1.2;
    T(s, h, { x: 6.2, y, w: 3.3, h: 0.35, fontSize: 16, bold: true, color: C.text1 });
    T(s, d, { x: 6.2, y: y + 0.36, w: 3.3, h: 0.7, fontSize: 14, color: C.accent5 });
  });
  s.addNotes("Numbers are from tests/benchmark_performance.py on our laptop under WSL. Decryption is the slowest because of pairings plus the integrity check. Denied decryption is fast because Charm prunes the tree before doing any pairing; that reveals nothing the user doesn't already learn from the denial. Trade-offs: PBKDF2 iterations, policy size, and the operational cost of revocation.");

  // =========================================================
  // 12. Demo
  // =========================================================
  pres.addSection({ title: "Demo & close" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Demo & close" });
  s.addText("Live demo", { placeholder: "title" });
  const demo = [
    ["alice", "opens the confidential file", C.accent4],
    ["david", "same file → Access Denied (Level-2)", C.accent3],
    ["admin", "raises David to Level-3", C.text1],
    ["david", "logs in again → key v2 → file opens", C.accent4],
    ["anyone", "Attack Lab → Run all → 6 / 6 blocked", C.accent1],
  ];
  demo.forEach(([who, what, col], i) => {
    const y = 1.3 + i * 0.72;
    s.addShape(pres.shapes.OVAL, { x: 0.5, y, w: 0.52, h: 0.52, fill: { color: col }, line: { color: col }, objectName: "Demo step " + (i + 1) });
    T(s, String(i + 1), { x: 0.5, y, w: 0.52, h: 0.52, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
    T(s, [{ text: who + "  ", options: { bold: true, color: C.text1, fontFace: "Courier New" } }, { text: what, options: { color: C.text1 } }],
      { x: 1.2, y, w: 5.2, h: 0.52, fontSize: 16, valign: "middle" });
  });
  card(s, 6.7, 1.3, 2.8, 3.4, C.background2, "Credentials card");
  circleIcon(s, I.play, 6.95, 1.5, 0.55, C.accent1, "Demo");
  T(s, "Demo passwords", { x: 6.95, y: 2.2, w: 2.4, h: 0.35, fontSize: 15, bold: true, color: C.text1 });
  T(s, "Alice@2026!\nDavid@2026!\nAdmin@2026!", { x: 6.95, y: 2.6, w: 2.4, h: 1.0, fontSize: 14, color: C.text1, fontFace: "Courier New" });
  T(s, "Wake the free Render instance a minute before presenting", { x: 6.95, y: 3.7, w: 2.4, h: 0.85, fontSize: 12, italic: true, color: C.accent5 });
  s.addNotes("Run the demo on the deployed URL. Order matters: show the denial before the attribute change so the flip is visible. If the network fails, fall back to the localhost build (backend in WSL, frontend npm run dev). Finish with the audit log's Verify Chain Integrity button.");

  // =========================================================
  // 13. Close
  // =========================================================
  s = pres.addSlide({ masterName: "CLOSING_DARK", sectionTitle: "Demo & close" });
  s.addText("Limits we know about, and what's next", { placeholder: "title" });
  const limits = [
    [I.server, "Authority co-located with the API", "Move the master key into an HSM or cloud KMS"],
    [I.shield, "BN254 is ~100-bit today", "Migrate to a 128-bit curve such as BLS12-381"],
    [I.cloud, "Free hosting forgets uploads on restart", "Persistent disk or managed database"],
  ];
  limits.forEach(([img, h, d], i) => {
    const y = 1.6 + i * 1.15;
    circleIcon(s, img, 0.5, y, 0.62, C.accent1, h);
    T(s, h, { x: 1.3, y: y - 0.03, w: 5.0, h: 0.35, fontSize: 16, bold: true, color: C.background1 });
    T(s, d, { x: 1.3, y: y + 0.32, w: 5.0, h: 0.35, fontSize: 14, color: C.accent5 });
  });
  T(s, "Questions?", { x: 6.4, y: 1.9, w: 3.1, h: 0.9, fontSize: 40, bold: true, color: C.accent2, fontFace: "Cambria" });
  T(s, "75 automated tests · 6 attacks blocked · code, report and slides on GitHub", { x: 6.4, y: 2.9, w: 3.1, h: 1.2, fontSize: 14, color: C.background1 });
  s.addNotes("Close on honest limitations, then open Q&A. Likely questions: why BSW07 over KP-ABE (policy chosen by the data owner at encryption time); how collusion resistance works (per-user r); what happens if the server is compromised (storage yes, live authority no); why not client-side decryption (pairing cost in the browser).");

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("written", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
