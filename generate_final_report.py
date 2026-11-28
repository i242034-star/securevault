"""
generate_final_report.py — Generates the complete, university-level Project Report
for 'SecureVault — CP-ABE Based Secure Document Locker' in both DOCX and PDF formats.
"""
import os
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)

NAVY = RGBColor(15, 44, 89)      # #0F2C59
CYAN = RGBColor(0, 128, 128)     # #008080
DARK_GRAY = RGBColor(50, 50, 50)
LIGHT_BG = "F4F6F9"

TEAM_MEMBERS = [
    ("Abdullah Khan", "24i-2034"),
    ("Syed Ali Zaidi", "24i-2098"),
    ("Maryam Imran", "24i-2070"),
]
TOTAL_TESTS = 75  # 17 crypto + 18 API + 10 revocation + 14 hardening + 16 attack lab

SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "documentation_deliverables", "screenshots", "ss")
LIVE_APP_URL = "https://securevault-nine-rho.vercel.app"
LIVE_API_URL = "https://securevault-backend-production-8c4610c9.up.railway.app/api"
GITHUB_URL = "https://github.com/i242034-star/securevault"

SCREENSHOTS = [
    ("Screenshot 2026-11-10 200834.png", "Login page with demo personas (credentials unlock the user's CP-ABE key)."),
    ("Screenshot 2026-11-10 200936.png", "User dashboard: bound key attributes, key version and the core access policy matrix."),
    ("Screenshot 2026-11-10 201034.png", "Document Locker: every file is AES-256-GCM encrypted with a CP-ABE-wrapped key."),
    ("Screenshot 2026-11-10 201410.png", "Authorized user decrypts and downloads a document (attributes satisfy the policy)."),
    ("Screenshot 2026-11-10 201520.png", "Unauthorized user is mathematically denied: CP-ABE ACCESS DENIED."),
    ("Screenshot 2026-11-10 201311.png", "Admin panel: dynamic attribute management and per-user key versions."),
    ("Screenshot 2026-11-10 201637.png", "Epoch management, staged re-encryption and live revocation verification."),
    ("Screenshot 2026-11-10 201750.png", "Tamper-evident audit log with HMAC-SHA256 chain hashes and one-click verification."),
    ("Attack_Lab_6_of_6_blocked.png", "Attack Lab: all six simulated attacks launched against a sandbox authority, 6 of 6 blocked, with steps and countermeasures."),
]
BORDER_COLOR = "D0D5DD"


def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>'))


def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)


def build_docx_report(filepath):
    doc = Document()

    # Set page margins (1 inch)
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Base Styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = DARK_GRAY

    # Helper functions
    def add_title(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(36)
        p.paragraph_format.space_after = Pt(12)
        run = p.add_run(text)
        run.font.name = 'Arial'
        run.font.size = Pt(26)
        run.bold = True
        run.font.color.rgb = NAVY
        return p

    def add_subtitle(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(24)
        run = p.add_run(text)
        run.font.name = 'Calibri'
        run.font.size = Pt(15)
        run.font.color.rgb = CYAN
        return p

    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(20)
        p.paragraph_format.space_after = Pt(8)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = 'Arial'
        run.font.size = Pt(16)
        run.bold = True
        run.font.color.rgb = NAVY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = 'Arial'
        run.font.size = Pt(13)
        run.bold = True
        run.font.color.rgb = CYAN
        return p

    def add_h3(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = 'Calibri'
        run.font.size = Pt(11.5)
        run.bold = True
        run.font.color.rgb = NAVY
        return p

    def add_p(text, bold_prefix=None, space_after=6):
        text = text.replace("**", "").replace("`", "")
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_pre = p.add_run(bold_prefix)
            r_pre.bold = True
            r_pre.font.color.rgb = NAVY
        p.add_run(text)
        return p

    def add_bullet(text, bold_prefix=None):
        text = text.replace("**", "").replace("`", "").replace("$", "")
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_pre = p.add_run(bold_prefix)
            r_pre.bold = True
            r_pre.font.color.rgb = NAVY
        p.add_run(text)
        return p

    def add_callout(text, title="KEY ARCHITECTURAL HIGHLIGHT"):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = False
        cell = tbl.cell(0, 0)
        cell.width = Inches(6.5)
        set_cell_background(cell, "EBF3FA")
        set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(4)
        r_title = p.add_run(f"📌 {title}\n")
        r_title.bold = True
        r_title.font.size = Pt(10.5)
        r_title.font.color.rgb = NAVY
        r_body = p.add_run(text)
        r_body.font.size = Pt(10)
        r_body.font.color.rgb = DARK_GRAY
        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    def add_table_data(headers, rows_data):
        tbl = doc.add_table(rows=len(rows_data) + 1, cols=len(headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = True

        # Header Row
        hdr_cells = tbl.rows[0].cells
        for idx, title in enumerate(headers):
            hdr_cells[idx].text = title
            set_cell_background(hdr_cells[idx], "0F2C59")
            set_cell_margins(hdr_cells[idx], top=100, bottom=100, left=120, right=120)
            p = hdr_cells[idx].paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for r in p.runs:
                r.font.name = 'Arial'
                r.font.bold = True
                r.font.size = Pt(9.5)
                r.font.color.rgb = RGBColor(255, 255, 255)

        # Body Rows
        for r_idx, row in enumerate(rows_data):
            row_cells = tbl.rows[r_idx + 1].cells
            bg_color = "FFFFFF" if r_idx % 2 == 0 else "F8FAFC"
            for c_idx, val in enumerate(row):
                row_cells[c_idx].text = str(val)
                set_cell_background(row_cells[c_idx], bg_color)
                set_cell_margins(row_cells[c_idx], top=80, bottom=80, left=120, right=120)
                p = row_cells[c_idx].paragraphs[0]
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                for r in p.runs:
                    r.font.name = 'Calibri'
                    r.font.size = Pt(9.5)
                    r.font.color.rgb = DARK_GRAY
        doc.add_paragraph().paragraph_format.space_after = Pt(8)

    # =========================================================================
    # 1. TITLE PAGE
    # =========================================================================
    add_title("SECUREVAULT")
    add_subtitle("CP-ABE Based Secure Document Locker with Hybrid Encryption,\nDynamic Attribute Management, and Tamper-Evident Audit Logging")

    p_meta = doc.add_paragraph()
    p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_meta.paragraph_format.space_before = Pt(40)
    p_meta.paragraph_format.space_after = Pt(20)
    p_meta.paragraph_format.line_spacing = 1.3
    r = p_meta.add_run("CS-3002 Information Security — Term Project Report\n\n"
                       "Topic 12: Attribute-Based Encryption (ABE) for Fine-Grained Access Control\n"
                       "Ciphertext-Policy ABE (BSW07) Confidential Project Document Locker\n\n")
    r.font.size = Pt(12)
    r.bold = True
    r.font.color.rgb = NAVY

    p_info = doc.add_paragraph()
    p_info.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_info.paragraph_format.space_before = Pt(40)
    p_info.paragraph_format.line_spacing = 1.2
    r_cand = p_info.add_run("Team Members:\n")
    r_cand.bold = True
    for name, roll in TEAM_MEMBERS:
        p_info.add_run(f"{name}  ({roll})\n")
    r_sup = p_info.add_run("Academic Session: ")
    r_sup.bold = True
    p_info.add_run("2025 – 2026\n")
    r_dep = p_info.add_run("Department: ")
    r_dep.bold = True
    p_info.add_run("Department of Cyber Security & Computer Science\n")
    r_sub = p_info.add_run("Submission Date: ")
    r_sub.bold = True
    p_info.add_run("November 2026\n")

    doc.add_page_break()

    # =========================================================================
    # 2. ABSTRACT
    # =========================================================================
    add_h1("2. Abstract")
    add_p(
        "Modern cloud-hosted document repositories face severe security risks regarding data confidentiality, "
        "privilege escalation, and rogue administrators. Conventional discretionary access control (DAC) and "
        "role-based access control (RBAC) mechanisms enforce authorization at the software or database layer; "
        "consequently, any attacker gaining raw disk access, physical storage snapshots, or compromised database "
        "credentials can immediately exfiltrate all stored files in plaintext. Furthermore, traditional public-key "
        "cryptography scales poorly when encrypting documents intended for dynamic groups of recipients."
    )
    add_p(
        "SecureVault addresses these vulnerabilities by engineering an end-to-end secure document locker utilizing "
        "Ciphertext-Policy Attribute-Based Encryption (CP-ABE). Based on the Bethencourt-Sahai-Waters (BSW07) scheme "
        "instantiated over the BN254 pairing-friendly elliptic curve (Stanford PBC library), SecureVault embeds boolean "
        "access policies directly into document ciphertexts. SecureVault uses a two-tier Hybrid Encryption system: a "
        "Key Encapsulation Mechanism (KEM) via CP-ABE protects an ephemeral group element, which derives a 256-bit AES "
        "key via SHA-256 to encrypt the document body using AES-256-GCM (DEM) with authenticated integrity tags. "
        "To solve the notorious revocation bottleneck in attribute-based encryption, SecureVault incorporates an Epoch-Based "
        "Revocation Lifecycle with asynchronous user key claiming, ensuring administrators never handle user passwords. "
        "Finally, SecureVault introduces a tamper-evident audit logging architecture using canonical JSON serialization "
        "and HMAC-SHA256 sequential hash chaining with transactional safety. The complete full-stack platform comprises "
        f"a Flask backend and a modern React 19/Vite frontend, backed by {TOTAL_TESTS} automated test cases executed across multiple "
        "verification phases with a 100% pass rate. An integrated Attack Lab empirically demonstrates six attacks (collusion, "
        "policy tampering, ciphertext bit-flipping, revoked-key replay, password brute force and a timing side channel) and "
        "the countermeasure that defeats each."
    )

    # =========================================================================
    # 3. INTRODUCTION
    # =========================================================================
    add_h1("3. Introduction")
    add_p(
        "In the contemporary enterprise landscape, organizations store and exchange sensitive intellectual property, "
        "classified legal records, defense schematics, and medical histories over untrusted networks and shared multi-tenant "
        "cloud infrastructure. While traditional security perimeters rely on network firewalls and database access control lists, "
        "these safeguards are vulnerable to insider threats, SQL injection, privilege abuse, and cloud hypervisor compromises."
    )
    add_p(
        "To achieve genuine zero-trust data protection, data must be encrypted cryptographically in such a manner that access "
        "decisions are made mathematically at the cryptographic layer rather than administratively by the database server. "
        "Ciphertext-Policy Attribute-Based Encryption (CP-ABE), introduced by Bethencourt, Sahai, and Waters in 2007, represents "
        "a revolutionary paradigm: ciphertexts are labeled with access policies (e.g., '(Role:Engineer OR Role:Manager) AND "
        "Clearance:Level-3'), while private keys are bound to user attribute sets. Decryption is mathematically possible if and "
        "only if the attributes satisfy the ciphertext policy tree."
    )
    add_p(
        "SecureVault implements this vision as a complete, production-grade secure document locker. It combines genuine "
        "bilinear pairing cryptography, authenticated symmetric encryption, administrative attribute lifecycle management, "
        "and cryptographic audit logging into a cohesive, highly usable full-stack application."
    )

    # =========================================================================
    # 4. PROBLEM STATEMENT
    # =========================================================================
    add_h1("4. Problem Statement")
    add_p("Current enterprise document management solutions suffer from three fundamental architectural flaws:")
    add_bullet(
        "In traditional architectures, the database or application server checks user roles and reads plaintext from disk. "
        "A malicious database administrator (DBA) or compromised server directly bypasses application access rules.",
        bold_prefix="1. Server-Side Privilege Dependence: "
    )
    add_bullet(
        "Encrypting a single document for N recipients using standard RSA or ECC requires either encrypting N distinct copies "
        "(causing massive storage explosion) or sharing a single symmetric key (destroying individual accountability).",
        bold_prefix="2. Public-Key Cryptography Inefficiency in Group Access: "
    )
    add_bullet(
        "Revoking access in CP-ABE is historically computationally prohibitive. When an employee departs or is demoted, "
        "re-keying the entire organization and re-encrypting all historical documents introduces unacceptable downtime.",
        bold_prefix="3. The Revocation Bottleneck in ABE: "
    )
    add_bullet(
        "Standard database audit logs stored in relational tables can be trivially modified, truncated, or deleted by attackers "
        "who obtain database credentials, erasing evidence of unauthorized breaches.",
        bold_prefix="4. Tamper-Vulnerable Audit Trails: "
    )

    # =========================================================================
    # 5. PROJECT OBJECTIVES
    # =========================================================================
    add_h1("5. Project Objectives")
    add_p("The primary technical and operational goals of SecureVault are:")
    add_bullet("Implement a genuine BSW07 CP-ABE cryptographic engine using Charm-Crypto and Stanford PBC over BN254 elliptic curves.")
    add_bullet("Build a Hybrid Cipher (KEM/DEM) combining CP-ABE with AES-256-GCM for authenticated, tamper-proof document encryption.")
    add_bullet("Enable fine-grained, policy-driven access control where documents are restricted using arbitrary Boolean access trees.")
    add_bullet("Engineer a dynamic attribute management system allowing administrators to adjust roles and clearances without password access.")
    add_bullet("Design and demonstrate an Epoch-Based Revocation Lifecycle that mathematically invalidates expired private keys.")
    add_bullet("Implement an asynchronous key-claim workflow where users securely claim refreshed keys using their own credentials.")
    add_bullet("Establish a tamper-evident audit logging system using canonical JSON serialization and HMAC-SHA256 hash chaining.")
    add_bullet("Deliver a complete full-stack application featuring a Flask REST API and a responsive React 19/Vite web interface.")
    add_bullet("Validate system correctness, performance, and security through comprehensive multi-phase automated regression testing.")

    # =========================================================================
    # 6. SCOPE OF THE PROJECT
    # =========================================================================
    add_h1("6. Scope of the Project")
    add_p(
        "SecureVault encompasses the full software lifecycle of a secure document locker designed for enterprise environments. "
        "Its operational scope includes user identity provisioning, cryptographic key generation, document encryption and upload, "
        "authorized decryption, dynamic attribute modification, epoch advance, staged ciphertext re-encryption, and audit log verification."
    )
    add_p(
        "Scope Boundaries: SecureVault specifically targets high-security document storage (PDFs, reports, schematics). It does not "
        "implement real-time collaborative document editing (such as operational transformations) or enterprise directory federation "
        "(LDAP/SAML), focusing squarely on zero-trust cryptographic enforcement, mathematical revocation, and tamper-evident auditing."
    )

    # =========================================================================
    # 7. EXISTING SYSTEM AND ITS LIMITATIONS
    # =========================================================================
    add_h1("7. Existing System and Its Limitations")
    add_p("Conventional enterprise document security relies on the following mechanisms:")
    add_table_data(
        ["Mechanism", "How it Works", "Critical Limitations"],
        [
            ["Role-Based Access Control (RBAC)", "Database flags determine permissions (e.g., SELECT on table).", "Files reside unencrypted or under static server keys; DB compromise leaks all data."],
            ["Discretionary Access Control (DAC)", "File owners set read/write permissions at the OS level.", "Vulnerable to root privilege escalation, physical drive extraction, and backup exfiltration."],
            ["Traditional PKI (RSA/ECC)", "Files encrypted with individual recipient public keys.", "O(N) storage or key distribution complexity; impossible to express dynamic group policies."],
            ["Plain Database Auditing", "Event rows inserted into standard relational logging tables.", "Rows can be altered, truncated, or dropped with standard SQL UPDATE/DELETE commands."]
        ]
    )

    # =========================================================================
    # 8. PROPOSED SYSTEM
    # =========================================================================
    add_h1("8. Proposed System: SecureVault Architecture")
    add_p(
        "SecureVault replaces server-side access assumptions with mathematical cryptographic access control. In SecureVault, "
        "data security is decoupled from server trust: ciphertexts remain secure even on completely compromised or public storage."
    )
    add_callout(
        "An adversary who steals the SQLite database, the encrypted filesystem blobs and the encrypted master-key file "
        "(a storage, backup or snapshot compromise) cannot decrypt any document: they still need a CP-ABE private key whose "
        "attributes satisfy the policy, and every stored key is wrapped under a PBKDF2-derived key. The guarantee does NOT "
        "extend to an attacker who takes over the running Trusted Authority process (see Section 23, Threat Model).",
        title="SECURITY GUARANTEE (AND ITS BOUNDARY)"
    )
    add_p("Key architectural innovations of SecureVault include:")
    add_bullet("Decoupled Authority: Master Secret Key ($MK$) is stored encrypted at rest via PBKDF2-HMAC-SHA256 + AES-256-GCM.")
    add_bullet("KEM/DEM Hybrid Pipeline: Protects arbitrary document sizes with AES-256-GCM while enforcing CP-ABE policy access.")
    add_bullet("Zero-Knowledge Admin Workflow: Administrators modify organizational roles and clearance levels without ever learning, requesting, or handling user passwords.")
    add_bullet("Asynchronous Key Claiming: Users claim updated private keys on-demand or upon their next login using their own password.")
    add_bullet("Cryptographic Audit Chaining: Every security event is chained to its predecessor via HMAC-SHA256, detecting any row modification, reordering, insertion, or deletion.")

    # =========================================================================
    # 9. FUNCTIONAL REQUIREMENTS
    # =========================================================================
    add_h1("9. Functional Requirements")
    add_p("SecureVault satisfies the following functional requirements across user and administrator roles:")
    add_bullet("FR-01 (Authentication): Users and administrators must authenticate using secure passwords, receiving an HMAC-SHA256 signed JWT session token valid for 24 hours.", bold_prefix="FR-01: ")
    add_bullet("FR-02 (Key Provisioning): Upon registration, the system must derive and envelope-encrypt an initial BSW07 private key matching the user's assigned attributes and current epoch.", bold_prefix="FR-02: ")
    add_bullet("FR-03 (Document Encryption): Users must be able to upload documents and apply customized or default Boolean CP-ABE policies (AND, OR, OF) with optional Epoch attachment.", bold_prefix="FR-03: ")
    add_bullet("FR-04 (Authorized Decryption): Users satisfying document policy trees must decrypt documents by supplying their personal password to unlock their private key in transient memory.", bold_prefix="FR-04: ")
    add_bullet("FR-05 (Cryptographic Denial): Users failing policy requirements must be mathematically denied access (HTTP 403) by the CP-ABE engine.", bold_prefix="FR-05: ")
    add_bullet("FR-06 (Attribute Management): Administrators must be able to adjust roles, clearance levels, and custom tags for any registered identity.", bold_prefix="FR-06: ")
    add_bullet("FR-07 (Key Reissuance Flagging): Updating a user's attributes must flag the user for key re-issuance without exposing user passwords to the administrator.", bold_prefix="FR-07: ")
    add_bullet("FR-08 (Asynchronous Key Claim): Users must be able to claim updated cryptographic keys using their own password at any time or during routine login.", bold_prefix="FR-08: ")
    add_bullet("FR-09 (Epoch Advancement): Administrators must be able to increment the global system epoch, invalidating older keys for newly re-encrypted documents.", bold_prefix="FR-09: ")
    add_bullet("FR-10 (Staged Re-encryption): The system must support re-encrypting existing documents under the active epoch using crash-safe staged filesystem replacement.", bold_prefix="FR-10: ")
    add_bullet("FR-11 (Audit Logging): All security-critical actions (login, key issuance, upload, decrypt success/denial, attribute update, epoch rotation) must be recorded in an HMAC-chained audit log.", bold_prefix="FR-11: ")
    add_bullet("FR-12 (Audit Verification): Administrators must be able to execute one-click cryptographic chain verification to detect any database tampering.", bold_prefix="FR-12: ")
    add_bullet("FR-13 (Authority-Controlled Enrolment): Only the Trusted Authority (an administrator) may enrol users and assign attributes; the very first account bootstraps the system as admin.", bold_prefix="FR-13: ")
    add_bullet("FR-14 (Attack Lab): Any authenticated user must be able to launch sandboxed attack simulations and see the countermeasure that defeats each one.", bold_prefix="FR-14: ")

    # =========================================================================
    # 10. NON-FUNCTIONAL REQUIREMENTS
    # =========================================================================
    add_h1("10. Non-Functional Requirements")
    add_table_data(
        ["Category", "Requirement", "Implementation in SecureVault"],
        [
            ["Security Level", "At least 100-bit security for every primitive.", "BN254 pairing curve (~100-bit after 2016 exTNFS attacks; 128-bit was the original estimate) + AES-256-GCM."],
            ["Data Integrity", "Detect ciphertext corruption or tampering.", "AES-256-GCM 128-bit authentication tags verified on all decrypt operations."],
            ["Confidentiality at Rest", "Zero plaintext keys or passwords on disk.", "Master Key and User Private Keys encrypted via PBKDF2 (100k rounds) + AES-GCM."],
            ["Audit Tamper-Evidence", "Cryptographic detection of log modifications.", "Sequential HMAC-SHA256 hash chaining using an out-of-database secret key."],
            ["Concurrency Safety", "Thread-safe audit writing under load.", "SQLite serialized transactions via explicit BEGIN IMMEDIATE isolation."],
            ["Crash Resilience", "Zero data loss during re-encryption failure.", "Staged file writes (.staged.enc) committed before deleting prior ciphertexts."],
            ["Performance", "Sub-second cryptographic operations.", "Measured: keygen 5 ms, hybrid encrypt ~29 ms (1 KB to 1 MB), authorized decrypt ~154 ms."],
            ["Abuse Resistance", "Throttle online guessing, cap resource use.", "5-failure login lockout per (user, IP) with HTTP 429; 20 MB upload cap; generic error bodies."]
        ]
    )

    # =========================================================================
    # 11. SYSTEM ARCHITECTURE
    # =========================================================================
    add_h1("11. System Architecture")
    add_p(
        "SecureVault adopts a modular, tiered service architecture designed for strict separation of concerns, high maintainability, "
        "and clear cryptographic boundaries. The architecture consists of four distinct layers:"
    )
    add_bullet("1. Client Presentation Layer: Built with React 19, Vite, and Tailwind CSS. Manages local session tokens, UI routing, modal dialogs, and asynchronous API communication.", bold_prefix="Layer 1: ")
    add_bullet("2. API & Gateway Layer: Flask application factory registering modular blueprints (/api/auth, /api/admin, /api/documents, /api/audit, /api/attacks). Enforces strict CORS origin allowlists and JWT bearer token authorization.", bold_prefix="Layer 2: ")
    add_bullet("3. Core Cryptographic Services: Singleton orchestrator (CryptoService) managing CharmEngine (BSW07 CP-ABE), HybridCipher (KEM/DEM), KeyStore (PBKDF2/AES envelope encryption), and AuditChain (HMAC logging).", bold_prefix="Layer 3: ")
    add_bullet("4. Persistence Layer: SQLite database (securevault.db) storing structured relations and audit logs, paired with secure filesystem storage for encrypted ciphertext blobs (/storage/encrypted/) and authority parameters (/storage/keys/).", bold_prefix="Layer 4: ")

    # =========================================================================
    # 12. TECHNOLOGIES AND TOOLS USED
    # =========================================================================
    add_h1("12. Technologies and Tools Used")
    add_table_data(
        ["Component", "Technology / Library", "Version / Standard", "Role in Project"],
        [
            ["CP-ABE Library", "Charm-Crypto (Stanford PBC)", "v0.63 / PBC 0.5.14 / BN254", "Bilinear pairings, polynomial secret sharing, BSW07 scheme."],
            ["Symmetric Crypto", "PyCryptodome", "v4.4.0 (AES-256-GCM)", "Authenticated document payload encryption and envelope KEKs."],
            ["Backend Framework", "Python / Flask", "Python 3.12 / Flask 3.0", "REST API architecture, routing blueprints, error handlers."],
            ["CORS Security", "Flask-CORS", "v4.0.0", "Strict cross-origin request validation (no wildcard origins)."],
            ["Database", "SQLite3", "v3.45 (Foreign Keys ON)", "Relational persistence, ACID transactions, audit chain log."],
            ["Frontend Framework", "React / Vite", "React 19.3 / Vite 8.3", "Single Page Application (SPA), state management, UI kit."],
            ["Styling", "Tailwind CSS", "v4.3", "Responsive dark-mode cybersecurity user interface."],
            ["HTTP Client", "Axios", "v1.21", "Centralized API client with JWT bearer request interceptors."],
            ["Development OS", "Ubuntu WSL2 & Windows 11", "WSL 2.0 / Ubuntu 24.04", "Linux runtime for Charm PBC; Windows for Vite frontend."]
        ]
    )

    # =========================================================================
    # 13. DATABASE DESIGN AND TABLES
    # =========================================================================
    add_h1("13. Database Design and Tables")
    add_p(
        "SecureVault uses SQLite with enforced foreign key constraints (`PRAGMA foreign_keys = ON;`). "
        "The schema consists of five core tables designed for efficiency and cryptographic envelope storage:"
    )
    add_table_data(
        ["Table Name", "Primary Columns", "Purpose & Cryptographic Details"],
        [
            ["users", "id, username, password_hash, system_role, role_attr, clearance_attr, custom_attributes, pending_key_reissue", "Identity store. Passwords stored as PBKDF2-HMAC-SHA256 hashes. Tracks pending key updates."],
            ["user_keys", "id, user_id, key_version, bound_attributes, encrypted_sk, is_active, issued_at", "Private key store. encrypted_sk holds the AES-256-GCM envelope locked by user password. Zero plaintext."],
            ["documents", "id, uploader_id, original_filename, stored_filename, file_size, access_policy, cpabe_ciphertext, aes_nonce, aes_tag, epoch", "Document metadata. stored_filename references disk .enc UUID. Holds KEM ciphertext, nonce, tag, and epoch."],
            ["audit_logs", "id, sequence_number, user_id, username, action, status, details, ip_address, timestamp, previous_hash, record_hash", "Tamper-evident log. Monotonic sequence, previous hash pointer, and HMAC-SHA256 signature."],
            ["system_epochs", "id, epoch_number, reason, initiated_by, status, created_at", "Global revocation lifecycle. Tracks active epoch, rotation reason, and re-encryption progress."]
        ]
    )

    # =========================================================================
    # 14. CP-ABE BSW07 CRYPTOGRAPHIC IMPLEMENTATION
    # =========================================================================
    add_h1("14. CP-ABE BSW07 Cryptographic Implementation")
    add_p(
        "The mathematical foundation of SecureVault is the Bethencourt-Sahai-Waters (BSW07) Ciphertext-Policy Attribute-Based "
        "Encryption scheme, executed over a pairing-friendly elliptic curve with a bilinear map:"
    )
    add_p("e : G1 × G2 → GT, with e(g^a, h^b) = e(g, h)^(ab) for all a, b in Z_p", bold_prefix="Bilinear Map: ")
    add_p(
        "SecureVault instantiates the scheme over the BN254 Barreto-Naehrig curve (a Type-3 asymmetric pairing) through "
        "Charm-Crypto and the Stanford Pairing-Based Cryptography (PBC) library. BN254 was originally rated at 128-bit "
        "security; after the 2016 extended Tower Number Field Sieve (exTNFS) results it is estimated at roughly 100 bits. "
        "That is adequate for a course prototype; a production system would move to BLS12-381 (see Section 30)."
    )
    add_h2("The Four Fundamental Algorithms:")
    add_bullet(
        "Setup(1^lambda) -> (PK, MK): Selects bilinear group G_0 of prime order p with generator g. Chooses random alpha, beta in Z_p. "
        "Sets PK = (G_0, g, h = g^beta, e(g,g)^alpha). Sets MK = (beta, g^alpha).",
        bold_prefix="1. Authority Setup: "
    )
    add_bullet(
        "KeyGen(MK, S) -> SK: Given an attribute set S (e.g. {ROLE_ENGINEER, CLEARANCE_LEVEL3, EPOCH1}), chooses random r in Z_p, "
        "and for each attribute j in S chooses random r_j in Z_p. Derives private key components satisfying: "
        "D = g^((alpha + r)/beta), and for each attribute D_j = g^r * H(j)^r_j, D'_j = g^r_j.",
        bold_prefix="2. User Key Generation: "
    )
    add_bullet(
        "Encrypt(PK, M, T) -> CT: Encrypts group element M in G_T under an access tree T. Selects polynomial q_x for each node x "
        "in the policy tree. Sets secret s = q_R(0). Ciphertext contains C_tilde = M * e(g,g)^(alpha * s), C = h^s, and for each leaf node y "
        "representing attribute att(y), C_y = g^(q_y(0)), C'_y = H(att(y))^(q_y(0)).",
        bold_prefix="3. Policy Encryption: "
    )
    add_bullet(
        "Decrypt(CT, SK) -> M: Recursive pairing evaluation over policy tree nodes. If user attributes satisfy node x, computes "
        "F_x = e(D_j, C_y) / e(D'_j, C'_y) = e(g,g)^(r * q_y(0)). Reconstructs e(g,g)^(r * s) at root via Lagrange interpolation. "
        "Finally recovers M = C_tilde / (e(C, D) / e(g,g)^(r * s)). If attributes fail policy, reconstruction fails mathematically.",
        bold_prefix="4. Bilinear Decryption: "
    )

    # =========================================================================
    # 15. HYBRID ENCRYPTION USING AES-256-GCM
    # =========================================================================
    add_h1("15. Hybrid Encryption Using AES-256-GCM (KEM / DEM)")
    add_p(
        "Asymmetric pairing operations over elliptic curves are computationally intensive and restricted to small message payloads "
        "(elements of G_T). Encrypting multi-megabyte PDF documents directly under CP-ABE is computationally infeasible. "
        "SecureVault resolves this through a two-tier **Hybrid Encryption (KEM/DEM)** pipeline:"
    )
    add_bullet(
        "Key Encapsulation Mechanism (KEM): The Charm engine samples a cryptographically random element M in G_T. "
        "M is encrypted under the document access policy tree using CP-ABE: CT_cpabe = Encrypt(PK, M, Policy). "
        "The actual 256-bit symmetric encryption key is derived deterministically via SHA-256(str(M)).",
        bold_prefix="KEM Tier: "
    )
    add_bullet(
        "Data Encapsulation Mechanism (DEM): The document payload (e.g., PDF bytes) is encrypted using AES-256 in Galois/Counter Mode "
        "(AES-256-GCM) with a unique 96-bit random nonce. AES-GCM produces ciphertext bytes and a 128-bit authentication tag. "
        "This guarantees both data confidentiality and cryptographic tamper-detection.",
        bold_prefix="DEM Tier: "
    )
    add_callout(
        "Storage Efficiency: A 10 MB document produces only ~350 bytes of CP-ABE policy metadata, 12 bytes of nonce, and 16 bytes of tag. "
        "The document body is processed at symmetric hardware speeds (AES-NI), delivering sub-second encryption and decryption.",
        title="HYBRID PERFORMANCE ADVANTAGE"
    )

    # =========================================================================
    # 16. ATTRIBUTE-BASED ACCESS CONTROL (ABAC)
    # =========================================================================
    add_h1("16. Attribute-Based Access Control (ABAC)")
    add_p(
        "SecureVault enforces multi-dimensional access policies structured around three distinct attribute classes: "
        "Organizational Role, Security Clearance, and Temporal Epoch:"
    )
    add_table_data(
        ["Attribute Class", "Supported Values", "Semantics & Purpose"],
        [
            ["Role Attribute", "Role:Engineer, Role:Manager, Role:Student, Role:Analyst", "Defines the user's operational functional capacity."],
            ["Clearance Attribute", "Clearance:Level-1, Clearance:Level-2, Clearance:Level-3", "Defines hierarchical access classification tier."],
            ["Epoch Attribute", "Epoch:1, Epoch:2, Epoch:3...", "Dynamic temporal tag enforcing cryptographic revocation."]
        ]
    )
    add_p(
        "SecureVault normalizes all attributes via `format_attribute` (e.g. `Role:Engineer` -> `ROLE_ENGINEER`) and formats policies "
        "via `format_policy` into Charm-compatible boolean trees: `(ROLE_ENGINEER or ROLE_MANAGER) and CLEARANCE_LEVEL3 and EPOCH1`."
    )

    # =========================================================================
    # 17. DYNAMIC ATTRIBUTE MANAGEMENT
    # =========================================================================
    add_h1("17. Dynamic Attribute Management")
    add_p(
        "In a live organization, users frequently change departments, earn security promotions, or transition between projects. "
        "SecureVault provides dynamic administrative attribute modification without requiring database migrations or code changes:"
    )
    add_bullet("Custom Tag Support: Administrators can attach arbitrary custom tags (e.g. 'Project:Apollo', 'Region:EU') stored as JSON lists in the database.")
    add_bullet("Zero Password Admin Privilege: Administrators update attributes via PUT /api/admin/users/<id>/attributes. The endpoint accepts zero password parameters, ensuring administrators never see or handle user credentials.")
    add_bullet("Pending Key Re-issuance Flag: When attributes change, the system sets pending_key_reissue = 1 for that user. The user's previous key remains active until they claim their renewed key, preventing abrupt operational lockout.")

    # =========================================================================
    # 18. EPOCH-BASED CRYPTOGRAPHIC REVOCATION
    # =========================================================================
    add_h1("18. Epoch-Based Cryptographic Revocation")
    add_p(
        "Revocation is the most challenging problem in attribute-based encryption. If a compromised user holds a private key matching "
        "required role and clearance attributes, how can their access be revoked without re-encrypting the entire world?"
    )
    add_p(
        "SecureVault solves this through an **Epoch-Based Revocation Lifecycle**:"
    )
    add_bullet("1. Epoch Declaration: When access is revoked (e.g. employee departure), the administrator advances the system epoch (e.g. 1 -> 2) via POST /api/admin/epoch/advance. All non-admin users are flagged with pending_key_reissue = 1.", bold_prefix="Stage 1: ")
    add_bullet("2. Staged Document Re-encryption: Critical documents are re-encrypted under the new epoch: (Policy) AND Epoch:2. Staged filesystem replacement writes <uuid>.staged.enc, verifies integrity, renames to final, commits to SQLite, and purges the old ciphertext only upon transaction success.", bold_prefix="Stage 2: ")
    add_bullet("3. Mathematical Denial: When the revoked user attempts decryption using their old Epoch-1 private key, Charm's bilinear pairing fails mathematically because their key lacks Epoch:2 shares. Access is rejected with AccessDeniedError.", bold_prefix="Stage 3: ")
    add_bullet("4. Authorized Key Renewal: Authorized users claim updated keys embedding Epoch:2 using their own password. Upon claiming, their renewed key decrypts Epoch 2 documents immediately.", bold_prefix="Stage 4: ")
    add_bullet("5. Backward Compatibility: Documents uploaded without epoch constraints (legacy documents, epoch=0) continue to decrypt normally for users with matching role/clearance attributes.", bold_prefix="Stage 5: ")

    # =========================================================================
    # 19. AUTHENTICATION AND AUTHORIZATION
    # =========================================================================
    add_h1("19. Authentication and Authorization")
    add_p(
        "SecureVault enforces defence-in-depth through multi-tiered identity and credential controls:"
    )
    add_bullet("PBKDF2 Password Hashing: Uses PBKDF2-HMAC-SHA256 with 100,000 rounds and a 16-byte random salt per user. Hash format: pbkdf2_sha256$100000$<salt>$<dk>.", bold_prefix="Passwords: ")
    add_bullet("Session Bearer Tokens: Signed HMAC-SHA256 bearer tokens with 24-hour expiration. Evaluated on protected routes via the @require_auth decorator.", bold_prefix="Tokens: ")
    add_bullet("Role-Based Route Enforcement: Administrative endpoints (/api/admin/*, /api/audit/*) enforce the @require_admin decorator. Non-admin tokens are rejected with HTTP 403 Forbidden at the backend server.", bold_prefix="RBAC: ")
    add_bullet("Envelope-Encrypted Key Store: User private keys are encrypted at rest using AES-256-GCM envelopes derived from user passwords. Keys are unlocked only in transient RAM during authorized decryption.", bold_prefix="Key Protection: ")

    # =========================================================================
    # 20. HMAC-SHA256 AUDIT LOG INTEGRITY
    # =========================================================================
    add_h1("20. HMAC-SHA256 Audit Log Integrity")
    add_p(
        "Traditional database audit logs are vulnerable to tampering: a rogue admin can delete or modify log entries. "
        "SecureVault implements a **tamper-evident cryptographic hash chain**:"
    )
    add_p("PreviousHash(1) = 64 hex zeros (the genesis value)", bold_prefix="Chaining Rule: ")
    add_p("RecordHash(i) = HMAC-SHA256( K_audit, CanonicalBytes(Record(i)) ), where Record(i) includes PreviousHash(i)")
    add_p("PreviousHash(i+1) = RecordHash(i)")
    add_bullet("Deterministic Canonicalization: Record fields are serialized using RFC 8785-compliant sorted JSON with no whitespace (separators=(',', ':')).", bold_prefix="Canonical JSON: ")
    add_bullet("Out-of-Database Secret: The HMAC secret key (AUDIT_HMAC_SECRET) is stored in the environment configuration, never written to SQLite.", bold_prefix="Secret Storage: ")
    add_bullet("Concurrency Safety: Insertion uses SQLite serialized transactions (BEGIN IMMEDIATE), preventing race conditions or sequence gaps under concurrent load.", bold_prefix="Thread Safety: ")
    add_bullet("Verification Engine: verify_chain_integrity() recomputes the entire chain from Genesis, detecting any record modification, reordering, insertion, or deletion.", bold_prefix="Verification: ")

    # =========================================================================
    # 21. FRONTEND AND BACKEND INTEGRATION
    # =========================================================================
    add_h1("21. Frontend and Backend Integration")
    add_p(
        "The SecureVault frontend is a responsive Single Page Application (SPA) built with React 19, Vite, and Tailwind CSS. "
        "Communication with the Flask backend is managed via a centralized Axios instance with request/response interceptors:"
    )
    add_bullet("Vite Reverse Proxy: In development, requests to /api are proxied to http://127.0.0.1:5000, eliminating browser cross-origin friction while maintaining production parity.", bold_prefix="Proxy Routing: ")
    add_bullet("JWT Interceptor: Automatically injects Authorization: Bearer <token> from sessionStorage onto every outbound request.", bold_prefix="Auth Header: ")
    add_bullet("Session Interceptor: Automatically catches HTTP 401 responses, purges expired session data, and redirects the user to /login.", bold_prefix="Session Expiry: ")
    add_bullet("Real-Time Audit Verification: The AuditLogs page features a one-click 'Verify Chain Integrity' button calling GET /api/audit/verify, presenting instant visual confirmation of log integrity.", bold_prefix="Chain UI: ")

    # =========================================================================
    # 22. TESTING METHODOLOGY AND ACTUAL TEST RESULTS
    # =========================================================================
    add_h1("22. Testing Methodology and Actual Test Results")
    add_p(
        "SecureVault underwent rigorous automated unit, integration, and security regression testing across four testing phases. "
        f"All {TOTAL_TESTS} automated test cases executed with a 100% pass rate (Ubuntu 24.04 / WSL2, Python 3.12, Charm 0.63). "
        "Testing results are summarized below:"
    )
    add_table_data(
        ["Test Suite", "Target Component", "Tests Run", "Passed", "Failed"],
        [
            ["Phase 1 (run_all_tests.py)", "Charm BSW07 CP-ABE, Hybrid Cipher, Access Matrix, KeyStore", "17", "17", "0"],
            ["Phase 2 (test_api.py)", "REST API Endpoints, Auth, Document Upload/Decrypt, RBAC", "18", "18", "0"],
            ["Phase 4 (test_phase4_revocation.py)", "Attribute Management, Async Claim, Epoch Revocation, Recovery", "10", "10", "0"],
            ["Hardening (test_audit_chain_and_cors.py)", "CORS Allowlist, HMAC Chaining, Tamper Detection, Concurrency", "14", "14", "0"],
            ["Attack Lab (test_attack_lab.py)", "Six simulated attacks, login lockout, admin-only enrolment, timing", "16", "16", "0"],
            ["Total Automated Tests", "Complete Backend & Cryptographic Engine", str(TOTAL_TESTS), str(TOTAL_TESTS), "0"]
        ]
    )

    add_h2("Live Cryptographic Revocation Scenario Verification:")
    add_p("The exact 9-step revocation demonstration (verify_revocation_demo.py) was executed with real terminal output:")
    add_bullet("Step 1: Alice assigned attributes [Role:Engineer, Clearance:Level-3, Epoch:1] -> Key v1 generated.")
    add_bullet("Step 2: Document encrypted under policy: (Role:Engineer OR Role:Manager) AND Clearance:Level-3 AND Epoch:1.")
    add_bullet("Step 3: Alice decrypts using Epoch 1 key -> SUCCESS (valid PDF recovered).")
    add_bullet("Step 4: System epoch advanced 1 -> 2.")
    add_bullet("Step 5: Document re-encrypted under updated policy embedding Epoch:2.")
    add_bullet("Steps 6 & 7: Alice attempts decryption using OLD Epoch 1 key -> MATHEMATICAL REVOCATION VERIFIED (AccessDeniedError).")
    add_bullet("Step 8: Alice claims updated key embedding Epoch:2 -> Key v2 generated.")
    add_bullet("Step 9: Alice decrypts using updated Epoch 2 key -> SUCCESS (valid PDF recovered).")
    add_bullet("Peer Test 1: Revoked user Bob (Role:Student, Epoch:2) attempts decryption -> MATHEMATICALLY DENIED.")
    add_bullet("Peer Test 2: Authorized peer Charlie (Role:Manager, Epoch:2) attempts decryption -> SUCCESS.")

    add_h2("Frontend Production Build Verification:")
    add_p("Executed npm run build using Vite 8.3.6: 93 modules transformed; the client production bundle builds with 0 errors.")

    # =========================================================================
    # 23. THREAT MODEL
    # =========================================================================
    add_h1("23. Threat Model")
    add_p(
        "A threat model states who the adversary is, what they can do, which components we trust, and exactly what "
        "SecureVault promises. Every guarantee in this report is conditional on the assumptions below."
    )
    add_h2("23.1 Parties and Trust Assumptions")
    add_table_data(
        ["Party", "Trust Level", "Assumption"],
        [
            ["Trusted Authority (TA)", "Fully trusted", "Runs Setup and KeyGen, holds the master secret key MK, and assigns attributes honestly. Co-located with the backend in this prototype."],
            ["Backend server / storage", "Honest-but-curious", "Executes the protocol correctly but may read everything it stores (DB, ciphertext blobs, wrapped keys). Storage, backups and snapshots may leak to outsiders."],
            ["Administrator", "Trusted for attributes only", "May change attributes and rotate epochs, but never learns user passwords and cannot unwrap user keys."],
            ["Registered users", "Untrusted / possibly malicious", "May lie, collude with each other, keep old keys after revocation, and tamper with any ciphertext they can reach."],
            ["Network attacker", "Untrusted", "Can observe and replay traffic. TLS (terminated by Railway/Vercel) is assumed for confidentiality in transit."],
            ["Client browser", "Trusted by its own user", "Receives plaintext only for documents the user is authorized to read."],
        ]
    )
    add_h2("23.2 Trust Boundaries")
    add_bullet("Browser to API (HTTPS): every request crosses an authentication boundary checked by the signed bearer token.", bold_prefix="B1: ")
    add_bullet("API to Trusted Authority: only the CryptoService touches MK; MK lives in memory and is stored on disk only as a PBKDF2 + AES-256-GCM envelope keyed by MASTER_KEY_PASSPHRASE (an environment secret, never in git).", bold_prefix="B2: ")
    add_bullet("Application to storage: everything written to SQLite and the encrypted/ folder is ciphertext, a password hash, or a password-wrapped key.", bold_prefix="B3: ")
    add_bullet("User key envelope: a user's CP-ABE key is unwrapped only in transient memory for one request, using the password the user supplies on that request.", bold_prefix="B4: ")
    add_h2("23.3 Adversaries Considered")
    add_bullet("Under-privileged insider who wants to read documents their attributes don't permit, alone or by colluding with other users.", bold_prefix="A1: ")
    add_bullet("Storage thief: obtains a copy of the database, ciphertext files and encrypted master key (stolen backup, misconfigured bucket, rogue DBA).", bold_prefix="A2: ")
    add_bullet("Revoked user: still holds a pre-revocation private key and tries to keep using it.", bold_prefix="A3: ")
    add_bullet("Active tamperer: modifies stored ciphertexts or audit rows to change content or erase evidence.", bold_prefix="A4: ")
    add_bullet("Remote attacker: guesses passwords online, measures response timing, or tries to self-register with elevated attributes.", bold_prefix="A5: ")
    add_h2("23.4 Security Guarantees")
    add_bullet("Confidentiality under policy: a document is readable only with a key whose attribute set satisfies its access tree (IND-CPA security of BSW07 in the generic group model).", bold_prefix="G1: ")
    add_bullet("Collusion resistance: users cannot combine keys to satisfy a policy none of them satisfies alone.", bold_prefix="G2: ")
    add_bullet("Integrity: any modification of the CP-ABE ciphertext or the AES-GCM payload is detected before plaintext is released.", bold_prefix="G3: ")
    add_bullet("Forward revocation: after an epoch rotation and re-encryption, old keys cannot open re-encrypted documents.", bold_prefix="G4: ")
    add_bullet("Accountability: modification, insertion, deletion or reordering of audit records is detected by HMAC chain verification.", bold_prefix="G5: ")
    add_h2("23.5 Out of Scope (Explicit Non-Guarantees)")
    add_bullet("Compromise of the running TA process: an attacker with code execution inside the backend while it runs can read MK from memory and mint any key. A production deployment would isolate the TA in an HSM or KMS.")
    add_bullet("Plaintext already released: CP-ABE cannot stop an authorized user from sharing a decrypted file, and revocation is not retroactive for documents the user already downloaded.")
    add_bullet("Server-side decryption: decryption runs on the backend, so the server sees plaintext transiently. Client-side decryption (WebAssembly pairings) would remove this, at a significant usability cost.")
    add_bullet("Denial of service against the hosting provider, and physical/side-channel attacks on the host CPU.")

    # =========================================================================
    # 24. ATTACK SURFACE MAPPING
    # =========================================================================
    add_h1("24. Attack Surface Mapping")
    add_p("Each externally reachable entry point and data store, what an attacker could try there, and the control that applies:")
    add_table_data(
        ["Entry Point / Asset", "Potential Vulnerability / Leakage", "Control in SecureVault"],
        [
            ["POST /api/auth/login", "Online password guessing; username enumeration via timing or error text.", "5-failure lockout per (username, IP), HTTP 429 + Retry-After; dummy PBKDF2 for unknown users; identical 401 body."],
            ["POST /api/auth/register", "Self-registration with Clearance:Level-3 or system_role=admin (privilege escalation).", "Admin-only after bootstrap; role whitelist; first account forced to admin. (Found and fixed during security review.)"],
            ["Bearer tokens", "Forgery, tampering, replay after expiry.", "HMAC-SHA256 signature with constant-time compare; 24 h expiry; user re-loaded from DB on each request."],
            ["POST /api/documents/upload", "Oversized uploads exhausting memory; malicious filenames.", "20 MB MAX_CONTENT_LENGTH (HTTP 413); files stored under random UUID names, never user-supplied paths."],
            ["POST /api/documents/<id>/decrypt", "Policy bypass; wrong-password key unwrap; crash on forged ciphertext.", "CP-ABE decides access (HTTP 403); envelope unwrap fails closed; forged/colluded ciphertexts mapped to Access Denied instead of HTTP 500."],
            ["/api/admin/*, /api/audit/*", "Horizontal/vertical privilege escalation.", "@require_admin re-checks role from the database, not from the token claim alone."],
            ["/api/attacks/*", "Leaking real key material through the demo.", "Runs on a throw-away sandbox authority; returns verdicts and timings only."],
            ["Error responses", "Stack traces / exception text disclosure.", "Generic 500 body unless FLASK_DEBUG=true."],
            ["CORS", "Malicious site calling the API with a victim's session.", "Explicit origin allowlist, no wildcard."],
            ["storage/securevault.db", "Theft of password hashes and wrapped keys.", "Salted PBKDF2 (100k); keys AES-256-GCM wrapped per user; storage/ excluded from git and the Docker image."],
            ["storage/keys/master_secret_key.enc", "Theft of the master key file.", "AES-256-GCM envelope; passphrase only in deployment secrets (a random Railway service variable, never in git)."],
            ["storage/encrypted/*.enc", "Reading or modifying document blobs.", "AES-256-GCM; key only recoverable through CP-ABE."],
            ["audit_logs table", "Editing or deleting evidence.", "HMAC-SHA256 chain with an out-of-DB secret; verification endpoint (tail truncation is a known limitation)."],
        ]
    )

    # =========================================================================
    # 25. SIMULATED ATTACKS AND COUNTERMEASURES (ATTACK LAB)
    # =========================================================================
    add_h1("25. Simulated Attacks and Countermeasures (Attack Lab)")
    add_p(
        "SecureVault ships an Attack Lab page (/attacks) and API (POST /api/attacks/<id>/run). Each attack runs real cryptography "
        "against a fresh sandbox Trusted Authority, never the production master key, and every run is written to the audit log as "
        "ATTACK_SIMULATION. The results below are the actual output of crypto/attack_simulator.py and are re-checked on every test "
        "run by tests/test_attack_lab.py."
    )
    add_table_data(
        ["#", "Attack", "What the Attacker Does", "Observed Result", "Countermeasure"],
        [
            ["1", "Collusion (key merging)", "Bob {Student, L3} and David {Engineer, L2} build a merged key {Engineer, L3}.", "Each alone: POLICY_UNSATISFIED. Merged: PAIRING_MISMATCH, nothing recovered.", "Per-user randomness r in every key component; e(g,g)^(rs) cannot be cancelled across users."],
            ["2", "Policy tampering", "Rewrites the ciphertext policy Role:Engineer to Role:Student and relabels C_y / C'_y.", "PAIRING_MISMATCH; session secret not recovered.", "C'_y = H(attr)^q_y(0) binds the hash of the real attribute; AEAD seal over the ciphertext."],
            ["3", "Ciphertext bit-flip", "Flips one bit at the start, middle and end of the AES payload, and in the GCM tag.", "4/4 modifications rejected; authorized baseline still decrypts.", "AES-256-GCM authentication tag verified before any plaintext is returned."],
            ["4", "Revoked-key replay", "Keeps an Epoch:1 key and opens a document re-encrypted under Epoch:2.", "Before rotation: GRANTED. After: DENIED. Re-issued Epoch:2 key: GRANTED.", "Epoch attribute inside the access tree + staged re-encryption."],
            ["5", "Password brute force", "10-word dictionary attack (correct password at #9); offline cracking estimate.", "Locked out after 5 wrong guesses; not cracked. PBKDF2 26.1 ms vs SHA-256 0.42 µs per guess (~61,600x).", "Per-(user, IP) lockout + HTTP 429; salted PBKDF2-HMAC-SHA256, 100,000 iterations."],
            ["6", "Timing side channel", "Times login rejection for existing vs non-existent usernames.", "Naive gap 26.0 ms (leaks). SecureVault gap 0.6 ms.", "Dummy PBKDF2 for unknown users, constant-time compare, identical error body."],
        ]
    )
    add_callout(
        "Two of these countermeasures were added because the security review found real flaws. (1) /api/auth/register was public "
        "and accepted any attributes and system_role, so anyone could make themselves an admin with Level-3 clearance, which "
        "defeats the whole point of an attribute authority. It is now admin-only. (2) Charm 0.63 raises InvalidCiphertext when a "
        "forged or colluded key produces the wrong session element. That exception was unhandled, so a collusion attempt crashed "
        "the request with HTTP 500. It is now classified as PAIRING_MISMATCH and returned as Access Denied (HTTP 403).",
        title="VULNERABILITIES FOUND AND PATCHED"
    )

    # =========================================================================
    # 26. SECURITY VS USABILITY TRADE-OFFS
    # =========================================================================
    add_h1("26. Security vs. Usability Trade-offs")
    add_p("Measured on the development machine (WSL2, single core per operation, mean of 5 runs, benchmark_performance.py):")
    add_table_data(
        ["Operation", "Latency", "Notes"],
        [
            ["TA Setup (BN254)", "32.2 ms", "One-time per deployment."],
            ["KeyGen, 2 / 4 / 8 attributes", "5.0 / 8.6 / 13.3 ms", "Linear in the number of attributes."],
            ["Hybrid encrypt, 1 KB / 100 KB / 1 MB", "29.3 / 27.5 / 28.5 ms", "Dominated by the CP-ABE KEM; AES-GCM cost is negligible."],
            ["Authorized decrypt", "154.4 ms", "Pairings scale with the number of satisfied leaves + integrity check."],
            ["Denied decrypt", "2.4 ms", "Charm prunes the tree before any pairing."],
            ["Key-envelope unlock (PBKDF2 100k)", "13.0 ms", "Paid on every decrypt and login."],
        ]
    )
    add_bullet(
        "Raising iterations from 100k to 600k (the OWASP 2023 recommendation for PBKDF2-SHA256) would make offline cracking 6x "
        "harder but add ~65 ms to every login and decrypt. 100k keeps interactive latency low; Argon2id would be the better upgrade.",
        bold_prefix="PBKDF2 cost: "
    )
    add_bullet(
        "Ciphertext size and decryption time grow linearly with the number of attributes in the policy. Rich policies with dozens "
        "of leaves would push decryption toward a second; the 3-4 leaf policies used here stay well under 200 ms.",
        bold_prefix="Policy expressiveness: "
    )
    add_bullet(
        "Epoch rotation gives real cryptographic revocation, but every user must claim a new key and every affected document must "
        "be re-encrypted (one decrypt + one encrypt each, ~0.2 s per document). Key claiming is folded into the next login so users "
        "barely notice; re-encryption is an explicit admin action.",
        bold_prefix="Revocation cost: "
    )
    add_bullet(
        "A lockout of 5 failures / 60 s stops online guessing (~7,200 guesses per day at most per IP instead of thousands per "
        "second) but can briefly lock out a user who mistypes. Keying on (username, IP) prevents attackers from locking victims out remotely.",
        bold_prefix="Lockout policy: "
    )
    add_bullet(
        "Denied decryptions return in 2.4 ms versus 154 ms for successful ones. This reveals whether the policy was satisfied, but "
        "the user learns that from the response anyway, so it is not an additional leak. It also makes denials cheap for the server.",
        bold_prefix="Timing of denials: "
    )
    add_bullet(
        "Decrypting on the server keeps the browser simple and fast, but the server sees plaintext transiently (see 23.5).",
        bold_prefix="Server-side decryption: "
    )

    # =========================================================================
    # 28. DEPLOYMENT AND SOURCE CONTROL  (numbered after Security Analysis)
    # =========================================================================
    def add_deployment_section():
        add_h1("28. Deployment, Connectivity and Source Control")
        add_p("The application is publicly deployed on free cloud platforms and reachable for peer interaction:")
        add_table_data(
            ["Component", "Platform", "Public URL"],
            [
                ["Web application (frontend)", "Vercel", LIVE_APP_URL],
                ["REST API (backend)", "Railway (Docker)", LIVE_API_URL + "/health"],
                ["Source code, report and slides", "GitHub", GITHUB_URL],
            ]
        )
        add_bullet("backend/Dockerfile builds Ubuntu 24.04 with PBC 0.5.14 (download verified against its SHA-256 over TLS) and Charm-Crypto pinned to the exact commit the test suite passes on, then runs Gunicorn as an unprivileged user (UID 1000) that can write only to storage/. Railway builds it from the backend/ folder on every push to main and only routes traffic once GET /api/health answers.", bold_prefix="Backend: ")
        add_bullet("The React/Vite frontend is built by Vercel from the frontend/ folder (frontend/vercel.json provides SPA rewrites). VITE_API_BASE_URL points it at the Railway API.", bold_prefix="Frontend: ")
        add_bullet("FLASK_ENV=production enables a startup check that refuses to boot with missing or development-default secrets. JWT_SECRET, AUDIT_HMAC_SECRET and MASTER_KEY_PASSPHRASE are strong random values stored as Railway service variables and never committed.", bold_prefix="Secrets: ")
        add_bullet("CORS_ALLOWED_ORIGINS lists only the Vercel origin (plus localhost for development), so other websites cannot call the API from a browser.", bold_prefix="CORS: ")
        add_bullet("backend/storage/ (database, encrypted master key, ciphertexts) is excluded by .gitignore and .dockerignore, so no key material ever reaches GitHub or the image. Each deployment creates its own Trusted Authority on first boot.", bold_prefix="Key hygiene: ")
        add_bullet("The free Railway service has no persistent volume, so the backend auto-seeds the demo personas and an encrypted sample document whenever it starts with an empty database (SEED_DEMO_DATA=true).", bold_prefix="Ephemeral storage: ")
        add_bullet("Gunicorn runs one worker process with four threads: the master key is created once, and the login rate limiter and SQLite file are shared by every request.", bold_prefix="Process model: ")
        add_bullet("REST endpoints: /api/auth, /api/documents, /api/admin, /api/audit, /api/attacks and /api/health, all JSON over HTTPS.", bold_prefix="API: ")
        add_bullet("render.yaml is kept as an equivalent Render Blueprint; Railway was used because Render requires a payment card even for its free tier.", bold_prefix="Alternative: ")

    # =========================================================================
    # 27. SECURITY ANALYSIS
    # =========================================================================
    add_h1("27. Security Analysis Summary")
    add_table_data(
        ["Threat Vector", "Vulnerability in Standard Systems", "SecureVault Mitigation & Proof"],
        [
            ["Database Theft / Leakage", "Raw tables reveal document contents and plaintext keys.", "All documents stored as AES-256-GCM ciphertexts; keys encrypted via PBKDF2/AES-GCM envelopes."],
            ["Curious Administrator", "Admin reads files directly from the filesystem.", "Files are ciphertext; user keys are wrapped under the user's password, which admins never receive. (A fully compromised TA process is out of scope, see 23.5.)"],
            ["Collusion Between Users", "Group keys or shared secrets let users pool privileges.", "BSW07 per-user randomisation; merged keys fail (Attack Lab #1)."],
            ["Self-Assigned Attributes", "Open sign-up lets users choose their own role/clearance.", "Only the Trusted Authority (admin) enrols users and assigns attributes."],
            ["Password Guessing / Enumeration", "Unlimited login attempts; faster rejection for unknown users.", "Lockout + HTTP 429; constant-work login path (Attack Lab #5, #6)."],
            ["Revoked Users", "Old credentials keep working after role change.", "Epoch attribute + re-encryption; old keys mathematically denied (Attack Lab #4)."],
            ["Unauthorized Access / Policy Bypass", "Bypassing frontend/SQL allows unauthorized file reads.", "Mathematical CP-ABE enforcement; bilinear pairing reconstruction fails without required attributes."],
            ["Ciphertext Tampering", "Flipping bits in encrypted data goes unnoticed.", "AES-256-GCM produces 128-bit authentication tags; TamperError triggered on mismatch."],
            ["Cross-Origin Attacks (CORS)", "Wildcard CORS (*) exposes authenticated endpoints to malicious web pages.", "Strict allowlist (DEFAULT_CORS_ORIGINS); untrusted origins blocked by browser SOP."],
            ["Audit Log Tampering", "Attacker modifies or drops incriminating log rows.", "HMAC-SHA256 sequential hash chaining; any modification or deletion invalidates the chain."]
        ]
    )

    # =========================================================================
    # 24. KNOWN LIMITATIONS AND FUTURE IMPROVEMENTS
    # =========================================================================
    add_deployment_section()

    # =========================================================================
    # 29. IMPLEMENTATION HURDLES AND LESSONS LEARNED
    # =========================================================================
    add_h1("29. Implementation Hurdles and Lessons Learned")
    add_p("The main problems met while building and deploying SecureVault, what caused them, and how each was resolved:")
    add_table_data(
        ["Hurdle", "Root Cause", "Resolution"],
        [
            ["Charm-Crypto does not build on Windows", "Charm wraps the C libraries PBC and GMP and targets Linux.", "Development and tests run in WSL2 Ubuntu; production uses a Linux Docker image that compiles PBC and Charm from source."],
            ["Policy attributes such as Clearance:Level-3 failed to parse", "Charm's policy parser reserves the pattern _<digit> for repeated-attribute indices and expects lowercase and/or.", "CharmEngine.format_attribute/format_policy normalise attributes (CLEARANCE_LEVEL3) and operators before every KeyGen and Encrypt."],
            ["Collusion attempts crashed the API with HTTP 500", "Charm 0.63 seals ciphertexts with an AEAD tag and raises InvalidCiphertext on a wrong session element.", "decrypt_detailed() classifies the failure (POLICY_UNSATISFIED, PAIRING_MISMATCH, MALFORMED) and the API answers a clean 403 Access Denied."],
            ["Charm release tag incompatible", "The tagged v0.63 release fails the project's crypto tests; the working local build came from a later commit.", "Built and tested both; the Dockerfile pins Charm to commit b2db00b, on which all 30 crypto and Attack Lab tests pass."],
            ["Cloud build failed downloading PBC", "Stanford moved pbc-0.5.14.tar.gz from /pbc/news/ to /pbc/files/ (HTTP 404), and the old step disabled TLS checks.", "New URL, TLS verification restored, and the tarball pinned by SHA-256 so a tampered download fails the build (supply-chain check)."],
            ["Container crashed on start (health check failed)", "pyparsing, needed by Charm's policy parser, was installed system-wide locally but is not pulled in by Charm's installer.", "Diagnosed from the deploy logs; pyparsing==3.1.1 (the tested version) added to requirements.txt."],
            ["Free hosting for a native-code backend", "Render requires a card; Hugging Face made Docker Spaces paid; Cloudflare Workers cannot load native C extensions and Containers are paid.", "Backend on Railway (Docker, trial credit, no card); frontend on Vercel (static build)."],
            ["Live site could not log in", "The API's CORS allowlist contained only localhost.", "CORS_ALLOWED_ORIGINS set to the Vercel origin; unknown origins still receive no CORS header."],
            ["Ephemeral disk and multiple workers", "A fresh container has an empty database; several Gunicorn workers would each create a different master key.", "Auto-seeding on an empty database, and a single worker with threads."],
            ["Flaky timing-attack measurement", "Network and scheduler noise swamped a fixed millisecond threshold.", "Interleaved sampling of known/unknown usernames and a relative criterion (mitigated gap < 50% of the unmitigated gap)."],
            ["Privilege escalation found in review", "The original /register endpoint let anyone create an account with any attributes or the admin role.", "Registration is admin-only after the bootstrap account; roles are whitelisted (regression-tested)."],
        ]
    )
    add_p("Lessons: pin and verify every third-party build input, test the exact artifact that is deployed rather than a developer machine, and treat deploy logs and health checks as part of the security pipeline.")

    add_h1("30. Known Limitations and Future Improvements")
    add_bullet(
        "The HMAC-SHA256 audit chain detects any inline row alteration, insertion, or reordering. However, if an attacker "
        "with root database access truncates the table from the tail (deleting the last k records), the remaining prefix is "
        "still internally valid. Mitigation: Publish periodic head hashes to an external immutable checkpoint (WORM storage or witness server).",
        bold_prefix="1. Audit Tail Truncation: "
    )
    add_bullet(
        "Master Authority Key (MK) protection relies on MASTER_KEY_PASSPHRASE in the environment. In a production cloud deployment, "
        "the authority key should reside inside a dedicated Hardware Security Module (HSM) or cloud KMS.",
        bold_prefix="2. Hardware Security Module (HSM) Integration: "
    )
    add_bullet(
        "Currently, re-encryption is initiated per-document or via batch admin triggers. Future versions could integrate "
        "automated background worker queues (e.g. Celery/Redis) for continuous staged re-encryption across millions of records.",
        bold_prefix="3. Asynchronous Worker Re-encryption: "
    )
    add_bullet(
        "BN254 offers roughly 100-bit security after the exTNFS attacks. Migrating to BLS12-381 (about 128-bit) needs a pairing "
        "library that supports it for ABE; Charm's PBC backend does not ship that curve.",
        bold_prefix="4. Curve Strength: "
    )
    add_bullet(
        "The login rate limiter keeps its counters in process memory. That is correct for the single-worker deployment, but a "
        "horizontally scaled deployment would need a shared store such as Redis.",
        bold_prefix="5. Rate-Limiter State: "
    )
    add_bullet(
        "The free hosting tier has an ephemeral disk: uploaded documents disappear when the instance restarts, and a new authority "
        "is generated. A persistent disk or managed database is required for real use.",
        bold_prefix="6. Persistent Storage: "
    )
    add_bullet(
        "The KEM derives the AES key as SHA-256(str(M)). A dedicated KDF (HKDF over the canonical serialization of M, with a "
        "context label) would be cleaner, although Charm 0.63's own AEAD seal over the ciphertext already authenticates the KEM.",
        bold_prefix="7. KEM Key Derivation: "
    )

    # =========================================================================
    # 25. CONCLUSION
    # =========================================================================
    add_h1("31. Conclusion")
    add_p(
        "SecureVault demonstrates the practical, high-performance implementation of Ciphertext-Policy Attribute-Based Encryption "
        "within a full-stack document repository. By integrating genuine BSW07 bilinear pairings over the BN254 elliptic curve with "
        "AES-256-GCM hybrid encryption, SecureVault elevates data protection from server-dependent administrative rules to mathematical "
        "cryptographic guarantees. The project successfully overcomes the classic ABE revocation bottleneck through its Epoch-Based "
        "Revocation Lifecycle and asynchronous key-claiming workflow, while guaranteeing audit accountability via HMAC-SHA256 hash chaining."
    )
    add_p(
        f"Backed by {TOTAL_TESTS} automated test cases passing at 100%, an explicit threat model, and an Attack Lab that empirically "
        "defeats collusion, policy tampering, ciphertext tampering, revoked-key replay, brute force and timing attacks, SecureVault "
        "shows that fine-grained, policy-based access control can be enforced by cryptography rather than by trusting the server."
    )

    # =========================================================================
    # 26. REFERENCES
    # =========================================================================
    add_h1("32. References")
    add_bullet("Bethencourt, J., Sahai, A., & Waters, B. (2007). Ciphertext-policy attribute-based encryption. In 2007 IEEE Symposium on Security and Privacy (SP '07) (pp. 321-334). IEEE.", bold_prefix="[1] ")
    add_bullet("Goyal, V., Pandey, O., Sahai, A., & Waters, B. (2006). Attribute-based encryption for fine-grained access control of encrypted data. In Proceedings of the 13th ACM conference on Computer and Communications Security (CCS '06) (pp. 89-98).", bold_prefix="[2] ")
    add_bullet("Akinyele, J. A., Garman, C., Miers, I., Pagano, M. W., Rushanan, M., Green, M., & Rubin, A. D. (2013). Charm: a framework for rapidly prototyping cryptosystems. Journal of Cryptographic Engineering, 3(2), 111-128.", bold_prefix="[3] ")
    add_bullet("National Institute of Standards and Technology (NIST). (2007). Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. NIST Special Publication 800-38D.", bold_prefix="[4] ")
    add_bullet("National Institute of Standards and Technology (NIST). (2000). Password-Based Cryptography Specification (PBKDF2). RFC 2898 / PKCS #5 v2.0.", bold_prefix="[5] ")
    add_bullet("Krawczyk, H., Bellare, M., & Canetti, R. (1997). HMAC: Keyed-Hashing for Message Authentication. RFC 2104.", bold_prefix="[6] ")
    add_bullet("Rundgren, A., Jordan, B., & Erdtman, S. (2020). JSON Canonicalization Scheme (JCS). RFC 8785.", bold_prefix="[7] ")
    add_bullet("Barreto, P. S., & Naehrig, M. (2005). Pairing-friendly elliptic curves of prime order. In Selected Areas in Cryptography (SAC 2005) (pp. 319-331). Springer, Berlin, Heidelberg.", bold_prefix="[8] ")
    add_bullet("Kim, T., & Barbulescu, R. (2016). Extended Tower Number Field Sieve: A New Complexity for the Medium Prime Case. In CRYPTO 2016 (pp. 543-571). Springer.", bold_prefix="[9] ")
    add_bullet("OWASP Foundation. (2023). Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html", bold_prefix="[10] ")

    # =========================================================================
    # APPENDIX A. APPLICATION SCREENSHOTS
    # =========================================================================
    shots = [(f, c) for f, c in SCREENSHOTS if os.path.exists(os.path.join(SCREENSHOT_DIR, f))]
    if shots:
        doc.add_page_break()
        add_h1("Appendix A. Application Screenshots")
        add_p("Captured from the running application (localhost, November 2026).")
        for i, (fname, caption) in enumerate(shots, start=1):
            pic = doc.add_paragraph()
            pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
            pic.paragraph_format.keep_with_next = True
            pic.add_run().add_picture(os.path.join(SCREENSHOT_DIR, fname), width=Inches(6.3))
            cap = doc.add_paragraph()
            cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            cap.paragraph_format.space_after = Pt(14)
            r_cap = cap.add_run(f"Figure A.{i}: {caption}")
            r_cap.italic = True
            r_cap.font.size = Pt(9.5)
            r_cap.font.color.rgb = DARK_GRAY

    doc.save(filepath)
    print(f"[OK] DOCX Report successfully saved to: {filepath}")


def build_pdf_report(filepath):
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0F2C59'),
        alignment=1, # Center
        spaceAfter=10
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#008080'),
        alignment=1,
        spaceAfter=25
    )

    h1_style = ParagraphStyle(
        'DocH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=colors.HexColor('#0F2C59'),
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#008080'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#262626'),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'DocBullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#262626'),
        leftIndent=15,
        spaceAfter=4
    )

    callout_style = ParagraphStyle(
        'DocCallout',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#0F2C59'),
    )

    th_style = ParagraphStyle(
        'DocTH',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    td_style = ParagraphStyle(
        'DocTD',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#262626')
    )

    story = []

    # Title Page
    story.append(Spacer(1, 40))
    story.append(Paragraph("SECUREVAULT", title_style))
    story.append(Paragraph("CP-ABE Based Secure Document Locker with Hybrid Encryption,<br/>Dynamic Attribute Management, and Tamper-Evident Audit Logging", subtitle_style))
    story.append(HRFlowable(width="80%", thickness=2, color=colors.HexColor('#0F2C59'), spaceAfter=40))

    meta_text = (
        "<b>A Final Year University Project Report Submitted in Partial Fulfillment<br/>"
        "of the Requirements for the Degree of<br/><br/>"
        "BACHELOR OF SCIENCE IN CYBER SECURITY / COMPUTER SCIENCE</b><br/><br/><br/>"
        "<b>Team Members:</b><br/>"
        + "".join(f"{name} ({roll})<br/>" for name, roll in TEAM_MEMBERS) +
        "<b>Academic Session:</b> 2025 – 2026<br/>"
        "<b>Department:</b> Department of Cyber Security & Computer Science<br/>"
        "<b>Submission Date:</b> November 2026"
    )
    story.append(Paragraph(meta_text, ParagraphStyle('Meta', parent=styles['Normal'], fontName='Helvetica', fontSize=11, leading=16, alignment=1, textColor=colors.HexColor('#0F2C59'))))
    story.append(PageBreak())

    def make_table(headers, data, col_widths=None):
        table_data = [[Paragraph(h, th_style) for h in headers]]
        for row in data:
            table_data.append([Paragraph(str(c), td_style) for c in row])
        t = Table(table_data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F2C59')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ]))
        return t

    # 2. Abstract
    story.append(Paragraph("2. Abstract", h1_style))
    story.append(Paragraph(
        "Modern cloud-hosted document repositories face severe security risks regarding data confidentiality, privilege escalation, and rogue administrators. Conventional discretionary access control (DAC) and role-based access control (RBAC) mechanisms enforce authorization at the software or database layer; consequently, any attacker gaining raw disk access, physical storage snapshots, or compromised database credentials can immediately exfiltrate all stored files in plaintext.",
        body_style
    ))
    story.append(Paragraph(
        "SecureVault addresses these vulnerabilities by engineering an end-to-end secure document locker utilizing Ciphertext-Policy Attribute-Based Encryption (CP-ABE). Based on the Bethencourt-Sahai-Waters (BSW07) scheme instantiated over the BN254 pairing-friendly elliptic curve (Stanford PBC library), SecureVault embeds boolean access policies directly into document ciphertexts. SecureVault uses a two-tier Hybrid Encryption system: a Key Encapsulation Mechanism (KEM) via CP-ABE protects an ephemeral group element, which derives a 256-bit AES key via SHA-256 to encrypt the document body using AES-256-GCM (DEM) with authenticated integrity tags. To solve the notorious revocation bottleneck in attribute-based encryption, SecureVault incorporates an Epoch-Based Revocation Lifecycle with asynchronous user key claiming, ensuring administrators never handle user passwords. Finally, SecureVault introduces a tamper-evident audit logging architecture using canonical JSON serialization and HMAC-SHA256 sequential hash chaining. Backed by 59 passing automated tests and a production-built React 19 interface, SecureVault provides a zero-trust cryptographic document storage foundation.",
        body_style
    ))

    # 3. Introduction
    story.append(Paragraph("3. Introduction", h1_style))
    story.append(Paragraph(
        "In the contemporary enterprise landscape, organizations store and exchange sensitive intellectual property, classified legal records, defense schematics, and medical histories over untrusted networks and shared multi-tenant cloud infrastructure. While traditional security perimeters rely on network firewalls and database access control lists, these safeguards are vulnerable to insider threats, SQL injection, privilege abuse, and cloud hypervisor compromises.",
        body_style
    ))
    story.append(Paragraph(
        "To achieve genuine zero-trust data protection, data must be encrypted cryptographically in such a manner that access decisions are made mathematically at the cryptographic layer rather than administratively by the database server. Ciphertext-Policy Attribute-Based Encryption (CP-ABE) represents a revolutionary paradigm: ciphertexts are labeled with access policies (e.g., '(Role:Engineer OR Role:Manager) AND Clearance:Level-3'), while private keys are bound to user attribute sets. Decryption is mathematically possible if and only if the attributes satisfy the ciphertext policy tree.",
        body_style
    ))

    # 4. Problem Statement
    story.append(Paragraph("4. Problem Statement", h1_style))
    story.append(Paragraph("<b>1. Server-Side Privilege Dependence:</b> Traditional database checks mean a malicious DBA or compromised root server directly bypasses application access rules.", bullet_style))
    story.append(Paragraph("<b>2. Group Encryption Inefficiency:</b> Standard PKI (RSA/ECC) requires either O(N) duplicate ciphertexts or shared symmetric keys, destroying accountability.", bullet_style))
    story.append(Paragraph("<b>3. ABE Revocation Bottleneck:</b> Historical ABE systems require full re-keying and system-wide downtime when a user departs or is demoted.", bullet_style))
    story.append(Paragraph("<b>4. Tamper-Vulnerable Audit Trails:</b> Relational logging tables can be modified or deleted by attackers with SQL access, erasing breach evidence.", bullet_style))

    # 5. Project Objectives
    story.append(Paragraph("5. Project Objectives", h1_style))
    story.append(Paragraph("• Implement genuine BSW07 CP-ABE using Charm-Crypto and Stanford PBC over BN254 elliptic curves.", bullet_style))
    story.append(Paragraph("• Build a Hybrid Cipher (KEM/DEM) combining CP-ABE with AES-256-GCM for authenticated, tamper-proof document encryption.", bullet_style))
    story.append(Paragraph("• Engineer dynamic attribute management and asynchronous key-claim workflows without administrator password access.", bullet_style))
    story.append(Paragraph("• Implement an Epoch-Based Revocation Lifecycle that mathematically invalidates expired private keys.", bullet_style))
    story.append(Paragraph("• Establish tamper-evident audit logging using canonical JSON serialization and HMAC-SHA256 sequential chaining.", bullet_style))
    story.append(Paragraph("• Deliver a full-stack platform (Flask REST API + React 19/Vite frontend) validated by 59 automated tests.", bullet_style))

    # 8. Proposed System & Architecture
    story.append(Paragraph("8. Proposed System & Architecture", h1_style))
    story.append(Paragraph(
        "SecureVault guarantees zero-trust security: ciphertexts remain mathematically secure even on completely compromised or public storage. The architecture consists of four distinct layers:",
        body_style
    ))
    story.append(Paragraph("<b>Layer 1 (Client):</b> React 19, Vite, and Tailwind CSS SPA with centralized Axios interceptors for bearer tokens.", bullet_style))
    story.append(Paragraph("<b>Layer 2 (API Gateway):</b> Flask blueprints (/api/auth, /api/admin, /api/documents, /api/audit) with strict CORS allowlists.", bullet_style))
    story.append(Paragraph("<b>Layer 3 (Crypto Core):</b> Singleton CryptoService orchestrating CharmEngine (BSW07), HybridCipher (KEM/DEM), KeyStore, and AuditChain.", bullet_style))
    story.append(Paragraph("<b>Layer 4 (Storage):</b> SQLite (securevault.db) with foreign keys ON, filesystem ciphertext repository, and encrypted authority keys.", bullet_style))

    # 13. Database Schema
    story.append(Paragraph("13. Database Design and Tables", h1_style))
    db_headers = ["Table", "Primary Fields", "Cryptographic Details"]
    db_rows = [
        ["users", "id, username, password_hash, system_role, role_attr, clearance_attr, pending_key_reissue", "PBKDF2-HMAC-SHA256 hashes (100k rounds, salt)."],
        ["user_keys", "id, user_id, key_version, bound_attributes, encrypted_sk, is_active", "AES-256-GCM envelope locked by user password. Zero plaintext."],
        ["documents", "id, stored_filename, access_policy, cpabe_ciphertext, aes_nonce, aes_tag, epoch", "UUID disk reference. Stores KEM ciphertext, nonce, tag, epoch."],
        ["audit_logs", "id, sequence_number, user_id, action, status, details, previous_hash, record_hash", "Tamper-evident log. Monotonic sequence, previous hash, HMAC."],
        ["system_epochs", "id, epoch_number, reason, initiated_by, status, created_at", "Global epoch state machine and re-encryption tracker."]
    ]
    story.append(make_table(db_headers, db_rows, [70, 200, 230]))

    # 14. CP-ABE & Hybrid Cipher
    story.append(Paragraph("14. Cryptographic Engine & Hybrid Cipher", h1_style))
    story.append(Paragraph(
        "<b>Bilinear Pairing:</b> Instantiated over the BN254 Barreto-Naehrig curve: e: G0 x G0 -> GT. Stanford PBC executes pairings in sub-second time. Four core algorithms: Setup(), KeyGen(), Encrypt(), Decrypt().",
        body_style
    ))
    story.append(Paragraph(
        "<b>Hybrid KEM/DEM:</b> The Charm engine samples random M in GT. M is encapsulated under the policy tree using CP-ABE. AES-256 key is derived as SHA-256(str(M)). The document body is encrypted using authenticated AES-256-GCM. Storage overhead is only ~350 bytes for CP-ABE metadata regardless of document size.",
        body_style
    ))

    # 18. Revocation & Audit Chaining
    story.append(Paragraph("18. Epoch Revocation & HMAC Audit Chaining", h1_style))
    story.append(Paragraph(
        "<b>Epoch Revocation:</b> System advances epoch (e.g. 1 -> 2). Documents re-encrypted under updated policy: (Policy) AND Epoch:2. Old Epoch-1 keys fail mathematically (AccessDeniedError). Users claim Epoch-2 keys asynchronously with their own password.",
        body_style
    ))
    story.append(Paragraph(
        "<b>HMAC-SHA256 Audit Chaining:</b> Deterministic canonical JSON (RFC 8785) hashed via dedicated AUDIT_HMAC_SECRET. Previous hash pointer links record i to record i-1. Concurrency safety ensured via SQLite BEGIN IMMEDIATE serialization. Detects edits, swaps, deletions, and insertions.",
        body_style
    ))

    # 22. Test Results
    story.append(Paragraph("22. Verification & Testing Results", h1_style))
    test_headers = ["Test Suite", "Target Component", "Tests", "Passed", "Failed", "Time"]
    test_rows = [
        ["Phase 1 (run_all_tests.py)", "BSW07 CP-ABE, Hybrid Cipher, Access Matrix, KeyStore", "17", "17", "0", "1.939s"],
        ["Phase 2 (test_api.py)", "REST API Endpoints, JWT Auth, Document Decrypt, RBAC", "18", "18", "0", "1.207s"],
        ["Phase 4 (test_phase4_revocation.py)", "Attribute Management, Async Claim, Epoch Revocation", "10", "10", "0", "1.526s"],
        ["Hardening (test_audit_chain_and_cors.py)", "CORS Allowlist, HMAC Chaining, Tamper Detection", "14", "14", "0", "0.733s"],
        ["Total Automated Tests", "Complete Backend & Cryptographic Engine", "59", "59", "0", "5.405s"]
    ]
    story.append(make_table(test_headers, test_rows, [120, 180, 50, 50, 50, 50]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Revocation Demonstration:</b> 9-step live verification executed with 100% success; Alice Epoch 1 key denied on Epoch 2; updated key allowed; Bob denied; Charlie allowed.", body_style))
    story.append(Paragraph("<b>Frontend Production Build:</b> Vite 8.3.6 built 92 modules into client production bundle in 313ms (0 errors, 0 warnings).", body_style))

    # 24. Security Analysis & Limitations
    story.append(Paragraph("24. Security Analysis & Limitations", h1_style))
    story.append(Paragraph("• <b>Zero Data Leakage:</b> Passwords, bearer tokens, private keys, and HMAC secret never appear in audit records or plaintext disk files.", bullet_style))
    story.append(Paragraph("• <b>CORS Hardening:</b> Wildcard origins eliminated; strict allowlist restricted to localhost:5173 / configured production domains.", bullet_style))
    story.append(Paragraph("• <b>Audit Tail Truncation:</b> Internal hash chain detects inline edits, reordering, and deletions; external trusted checkpoints (e.g. WORM storage) recommended to detect tail truncation.", bullet_style))

    # 25. Conclusion
    story.append(Paragraph("25. Conclusion", h1_style))
    story.append(Paragraph(
        "SecureVault demonstrates the practical, high-performance implementation of Ciphertext-Policy Attribute-Based Encryption within a full-stack document repository. By integrating genuine BSW07 bilinear pairings over the BN254 elliptic curve with AES-256-GCM hybrid encryption, SecureVault elevates data protection from server-dependent administrative rules to mathematical cryptographic guarantees. The project successfully overcomes the classic ABE revocation bottleneck through its Epoch-Based Revocation Lifecycle and asynchronous key-claiming workflow, while guaranteeing audit accountability via HMAC-SHA256 hash chaining. Backed by 59 passing automated tests and a production-grade user interface, SecureVault provides an authentic zero-trust foundation for modern enterprise data security.",
        body_style
    ))

    doc.build(story)
    print(f"[OK] PDF Report successfully saved to: {filepath}")


def export_pdf_with_word(docx_path, pdf_path):
    """Export the DOCX to PDF through Microsoft Word (Windows) so the PDF matches the DOCX exactly."""
    try:
        import win32com.client  # pywin32
    except ImportError:
        return _export_pdf_with_powershell(docx_path, pdf_path)
    word = win32com.client.DispatchEx("Word.Application")
    word.Visible = False
    try:
        d = word.Documents.Open(docx_path, ReadOnly=True)
        d.SaveAs(pdf_path, FileFormat=17)  # 17 = wdFormatPDF
        d.Close(False)
    finally:
        word.Quit()
    print(f"[OK] PDF Report (Word export) saved to: {pdf_path}")
    return True


def _export_pdf_with_powershell(docx_path, pdf_path):
    import subprocess
    if os.name != "nt":
        return False
    script = (
        "$w = New-Object -ComObject Word.Application; $w.Visible = $false; "
        f"$d = $w.Documents.Open('{docx_path}', $false, $true); "
        f"$d.SaveAs([ref]'{pdf_path}', [ref]17); $d.Close($false); "
        # never close a Word instance the user has other documents open in
        "if ($w.Documents.Count -eq 0) { $w.Quit() }"
    )
    r = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(pdf_path):
        print(r.stderr)
        return False
    print(f"[OK] PDF Report (Word export) saved to: {pdf_path}")
    return True


if __name__ == "__main__":
    deliverables_dir = os.path.abspath("documentation_deliverables")
    os.makedirs(deliverables_dir, exist_ok=True)
    report_docx_path = os.path.join(deliverables_dir, "SecureVault_Project_Report.docx")
    report_pdf_path = os.path.join(deliverables_dir, "SecureVault_Project_Report.pdf")

    print("[*] Generating Final University Project Report...")
    build_docx_report(report_docx_path)
    if not export_pdf_with_word(report_docx_path, report_pdf_path):
        print("[!] Microsoft Word not available - falling back to the condensed ReportLab PDF.")
        build_pdf_report(report_pdf_path)

    print(f"[*] Report written to: {deliverables_dir}")
