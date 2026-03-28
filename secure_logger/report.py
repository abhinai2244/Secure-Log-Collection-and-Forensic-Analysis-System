from fpdf import FPDF
import time
from datetime import datetime

class ForensicReportGenerator:
    """
    Generates PDF Forensic Reports for security incidents and chain integrity.
    """
    def generate(self, log_chain, detection_stats, alerts, output_path="forensic_report.pdf"):
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Helvetica", 'B', 24)
        pdf.set_text_color(0, 51, 102) # Dark Blue
        pdf.cell(0, 20, "Forensic Analysis Report", 0, 1, 'C')
        
        # Subtitle
        pdf.set_font("Helvetica", 'I', 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        pdf.ln(10)

        # 1. Executive Summary
        pdf.set_font("Helvetica", 'B', 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "1. Executive Summary", 0, 1, 'L')
        pdf.set_font("Helvetica", size=11)
        
        integrity = log_chain.verify_integrity()
        status_text = "PASSED" if integrity['valid'] else "FAILED"
        
        summary = (
            f"This report provides a forensic breakdown of log data captured. "
            f"Total Logs Captured: {len(log_chain.chain)}. "
            f"Chain Integrity Status: {status_text}.\n\n"
            f"Detection System identified {len(alerts)} suspicious events."
        )
        pdf.multi_cell(0, 10, summary)
        pdf.ln(5)

        # 2. Blockchain Integrity Proof
        pdf.set_font("Helvetica", 'B', 16)
        pdf.cell(0, 10, "2. Blockchain Integrity Check", 0, 1, 'L')
        pdf.set_font("Helvetica", size=10)
        
        pdf.cell(50, 8, "Block Index", 1)
        pdf.cell(100, 8, "Block Hash (Recalculated)", 1)
        pdf.cell(40, 8, "Status", 1)
        pdf.ln()

        # Show first 10 and last 5 blocks (to keep report short)
        blocks_to_show = log_chain.chain[:10]
        if len(log_chain.chain) > 15:
            blocks_to_show += log_chain.chain[-5:]

        for block in blocks_to_show:
            recalc = block.calculate_hash()
            valid = "VALID" if recalc == block.hash else "TAMPERED"
            pdf.cell(50, 8, str(block.index), 1)
            pdf.cell(100, 8, f"{recalc[:32]}...", 1)
            pdf.set_text_color(255, 0, 0) if valid == "TAMPERED" else pdf.set_text_color(0, 128, 0)
            pdf.cell(40, 8, valid, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.ln()
        
        pdf.ln(10)

        # 3. Security Alerts Timeline
        pdf.set_font("Helvetica", 'B', 16)
        pdf.cell(0, 10, "3. Attack Timeline & Evidence", 0, 1, 'L')
        pdf.set_font("Helvetica", size=10)

        if not alerts:
            pdf.cell(0, 10, "No attacks detected during this period.", 0, 1)
        else:
            for alert in alerts[-20:]: # Last 20 alerts
                pdf.set_font("Helvetica", 'B', 10)
                pdf.cell(0, 8, f"ALERT: {alert['type']} (Risk: {alert['risk_score']})", 0, 1)
                pdf.set_font("Helvetica", size=9)
                pdf.multi_cell(0, 6, f"Evidence: {alert['details']}\nTimestamp: {datetime.now().isoformat()}")
                pdf.ln(2)

        # Footer
        pdf.set_y(-20)
        pdf.set_font("Helvetica", 'I', 8)
        pdf.cell(0, 10, "Confidential - Forensic Analysis System Alpha v2.0", 0, 0, 'C')
        
        pdf.output(output_path)
        return output_path
