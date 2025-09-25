import json
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import sys

with open("wipe_certificate.json", "r") as f:
    data = json.load(f)

c = canvas.Canvas("wipe_certificate.pdf", pagesize=A4)
c.setFont("Helvetica-Bold", 16)
c.drawString(200, 800, "Data Wipe Certificate")

c.setFont("Helvetica", 12)
y = 760
c.drawString(100, y, f"Timestamp: {data['timestamp']}")
y -= 20
c.drawString(100, y, f"Digital Signature: {data['signature'][:40]}...")
y -= 40

c.setFont("Helvetica-Bold", 12)
c.drawString(100, y, "Drives Sanitized:")
y -= 20

c.setFont("Helvetica", 10)
for d in data["drives"]:
    c.drawString(100, y, f"{d['drive_name']} - {d['model']} - {d['method']} - {d['result']}")
    y -= 15

c.save()
