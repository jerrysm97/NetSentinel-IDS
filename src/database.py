from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Integer)
    verdict = db.Column(db.String(50))
    category = db.Column(db.String(100))
    threat_badges = db.Column(db.String(500))  # JSON string
    full_json = db.Column(db.Text)  # Store complete analysis JSON

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'timestamp': self.timestamp.isoformat(),
            'risk_score': self.risk_score,
            'verdict': self.verdict,
            'category': self.category,
            'threat_badges': json.loads(self.threat_badges) if self.threat_badges else [],
            'full_json': json.loads(self.full_json) if self.full_json else {}
        }

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(100), nullable=False)  # e.g., "SYN Flood", "Plaintext Leak"
    source_ip = db.Column(db.String(50))
    details = db.Column(db.Text)
    severity = db.Column(db.String(20))  # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type,
            'source_ip': self.source_ip,
            'details': self.details,
            'severity': self.severity
        }
