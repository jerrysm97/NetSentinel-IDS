# Network Configuration
INTERFACE = "eth0"  # Change to match your interface

# Detection Thresholds
SYN_FLOOD_THRESHOLD = 50  # Packets per second
PLAINTEXT_KEYWORDS = ["password=", "passwd=", "apikey=", "Bearer "]

# Logging Configuration
LOG_FILE = "logs/netsentinel.log"
LOG_LEVEL = "INFO"
