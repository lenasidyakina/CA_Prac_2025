import logging
from pathlib import Path
from pykeepass import PyKeePass, create_database
import os

# Configuration
DATA_DIR = "/var/lib/myapp"
DB_FILENAME = "secrets.kdbx"
DB_PATH = os.path.join(DATA_DIR, DB_FILENAME)


# Logging setup
log_dir = Path("/var/log/myapp")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename='/var/log/myapp/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

try:
    os.makedirs(DATA_DIR, exist_ok=True)
except PermissionError:
    logger.error(f"Permission denied when creating {DATA_DIR}")
    raise

try:
    if not os.path.exists(DB_PATH):
        # First create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        # Then create the database
        db = create_database(filename=DB_PATH, password="prac2025")
        db.save()
        logger.info(f"New KeePassXC database created: {DB_PATH}")
    else:
        db = PyKeePass(filename=DB_PATH, password="prac2025")
        logger.info(f"Existing KeePassXC database opened: {DB_PATH}")
        
except Exception as e:
    logger.error(f"Error working with KeePassXC: {str(e)}", exc_info=True)
    raise  # Re-raise the exception after logging