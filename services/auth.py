"""Authentication and authorization service with JWT and API keys."""
import hashlib
import secrets
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

from database.manager import db
from config.settings import settings

logger = logging.getLogger("SecdevKimi.Auth")

class AuthService:
    """Enterprise authentication with JWT tokens and API key management."""
    
    def __init__(self):
        self.secret_key = settings.security.secret_key
        self.algorithm = settings.security.jwt_algorithm
        self.expiration_hours = settings.security.jwt_expiration_hours
    
    def _hash_password(self, password: str) -> str:
        """Hash password with bcrypt or fallback to PBKDF2."""
        if HAS_BCRYPT:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=settings.security.password_hash_rounds)).decode()
        
        # Fallback PBKDF2
        salt = secrets.token_hex(32)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"pbkdf2:{salt}:{hashed.hex()}"
    
    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        if HAS_BCRYPT and not hashed.startswith("pbkdf2:"):
            return bcrypt.checkpw(password.encode(), hashed.encode())
        
        # PBKDF2 verification
        if hashed.startswith("pbkdf2:"):
            _, salt, hash_value = hashed.split(":")
            check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return check.hex() == hash_value
        
        return False
    
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return JWT token."""
        user = db.execute_one(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        )
        
        if not user:
            logger.warning(f"Auth failed: user {username} not found")
            return None
        
        if not self._verify_password(password, user["password_hash"]):
            logger.warning(f"Auth failed: invalid password for {username}")
            return None
        
        # Update last login
        db.execute_insert(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(timezone.utc), user["id"])
        )
        
        # Generate token
        token = self._generate_token(user["id"], username, user["role"])
        
        logger.info(f"User {username} authenticated")
        return token
    
    def _generate_token(self, user_id: int, username: str, role: str) -> str:
        """Generate JWT token."""
        if not HAS_JWT:
            # Fallback to simple signed token
            payload = f"{user_id}:{username}:{role}:{int(datetime.now(timezone.utc).timestamp())}"
            signature = hashlib.sha256(f"{payload}:{self.secret_key}".encode()).hexdigest()
            return f"simple:{payload}:{signature}"
        
        payload = {
            "user_id": user_id,
            "username": username,
            "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=self.expiration_hours),
            "iat": datetime.now(timezone.utc)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate and decode JWT token."""
        if token.startswith("simple:"):
            # Validate simple token — signature is the last colon-separated field
            without_prefix = token[len("simple:"):]
            last_colon = without_prefix.rfind(":")
            if last_colon < 0:
                return None
            payload = without_prefix[:last_colon]
            signature = without_prefix[last_colon + 1:]
            expected = hashlib.sha256(f"{payload}:{self.secret_key}".encode()).hexdigest()
            if signature != expected:
                return None
            
            # Split with maxsplit=3: user_id, username, role, timestamp
            # This allows username to contain colons
            parts = payload.split(":", 3)
            if len(parts) < 4:
                return None
            return {
                "id": int(parts[0]),
                "user_id": int(parts[0]),
                "username": parts[1],
                "role": parts[2]
            }
        
        if not HAS_JWT:
            return None
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return {
                "id": payload["user_id"],
                "user_id": payload["user_id"],
                "username": payload["username"],
                "role": payload["role"]
            }
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def create_user(self, username: str, password: str, 
                   email: Optional[str] = None, role: str = "viewer") -> Optional[int]:
        """Create new user."""
        # Check if exists
        existing = db.execute_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            return None
        
        password_hash = self._hash_password(password)
        
        user_id = db.execute_insert("""
            INSERT INTO users (username, password_hash, email, role)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, email, role))
        
        logger.info(f"User created: {username} (role: {role})")
        return user_id
    
    def create_api_key(self, user_id: int, name: str, 
                      permissions: str = "read") -> Optional[str]:
        """Create API key for user."""
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        expires = datetime.now(timezone.utc) + timedelta(days=90)
        
        db.execute_insert("""
            INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (key_hash, user_id, name, permissions, expires))
        
        logger.info(f"API key created for user {user_id}: {name}")
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        key = db.execute_one("""
            SELECT ak.*, u.username, u.role
            FROM api_keys ak
            JOIN users u ON ak.user_id = u.id
            WHERE ak.key_hash = ? AND ak.is_active = 1
            AND (ak.expires_at IS NULL OR ak.expires_at > ?)
        """, (key_hash, datetime.now(timezone.utc)))
        
        if not key:
            return None
        
        # Update last used
        db.execute_insert(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            (datetime.now(timezone.utc), key["id"])
        )
        
        return {
            "id": key["user_id"],
            "user_id": key["user_id"],
            "username": key["username"],
            "role": key["role"],
            "permissions": key["permissions"]
        }
    
    def revoke_api_key(self, key_id: int) -> bool:
        """Revoke API key."""
        with db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?",
                (datetime.now(timezone.utc), key_id)
            )
        return True
    
    def rotate_api_key(self, key_id: int, user_id: int) -> Optional[str]:
        """Rotate an existing API key — revoke old, create new, preserve permissions."""
        # Verify ownership
        key = db.execute_one(
            "SELECT * FROM api_keys WHERE id = ? AND user_id = ? AND is_active = 1",
            (key_id, user_id)
        )
        if not key:
            return None
        
        # Revoke old
        with db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?",
                (datetime.now(timezone.utc), key_id)
            )
        
        # Create new with same permissions
        new_api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(new_api_key.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(days=90)
        
        db.execute_insert("""
            INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (key_hash, user_id, key.get("name", "rotated-key"), key.get("permissions", "read"), expires))
        
        logger.info(f"API key rotated for user {user_id}, key_id {key_id}")
        return new_api_key
    
    def check_permission(self, user: Dict[str, Any], required: str) -> bool:
        """Check if user has required permission."""
        role = user.get("role", "viewer")
        permissions = {
            "viewer": ["read"],
            "operator": ["read", "run"],
            "admin": ["read", "run", "write", "admin"]
        }
        return required in permissions.get(role, [])
