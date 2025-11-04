from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional, Dict
import uuid
from datetime import datetime, timezone
import bcrypt
import jwt


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# ==================== IN-MEMORY MOCK DATABASE ====================
# This replaces MongoDB with a simple in-memory dictionary
mock_db: Dict[str, dict] = {}

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Security
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# ==================== MODELS ====================

class PriceEstimate(BaseModel):
    source: str
    currency: str
    low: float
    average: float
    high: float

class GameItem(BaseModel):
    id: Optional[str] = None
    title: str
    publisher: str
    platform: str
    releaseYear: int
    itemType: str = "Game"
    addedAt: Optional[str] = None
    estimatedPrices: Optional[List[PriceEstimate]] = []
    
    model_config = ConfigDict(populate_by_name=True)

class GameItemCreate(BaseModel):
    title: str
    publisher: str
    platform: str
    releaseYear: int
    itemType: str = "Game"
    estimatedPrices: Optional[List[PriceEstimate]] = []

class User(BaseModel):
    id: Optional[str] = None
    email: EmailStr
    createdAt: str
    collection: List[GameItem] = []
    wishlist: List[GameItem] = []
    
    model_config = ConfigDict(populate_by_name=True)

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    email: str


# ==================== HELPER FUNCTIONS ====================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc).timestamp() + (ACCESS_TOKEN_EXPIRE_HOURS * 3600)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Dependency to get current authenticated user"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {"user_id": user_id, "email": payload.get("email")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# ==================== AUTHENTICATION ENDPOINTS ====================

@api_router.post("/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Register a new user"""
    # Check if user already exists
    for user_id, user in mock_db.items():
        if user.get("email") == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    # Create new user
    user_id = str(uuid.uuid4())
    mock_db[user_id] = {
        "id": user_id,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "collection": [],
        "wishlist": []
    }
    
    # Create access token
    access_token = create_access_token({
        "user_id": user_id,
        "email": user_data.email
    })
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=user_id,
        email=user_data.email
    )

@api_router.post("/auth/login", response_model=Token)
async def login(credentials: UserLogin):
    """Login user"""
    # Find user
    user = None
    user_id = None
    for uid, u in mock_db.items():
        if u.get("email") == credentials.email:
            user = u
            user_id = uid
            break
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not verify_password(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Create access token
    access_token = create_access_token({
        "user_id": user_id,
        "email": user["email"]
    })
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=user_id,
        email=user["email"]
    )


# ==================== COLLECTION ENDPOINTS ====================

@api_router.get("/users/{user_id}/collection", response_model=List[GameItem])
async def get_user_collection(
    user_id: str,
    title: Optional[str] = None,
    platform: Optional[str] = None,
    publisher: Optional[str] = None,
    releaseYear: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get user's collection with optional filters"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    collection = user.get("collection", [])
    
    # Apply filters
    if title:
        collection = [item for item in collection if title.lower() in item.get("title", "").lower()]
    if platform:
        collection = [item for item in collection if platform.lower() in item.get("platform", "").lower()]
    if publisher:
        collection = [item for item in collection if publisher.lower() in item.get("publisher", "").lower()]
    if releaseYear:
        collection = [item for item in collection if item.get("releaseYear") == releaseYear]
    
    return collection

@api_router.post("/users/{user_id}/collection", status_code=status.HTTP_201_CREATED)
async def add_to_collection(
    user_id: str,
    items: List[GameItemCreate],
    current_user: dict = Depends(get_current_user)
):
    """Add items to user's collection"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Create items with IDs and timestamps
    new_items = []
    for item in items:
        item_dict = item.model_dump()
        item_dict["id"] = str(uuid.uuid4())
        item_dict["addedAt"] = datetime.now(timezone.utc).isoformat()
        new_items.append(item_dict)
    
    # Add to collection
    mock_db[user_id]["collection"].extend(new_items)
    
    return {"message": f"Added {len(new_items)} item(s) to collection", "items": new_items}

@api_router.put("/users/{user_id}/collection/{item_id}")
async def update_collection_item(
    user_id: str,
    item_id: str,
    updated_item: GameItem,
    current_user: dict = Depends(get_current_user)
):
    """Update an item in user's collection"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Find and update item
    collection = user.get("collection", [])
    item_index = None
    for idx, item in enumerate(collection):
        if item.get("id") == item_id:
            item_index = idx
            break
    
    if item_index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    
    # Update the item
    updated_dict = updated_item.model_dump()
    updated_dict["id"] = item_id  # Preserve the original ID
    mock_db[user_id]["collection"][item_index] = updated_dict
    
    return {"message": "Item updated successfully", "item": updated_dict}

@api_router.delete("/users/{user_id}/collection/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_from_collection(
    user_id: str,
    item_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove an item from user's collection"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Remove item
    collection = user.get("collection", [])
    original_length = len(collection)
    mock_db[user_id]["collection"] = [item for item in collection if item.get("id") != item_id]
    
    if len(mock_db[user_id]["collection"]) == original_length:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    
    return None


# ==================== WISHLIST ENDPOINTS ====================

@api_router.get("/users/{user_id}/wishlist", response_model=List[GameItem])
async def get_user_wishlist(
    user_id: str,
    title: Optional[str] = None,
    platform: Optional[str] = None,
    publisher: Optional[str] = None,
    releaseYear: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get user's wishlist with optional filters"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    wishlist = user.get("wishlist", [])
    
    # Apply filters
    if title:
        wishlist = [item for item in wishlist if title.lower() in item.get("title", "").lower()]
    if platform:
        wishlist = [item for item in wishlist if platform.lower() in item.get("platform", "").lower()]
    if publisher:
        wishlist = [item for item in wishlist if publisher.lower() in item.get("publisher", "").lower()]
    if releaseYear:
        wishlist = [item for item in wishlist if item.get("releaseYear") == releaseYear]
    
    return wishlist

@api_router.post("/users/{user_id}/wishlist", status_code=status.HTTP_201_CREATED)
async def add_to_wishlist(
    user_id: str,
    items: List[GameItemCreate],
    current_user: dict = Depends(get_current_user)
):
    """Add items to user's wishlist"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Create items with IDs and timestamps
    new_items = []
    for item in items:
        item_dict = item.model_dump()
        item_dict["id"] = str(uuid.uuid4())
        item_dict["addedAt"] = datetime.now(timezone.utc).isoformat()
        new_items.append(item_dict)
    
    # Add to wishlist
    mock_db[user_id]["wishlist"].extend(new_items)
    
    return {"message": f"Added {len(new_items)} item(s) to wishlist", "items": new_items}

@api_router.put("/users/{user_id}/wishlist/{item_id}")
async def update_wishlist_item(
    user_id: str,
    item_id: str,
    updated_item: GameItem,
    current_user: dict = Depends(get_current_user)
):
    """Update an item in user's wishlist"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Find and update item
    wishlist = user.get("wishlist", [])
    item_index = None
    for idx, item in enumerate(wishlist):
        if item.get("id") == item_id:
            item_index = idx
            break
    
    if item_index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    
    # Update the item
    updated_dict = updated_item.model_dump()
    updated_dict["id"] = item_id  # Preserve the original ID
    mock_db[user_id]["wishlist"][item_index] = updated_dict
    
    return {"message": "Item updated successfully", "item": updated_dict}

@api_router.delete("/users/{user_id}/wishlist/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_from_wishlist(
    user_id: str,
    item_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove an item from user's wishlist"""
    # Verify user access
    if current_user["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    # Find user
    user = mock_db.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Remove item
    wishlist = user.get("wishlist", [])
    original_length = len(wishlist)
    mock_db[user_id]["wishlist"] = [item for item in wishlist if item.get("id") != item_id]
    
    if len(mock_db[user_id]["wishlist"]) == original_length:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    
    return None


# ==================== BASIC ENDPOINTS ====================

@api_router.get("/")
async def root():
    return {"message": "Video Game Collection API", "status": "running"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "database": "in-memory mock", "users_count": len(mock_db)}


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
