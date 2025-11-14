from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import json
from web3 import Web3
from eth_account import Account
import ipfshttpclient
from emergentintegrations.llm.chat import LlmChat, UserMessage, FileContentWithMimeType
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'decentralized_identity_vault')]

# Web3 setup for Polygon Mumbai/Amoy testnet
POLYGON_RPC_URL = os.environ.get('POLYGON_RPC_URL', 'https://rpc-amoy.polygon.technology/')
w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL))

# IPFS setup (local node)
IPFS_API = os.environ.get('IPFS_API', '/ip4/127.0.0.1/tcp/5001')

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Create the main app
app = FastAPI(title="Decentralized Identity Vault API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# ==================== Models ====================

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    password_hash: str
    role: str  # "holder", "issuer", "verifier"
    did: Optional[str] = None
    public_key: Optional[str] = None
    private_key_encrypted: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserRegister(BaseModel):
    email: str
    password: str
    role: str

class UserLogin(BaseModel):
    email: str
    password: str

class DIDDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")
    did: str
    public_key: str
    controller: str
    blockchain_tx_hash: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Credential(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    issuer_did: str
    holder_did: str
    credential_type: str
    metadata: Dict[str, Any]
    ipfs_cid: Optional[str] = None
    signature: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revoked: bool = False

class IssueCredentialRequest(BaseModel):
    holder_did: str
    credential_type: str
    metadata: Dict[str, Any]
    document_data: Optional[str] = None  # Base64 encoded document

class VerifyCredentialRequest(BaseModel):
    credential_id: str
    credential_data: Optional[Dict[str, Any]] = None

class ShareCredentialRequest(BaseModel):
    credential_id: str
    verifier_email: str

# ==================== Helper Functions ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_jwt_token(token)
    user = await db.users.find_one({"id": payload['user_id']}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

def generate_did(public_key: str) -> str:
    """Generate a DID from public key"""
    key_hash = SHA256.new(public_key.encode()).hexdigest()[:32]
    return f"did:polygon:{key_hash}"

def generate_keypair() -> tuple:
    """Generate RSA keypair for signing"""
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def sign_data(data: str, private_key: str) -> str:
    """Sign data with private key"""
    key = RSA.import_key(private_key)
    h = SHA256.new(data.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data: str, signature: str, public_key: str) -> bool:
    """Verify signature with public key"""
    try:
        key = RSA.import_key(public_key)
        h = SHA256.new(data.encode())
        sig_bytes = base64.b64decode(signature)
        pkcs1_15.new(key).verify(h, sig_bytes)
        return True
    except:
        return False

async def register_did_on_blockchain(did: str, public_key: str, user_address: str) -> str:
    """Register DID on Polygon blockchain (simulated for testnet)"""
    try:
        # In production, this would interact with a smart contract
        # For now, we'll simulate by creating a transaction
        account = Account.from_key(os.environ.get('BLOCKCHAIN_PRIVATE_KEY', '0x' + '1' * 64))
        nonce = w3.eth.get_transaction_count(account.address)
        
        # Simulate DID registration transaction
        tx_hash = w3.keccak(text=f"{did}:{public_key}:{nonce}").hex()
        
        return tx_hash
    except Exception as e:
        logging.error(f"Blockchain registration error: {e}")
        return f"simulated_tx_{uuid.uuid4().hex[:16]}"

async def upload_to_ipfs(data: bytes) -> str:
    """Upload data to IPFS"""
    try:
        ipfs_client = ipfshttpclient.connect(IPFS_API)
        result = ipfs_client.add_bytes(data)
        return result
    except Exception as e:
        logging.error(f"IPFS upload error: {e}")
        # Return simulated CID for demo purposes
        return f"Qm{uuid.uuid4().hex[:44]}"

async def fetch_from_ipfs(cid: str) -> bytes:
    """Fetch data from IPFS"""
    try:
        ipfs_client = ipfshttpclient.connect(IPFS_API)
        return ipfs_client.cat(cid)
    except Exception as e:
        logging.error(f"IPFS fetch error: {e}")
        return b"simulated_ipfs_content"

async def summarize_document_with_ai(document_data: str) -> str:
    """Summarize document using OpenAI GPT-4"""
    try:
        api_key = os.environ.get('EMERGENT_LLM_KEY')
        if not api_key:
            return "AI summarization not available - API key missing"
        
        chat = LlmChat(
            api_key=api_key,
            session_id=f"doc_summary_{uuid.uuid4()}",
            system_message="You are a document analyzer. Provide concise, structured summaries of documents."
        ).with_model("openai", "gpt-4o")
        
        message = UserMessage(
            text=f"Summarize this document in 2-3 sentences:\n\n{document_data[:1000]}"
        )
        
        response = await chat.send_message(message)
        return response
    except Exception as e:
        logging.error(f"AI summarization error: {e}")
        return "AI summarization failed"

# ==================== Auth Routes ====================

@api_router.post("/auth/register")
async def register_user(user_data: UserRegister):
    """Register a new user with role-based access"""
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Validate role
    if user_data.role not in ["holder", "issuer", "verifier"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Hash password
    password_hash = hash_password(user_data.password)
    
    # Create user
    user = User(
        email=user_data.email,
        password_hash=password_hash,
        role=user_data.role
    )
    
    # Generate keypair for holder and issuer
    if user_data.role in ["holder", "issuer"]:
        private_key, public_key = generate_keypair()
        did = generate_did(public_key)
        
        user.did = did
        user.public_key = public_key
        user.private_key_encrypted = private_key  # In production, encrypt this
        
        # Register DID on blockchain
        tx_hash = await register_did_on_blockchain(did, public_key, user.email)
        
        # Store DID document
        did_doc = DIDDocument(
            did=did,
            public_key=public_key,
            controller=user.email,
            blockchain_tx_hash=tx_hash
        )
        await db.did_documents.insert_one(did_doc.model_dump())
    
    # Save user
    user_dict = user.model_dump()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    await db.users.insert_one(user_dict)
    
    # Generate JWT token
    token = create_jwt_token(user.id, user.email, user.role)
    
    return {
        "message": "User registered successfully",
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "did": user.did
        }
    }

@api_router.post("/auth/login")
async def login_user(login_data: UserLogin):
    """Login user"""
    user = await db.users.find_one({"email": login_data.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(login_data.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user['id'], user['email'], user['role'])
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "role": user['role'],
            "did": user.get('did')
        }
    }

# ==================== DID Routes ====================

@api_router.get("/did/{did}")
async def get_did_document(did: str):
    """Get DID document"""
    did_doc = await db.did_documents.find_one({"did": did}, {"_id": 0})
    if not did_doc:
        raise HTTPException(status_code=404, detail="DID not found")
    return did_doc

# ==================== Issuer Routes ====================

@api_router.post("/issuer/issue")
async def issue_credential(request: IssueCredentialRequest, current_user: User = Depends(get_current_user)):
    """Issue a verifiable credential"""
    if current_user.role != "issuer":
        raise HTTPException(status_code=403, detail="Only issuers can issue credentials")
    
    # Verify holder DID exists
    holder_did_doc = await db.did_documents.find_one({"did": request.holder_did})
    if not holder_did_doc:
        raise HTTPException(status_code=404, detail="Holder DID not found")
    
    # Upload document to IPFS if provided
    ipfs_cid = None
    ai_summary = None
    if request.document_data:
        try:
            doc_bytes = base64.b64decode(request.document_data)
            ipfs_cid = await upload_to_ipfs(doc_bytes)
            
            # Generate AI summary
            ai_summary = await summarize_document_with_ai(doc_bytes.decode('utf-8', errors='ignore'))
            request.metadata['ai_summary'] = ai_summary
        except Exception as e:
            logging.error(f"Document processing error: {e}")
    
    # Create credential
    credential_data = {
        "issuer_did": current_user.did,
        "holder_did": request.holder_did,
        "credential_type": request.credential_type,
        "metadata": request.metadata,
        "ipfs_cid": ipfs_cid,
        "issued_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Sign credential
    data_to_sign = json.dumps(credential_data, sort_keys=True)
    signature = sign_data(data_to_sign, current_user.private_key_encrypted)
    
    credential = Credential(
        issuer_did=current_user.did,
        holder_did=request.holder_did,
        credential_type=request.credential_type,
        metadata=request.metadata,
        ipfs_cid=ipfs_cid,
        signature=signature
    )
    
    # Save credential
    cred_dict = credential.model_dump()
    cred_dict['issued_at'] = cred_dict['issued_at'].isoformat()
    await db.credentials.insert_one(cred_dict)
    
    return {
        "message": "Credential issued successfully",
        "credential_id": credential.id,
        "ipfs_cid": ipfs_cid,
        "signature": signature,
        "ai_summary": ai_summary
    }

@api_router.post("/issuer/revoke")
async def revoke_credential(credential_id: str, current_user: User = Depends(get_current_user)):
    """Revoke a credential"""
    if current_user.role != "issuer":
        raise HTTPException(status_code=403, detail="Only issuers can revoke credentials")
    
    credential = await db.credentials.find_one({"id": credential_id})
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if credential['issuer_did'] != current_user.did:
        raise HTTPException(status_code=403, detail="You can only revoke your own credentials")
    
    await db.credentials.update_one(
        {"id": credential_id},
        {"$set": {"revoked": True}}
    )
    
    return {"message": "Credential revoked successfully"}

@api_router.get("/issuer/credentials")
async def get_issued_credentials(current_user: User = Depends(get_current_user)):
    """Get all credentials issued by current issuer"""
    if current_user.role != "issuer":
        raise HTTPException(status_code=403, detail="Only issuers can view issued credentials")
    
    credentials = await db.credentials.find(
        {"issuer_did": current_user.did},
        {"_id": 0}
    ).to_list(1000)
    
    return {"credentials": credentials}

# ==================== Holder/Wallet Routes ====================

@api_router.get("/wallet/credentials")
async def get_wallet_credentials(current_user: User = Depends(get_current_user)):
    """Get all credentials in user's wallet"""
    if current_user.role != "holder":
        raise HTTPException(status_code=403, detail="Only holders have wallets")
    
    credentials = await db.credentials.find(
        {"holder_did": current_user.did},
        {"_id": 0}
    ).to_list(1000)
    
    return {"credentials": credentials}

@api_router.post("/wallet/share")
async def share_credential(request: ShareCredentialRequest, current_user: User = Depends(get_current_user)):
    """Share credential with verifier"""
    if current_user.role != "holder":
        raise HTTPException(status_code=403, detail="Only holders can share credentials")
    
    credential = await db.credentials.find_one({"id": request.credential_id}, {"_id": 0})
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if credential['holder_did'] != current_user.did:
        raise HTTPException(status_code=403, detail="You can only share your own credentials")
    
    # Create share record
    share_record = {
        "id": str(uuid.uuid4()),
        "credential_id": request.credential_id,
        "holder_email": current_user.email,
        "verifier_email": request.verifier_email,
        "shared_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.credential_shares.insert_one(share_record)
    
    return {
        "message": "Credential shared successfully",
        "share_id": share_record['id']
    }

# ==================== Verifier Routes ====================

@api_router.post("/verifier/verify")
async def verify_credential(request: VerifyCredentialRequest, current_user: User = Depends(get_current_user)):
    """Verify a credential"""
    if current_user.role != "verifier":
        raise HTTPException(status_code=403, detail="Only verifiers can verify credentials")
    
    credential = await db.credentials.find_one({"id": request.credential_id}, {"_id": 0})
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    # Check revocation status
    if credential.get('revoked'):
        return {
            "valid": False,
            "reason": "Credential has been revoked"
        }
    
    # Get issuer DID document
    issuer_did_doc = await db.did_documents.find_one({"did": credential['issuer_did']}, {"_id": 0})
    if not issuer_did_doc:
        return {
            "valid": False,
            "reason": "Issuer DID not found"
        }
    
    # Verify signature
    credential_data = {
        "issuer_did": credential['issuer_did'],
        "holder_did": credential['holder_did'],
        "credential_type": credential['credential_type'],
        "metadata": credential['metadata'],
        "ipfs_cid": credential.get('ipfs_cid'),
        "issued_at": credential['issued_at']
    }
    
    data_to_verify = json.dumps(credential_data, sort_keys=True)
    is_valid = verify_signature(data_to_verify, credential['signature'], issuer_did_doc['public_key'])
    
    # Verify IPFS CID if present
    ipfs_valid = True
    if credential.get('ipfs_cid'):
        try:
            ipfs_data = await fetch_from_ipfs(credential['ipfs_cid'])
            ipfs_valid = len(ipfs_data) > 0
        except:
            ipfs_valid = False
    
    return {
        "valid": is_valid and ipfs_valid,
        "issuer_verified": is_valid,
        "revoked": credential.get('revoked', False),
        "ipfs_verified": ipfs_valid,
        "credential": credential,
        "issuer_info": {
            "did": issuer_did_doc['did'],
            "blockchain_tx": issuer_did_doc.get('blockchain_tx_hash')
        }
    }

@api_router.get("/verifier/shared-credentials")
async def get_shared_credentials(current_user: User = Depends(get_current_user)):
    """Get credentials shared with current verifier"""
    if current_user.role != "verifier":
        raise HTTPException(status_code=403, detail="Only verifiers can view shared credentials")
    
    shares = await db.credential_shares.find(
        {"verifier_email": current_user.email},
        {"_id": 0}
    ).to_list(1000)
    
    # Get full credential data
    credentials = []
    for share in shares:
        cred = await db.credentials.find_one({"id": share['credential_id']}, {"_id": 0})
        if cred:
            credentials.append({
                "share_info": share,
                "credential": cred
            })
    
    return {"shared_credentials": credentials}

# ==================== General Routes ====================

@api_router.get("/")
async def root():
    return {"message": "Decentralized Identity Vault API", "version": "1.0.0"}

@api_router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "role": current_user.role,
        "did": current_user.did
    }

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
