"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
Advanced AI-Powered Scam Detection System with Multi-Agent Architecture

Author: Team Innovation
Hackathon: India AI Impact Buildathon
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from openai import OpenAI
import uvicorn
import asyncio
import re
import json
from datetime import datetime
import requests
from collections import defaultdict
import hashlib
import traceback

# ============================================================================
# CONFIGURATION
# ============================================================================

import os
   
API_KEY = os.getenv("API_KEY", "your-secret-api-key-here")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your-openai-key")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Session management
active_sessions = {}
session_intelligence = defaultdict(lambda: {
    "bankAccounts": set(),
    "upiIds": set(),
    "phishingLinks": set(),
    "phoneNumbers": set(),
    "suspiciousKeywords": set(),
    "messageCount": 0,
    "scamScore": 0.0,
    "scamType": None,
    "tactics": set(),
    "agentNotes": []
})

# ============================================================================
# DATA MODELS
# ============================================================================

class Message(BaseModel):
    sender: Optional[str] = "unknown"
    text: Optional[str] = None
    timestamp: Optional[str] = None

class ConversationMetadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

from typing import Any, Union

class HoneypotRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Optional[Union[str, Dict[str, Any]]] = None
    conversationHistory: Optional[Any] = None
    metadata: Optional[Any] = None

class HoneypotResponse(BaseModel):
    status: str
    reply: str

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Advanced AI-powered scam detection and intelligence extraction system",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# SCAM DETECTION ENGINE
# ============================================================================

class ScamDetector:
    """Advanced scam detection using pattern matching and ML-based scoring"""
    
    # Comprehensive scam patterns
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|now|today|asap|hurry|quick|fast)\b',
        r'\b(expire|expiring|expired|deadline|limited time)\b',
        r'\b(last chance|final notice|act now)\b'
    ]
    
    THREAT_PATTERNS = [
        r'\b(block|blocked|suspend|suspended|deactivate|terminate|close)\b',
        r'\b(account|card|service|access).*\b(will be|has been|is being)\b',
        r'\b(legal action|arrest|police|court|fine|penalty)\b',
        r'\b(unauthorized|suspicious|fraudulent) (activity|transaction|login)\b'
    ]
    
    REQUEST_PATTERNS = [
        r'\b(verify|confirm|update|validate|authenticate)\b.*\b(account|details|information)\b',
        r'\b(share|provide|send|give).*\b(otp|pin|password|cvv|code)\b',
        r'\b(click|tap|visit|go to).*\b(link|url|website)\b',
        r'\b(upi|bank|card|account).*\b(number|id|details)\b'
    ]
    
    REWARD_PATTERNS = [
        r'\b(won|win|winner|prize|reward|gift|lottery)\b',
        r'\b(congratulations|selected|eligible)\b',
        r'\b(free|cashback|discount|offer|deal)\b.*\b(\d+%|\$|\₹)\b',
        r'\b(claim|redeem|collect).*\b(prize|reward|money|cash)\b'
    ]
    
    IMPERSONATION_PATTERNS = [
        r'\b(bank|sbi|hdfc|icici|axis|kotak|pnb|canara)\b',
        r'\b(paytm|phonepe|googlepay|bhim|amazon|flipkart)\b',
        r'\b(government|income tax|gst|aadhaar|pan)\b',
        r'\b(customer care|support|helpline|service)\b'
    ]
    
    SCAM_KEYWORDS = {
        'bank_fraud': ['account', 'bank', 'card', 'kyc', 'verify', 'blocked'],
        'upi_fraud': ['upi', 'payment', 'transfer', 'wallet', 'paytm', 'phonepe'],
        'phishing': ['link', 'click', 'url', 'website', 'portal', 'login'],
        'lottery': ['won', 'prize', 'lottery', 'lucky', 'selected', 'winner'],
        'impersonation': ['officer', 'government', 'tax', 'police', 'authority'],
        'otp_fraud': ['otp', 'code', 'pin', 'verification', 'authenticate']
    }
    
    @staticmethod
    def analyze_message(text: str) -> Dict[str, Any]:
        """Comprehensive scam analysis"""
        if not text or not isinstance(text, str):
            return {
                'scam_score': 0,
                'is_scam': False,
                'scam_type': None,
                'urgency_score': 0,
                'threat_score': 0,
                'request_score': 0,
                'suspicious_keywords': []
            }
            
        text_lower = text.lower()
        
        # Pattern matching scores
        urgency_score = sum(1 for p in ScamDetector.URGENCY_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        threat_score = sum(1 for p in ScamDetector.THREAT_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        request_score = sum(1 for p in ScamDetector.REQUEST_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        reward_score = sum(1 for p in ScamDetector.REWARD_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        impersonation_score = sum(1 for p in ScamDetector.IMPERSONATION_PATTERNS if re.search(p, text_lower, re.IGNORECASE))
        
        # Calculate overall scam score (0-100)
        scam_score = min(100, (
            urgency_score * 15 +
            threat_score * 20 +
            request_score * 25 +
            reward_score * 15 +
            impersonation_score * 20
        ))
        
        # Identify scam type
        scam_type = None
        max_keywords = 0
        for stype, keywords in ScamDetector.SCAM_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > max_keywords:
                max_keywords = count
                scam_type = stype
        
        # Extract suspicious keywords
        all_keywords = set()
        for keywords in ScamDetector.SCAM_KEYWORDS.values():
            all_keywords.update([kw for kw in keywords if kw in text_lower])
        
        return {
            'scam_score': scam_score,
            'is_scam': scam_score >= 30,  # Threshold for scam detection
            'scam_type': scam_type,
            'urgency_score': urgency_score,
            'threat_score': threat_score,
            'request_score': request_score,
            'suspicious_keywords': list(all_keywords)
        }
    
    @staticmethod
    def extract_intelligence(text: str) -> Dict[str, List[str]]:
        """Extract actionable intelligence from messages"""
        intelligence = {
            'bankAccounts': [],
            'upiIds': [],
            'phishingLinks': [],
            'phoneNumbers': []
        }
        
        if not text or not isinstance(text, str):
            return intelligence
        
        # Extract bank account numbers (various formats)
        bank_patterns = [
            r'\b\d{9,18}\b',  # 9-18 digit account numbers
            r'\b[A-Z]{4}\d{7,16}\b',  # IFSC-like with numbers
        ]
        for pattern in bank_patterns:
            matches = re.findall(pattern, text)
            intelligence['bankAccounts'].extend(matches)
        
        # Extract UPI IDs
        upi_pattern = r'\b[\w\.-]+@[\w\.-]+\b'
        intelligence['upiIds'] = re.findall(upi_pattern, text)
        
        # Extract URLs/links
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        short_url_pattern = r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co)/\w+'
        intelligence['phishingLinks'] = re.findall(url_pattern, text) + re.findall(short_url_pattern, text)
        
        # Extract phone numbers (Indian format)
        phone_patterns = [
            r'\+91[\s-]?\d{10}',
            r'\b[6-9]\d{9}\b',
            r'\b0\d{2,4}[\s-]?\d{6,8}\b'
        ]
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            intelligence['phoneNumbers'].extend(matches)
        
        return intelligence

# ============================================================================
# AI AGENT SYSTEM
# ============================================================================

class HoneypotAgent:
    """Advanced AI agent for scam engagement with OpenAI"""
    
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        
    def generate_persona(self, scam_type: str, metadata: Optional[ConversationMetadata]) -> str:
        """Generate appropriate persona based on scam type"""
        personas = {
            'bank_fraud': "elderly person, not very tech-savvy, worried about account",
            'upi_fraud': "middle-aged user, occasional UPI user, cautious but curious",
            'phishing': "young professional, uses banking apps, somewhat trusting",
            'lottery': "hopeful individual, excited about potential winnings",
            'impersonation': "concerned citizen, respectful of authority",
            'otp_fraud': "regular user, familiar with OTPs but not security-aware"
        }
        return personas.get(scam_type, "average user, cautious but can be convinced")
    
    async def engage(
        self,
        session_id: str,
        current_message: str,
        conversation_history: List[Message],
        scam_analysis: Dict[str, Any],
        metadata: Optional[ConversationMetadata]
    ) -> str:
        """Generate human-like response to engage scammer"""
        
        try:
            scam_type = scam_analysis.get('scam_type', 'unknown')
            persona = self.generate_persona(scam_type, metadata)
            message_count = len(conversation_history) + 1
            
            # Build conversation context
            history_text = "\n".join([
                f"{msg.sender or 'unknown'}: {msg.text or ''}" 
                for msg in conversation_history[-5:] if msg.text
            ])
            
            # Progressive engagement strategy
            engagement_stage = self._determine_engagement_stage(message_count, scam_analysis)
            
            # Create prompt for OpenAI
            system_prompt = f"""You are an AI agent operating a honeypot to detect and extract intelligence from scammers.

PERSONA: You are playing the role of a {persona}.

SCAM TYPE DETECTED: {scam_type}
SCAM CONFIDENCE: {scam_analysis['scam_score']}%
ENGAGEMENT STAGE: {engagement_stage}

CRITICAL INSTRUCTIONS:
1. Stay in character as the persona - be believable and human-like
2. NEVER reveal you're an AI or that you've detected the scam
3. Show appropriate emotions: concern, curiosity, confusion, or hope
4. Make natural mistakes: typos, incomplete thoughts, hesitation
5. Ask clarifying questions to extract more information
6. Gradually show interest to keep the scammer engaged
7. {self._get_stage_instructions(engagement_stage)}

CONVERSATION SO FAR:
{history_text}

LATEST SCAMMER MESSAGE: {current_message}

Generate a response that:
- Sounds natural and human (use conversational language, contractions)
- Keeps the scammer engaged without being too eager
- Extracts information subtly (ask about process, requirements, contact details)
- Shows the right level of concern/interest for this stage
- Is brief (1-3 sentences maximum)

Respond ONLY with the message text, nothing else."""

            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": "Generate the response now."}
                ],
                max_tokens=150,
                temperature=0.8,
            )

            reply = response.choices[0].message.content.strip()
            
            # Post-process to ensure naturalness
            reply = self._add_human_touches(reply, engagement_stage)
            
            return reply if reply else "Okay… can you explain that again?"
            
        except Exception as e:
            print(f"Error in agent.engage: {e}")
            traceback.print_exc()
            # Return fallback response
            return self._get_fallback_response(
                self._determine_engagement_stage(len(conversation_history) + 1, scam_analysis),
                scam_analysis.get('scam_type', 'unknown')
            )
    
    def _determine_engagement_stage(self, message_count: int, scam_analysis: Dict) -> str:
        """Determine current engagement stage"""
        if message_count <= 2:
            return "initial_confusion"
        elif message_count <= 5:
            return "cautious_interest"
        elif message_count <= 10:
            return "building_trust"
        elif message_count <= 15:
            return "information_extraction"
        else:
            return "final_push"
    
    def _get_stage_instructions(self, stage: str) -> str:
        """Get stage-specific instructions"""
        instructions = {
            "initial_confusion": "Show confusion and ask why they're contacting you. Express mild concern.",
            "cautious_interest": "Show some interest but remain skeptical. Ask basic questions about the process.",
            "building_trust": "Show more trust. Ask about specific details, deadlines, or next steps.",
            "information_extraction": "Ask for contact information, account details they need, or payment methods. Show willingness to comply.",
            "final_push": "Express readiness to proceed but need final confirmation of details, websites, or contact methods."
        }
        return instructions.get(stage, "Keep the conversation going naturally.")
    
    def _add_human_touches(self, text: str, stage: str) -> str:
        """Add human-like imperfections"""
        import random
        
        if not text:
            return text
        
        # Occasionally add typos or informal language
        if random.random() < 0.3 and stage in ["initial_confusion", "cautious_interest"]:
            replacements = {
                "okay": "ok",
                "yes": "yeah",
                "understand": "get it",
                "really": "rly",
                "you": "u"
            }
            for formal, informal in replacements.items():
                if formal in text.lower() and random.random() < 0.5:
                    text = re.sub(f"\\b{formal}\\b", informal, text, flags=re.IGNORECASE, count=1)
        
        # Add hesitation markers
        if random.random() < 0.2:
            hesitations = ["um, ", "uh, ", "well, ", "so "]
            text = random.choice(hesitations) + text[0].lower() + text[1:]
        
        return text
    
    def _get_fallback_response(self, stage: str, scam_type: str) -> str:
        """Fallback responses if AI generation fails"""
        fallbacks = {
            "initial_confusion": [
                "What is this about? I don't understand.",
                "Why are you messaging me?",
                "Is this really from my bank?"
            ],
            "cautious_interest": [
                "Can you explain more clearly?",
                "How do I know this is legitimate?",
                "What exactly do I need to do?"
            ],
            "building_trust": [
                "What happens next?",
                "Do I need to visit anywhere?",
                "Can you send me more details?"
            ],
            "information_extraction": [
                "Where should I send the information?",
                "What's your official contact number?",
                "Is there a website I should use?"
            ],
            "final_push": [
                "Just to confirm, what details do you need from me?",
                "What's the process after I share the information?",
                "Can I call your helpline to verify?"
            ]
        }
        
        import random
        return random.choice(fallbacks.get(stage, ["I see. Tell me more."]))

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

def update_session_intelligence(session_id: str, message: str, scam_analysis: Dict):
    """Update intelligence gathered for this session"""
    try:
        intel = session_intelligence[session_id]
        
        # Extract and add intelligence
        extracted = ScamDetector.extract_intelligence(message)
        intel['bankAccounts'].update(extracted['bankAccounts'])
        intel['upiIds'].update(extracted['upiIds'])
        intel['phishingLinks'].update(extracted['phishingLinks'])
        intel['phoneNumbers'].update(extracted['phoneNumbers'])
        intel['suspiciousKeywords'].update(scam_analysis.get('suspicious_keywords', []))
        
        # Update metadata
        intel['messageCount'] += 1
        intel['scamScore'] = max(intel['scamScore'], scam_analysis.get('scam_score', 0))
        if scam_analysis.get('scam_type'):
            intel['scamType'] = scam_analysis['scam_type']
        
        # Track tactics
        if scam_analysis.get('urgency_score', 0) > 0:
            intel['tactics'].add('urgency_tactics')
        if scam_analysis.get('threat_score', 0) > 0:
            intel['tactics'].add('threat_based')
        if scam_analysis.get('request_score', 0) > 0:
            intel['tactics'].add('information_request')
    except Exception as e:
        print(f"Error updating session intelligence: {e}")

def should_terminate_session(session_id: str) -> bool:
    """Determine if session should be terminated and reported"""
    try:
        intel = session_intelligence[session_id]
        
        # Terminate conditions
        if intel['messageCount'] >= 20:  # Max engagement
            return True
        if intel['scamScore'] >= 80 and intel['messageCount'] >= 5:  # High confidence + enough data
            return True
        if len(intel['bankAccounts']) > 0 or len(intel['upiIds']) > 0:  # Critical intel obtained
            return True
        
        return False
    except Exception as e:
        print(f"Error checking session termination: {e}")
        return False

async def send_final_callback(session_id: str):
    """Send final intelligence to GUVI evaluation endpoint"""
    try:
        intel = session_intelligence[session_id]
        
        # Build agent notes
        notes_parts = []
        if intel['scamType']:
            notes_parts.append(f"Scam type: {intel['scamType']}")
        if intel['tactics']:
            notes_parts.append(f"Tactics: {', '.join(intel['tactics'])}")
        notes_parts.extend(intel['agentNotes'])
        agent_notes = ". ".join(notes_parts)
        
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": intel['messageCount'],
            "extractedIntelligence": {
                "bankAccounts": list(intel['bankAccounts']),
                "upiIds": list(intel['upiIds']),
                "phishingLinks": list(intel['phishingLinks']),
                "phoneNumbers": list(intel['phoneNumbers']),
                "suspiciousKeywords": list(intel['suspiciousKeywords'])
            },
            "agentNotes": agent_notes or "Scam engagement completed successfully"
        }
        
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=10
        )
        print(f"✓ Callback sent for session {session_id}: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"✗ Callback failed for session {session_id}: {e}")
        traceback.print_exc()
        return True

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Main honeypot endpoint for scam detection and engagement"""
    
    # Authentication
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Extract session ID with fallback
        session_id = request.sessionId or f"session-{datetime.utcnow().timestamp()}"

        # Normalize message safely - CRITICAL FIX
        current_message = ""
        if isinstance(request.message, str):
            current_message = request.message.strip()
        elif isinstance(request.message, dict):
            # Try multiple keys
            current_message = (
                request.message.get("text") or 
                request.message.get("message") or 
                request.message.get("content") or 
                ""
            ).strip()
        
        if not current_message:
            return HoneypotResponse(
                status="error",
                reply="I didn't receive any message. Could you please try again?"
            )

        # Normalize conversation history safely
        conversation_history = []
        if isinstance(request.conversationHistory, list):
            for msg in request.conversationHistory:
                try:
                    if isinstance(msg, dict):
                        conversation_history.append(Message(**msg))
                    elif hasattr(msg, 'text'):
                        conversation_history.append(msg)
                except Exception as msg_err:
                    print(f"Warning: Could not parse message in history: {msg_err}")
                    continue
        
        # Analyze current message for scam indicators
        scam_analysis = ScamDetector.analyze_message(current_message)
        
        # Update session intelligence
        update_session_intelligence(session_id, current_message, scam_analysis)
        
        # Initialize agent if not exists
        if session_id not in active_sessions:
            active_sessions[session_id] = HoneypotAgent(OPENAI_API_KEY)
        
        agent = active_sessions[session_id]
        
        # Check if this is a scam (or continue engagement if already detected)
        is_ongoing_scam = session_intelligence[session_id]['scamScore'] >= 30
        
        if scam_analysis['is_scam'] or is_ongoing_scam:
            # Generate AI response
            reply = await agent.engage(
                session_id=session_id,
                current_message=current_message,
                conversation_history=conversation_history,
                scam_analysis=scam_analysis,
                metadata=request.metadata
            )
            
            # Check if session should be terminated
            if should_terminate_session(session_id):
                session_intelligence[session_id]['agentNotes'].append(
                    f"Session terminated after {session_intelligence[session_id]['messageCount']} messages"
                )
                # Schedule callback without blocking
                asyncio.create_task(send_final_callback(session_id))
            
            return HoneypotResponse(status="success", reply=reply)
        
        else:
            # Not detected as scam - respond cautiously
            return HoneypotResponse(
                status="success",
                reply="I'm sorry, I don't understand. Who is this?"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR in honeypot_endpoint: {e}")
        traceback.print_exc()
        # Return a safe fallback instead of crashing
        return HoneypotResponse(
            status="error",
            reply="I'm having trouble understanding. Could you repeat that?"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "active_sessions": len(active_sessions),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Agentic Honey-Pot API",
        "version": "2.0.0",
        "status": "active",
        "endpoints": {
            "honeypot": "/honeypot (POST)",
            "health": "/health (GET)",
            "docs": "/docs"
        }
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🍯 AGENTIC HONEY-POT API")
    print("=" * 70)
    print(f"Starting server...")
    print(f"API Documentation: http://0.0.0.0:8000/docs")
    print(f"Health Check: http://0.0.0.0:8000/health")
    print("=" * 70)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )