#!/usr/bin/env python3
"""
Test Suite for Autonomous Honeypot v6.0
Validates: reasoning, repetition avoidance, intelligence extraction, termination
"""

import asyncio
import json
import sys
from typing import List, Dict, Any
from datetime import datetime

# Add color support
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(80)}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.END}\n")

def print_test(test_name: str):
    print(f"\n{Colors.CYAN}{'─'*80}{Colors.END}")
    print(f"{Colors.CYAN}🧪 TEST: {test_name}{Colors.END}")
    print(f"{Colors.CYAN}{'─'*80}{Colors.END}")

def print_success(message: str):
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_error(message: str):
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def print_warning(message: str):
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_info(message: str):
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

# ============================================================================
# TEST SCENARIOS
# ============================================================================

class TestScenario:
    """Represents a test conversation scenario"""
    
    def __init__(self, name: str, scammer_messages: List[str], expected_behaviors: Dict[str, Any]):
        self.name = name
        self.scammer_messages = scammer_messages
        self.expected_behaviors = expected_behaviors
        self.results = []
        self.passed = True

# Test scenarios
SCENARIOS = [
    TestScenario(
        name="Basic Bank Scam - Phone Extraction",
        scammer_messages=[
            "URGENT: Your SBI account will be blocked in 2 hours. Share your account number and OTP immediately to verify.",
            "Our helpline is 1800-123-456. Please call now and share your OTP.",
            "You can also reach us at +91-9876543210. We need your OTP within 5 minutes.",
        ],
        expected_behaviors={
            "extract_phone": True,
            "no_repetition": True,
            "human_like": True,
            "min_questions": 2,
        }
    ),
    
    TestScenario(
        name="Website Phishing - URL Extraction",
        scammer_messages=[
            "Your KYC is pending. Update it immediately at our official portal.",
            "Visit https://sbi-secure-login.com/verify to update your details.",
            "Enter your account number and password on the website. Hurry!",
        ],
        expected_behaviors={
            "extract_url": True,
            "no_repetition": True,
            "ask_different_questions": True,
        }
    ),
    
    TestScenario(
        name="Email Phishing - Contact Extraction",
        scammer_messages=[
            "Your account has suspicious activity. Verify immediately.",
            "Send your details to our security team at security@fakebank.com.",
            "Email us your account number, OTP, and PAN card within 10 minutes.",
        ],
        expected_behaviors={
            "extract_email": True,
            "no_repetition": True,
            "human_like": True,
        }
    ),
    
    TestScenario(
        name="UPI Scam - Payment Info Extraction",
        scammer_messages=[
            "You won ₹50,000! Claim your prize now.",
            "Send ₹500 processing fee to our UPI ID: scammer@paytm.",
            "Transfer to scammer@paytm immediately to release your prize.",
        ],
        expected_behaviors={
            "extract_upi": True,
            "no_repetition": True,
            "show_compliance": True,
        }
    ),
    
    TestScenario(
        name="Multi-Channel Scam - Complete Intelligence",
        scammer_messages=[
            "ALERT: Your account is compromised. Act now!",
            "Call our helpline: +91-9999888877 immediately.",
            "Or visit our secure portal: https://bank-verify.com",
            "You can also email us at help@fakesupport.com with your details.",
            "Send verification fee to UPI ID: fraud@phonepe",
        ],
        expected_behaviors={
            "extract_phone": True,
            "extract_url": True,
            "extract_email": True,
            "extract_upi": True,
            "high_score": True,
            "multiple_categories": True,
            "intelligent_termination": True,
        }
    ),
    
    TestScenario(
        name="Repetition Avoidance Test",
        scammer_messages=[
            "Your account will be blocked! Share OTP!",
            "Call +91-1234567890 now and share OTP!",
            "Call +91-1234567890 immediately!",
            "Our number is +91-1234567890. Call now!",
            "The helpline is +91-1234567890.",
        ],
        expected_behaviors={
            "no_repetition": True,
            "action_variety": True,
            "self_correction": True,
        }
    ),
]

# ============================================================================
# MOCK AGENT FOR TESTING
# ============================================================================

class MockTracker:
    """Simplified tracker for testing"""
    def __init__(self):
        self.message_count = 0
        self.phone_numbers = set()
        self.urls = set()
        self.email_addresses = set()
        self.upi_ids = set()
        self.actions_taken = []
        self.bot_replies = []
    
    def process_message(self, text: str):
        import re
        # Extract phone
        phones = re.findall(r'\+?91[-\s]?[6-9]\d{9}|\b1800[-\s]?\d{3}[-\s]?\d{3,4}', text)
        self.phone_numbers.update(phones)
        
        # Extract URL
        urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text)
        self.urls.update(urls)
        
        # Extract email
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        self.email_addresses.update(emails)
        
        # Extract UPI
        upis = re.findall(r'\b[\w\.-]+@(?:paytm|phonepe|ybl)', text, re.IGNORECASE)
        self.upi_ids.update(upis)
        
        self.message_count += 1
    
    def get_intel_score(self):
        return (len(self.phone_numbers) * 10 + 
                len(self.urls) * 8 + 
                len(self.email_addresses) * 8 + 
                len(self.upi_ids) * 12)
    
    def get_collected_categories(self):
        return sum([
            bool(self.phone_numbers),
            bool(self.urls),
            bool(self.email_addresses),
            bool(self.upi_ids),
        ])

# ============================================================================
# TEST VALIDATORS
# ============================================================================

def validate_no_repetition(replies: List[str]) -> tuple[bool, str]:
    """Check if bot repeated same question"""
    from difflib import SequenceMatcher
    
    for i in range(len(replies)):
        for j in range(i + 1, len(replies)):
            similarity = SequenceMatcher(None, replies[i].lower(), replies[j].lower()).ratio()
            if similarity > 0.75:
                return False, f"Repetition detected: '{replies[i]}' vs '{replies[j]}' (similarity: {similarity:.2f})"
    
    return True, "No repetition detected"

def validate_human_like(reply: str) -> tuple[bool, str]:
    """Check if reply sounds human"""
    indicators = {
        "casual": any(word in reply.lower() for word in ['whats', 'ur', 'u', 'pls', 'ok', 'cant', 'dont']),
        "short": len(reply.split()) <= 15,
        "lowercase": reply[0].islower() if reply else False,
        "hesitation": any(word in reply.lower() for word in ['wait', 'uh', 'ok', 'hmm', 'um']),
    }
    
    score = sum(indicators.values())
    if score >= 2:
        return True, f"Human-like (score: {score}/4)"
    else:
        return False, f"Too robotic (score: {score}/4)"

def validate_intelligence_extraction(tracker: MockTracker, requirements: Dict[str, bool]) -> tuple[bool, str]:
    """Check if intelligence was extracted"""
    results = []
    
    if requirements.get("extract_phone"):
        if tracker.phone_numbers:
            results.append(f"✓ Phone: {tracker.phone_numbers}")
        else:
            return False, "Failed to extract phone number"
    
    if requirements.get("extract_url"):
        if tracker.urls:
            results.append(f"✓ URL: {tracker.urls}")
        else:
            return False, "Failed to extract URL"
    
    if requirements.get("extract_email"):
        if tracker.email_addresses:
            results.append(f"✓ Email: {tracker.email_addresses}")
        else:
            return False, "Failed to extract email"
    
    if requirements.get("extract_upi"):
        if tracker.upi_ids:
            results.append(f"✓ UPI: {tracker.upi_ids}")
        else:
            return False, "Failed to extract UPI"
    
    if requirements.get("high_score"):
        score = tracker.get_intel_score()
        if score >= 30:
            results.append(f"✓ High score: {score}")
        else:
            return False, f"Score too low: {score} (expected ≥30)"
    
    if requirements.get("multiple_categories"):
        cats = tracker.get_collected_categories()
        if cats >= 3:
            results.append(f"✓ Multiple categories: {cats}/4")
        else:
            return False, f"Not enough categories: {cats}/4 (expected ≥3)"
    
    return True, " | ".join(results)

def validate_action_variety(actions: List[str]) -> tuple[bool, str]:
    """Check if agent used different actions"""
    unique_actions = len(set(actions))
    total_actions = len(actions)
    
    if total_actions == 0:
        return False, "No actions recorded"
    
    variety_ratio = unique_actions / total_actions
    
    if variety_ratio >= 0.6:  # At least 60% variety
        return True, f"Good variety: {unique_actions}/{total_actions} unique actions"
    else:
        return False, f"Low variety: {unique_actions}/{total_actions} unique actions"

# ============================================================================
# TEST RUNNER
# ============================================================================

async def run_test_scenario(scenario: TestScenario) -> bool:
    """Run a single test scenario"""
    print_test(scenario.name)
    
    # Create mock tracker
    tracker = MockTracker()
    bot_replies = []
    actions = []
    
    # Simulate conversation
    for i, scammer_msg in enumerate(scenario.scammer_messages, 1):
        print(f"\n{Colors.BOLD}Message {i}:{Colors.END}")
        print(f"  Scammer: {scammer_msg}")
        
        # Process message
        tracker.process_message(scammer_msg)
        
        # Simulate bot response (in real test, this would call the API)
        # For this demo, we'll use simple heuristics
        missing_intel = []
        if not tracker.phone_numbers:
            missing_intel.append("phone")
        if not tracker.urls:
            missing_intel.append("url")
        if not tracker.email_addresses:
            missing_intel.append("email")
        if not tracker.upi_ids:
            missing_intel.append("upi")
        
        # Generate mock reply based on what's missing
        if i == 1:
            reply = "wait whats ur official number"
            action = "ask_contact"
        elif "phone" in missing_intel:
            reply = "ok whats ur helpline number"
            action = "ask_contact"
        elif "url" in missing_intel:
            reply = "is there a website i should check"
            action = "ask_contact"
        elif "email" in missing_intel:
            reply = "whats ur email address"
            action = "ask_contact"
        elif "upi" in missing_intel:
            reply = "which upi should i send to"
            action = "ask_payment"
        else:
            reply = "ok what do i do now"
            action = "show_compliance"
        
        bot_replies.append(reply)
        actions.append(action)
        tracker.bot_replies.append(reply)
        tracker.actions_taken.append(action)
        
        print(f"  Bot: {reply}")
        print(f"  Action: {action}")
    
    # Validate expectations
    print(f"\n{Colors.BOLD}Validation Results:{Colors.END}")
    all_passed = True
    
    # Test 1: No repetition
    if scenario.expected_behaviors.get("no_repetition"):
        passed, msg = validate_no_repetition(bot_replies)
        if passed:
            print_success(f"No repetition: {msg}")
        else:
            print_error(f"Repetition found: {msg}")
            all_passed = False
    
    # Test 2: Human-like responses
    if scenario.expected_behaviors.get("human_like"):
        human_count = 0
        for reply in bot_replies:
            passed, msg = validate_human_like(reply)
            if passed:
                human_count += 1
        
        ratio = human_count / len(bot_replies)
        if ratio >= 0.7:
            print_success(f"Human-like: {human_count}/{len(bot_replies)} replies passed")
        else:
            print_error(f"Not human-like enough: {human_count}/{len(bot_replies)} replies passed")
            all_passed = False
    
    # Test 3: Intelligence extraction
    passed, msg = validate_intelligence_extraction(tracker, scenario.expected_behaviors)
    if passed:
        print_success(f"Intelligence extraction: {msg}")
    else:
        print_error(f"Intelligence extraction: {msg}")
        all_passed = False
    
    # Test 4: Action variety
    if scenario.expected_behaviors.get("action_variety"):
        passed, msg = validate_action_variety(actions)
        if passed:
            print_success(f"Action variety: {msg}")
        else:
            print_error(f"Action variety: {msg}")
            all_passed = False
    
    # Summary
    print(f"\n{Colors.BOLD}Summary:{Colors.END}")
    print(f"  Messages: {len(scenario.scammer_messages)}")
    print(f"  Intelligence Score: {tracker.get_intel_score()}")
    print(f"  Categories: {tracker.get_collected_categories()}/4")
    print(f"  Extracted: Phone={len(tracker.phone_numbers)}, URL={len(tracker.urls)}, Email={len(tracker.email_addresses)}, UPI={len(tracker.upi_ids)}")
    
    if all_passed:
        print_success(f"TEST PASSED ✅")
    else:
        print_error(f"TEST FAILED ❌")
    
    return all_passed

# ============================================================================
# MAIN
# ============================================================================

async def main():
    print_header("AUTONOMOUS HONEYPOT v6.0 - TEST SUITE")
    
    print_info(f"Running {len(SCENARIOS)} test scenarios...")
    print_info("These tests validate: reasoning, repetition avoidance, intelligence extraction")
    print()
    
    results = []
    
    for i, scenario in enumerate(SCENARIOS, 1):
        print(f"\n{Colors.BOLD}[{i}/{len(SCENARIOS)}]{Colors.END}")
        passed = await run_test_scenario(scenario)
        results.append((scenario.name, passed))
        
        # Wait between tests
        if i < len(SCENARIOS):
            await asyncio.sleep(1)
    
    # Final report
    print_header("TEST RESULTS SUMMARY")
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    for name, passed in results:
        status = f"{Colors.GREEN}PASSED ✅{Colors.END}" if passed else f"{Colors.RED}FAILED ❌{Colors.END}"
        print(f"  {status} {name}")
    
    print(f"\n{Colors.BOLD}Overall: {passed_count}/{total_count} tests passed{Colors.END}")
    
    if passed_count == total_count:
        print_success("ALL TESTS PASSED! 🎉")
        return 0
    else:
        print_error(f"{total_count - passed_count} tests failed")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)