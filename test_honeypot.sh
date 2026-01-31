#!/bin/bash

# Known fallback responses (from your code)
FALLBACKS=(
    "What is this about? I don't understand."
    "Why are you messaging me?"
    "Is this really from my bank?"
    "Can you explain more clearly?"
    "How do I know this is legitimate?"
    "What exactly do I need to do?"
    "What happens next?"
    "Do I need to visit anywhere?"
    "Can you send me more details?"
    "Where should I send the information?"
    "What's your official contact number?"
    "Is there a website I should use?"
    "Just to confirm, what details do you need from me?"
    "What's the process after I share the information?"
    "Can I call your helpline to verify?"
    "I see. Tell me more."
)

echo "======================================================================"
echo "    HONEYPOT OPENAI DIAGNOSIS"
echo "======================================================================"
echo ""

API_KEY="Xk7pQm9RvT2nL5wY8hJcA1bN4fG6dS3e"
BASE_URL="https://honeypot-f1pp.onrender.com"

# Test 3 times to see if we get varied responses
echo "Running 3 tests with the same scam message..."
echo "If OpenAI is working: responses will be varied and unique"
echo "If OpenAI is failing: responses will be from fallback list"
echo ""

for i in 1 2 3; do
    echo "Test $i:"
    RESPONSE=$(curl -s -X POST "$BASE_URL/honeypot" \
      -H "Content-Type: application/json" \
      -H "x-api-key: $API_KEY" \
      -d '{
        "sessionId": "diagnosis-'$RANDOM'",
        "message": "URGENT: Your SBI account has been compromised. Share your account number and OTP immediately.",
        "conversationHistory": []
      }')
    
    REPLY=$(echo "$RESPONSE" | jq -r '.reply' 2>/dev/null)
    echo "  Reply: \"$REPLY\""
    
    # Check if it's a fallback
    IS_FALLBACK=false
    for fallback in "${FALLBACKS[@]}"; do
        if [ "$REPLY" = "$fallback" ]; then
            IS_FALLBACK=true
            break
        fi
    done
    
    if [ "$IS_FALLBACK" = true ]; then
        echo "  Status: ❌ FALLBACK (OpenAI not working)"
    else
        echo "  Status: ✅ Possibly AI-generated"
    fi
    echo ""
    sleep 1
done

echo "======================================================================"
echo "DIAGNOSIS:"
echo "======================================================================"
echo ""
echo "If you see FALLBACK responses above, your OpenAI API is failing."
echo ""
echo "MOST LIKELY CAUSES:"
echo "1. OpenAI API key not set in Render environment variables"
echo "2. OpenAI API key is invalid or expired"  
echo "3. OpenAI account has no credits/quota exceeded"
echo ""
echo "HOW TO FIX:"
echo "1. Get a valid OpenAI key: https://platform.openai.com/api-keys"
echo "2. Go to Render Dashboard → honeypot-f1pp → Environment"
echo "3. Add/Update: OPENAI_API_KEY = sk-proj-YOUR-KEY-HERE"
echo "4. Save (service will auto-redeploy)"
echo "5. Check Render logs for: '✓ OpenAI API call successful'"
echo ""
echo "TO CHECK RENDER LOGS:"
echo "https://dashboard.render.com → Your Service → Logs tab"
echo "Look for errors like: 'Error code: 401' or 'quota exceeded'"
echo ""
echo "======================================================================"