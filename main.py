"""
Combined Telegram Bot + Webhook Server
Runs on Render.com
"""

import os
import logging
import threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
import requests

# Import your existing bot functions
from bot import (
    get_or_create_user,
    get_active_subscription,
    create_btcpay_invoice,
    save_payment,
    SUPABASE_URL,
    SUPABASE_KEY,
    TELEGRAM_BOT_TOKEN,
    BTCPAY_URL,
    BTCPAY_API_KEY,
    BTCPAY_STORE_ID,
    SUBSCRIPTION_PRICE,
    SUBSCRIPTION_DAYS
)

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Flask app for webhook
app = Flask(__name__)

# Supabase helper (using REST API)
def supabase_request(method, table, params=None, data=None):
    """Make request to Supabase REST API"""
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
    }
    
    if method == 'GET':
        response = requests.get(url, headers=headers, params=params)
    elif method == 'POST':
        response = requests.post(url, headers=headers, json=data)
    elif method == 'PATCH':
        response = requests.patch(url, headers=headers, params=params, json=data)
    
    return response.json() if response.ok else None


def send_telegram_message(telegram_id, message):
    """Send message via Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={
            'chat_id': telegram_id,
            'text': message,
            'parse_mode': 'HTML'
        })
    except Exception as e:
        logger.error(f"Telegram error: {e}")


# Webhook endpoints
@app.route('/webhook/btcpay', methods=['POST'])
def btcpay_webhook():
    """Handle BTCPay payment notifications"""
    try:
        webhook_data = request.json
        event_type = webhook_data.get('type')
        invoice_id = webhook_data.get('invoiceId')
        
        logger.info(f"Webhook: {event_type} for invoice {invoice_id}")
        
        if event_type not in ['InvoiceSettled', 'InvoiceProcessing', 'InvoiceReceivedPayment']:
            return jsonify({'status': 'ignored'}), 200
        
        # Get payment from database
        payments = supabase_request('GET', 'payments', {
            'btcpay_invoice_id': f'eq.{invoice_id}'
        })
        
        if not payments:
            return jsonify({'error': 'Payment not found'}), 404
        
        payment = payments[0]
        telegram_id = payment['user_id']
        
        # Update payment status
        supabase_request('PATCH', 'payments', 
            {'id': f'eq.{payment["id"]}'},
            {'status': 'paid', 'paid_at': datetime.now().isoformat()}
        )
        
        # Check existing subscription
        subs = supabase_request('GET', 'subscriptions', {
            'user_id': f'eq.{telegram_id}',
            'status': f'eq.active'
        })
        
        now = datetime.now()
        
        if subs:
            # Extend subscription
            sub = subs[0]
            current_end = datetime.fromisoformat(sub['end_date'])
            new_end = max(current_end, now) + timedelta(days=SUBSCRIPTION_DAYS)
            
            supabase_request('PATCH', 'subscriptions',
                {'id': f'eq.{sub["id"]}'},
                {'end_date': new_end.isoformat()}
            )
        else:
            # Create new subscription
            end_date = now + timedelta(days=SUBSCRIPTION_DAYS)
            subabase_request('POST', 'subscriptions', data={
                'user_id': telegram_id,
                'status': 'active',
                'plan_type': 'monthly',
                'amount_paid': payment['amount'],
                'start_date': now.isoformat(),
                'end_date': end_date.isoformat()
            })
            new_end = end_date
        
        # Send confirmation
        send_telegram_message(telegram_id,
            f"✅ <b>Payment Confirmed!</b>\n\n"
            f"Your subscription is active until:\n"
            f"📅 {new_end.strftime('%B %d, %Y')}\n\n"
            f"Welcome to premium! 🎉"
        )
        
        # Log activity
        supabase_request('POST', 'activity_logs', data={
            'user_id': telegram_id,
            'action': 'payment_received',
            'details': {
                'invoice_id': invoice_id,
                'amount': payment['amount'],
                'end_date': new_end.isoformat()
            }
        })
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'bot': 'running',
        'webhook': 'ready'
    }), 200


def run_flask():
    """Run Flask server in a thread"""
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port)


def run_bot():
    """Run Telegram bot"""
    from bot import main as bot_main
    bot_main()


if __name__ == '__main__':
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    logger.info("Flask webhook server started")
    logger.info("Starting Telegram bot...")
    
    # Run bot in main thread
    run_bot()