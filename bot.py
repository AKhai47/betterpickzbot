"""
Telegram Subscription Bot with BTCPay & Supabase
Run this on PythonAnywhere or any Python hosting
"""

__all__ = [
    'get_or_create_user',
    'get_active_subscription', 
    'create_btcpay_invoice',
    'save_payment',
    'SUPABASE_URL',
    'SUPABASE_KEY',
    'TELEGRAM_BOT_TOKEN',
    'BTCPAY_URL',
    'BTCPAY_API_KEY',
    'BTCPAY_STORE_ID',
    'SUBSCRIPTION_PRICE',
    'SUBSCRIPTION_DAYS'
]

from dotenv import load_dotenv
load_dotenv()

import os
import requests
import logging
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from supabase import create_client, Client


# Configuration from environment variables
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
BTCPAY_URL = os.getenv('BTCPAY_URL')  # e.g., https://betterpickzbtcpay.duckdns.org
BTCPAY_API_KEY = os.getenv('BTCPAY_API_KEY')
BTCPAY_STORE_ID = os.getenv('BTCPAY_STORE_ID')
SUBSCRIPTION_PRICE = float(os.getenv('SUBSCRIPTION_PRICE', '10.00'))  # Default $10
SUBSCRIPTION_DAYS = int(os.getenv('SUBSCRIPTION_DAYS', '30'))  # Default 30 days

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Initialize Supabase
try:
    if SUPABASE_URL and SUPABASE_KEY:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    else:
        supabase = None
        logger.warning("Supabase credentials not set")
except Exception as e:
    logger.error(f"Error initializing Supabase: {e}")
    supabase = None

# Database Helper Functions
def get_or_create_user(telegram_id: int, username: str = None, first_name: str = None):
    """Get user from database or create if doesn't exist"""
    try:
        # Check if user exists
        result = supabase.table('users').select('*').eq('telegram_id', telegram_id).execute()
        
        if result.data:
            return result.data[0]
        
        # Create new user
        new_user = {
            'telegram_id': telegram_id,
            'username': username,
            'first_name': first_name
        }
        result = supabase.table('users').insert(new_user).execute()
        return result.data[0]
    except Exception as e:
        logger.error(f"Error in get_or_create_user: {e}")
        return None


def get_active_subscription(telegram_id: int):
    """Check if user has active subscription"""
    try:
        result = supabase.table('subscriptions')\
            .select('*')\
            .eq('user_id', telegram_id)\
            .eq('status', 'active')\
            .gte('end_date', datetime.now().isoformat())\
            .execute()
        
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        logger.error(f"Error checking subscription: {e}")
        return None


def create_btcpay_invoice(telegram_id: int, amount: float):
    """Create invoice in BTCPay Server"""
    try:
        url = f"{BTCPAY_URL}/api/v1/stores/{BTCPAY_STORE_ID}/invoices"
        headers = {
            'Authorization': f'token {BTCPAY_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'amount': str(amount),
            'currency': 'USD',
            'metadata': {
                'orderId': f'sub_{telegram_id}_{int(datetime.now().timestamp())}',
                'userId': str(telegram_id),
                'subscriptionDays': str(SUBSCRIPTION_DAYS)
            },
            'checkout': {
                'speedPolicy': 'HighSpeed',
                'paymentMethods': ['BTC', 'BTC-LightningNetwork'],
                'redirectURL': f'https://t.me/YOUR_BOT_USERNAME'
            }
        }
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        invoice_data = response.json()
        return invoice_data
    except Exception as e:
        logger.error(f"Error creating BTCPay invoice: {e}")
        return None


def save_payment(telegram_id: int, invoice_data: dict):
    """Save payment to database"""
    try:
        payment = {
            'user_id': telegram_id,
            'btcpay_invoice_id': invoice_data['id'],
            'amount': float(invoice_data['amount']),
            'currency': invoice_data['currency'],
            'status': 'pending',
            'invoice_url': invoice_data['checkoutLink']
        }
        result = supabase.table('payments').insert(payment).execute()
        return result.data[0]
    except Exception as e:
        logger.error(f"Error saving payment: {e}")
        return None


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    user = update.effective_user
    telegram_id = user.id
    
    # Create or get user
    get_or_create_user(telegram_id, user.username, user.first_name)
    
    # Check if user has active subscription
    subscription = get_active_subscription(telegram_id)
    
    if subscription:
        end_date = datetime.fromisoformat(subscription['end_date'])
        await update.message.reply_text(
            f"👋 Welcome back, {user.first_name}!\n\n"
            f"✅ Your subscription is active until:\n"
            f"📅 {end_date.strftime('%B %d, %Y')}\n\n"
            f"Commands:\n"
            f"/status - Check subscription status\n"
            f"/subscribe - Renew subscription"
        )
    else:
        await update.message.reply_text(
            f"👋 Welcome, {user.first_name}!\n\n"
            f"💎 Premium Subscription\n"
            f"💰 ${SUBSCRIPTION_PRICE}/month\n\n"
            f"Get access to exclusive content!\n\n"
            f"Commands:\n"
            f"/subscribe - Get started\n"
            f"/status - Check status"
        )


async def subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /subscribe command"""
    user = update.effective_user
    
    await update.message.reply_text(
        f"💎 Premium Subscription\n\n"
        f"💰 Price: ${SUBSCRIPTION_PRICE}\n"
        f"⏱ Duration: {SUBSCRIPTION_DAYS} days\n\n"
        f"✨ Benefits:\n"
        f"• Access to all premium content\n"
        f"• Priority support\n"
        f"• Exclusive updates\n\n"
        f"⚠️ Payment processing coming soon!\n"
        f"BTCPay Server is still syncing. Will be ready shortly!"
    )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command"""
    user = update.effective_user
    telegram_id = user.id
    
    subscription = get_active_subscription(telegram_id)
    
    if subscription:
        end_date = datetime.fromisoformat(subscription['end_date'])
        days_left = (end_date - datetime.now()).days
        
        await update.message.reply_text(
            f"📊 Subscription Status\n\n"
            f"✅ Status: Active\n"
            f"📅 Expires: {end_date.strftime('%B %d, %Y')}\n"
            f"⏳ Days remaining: {days_left}\n\n"
            f"Use /subscribe to renew!"
        )
    else:
        await update.message.reply_text(
            f"📊 Subscription Status\n\n"
            f"❌ Status: Inactive\n\n"
            f"Use /subscribe to get started!"
        )


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button clicks"""
    query = update.callback_query
    await query.answer()
    
    user = query.from_user
    telegram_id = user.id
    
    if query.data == 'create_invoice':
        # Send "creating invoice" message
        await query.edit_message_text("⏳ Creating your payment invoice...")
        
        # Create BTCPay invoice
        invoice_data = create_btcpay_invoice(telegram_id, SUBSCRIPTION_PRICE)
        
        if not invoice_data:
            await query.edit_message_text(
                "❌ Error creating invoice. Please try again later or contact support."
            )
            return
        
        # Save to database
        save_payment(telegram_id, invoice_data)
        
        # Send invoice with QR code
        checkout_link = invoice_data['checkoutLink']
        
        keyboard = [
            [InlineKeyboardButton("💳 Open Payment Page", url=checkout_link)]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"✅ Invoice Created!\n\n"
            f"💰 Amount: ${SUBSCRIPTION_PRICE}\n"
            f"⏱ Valid for: 15 minutes\n\n"
            f"Click the button below to pay with your crypto wallet.\n"
            f"You'll receive a confirmation once payment is received!",
            reply_markup=reply_markup
        )
        
        logger.info(f"Invoice created for user {telegram_id}: {invoice_data['id']}")


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log errors"""
    logger.error(f"Update {update} caused error {context.error}")


def main():
    """Start the bot"""
    # Create application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("subscribe", subscribe))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_error_handler(error_handler)
    
    # Start bot
    logger.info("Bot started!")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
