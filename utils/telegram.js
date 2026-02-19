const TelegramBot = require('node-telegram-bot-api');

let bot = null;

const initBot = (token) => {
    if (!token) return null;
    
    try {
        bot = new TelegramBot(token, { polling: true });
        console.log('🤖 Telegram Bot Connected');
        
        bot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            let replyMsg = `👋 *Welcome to Lifafa Bot!*\n\n`;
            replyMsg += `Your Chat ID: \`${chatId}\`\n\n`;
            replyMsg += `Send /id to get your Chat ID`;
            bot.sendMessage(chatId, replyMsg, { parse_mode: 'Markdown' });
        });
        
        bot.onText(/\/id/, (msg) => {
            const chatId = msg.chat.id;
            bot.sendMessage(chatId, `📱 Your Chat ID is: \`${chatId}\``, { parse_mode: 'Markdown' });
        });
        
        return bot;
    } catch(err) {
        console.log('❌ Telegram Bot Error:', err.message);
        return null;
    }
};

const sendOTP = async (chatId, otp) => {
    if (!bot) return false;
    try {
        await bot.sendMessage(chatId, 
            `🔐 *Lifafa OTP Verification*\n\nYour OTP: *${otp}*\n\n⏱️ Valid for 5 minutes`,
            { parse_mode: 'Markdown' }
        );
        return true;
    } catch(err) {
        return false;
    }
};

const sendLoginAlert = async (chatId, user, ip) => {
    if (!bot) return;
    try {
        await bot.sendMessage(chatId,
            `🔐 *Login Alert*\n\n👤 *Username:* ${user.username}\n📱 *Number:* ${user.number}\n⏰ *Time:* ${new Date().toLocaleString()}\n🌐 *IP:* ${ip || 'Unknown'}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendTransactionAlert = async (chatId, type, amount, balance, description) => {
    if (!bot) return;
    try {
        const emoji = type === 'credit' ? '💰' : '💸';
        const sign = type === 'credit' ? '+' : '-';
        await bot.sendMessage(chatId,
            `${emoji} *Transaction Alert*\n\n*Type:* ${type.toUpperCase()}\n*Amount:* ${sign}₹${amount}\n*New Balance:* ₹${balance}\n*Description:* ${description}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendWithdrawalAlert = async (chatId, amount, status) => {
    if (!bot) return;
    try {
        const statusEmoji = { 'pending': '⏳', 'approved': '✅', 'rejected': '❌', 'refunded': '↩️' };
        await bot.sendMessage(chatId,
            `💸 *Withdrawal ${status.toUpperCase()}*\n\n*Status:* ${statusEmoji[status]} ${status}\n*Amount:* ₹${amount}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendLifafaAlert = async (chatId, lifafa) => {
    if (!bot) return;
    try {
        await bot.sendMessage(chatId,
            `🎁 *New Lifafa Created!*\n\n*Title:* ${lifafa.title}\n*Amount:* ₹${lifafa.amount}\n*Code:* \`${lifafa.code}\``,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendLifafaClaimAlert = async (chatId, lifafa, balance) => {
    if (!bot) return;
    try {
        await bot.sendMessage(chatId,
            `🧧 *Lifafa Claimed!*\n\n*Title:* ${lifafa.title}\n*Amount:* +₹${lifafa.amount}\n*New Balance:* ₹${balance}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendMessage = async (chatId, text, options = {}) => {
    if (!bot) return false;
    try {
        await bot.sendMessage(chatId, text, options);
        return true;
    } catch(err) {
        return false;
    }
};

// Add this to your Telegram bot code (utils/telegram.js)

// Handle /verify command
bot.onText(/\/verify (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const token = match[1]; // Verification token from URL
    
    try {
        // Get verification data from backend
        const response = await fetch(`${API_URL}/api/channel/verification-status/${token}`);
        const data = await response.json();
        
        if (!data.success) {
            return bot.sendMessage(chatId, '❌ Invalid verification token');
        }
        
        const channels = data.channels;
        let message = '🔐 *Channel Verification*\n\n';
        message += 'Please join the following channels:\n\n';
        
        channels.forEach((ch, index) => {
            message += `${index + 1}. ${ch.name}\n`;
        });
        
        message += '\nAfter joining, click "I\'ve Joined" for each channel.';
        
        // Create inline keyboard for each channel
        const keyboard = {
            inline_keyboard: channels.map(ch => [{
                text: `✅ I've joined ${ch.name}`,
                callback_data: `verify_${ch.name}_${token}`
            }])
        };
        
        await bot.sendMessage(chatId, message, {
            parse_mode: 'Markdown',
            reply_markup: keyboard
        });
        
    } catch(err) {
        bot.sendMessage(chatId, '❌ Verification failed. Please try again.');
    }
});

// Handle callback queries
bot.on('callback_query', async (callbackQuery) => {
    const msg = callbackQuery.message;
    const chatId = msg.chat.id;
    const data = callbackQuery.data;
    
    if (data.startsWith('verify_')) {
        const parts = data.split('_');
        const channel = parts[1];
        const token = parts[2];
        
        // Mark channel as verified in backend
        await fetch(`${API_URL}/api/channel/mark-verified`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, channel })
        });
        
        await bot.answerCallbackQuery(callbackQuery.id, {
            text: `✅ Verified ${channel}!`,
            show_alert: false
        });
        
        // Update message
        await bot.editMessageText(
            msg.text + `\n\n✅ ${channel} verified!`,
            {
                chat_id: chatId,
                message_id: msg.message_id,
                parse_mode: 'Markdown'
            }
        );
    }
});

// Handle /start with verification token
bot.onText(/\/start (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const token = match[1];
    
    if (token.startsWith('verify_')) {
        // Handle verification
        const channel = token.replace('verify_', '');
        // ... verification logic
    } else {
        // Normal start
        bot.sendMessage(chatId, '👋 Welcome to Lifafa Bot!');
    }
});

module.exports = {
    initBot,
    sendOTP,
    sendLoginAlert,
    sendTransactionAlert,
    sendWithdrawalAlert,
    sendLifafaAlert,
    sendLifafaClaimAlert,
    sendMessage
};
