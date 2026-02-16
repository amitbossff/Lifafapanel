const TelegramBot = require('node-telegram-bot-api');

let bot = null;

const initBot = (token) => {
    if (!token) return null;
    
    try {
        bot = new TelegramBot(token, { polling: true });
        console.log('🤖 Telegram Bot Connected');
        
        // Handle /start command
        bot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            const text = msg.text;
            
            // Check if它有 referral code
            const referralCode = text.split(' ')[1];
            
            let replyMsg = `👋 Welcome to Lifafa Bot!\n\nYour Chat ID: \`${chatId}\`\n\n`;
            replyMsg += `🔐 This ID will be used for OTP verification during registration.\n\n`;
            replyMsg += `📱 Features:\n`;
            replyMsg += `• OTP for Registration\n`;
            replyMsg += `• Login Alerts\n`;
            replyMsg += `• Transaction Notifications\n`;
            replyMsg += `• Withdrawal Updates\n\n`;
            
            if (referralCode) {
                replyMsg += `🎁 Referral Code: \`${referralCode}\`\n`;
                replyMsg += `Use this code during registration!`;
            }
            
            bot.sendMessage(chatId, replyMsg, { parse_mode: 'Markdown' });
        });
        
        // Handle any message
        bot.on('message', (msg) => {
            const chatId = msg.chat.id;
            // Ignore commands
            if (!msg.text.startsWith('/')) {
                bot.sendMessage(chatId, `Your Chat ID is: \`${chatId}\``, { parse_mode: 'Markdown' });
            }
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
            `🔐 *Lifafa OTP Verification*\n\nYour OTP: *${otp}*\n\nValid for 5 minutes\n\nIf you didn't request this, ignore.`,
            { 
                parse_mode: 'Markdown',
                reply_markup: {
                    inline_keyboard: [
                        [{ text: '✅ Verify Now', callback_data: 'verify_otp' }]
                    ]
                }
            }
        );
        return true;
    } catch(err) {
        console.log('OTP send error:', err.message);
        return false;
    }
};

const sendLoginAlert = async (chatId, user, ip) => {
    if (!bot) return;
    
    try {
        await bot.sendMessage(chatId,
            `🔐 *Login Alert*\n\n` +
            `👤 Username: ${user.username}\n` +
            `📱 Number: ${user.number}\n` +
            `⏰ Time: ${new Date().toLocaleString()}\n` +
            `🌐 IP: ${ip || 'Unknown'}\n\n` +
            `*Not you? Contact admin immediately!*`,
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
            `${emoji} *Transaction Alert*\n\n` +
            `Type: ${type.toUpperCase()}\n` +
            `Amount: ${sign}₹${amount}\n` +
            `Balance: ₹${balance}\n` +
            `Description: ${description}\n` +
            `Time: ${new Date().toLocaleString()}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendWithdrawalAlert = async (chatId, amount, status) => {
    if (!bot) return;
    
    try {
        const statusEmoji = {
            'pending': '⏳',
            'approved': '✅',
            'rejected': '❌'
        };
        
        await bot.sendMessage(chatId,
            `💸 *Withdrawal ${status.toUpperCase()}*\n\n` +
            `Amount: ₹${amount}\n` +
            `Status: ${statusEmoji[status]} ${status}\n` +
            `Time: ${new Date().toLocaleString()}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendLifafaAlert = async (chatId, lifafa) => {
    if (!bot) return;
    
    try {
        await bot.sendMessage(chatId,
            `🎁 *New Lifafa Created!*\n\n` +
            `Title: ${lifafa.title}\n` +
            `Amount: ₹${lifafa.amount}\n` +
            `Code: \`${lifafa.code}\`\n` +
            `Channel: ${lifafa.channel || 'None'}\n\n` +
            `Claim now in the app!`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendLifafaClaimAlert = async (chatId, lifafa, balance) => {
    if (!bot) return;
    
    try {
        await bot.sendMessage(chatId,
            `🧧 *Lifafa Claimed!*\n\n` +
            `Title: ${lifafa.title}\n` +
            `Amount: +₹${lifafa.amount}\n` +
            `New Balance: ₹${balance}\n\n` +
            `🎉 Congratulations!`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendBulkLifafaClaimAlert = async (chatId, totalLifafas, totalAmount, newBalance) => {
    if (!bot) return;
    
    try {
        await bot.sendMessage(chatId,
            `🎊 *Bulk Lifafa Claimed!*\n\n` +
            `Total Lifafas: ${totalLifafas}\n` +
            `Total Amount: +₹${totalAmount}\n` +
            `New Balance: ₹${newBalance}\n\n` +
            `✨ All unclaimed lifafas added to your account!`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const checkTelegramUID = async (chatId) => {
    if (!bot) return false;
    
    try {
        await bot.getChat(chatId);
        return true;
    } catch(err) {
        return false;
    }
};

module.exports = {
    initBot,
    sendOTP,
    sendLoginAlert,
    sendTransactionAlert,
    sendWithdrawalAlert,
    sendLifafaAlert,
    sendLifafaClaimAlert,
    sendBulkLifafaClaimAlert,
    checkTelegramUID
};
