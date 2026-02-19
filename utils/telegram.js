const TelegramBot = require('node-telegram-bot-api');

let bot = null;
const API_URL = process.env.BACKEND_URL || 'https://lifafa-backend.onrender.com';

const initBot = (token) => {
    if (!token) return null;
    
    try {
        bot = new TelegramBot(token, { polling: true });
        console.log('🤖 Telegram Bot Connected');
        
        // Handle /start command
        bot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            let replyMsg = `👋 *Welcome to Lifafa Bot!*\n\n`;
            replyMsg += `Your Chat ID: \`${chatId}\`\n\n`;
            replyMsg += `Send /id to get your Chat ID\n`;
            replyMsg += `Send /verify <token> to verify channels`;
            
            bot.sendMessage(chatId, replyMsg, { parse_mode: 'Markdown' });
        });
        
        // Handle /id command
        bot.onText(/\/id/, (msg) => {
            const chatId = msg.chat.id;
            bot.sendMessage(chatId, `📱 Your Chat ID is: \`${chatId}\``, { parse_mode: 'Markdown' });
        });
        
        // Handle /verify command
        bot.onText(/\/verify (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const token = match[1];
            
            try {
                const response = await fetch(`${API_URL}/api/channel/verification-status/${token}`);
                const data = await response.json();
                
                if (!data.success) {
                    return bot.sendMessage(chatId, '❌ Invalid verification token');
                }
                
                const channels = data.channels;
                
                let message = '🔐 *Channel Verification*\n\n';
                message += 'Please join the following channels:\n\n';
                
                channels.forEach((ch, index) => {
                    const status = ch.verified ? '✅' : '❌';
                    message += `${status} ${ch.name}\n`;
                });
                
                message += '\nClick the buttons below after joining each channel.';
                
                const keyboard = {
                    inline_keyboard: channels.map(ch => [{
                        text: `${ch.verified ? '✅' : '❌'} ${ch.name}`,
                        callback_data: `verify_${ch.name}_${token}`
                    }])
                };
                
                if (channels.every(c => c.verified)) {
                    message += '\n\n✅ All channels verified! You can now claim in the app.';
                    await bot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
                } else {
                    await bot.sendMessage(chatId, message, {
                        parse_mode: 'Markdown',
                        reply_markup: keyboard
                    });
                }
                
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
                
                try {
                    const response = await fetch(`${API_URL}/api/channel/mark-verified`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token, channel })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        await bot.answerCallbackQuery(callbackQuery.id, {
                            text: `✅ Verified ${channel}!`,
                            show_alert: false
                        });
                        
                        // Get updated status
                        const statusRes = await fetch(`${API_URL}/api/channel/verification-status/${token}`);
                        const statusData = await statusRes.json();
                        
                        let newMessage = '🔐 *Channel Verification*\n\n';
                        newMessage += 'Please join the following channels:\n\n';
                        
                        statusData.channels.forEach(ch => {
                            const status = ch.verified ? '✅' : '❌';
                            newMessage += `${status} ${ch.name}\n`;
                        });
                        
                        const newKeyboard = {
                            inline_keyboard: statusData.channels.map(ch => [{
                                text: `${ch.verified ? '✅' : '❌'} ${ch.name}`,
                                callback_data: `verify_${ch.name}_${token}`
                            }])
                        };
                        
                        if (statusData.allVerified) {
                            newMessage += '\n\n✅ All channels verified! You can now claim in the app.';
                            await bot.editMessageText(newMessage, {
                                chat_id: chatId,
                                message_id: msg.message_id,
                                parse_mode: 'Markdown'
                            });
                        } else {
                            await bot.editMessageText(newMessage, {
                                chat_id: chatId,
                                message_id: msg.message_id,
                                parse_mode: 'Markdown',
                                reply_markup: newKeyboard
                            });
                        }
                    }
                } catch(err) {
                    await bot.answerCallbackQuery(callbackQuery.id, {
                        text: '❌ Verification failed',
                        show_alert: true
                    });
                }
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
            `🔐 *Lifafa OTP*\n\nYour OTP: *${otp}*\n\nValid for 5 minutes`,
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
            `${emoji} *Transaction*\n\n*Type:* ${type.toUpperCase()}\n*Amount:* ${sign}₹${amount}\n*Balance:* ₹${balance}\n*Description:* ${description}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendWithdrawalAlert = async (chatId, amount, status) => {
    if (!bot) return;
    try {
        const emoji = { 'pending': '⏳', 'approved': '✅', 'rejected': '❌', 'refunded': '↩️' };
        await bot.sendMessage(chatId,
            `💸 *Withdrawal ${status.toUpperCase()}*\n\n*Status:* ${emoji[status]} ${status}\n*Amount:* ₹${amount}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendLifafaAlert = async (chatId, lifafa) => {
    if (!bot) return;
    try {
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const claimLink = `${baseUrl}/claimlifafa.html?code=${lifafa.code}`;
        await bot.sendMessage(chatId,
            `🎁 *New Lifafa Created!*\n\n📌 *Title:* ${lifafa.title}\n💰 *Amount:* ₹${lifafa.amount}\n🔗 *Link:* ${claimLink}`,
            { parse_mode: 'Markdown' }
        );
    } catch(err) {}
};

const sendLifafaClaimAlert = async (chatId, lifafa, balance) => {
    if (!bot) return;
    try {
        await bot.sendMessage(chatId,
            `🧧 *Lifafa Claimed!*\n\n📌 *Title:* ${lifafa.title}\n💰 *Amount:* +₹${lifafa.amount}\n💳 *Balance:* ₹${balance}`,
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
