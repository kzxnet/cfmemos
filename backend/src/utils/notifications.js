import { callTelegramApi } from './telegram.js';

/**
 * 发送 Webhook 通知
 * @param {string} webhookUrl - Webhook URL
 * @param {object} memoData - Memo 数据
 */
export async function sendWebhook(webhookUrl, memoData) {
  if (!webhookUrl || webhookUrl.trim() === '') {
    return;
  }

  try {
    const payload = {
      event: 'memo.created',
      timestamp: Date.now(),
      data: {
        id: memoData.id,
        content: memoData.content,
        visibility: memoData.visibility,
        creator: {
          id: memoData.creatorId,
          username: memoData.creatorUsername,
          name: memoData.creatorName,
        },
        createdTs: memoData.createdTs,
        tags: memoData.tags || [],
        resourceCount: memoData.resourceCount || 0,
      }
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Cloudflare-Memos-Webhook/1.0',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      console.error(`Webhook failed: ${response.status} ${response.statusText}`);
    } else {
      console.log('Webhook sent successfully');
    }
  } catch (error) {
    console.error('Error sending webhook:', error);
  }
}

/**
 * 发送 Telegram 通知
 * @param {string} botToken - Telegram Bot Token
 * @param {string} chatId - Telegram Chat ID
 * @param {object} memoData - Memo 数据
 * @param {string} instanceUrl - 实例 URL
 */
export async function sendTelegramNotification(botToken, chatId, memoData, instanceUrl) {
  if (!botToken || botToken.trim() === '' || !chatId || chatId.trim() === '') {
    return;
  }

  try {
    // 构建消息内容
    let message = `🆕 <b>新 Memo</b>\n\n`;
    message += `👤 <b>作者:</b> ${memoData.creatorName || memoData.creatorUsername}\n`;
    message += `⏰ <b>时间:</b> ${new Date(memoData.createdTs * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n`;
    message += `🔒 <b>可见性:</b> ${memoData.visibility === 'PUBLIC' ? '公开' : memoData.visibility === 'PRIVATE' ? '私密' : '受保护'}\n`;

    if (memoData.tags && memoData.tags.length > 0) {
      message += `🏷️ <b>标签:</b> ${memoData.tags.map(t => `#${t}`).join(' ')}\n`;
    }

    message += `\n📝 <b>内容:</b>\n`;

    // 截断过长的内容
    let content = memoData.content || '';
    if (content.length > 500) {
      content = content.substring(0, 500) + '...';
    }

    // 转义 HTML 特殊字符
    content = content
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    message += content;

    // 添加链接
    if (instanceUrl) {
      const memoUrl = `${instanceUrl}/m/${memoData.id}`;
      message += `\n\n🔗 <a href="${memoUrl}">查看详情</a>`;
    }

    const result = await callTelegramApi(botToken, 'sendMessage', {
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML',
      disable_web_page_preview: false,
    });

    if (!result.ok) {
      console.error('Telegram notification failed:', result);
    } else {
      console.log('Telegram notification sent successfully');
    }
  } catch (error) {
    console.error('Error sending Telegram notification:', error);
  }
}

/**
 * 发送所有配置的通知
 * @param {object} db - 数据库连接
 * @param {object} memoData - Memo 数据
 */
export async function sendAllNotifications(db, memoData, options = {}) {
  console.log('🔔 sendAllNotifications called for memo:', memoData.id);

  try {
    // 只通知公开的 memo
    if (memoData.visibility !== 'PUBLIC') {
      console.log('⏭️  Skipping notifications for non-public memo');
      return;
    }

    console.log('✅ Memo is PUBLIC, proceeding with notifications');

    // 获取创建者的用户设置（获取 telegram_user_id）
    const userSettingStmt = db.prepare(`
      SELECT telegram_user_id
      FROM user_settings
      WHERE user_id = ?
    `);
    const userSetting = await userSettingStmt.bind(memoData.creatorId).first();
    console.log('👤 User settings:', { userId: memoData.creatorId, telegramUserId: userSetting?.telegram_user_id });

    // 获取创建者的所有 webhooks
    const webhooksStmt = db.prepare(`
      SELECT url
      FROM webhooks
      WHERE user_id = ?
    `);
    const { results: webhooks } = await webhooksStmt.bind(memoData.creatorId).all();
    console.log('🔗 Webhooks found:', webhooks?.length || 0);

    // 获取系统设置（用于 Instance URL 和 Telegram Bot Token）
    const settingsStmt = db.prepare(`
      SELECT key, value
      FROM settings
      WHERE key IN ('telegram-bot-token', 'instance-url')
    `);
    const { results: settings } = await settingsStmt.all();

    const settingsMap = {};
    settings.forEach(s => {
      settingsMap[s.key] = s.value;
    });

    const telegramBotToken = settingsMap['telegram-bot-token'];
    const instanceUrl = settingsMap['instance-url'];

    console.log('⚙️  System settings:', {
      hasBotToken: !!telegramBotToken,
      botTokenPrefix: telegramBotToken?.substring(0, 10) + '...',
      instanceUrl
    });

    // 从用户设置中读取 telegram_user_id
    const telegramUserId = userSetting?.telegram_user_id;

    // 并行发送通知
    const promises = [];

    // 发送到所有配置的 webhooks
    if (webhooks && webhooks.length > 0) {
      webhooks.forEach(webhook => {
        if (webhook.url) {
          console.log('📤 Adding webhook to queue:', webhook.url);
          promises.push(sendWebhook(webhook.url, memoData));
        }
      });
    }

    // 发送 Telegram 通知
    if (!options.skipTelegram && telegramBotToken && telegramUserId) {
      console.log('📱 Adding Telegram notification to queue for user:', telegramUserId);
      promises.push(sendTelegramNotification(telegramBotToken, telegramUserId, memoData, instanceUrl));
    } else {
      console.log('⚠️  Telegram notification not queued:', {
        skipTelegram: Boolean(options.skipTelegram),
        hasBotToken: !!telegramBotToken,
        hasTelegramUserId: !!telegramUserId
      });
    }

    if (promises.length > 0) {
      console.log(`🚀 Sending ${promises.length} notification(s)...`);
      const results = await Promise.allSettled(promises);
      console.log('✅ All notifications processed:', results.map(r => r.status));
    } else {
      console.log('⚠️  No notification endpoints configured for this user');
    }
  } catch (error) {
    console.error('Error in sendAllNotifications:', error);
  }
}
