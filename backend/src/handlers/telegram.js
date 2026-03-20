import { Hono } from 'hono';
import { jsonResponse, errorResponse, requireAdmin } from '../utils/auth.js';
import { sendAllNotifications } from '../utils/notifications.js';
import { callTelegramApi, sendTelegramText } from '../utils/telegram.js';

const app = new Hono();

function extractTagNames(content) {
  if (!content) {
    return [];
  }

  const tagRegex = /#([^\s#]+)/g;
  const tagMatches = [...content.matchAll(tagRegex)];
  return [...new Set(tagMatches.map((match) => match[1]))];
}

function buildSettingsMap(settings) {
  const settingsMap = {};
  (settings || []).forEach((setting) => {
    settingsMap[setting.key] = setting.value;
  });
  return settingsMap;
}

function buildBindingMessage(chatId, fromId, boundUser) {
  const lines = [
    'Telegram 已连接到 Memos。',
    `Chat ID: ${chatId}`,
    `User ID: ${fromId}`,
  ];

  if (boundUser) {
    lines.push(`当前绑定用户: ${boundUser.nickname || boundUser.username}`);
    lines.push('直接发送文本消息即可创建 memo。');
  } else {
    lines.push('请把上面的 User ID 填到 Memos 的 Telegram UserID 设置里。');
  }

  return lines.join('\n');
}

async function findUserByTelegramId(db, candidateIds) {
  const uniqueCandidateIds = [...new Set((candidateIds || [])
    .filter((value) => value !== undefined && value !== null && value !== '')
    .map((value) => String(value)))];

  if (uniqueCandidateIds.length === 0) {
    return null;
  }

  const placeholders = uniqueCandidateIds.map(() => '?').join(', ');
  const stmt = db.prepare(`
    SELECT
      u.id,
      u.username,
      u.nickname,
      COALESCE(us.memo_visibility, 'PRIVATE') AS memoVisibility,
      us.telegram_user_id AS telegramUserId
    FROM user_settings us
    INNER JOIN users u ON us.user_id = u.id
    WHERE us.telegram_user_id IN (${placeholders})
    LIMIT 1
  `);

  return stmt.bind(...uniqueCandidateIds).first();
}

async function ensureMemoTags(db, memoId, tagNames) {
  for (const tagName of tagNames) {
    const existingTag = await db.prepare('SELECT id FROM tags WHERE name = ?').bind(tagName).first();

    let tagId = existingTag?.id;
    if (!tagId) {
      const insertResult = await db.prepare('INSERT INTO tags (name) VALUES (?)').bind(tagName).run();
      tagId = insertResult.meta.last_row_id;
    }

    await db.prepare('INSERT INTO memo_tags (memo_id, tag_id) VALUES (?, ?)').bind(memoId, tagId).run();
  }
}

async function createTelegramMemo(db, user, content) {
  const now = Math.floor(Date.now() / 1000);
  const visibility = user.memoVisibility || 'PRIVATE';
  const insertResult = await db.prepare(`
    INSERT INTO memos (creator_id, content, visibility, display_ts)
    VALUES (?, ?, ?, ?)
  `).bind(user.id, content, visibility, now).run();

  const memoId = insertResult.meta.last_row_id;
  const tagNames = extractTagNames(content);
  await ensureMemoTags(db, memoId, tagNames);

  return {
    memoId,
    createdTs: now,
    visibility,
    tagNames,
  };
}

async function getTelegramSettings(db) {
  const { results: settings } = await db.prepare(`
    SELECT key, value
    FROM settings
    WHERE key IN ('telegram-bot-token', 'instance-url')
  `).all();

  const settingsMap = buildSettingsMap(settings);
  return {
    telegramBotToken: settingsMap['telegram-bot-token'],
    instanceUrl: settingsMap['instance-url']?.replace(/\/+$/, ''),
  };
}

app.get('/webhook/info', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const { telegramBotToken } = await getTelegramSettings(db);

    if (!telegramBotToken) {
      return errorResponse('Telegram bot token is not configured', 400);
    }

    const result = await callTelegramApi(telegramBotToken, 'getWebhookInfo', {});
    return jsonResponse(result.result || {});
  } catch (error) {
    console.error('Error fetching Telegram webhook info:', error);
    return errorResponse(error.message || 'Failed to fetch Telegram webhook info', 500);
  }
});

app.post('/webhook/sync', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const body = await c.req.json().catch(() => ({}));
    const { telegramBotToken } = await getTelegramSettings(db);

    if (!telegramBotToken) {
      return errorResponse('Telegram bot token is not configured', 400);
    }

    const defaultWebhookUrl = `${new URL(c.req.url).origin}/api/v1/telegram/webhook`;
    const webhookUrl = (body.webhookUrl || defaultWebhookUrl).trim();
    const payload = {
      url: webhookUrl,
      drop_pending_updates: Boolean(body.dropPendingUpdates),
    };

    if (c.env.TELEGRAM_WEBHOOK_SECRET) {
      payload.secret_token = c.env.TELEGRAM_WEBHOOK_SECRET;
    }

    const setWebhookResult = await callTelegramApi(telegramBotToken, 'setWebhook', payload);
    const webhookInfoResult = await callTelegramApi(telegramBotToken, 'getWebhookInfo', {});

    return jsonResponse({
      message: setWebhookResult.description || 'Webhook updated',
      webhookUrl,
      webhookInfo: webhookInfoResult.result || {},
    });
  } catch (error) {
    console.error('Error syncing Telegram webhook:', error);
    return errorResponse(error.message || 'Failed to sync Telegram webhook', 500);
  }
});

app.post('/webhook', async (c) => {
  try {
    const db = c.env.DB;
    const expectedSecret = c.env.TELEGRAM_WEBHOOK_SECRET;
    if (expectedSecret) {
      const providedSecret = c.req.header('X-Telegram-Bot-Api-Secret-Token');
      if (providedSecret !== expectedSecret) {
        return errorResponse('Forbidden', 403);
      }
    }

    let update;
    try {
      update = await c.req.json();
    } catch (error) {
      return errorResponse('Invalid Telegram update payload', 400);
    }

    const { telegramBotToken, instanceUrl } = await getTelegramSettings(db);

    if (!telegramBotToken) {
      console.warn('Telegram webhook called without telegram-bot-token configured');
      return jsonResponse({ ok: true, ignored: 'telegram bot token not configured' });
    }

    const message = update?.message || update?.edited_message;
    if (!message) {
      return jsonResponse({ ok: true, ignored: 'unsupported update type' });
    }

    const chatId = String(message.chat?.id ?? '');
    const fromId = String(message.from?.id ?? '');
    const chatType = message.chat?.type;
    const content = (message.text ?? message.caption ?? '').trim();
    const normalizedContent = content.toLowerCase();

    if (!chatId || !fromId) {
      return jsonResponse({ ok: true, ignored: 'missing chat context' });
    }

    if (chatType !== 'private') {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        '当前只支持通过和机器人私聊发送文本 memo。'
      );
      return jsonResponse({ ok: true, ignored: 'non-private chat' });
    }

    const boundUser = await findUserByTelegramId(db, [chatId, fromId]);
    const isStartCommand = normalizedContent.startsWith('/start');
    const isIdCommand = normalizedContent === '/id' || normalizedContent.startsWith('/id@');

    if (isStartCommand || isIdCommand) {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        buildBindingMessage(chatId, fromId, boundUser)
      );
      return jsonResponse({ ok: true, handled: 'binding-info' });
    }

    if (!boundUser) {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        buildBindingMessage(chatId, fromId, null)
      );
      return jsonResponse({ ok: true, ignored: 'telegram user not bound' });
    }

    if (!content) {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        '当前只支持发送文本消息创建 memo。'
      );
      return jsonResponse({ ok: true, ignored: 'empty message' });
    }

    const memo = await createTelegramMemo(db, boundUser, content);
    const memoUrl = instanceUrl ? `${instanceUrl}/m/${memo.memoId}` : '';

    c.executionCtx.waitUntil(
      sendAllNotifications(db, {
        id: memo.memoId,
        content,
        visibility: memo.visibility,
        creatorId: boundUser.id,
        creatorUsername: boundUser.username,
        creatorName: boundUser.nickname || boundUser.username,
        createdTs: memo.createdTs,
        tags: memo.tagNames,
        resourceCount: 0,
      }, {
        skipTelegram: true,
      }).catch((error) => {
        console.error('Error sending notifications for Telegram memo:', error);
      })
    );

    const confirmationLines = [`已保存为 memo #${memo.memoId}。`];
    if (memoUrl) {
      confirmationLines.push(memoUrl);
    }

    await sendTelegramText(telegramBotToken, chatId, confirmationLines.join('\n'));

    return jsonResponse({
      ok: true,
      memoId: memo.memoId,
    });
  } catch (error) {
    console.error('Error handling Telegram webhook:', error);
    return errorResponse('Failed to handle Telegram webhook', 500);
  }
});

export default app;
