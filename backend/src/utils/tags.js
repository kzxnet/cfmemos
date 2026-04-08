let cachedTagSchemaPromise = null;

function buildTagSelectColumns(schema) {
  return [
    'id',
    'name',
    schema.hasCreatorId ? 'creator_id as creatorId' : 'NULL as creatorId',
    schema.hasCreatedTs ? 'created_ts as createdTs' : 'NULL as createdTs',
  ].join(', ');
}

async function loadTagSchema(db) {
  const { results } = await db.prepare('PRAGMA table_info(tags)').all();
  const columns = new Set((results || []).map((column) => column.name));

  return {
    hasCreatorId: columns.has('creator_id'),
    hasCreatedTs: columns.has('created_ts'),
  };
}

async function getTagById(db, id, schema) {
  const stmt = db.prepare(`
    SELECT ${buildTagSelectColumns(schema)}
    FROM tags
    WHERE id = ?
  `);
  return stmt.bind(id).first();
}

export async function getTagSchema(db) {
  if (!cachedTagSchemaPromise) {
    cachedTagSchemaPromise = loadTagSchema(db).catch((error) => {
      cachedTagSchemaPromise = null;
      throw error;
    });
  }

  return cachedTagSchemaPromise;
}

export async function findTagByName(db, tagName, creatorId = null) {
  const schema = await getTagSchema(db);
  const selectColumns = buildTagSelectColumns(schema);

  if (schema.hasCreatorId && creatorId !== null && creatorId !== undefined) {
    const exactMatch = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ? AND creator_id = ?
      LIMIT 1
    `).bind(tagName, creatorId).first();

    if (exactMatch) {
      return { schema, tag: exactMatch, matchType: 'owned' };
    }

    const legacyTag = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ? AND creator_id IS NULL
      LIMIT 1
    `).bind(tagName).first();

    if (legacyTag) {
      return { schema, tag: legacyTag, matchType: 'legacy' };
    }

    const globalTag = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ?
      LIMIT 1
    `).bind(tagName).first();

    if (globalTag) {
      return { schema, tag: globalTag, matchType: 'global' };
    }
  } else {
    const tag = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ?
      LIMIT 1
    `).bind(tagName).first();

    if (tag) {
      return { schema, tag, matchType: 'global' };
    }
  }

  return { schema, tag: null, matchType: null };
}

export async function upsertTagRecord(db, rawTagName, creatorId = null) {
  const tagName = rawTagName?.trim();
  const lookup = await findTagByName(db, tagName, creatorId);
  const { schema } = lookup;

  if (lookup.tag) {
    if (lookup.matchType === 'legacy' && schema.hasCreatorId && creatorId !== null && creatorId !== undefined) {
      await db.prepare(`
        UPDATE tags
        SET creator_id = ?
        WHERE id = ? AND creator_id IS NULL
      `).bind(creatorId, lookup.tag.id).run();

      const adoptedTag = await getTagById(db, lookup.tag.id, schema);
      return { tag: adoptedTag, created: false, adopted: true, schema };
    }

    return {
      tag: lookup.tag,
      created: false,
      adopted: false,
      schema,
      conflict: lookup.matchType === 'global' && schema.hasCreatorId && lookup.tag.creatorId !== null && lookup.tag.creatorId !== creatorId,
    };
  }

  const insertStmt = schema.hasCreatorId && creatorId !== null && creatorId !== undefined
    ? db.prepare('INSERT INTO tags (name, creator_id) VALUES (?, ?)')
    : db.prepare('INSERT INTO tags (name) VALUES (?)');
  const bindValues = schema.hasCreatorId && creatorId !== null && creatorId !== undefined
    ? [tagName, creatorId]
    : [tagName];

  try {
    const result = await insertStmt.bind(...bindValues).run();
    const createdTag = await getTagById(db, result.meta.last_row_id, schema);
    return { tag: createdTag, created: true, adopted: false, schema, conflict: false };
  } catch (error) {
    const conflictLookup = await findTagByName(db, tagName, creatorId);
    if (conflictLookup.tag) {
      return {
        tag: conflictLookup.tag,
        created: false,
        adopted: false,
        schema,
        conflict: conflictLookup.matchType === 'global' && schema.hasCreatorId && conflictLookup.tag.creatorId !== null && conflictLookup.tag.creatorId !== creatorId,
      };
    }

    throw error;
  }
}

export async function attachTagToMemo(db, memoId, rawTagName, creatorId = null) {
  const { tag, conflict } = await upsertTagRecord(db, rawTagName, creatorId);

  await db.prepare(`
    INSERT OR IGNORE INTO memo_tags (memo_id, tag_id)
    VALUES (?, ?)
  `).bind(memoId, tag.id).run();

  return { tag, conflict };
}
