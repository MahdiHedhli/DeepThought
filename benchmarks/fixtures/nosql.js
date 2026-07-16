// Minimized NoSQL operator-injection shapes (CWE-943).

async function vulnerableGetTuple(config, collection) {
  const {
    thread_id,
    checkpoint_ns = "",
    checkpoint_id,
  } = config.configurable ?? {};
  const query = { thread_id, checkpoint_ns };
  if (checkpoint_id) {
    query.checkpoint_id = checkpoint_id;
  }
  return collection.find(query).toArray();
}

async function patchedGetTuple(config, collection) {
  function getStringConfigValue(name, value) {
    if (value === undefined) return undefined;
    if (value === null || typeof value !== "string") {
      throw new Error(`Invalid configurable.${name}: expected a string`);
    }
    return value;
  }
  const thread_id = getStringConfigValue("thread_id", config.configurable?.thread_id);
  const checkpoint_ns = getStringConfigValue("checkpoint_ns", config.configurable?.checkpoint_ns) ?? "";
  const query = { thread_id, checkpoint_ns };
  return collection.find(query).toArray();
}

async function vulnerableToken(req, db) {
  const token = req.body?.token;
  return db.collection("_User").findOne({ _perishable_token: token });
}

async function patchedToken(req, db) {
  const token = req.body?.token;
  if (token && typeof token !== "string") {
    throw new Error("token must be a string");
  }
  return db.collection("_User").findOne({ _perishable_token: token });
}
