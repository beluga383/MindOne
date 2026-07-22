-- 同一名称和权重哈希代表同一 canonical 模型，可由不同用户的节点共同承载。
-- owner_user_id 仍记录首个发布者；后续发布者只能创建自己的实例，不能覆盖模型元数据。
CREATE UNIQUE INDEX IF NOT EXISTS models_canonical_name_hash_idx
    ON models (name, weights_hash);
