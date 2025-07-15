use ethers::abi::ethereum_types;
use serde_derive::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Serialize, Deserialize, Debug, Clone, Default, sqlx::FromRow)]
pub struct StageTask {
    pub id: String,
    pub status: i32,
    pub context: Option<String>,
    pub result: Option<String>,
    pub check_at: i64,
    pub step: i32,
}

#[warn(unused_macros)]
#[derive(Serialize, Deserialize, Debug, Clone, Default, sqlx::FromRow)]
pub struct ProveTask {
    pub id: String,
    pub itype: i32,
    pub proof_id: String,
    pub status: i32,
    pub time_cost: i64,
    pub node_info: String,
    pub content: Option<String>,
    pub check_at: i64,
}

#[warn(unused_macros)]
#[derive(Serialize, Deserialize, Debug, Clone, Default, sqlx::FromRow)]
pub struct User {
    pub address: String,
}

#[derive(Clone)]
pub struct Database {
    pub db_pool: sqlx::mysql::MySqlPool,
}

impl Database {
    pub fn new(database_url: &str) -> Self {
        let db_pool = sqlx::mysql::MySqlPool::connect_lazy(database_url).unwrap();
        Database { db_pool }
    }

    #[allow(dead_code)]
    pub async fn get_incomplete_stage_tasks(
        &self,
        status: i32,
        check_at: i64,
        limit: i32,
    ) -> anyhow::Result<Vec<StageTask>> {
        let rows = sqlx::query_as!(
            StageTask,
            "SELECT id, status, context, result, check_at, step from stage_task where status = ? and check_at < ? limit ?",
            status,
            check_at,
            limit,
        )
            .fetch_all(&self.db_pool)
            .await?;
        Ok(rows)
    }

    #[allow(dead_code)]
    pub async fn get_stage_task(&self, proof_id: &str) -> anyhow::Result<StageTask> {
        let row = sqlx::query_as!(
            StageTask,
            "SELECT id, status, context, result, check_at, step from stage_task where id = ?",
            proof_id,
        )
        .fetch_one(&self.db_pool)
        .await?;
        Ok(row)
    }

    #[allow(dead_code)]
    pub async fn insert_stage_task(
        &self,
        proof_id: &str,
        address: &str,
        status: i32,
        context: &str,
    ) -> anyhow::Result<bool> {
        sqlx::query!(
            "INSERT INTO stage_task (id, address, status, context) values (?,?,?,?)",
            proof_id,
            address,
            status,
            context
        )
        .execute(&self.db_pool)
        .await?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub async fn update_stage_task(
        &self,
        proof_id: &str,
        status: i32,
        result: &str,
    ) -> anyhow::Result<bool> {
        sqlx::query!(
            "UPDATE stage_task set status = ?, result = ? where id = ?",
            status,
            result,
            proof_id
        )
        .execute(&self.db_pool)
        .await?;
        Ok(true)
    }

    #[allow(dead_code)]
    #[instrument(level = "info", skip_all, fields(Step = %step))]
    pub async fn update_stage_task_check_at(
        &self,
        proof_id: &str,
        old_check_at: u64,
        check_at: u64,
        step: i32,
    ) -> anyhow::Result<u64> {
        let rows_affected = sqlx::query!(
            "UPDATE stage_task set check_at = ?, step = ? where id = ? and check_at = ?",
            check_at,
            step,
            proof_id,
            old_check_at
        )
        .execute(&self.db_pool)
        .await?
        .rows_affected();
        Ok(rows_affected)
    }

    #[allow(dead_code)]
    pub async fn insert_prove_task(&self, task: &ProveTask) -> anyhow::Result<bool> {
        sqlx::query!(
            "INSERT INTO prove_task (id, itype, proof_id, status, time_cost, node_info, content, check_at) values (?,?,?,?,?,?,?,?)",
            task.id,
            task.itype,
            task.proof_id,
            task.status,
            task.time_cost,
            task.node_info,
            task.content,
            task.check_at
        )
            .execute(&self.db_pool)
            .await?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub async fn get_prove_tasks(&self, proof_id: &str) -> anyhow::Result<Vec<ProveTask>> {
        let rows = sqlx::query_as!(
            ProveTask,
            "SELECT id, itype, proof_id, status, time_cost, node_info, content, check_at from prove_task where proof_id = ?",
            proof_id,
        )
            .fetch_all(&self.db_pool)
            .await?;
        Ok(rows)
    }

    #[allow(dead_code)]
    pub async fn get_prove_task_infos<Info>(
        &self,
        proof_id: &str,
        itype: i32,
    ) -> anyhow::Result<Vec<Info>>
    where
        Info: serde::de::DeserializeOwned,
    {
        let rows = sqlx::query_as!(
            ProveTask,
            "SELECT id, itype, proof_id, status, time_cost, node_info, content, check_at from prove_task where proof_id = ? and itype = ?",
            proof_id,
            itype,
        )
            .fetch_all(&self.db_pool)
            .await?;
        let mut task_infos: Vec<Info> = vec![];
        for row in rows {
            let task_info = serde_json::from_str(row.content.as_ref().unwrap())
                .map_err(|e| anyhow::anyhow!(e))?;
            task_infos.push(task_info);
        }
        Ok(task_infos)
    }

    /// Query the whitelisting user
    /// EIP55 support
    #[allow(dead_code)]
    pub async fn get_user(&self, address: &str) -> anyhow::Result<Vec<User>> {
        let checksum_address =
            ethers::utils::to_checksum(&address.parse::<ethereum_types::Address>()?, None);
        // Determine whether “0x” is needed based on the specific `User` table in the database.
        let checksum_address = checksum_address.trim_start_matches("0x");
        tracing::debug!("searching address {}", checksum_address);
        let rows = sqlx::query_as!(
            User,
            "SELECT address from user where address = ?",
            checksum_address,
        )
        .fetch_all(&self.db_pool)
        .await?;
        tracing::debug!("get_user: {:?}", rows);
        Ok(rows)
    }
}
