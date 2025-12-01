use serde::{Deserialize, Serialize};

use crate::proto::includes::v1::AggregateInput;
use crate::stage::tasks::{ProveTask, Trace, TASK_STATE_SUCCESS, TASK_STATE_UNPROCESSED};

pub fn from_prove_task(prove_task: &ProveTask) -> AggregateInput {
    AggregateInput {
        // we put the receipt of prove_task, instead of the file path
        receipt_input: vec![],
        computed_request_id: prove_task.task_id.clone(),
        is_agg: false,
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AggTask {
    pub task_id: String,
    pub state: u32,
    pub proof_id: String,

    pub block_no: Option<u64>,
    pub seg_size: u32,
    // vk for zkm2 core proof
    pub vk: Vec<u8>,
    // #[serde(skip_serializing, skip_deserializing)]
    pub inputs: Vec<AggregateInput>,
    pub is_final: bool,
    pub is_first_shard: bool,
    pub is_leaf_layer: bool,
    pub from_prove: bool,
    pub agg_index: i32,
    pub is_deferred: bool,

    pub trace: Trace,

    #[serde(skip_serializing, skip_deserializing)]
    pub output: Vec<u8>, // output_receipt: Vec<u8>,

    // depend
    // TODO: default value may be dangerous
    pub childs: Vec<Option<String>>,
}

impl AggTask {
    pub fn clear_child_task(&mut self, task_id: &str) -> bool {
        if self.state == TASK_STATE_UNPROCESSED {
            for child in &mut self.childs {
                if let Some(t) = child {
                    if *t == task_id {
                        *child = None;
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn to_agg_input(&self) -> AggregateInput {
        // For the receipt_input, nothing we can do here when we create the calculation graph, so give it a default value
        AggregateInput {
            receipt_input: vec![],
            computed_request_id: self.task_id.clone(),
            is_agg: !self.from_prove,
        }
    }

    pub fn init_from_prove_tasks(
        vk: &[u8],
        prove_tasks: &[ProveTask],
        agg_index: i32,
        is_final: bool,
        is_first_shard: bool,
        is_deferred: bool,
    ) -> AggTask {
        let mut agg_task = AggTask {
            task_id: uuid::Uuid::new_v4().to_string(),
            block_no: prove_tasks[0].program.block_no,
            state: TASK_STATE_UNPROCESSED,
            seg_size: prove_tasks[0].program.seg_size,
            proof_id: prove_tasks[0].program.proof_id.clone(),
            vk: vk.to_owned(),
            inputs: prove_tasks.iter().map(from_prove_task).collect(),
            is_final,
            is_first_shard,
            is_leaf_layer: true,
            is_deferred,
            agg_index,
            ..Default::default()
        };

        if !is_deferred {
            agg_task.childs = prove_tasks
                .iter()
                .map(|t| Some(t.task_id.to_owned()))
                .collect();
        }

        agg_task
    }

    pub fn init_from_agg_tasks(agg_tasks: &[AggTask], agg_index: i32, is_final: bool) -> AggTask {
        let agg_task = AggTask {
            task_id: uuid::Uuid::new_v4().to_string(),
            block_no: agg_tasks[0].block_no,
            state: TASK_STATE_UNPROCESSED,
            seg_size: agg_tasks[0].seg_size,
            proof_id: agg_tasks[0].proof_id.clone(),
            inputs: agg_tasks.iter().map(|t| t.to_agg_input()).collect(),
            is_final,
            is_leaf_layer: false,
            agg_index,
            childs: agg_tasks
                .iter()
                .map(|t| Some(t.task_id.to_owned()))
                .collect(),
            ..Default::default()
        };
        // for (raw_agg_task, child) in agg_tasks.iter().zip(agg_task.childs.iter_mut()) {
        //     if !raw_agg_task.from_prove {
        //         *child = Some(raw_agg_task.task_id.clone());
        //     }
        // }
        agg_task
    }

    // FIXME: if we have a single prove task, and try to aggegate its root proof, panic will raise
    // So we just set up the state successful
    pub fn init_from_single_prove_task(prove_task: &ProveTask, agg_index: i32) -> AggTask {
        // let task_id = uuid::Uuid::new_v4().to_string();
        AggTask {
            task_id: prove_task.task_id.clone(),
            block_no: prove_task.program.block_no,
            state: TASK_STATE_SUCCESS,
            seg_size: prove_task.program.seg_size,
            proof_id: prove_task.program.proof_id.clone(),
            // inputs: vec![from_prove_task(prove_task)],
            from_prove: true,
            agg_index,
            ..Default::default()
        }
    }

    // TODO: merge init_from_single_prove_task and init_from_two_prove_task
    pub fn init_from_two_prove_task(
        left: &ProveTask,
        right: &ProveTask,
        agg_index: i32,
    ) -> AggTask {
        AggTask {
            task_id: uuid::Uuid::new_v4().to_string(),
            block_no: left.program.block_no,
            state: TASK_STATE_UNPROCESSED,
            seg_size: left.program.seg_size,
            proof_id: left.program.proof_id.clone(),
            inputs: vec![from_prove_task(left), from_prove_task(right)],
            agg_index,
            childs: vec![Some(left.task_id.clone()), Some(right.task_id.clone())],
            ..Default::default()
        }
    }

    pub fn init_from_two_agg_task(left: &AggTask, right: &AggTask, agg_index: i32) -> AggTask {
        let mut agg_task = AggTask {
            task_id: uuid::Uuid::new_v4().to_string(),
            block_no: left.block_no,
            state: TASK_STATE_UNPROCESSED,
            seg_size: left.seg_size,
            proof_id: left.proof_id.clone(),
            inputs: vec![left.to_agg_input(), right.to_agg_input()],
            agg_index,
            childs: vec![None, None],
            ..Default::default()
        };
        // if !left.from_prove {
        agg_task.childs[0] = Some(left.task_id.clone());
        // }
        // if !right.from_prove {
        agg_task.childs[1] = Some(right.task_id.clone());
        // }
        agg_task
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_clear_child_task() {
        let left_task_id = "test_id_1";
        let right_task_id = "test_id_2";
        let mut agg_task = AggTask {
            state: TASK_STATE_UNPROCESSED,
            childs: vec![
                Some(left_task_id.to_string()),
                Some(right_task_id.to_string()),
            ],
            ..Default::default()
        };
        agg_task.clear_child_task(left_task_id);
        agg_task.clear_child_task(right_task_id);
        assert!(agg_task.childs[0].is_none());
        assert!(agg_task.childs[1].is_none());
    }

    #[test]
    fn test_init_from_single_prove_task() {
        let prove_task = ProveTask {
            file_no: 1,
            ..Default::default()
        };
        let agg_task = crate::stage::tasks::AggTask::init_from_single_prove_task(&prove_task, 1);
        assert_eq!(agg_task.state, TASK_STATE_SUCCESS);
    }

    #[test]
    fn test_init_from_two_prove_task() {
        let left_prove_task = ProveTask {
            file_no: 1,
            output: vec![1, 2, 3],
            ..Default::default()
        };
        let right_prove_task = ProveTask {
            file_no: 2,
            output: vec![3, 4, 5],
            ..Default::default()
        };
        let agg_task = crate::stage::tasks::AggTask::init_from_two_prove_task(
            &left_prove_task,
            &right_prove_task,
            1,
        );
        assert_eq!(agg_task.state, TASK_STATE_UNPROCESSED);
    }

    #[test]
    fn test_init_from_two_agg_task() {
        let left_agg_task = AggTask {
            task_id: "1".to_string(),
            ..Default::default()
        };
        let right_agg_task = AggTask {
            task_id: "2".to_string(),
            ..Default::default()
        };
        let agg_task = crate::stage::tasks::AggTask::init_from_two_agg_task(
            &left_agg_task,
            &right_agg_task,
            1,
        );
        assert_eq!(agg_task.state, TASK_STATE_UNPROCESSED);
        assert!(agg_task.childs[0].is_some());
        assert!(agg_task.childs[1].is_some());
    }
}
