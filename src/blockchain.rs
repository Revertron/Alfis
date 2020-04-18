use crate::{Block, Transaction, Key};
use chrono::Utc;

pub struct Blockchain {
    pub chain_id: u32,
    pub version: u32,
    pub blocks: Vec<Block>,
}

impl Blockchain {
    pub fn new(chain_id: u32, version: u32) -> Self {
        let mut blockchain = Blockchain{chain_id, version, blocks: Vec::new()};
        blockchain
    }

    pub fn new_block(&self, transaction: Transaction) -> Block {
        let prev_block = self.blocks.last().unwrap();
        let block = Block::new(prev_block.index + 1,Utc::now().timestamp(), self.chain_id, self.version, prev_block.hash.clone(), Some(transaction));
        block
    }

    pub fn genesis(chain_id: u32, version: u32) -> Block {
        Block::new(0, Utc::now().timestamp(), chain_id, version, Key::zero32(), None)
    }

    pub fn make_genesis(&mut self) {
        let mut genesis = Self::genesis(self.chain_id, self.version);
        genesis.mine();
        self.add_block(genesis);
    }

    pub fn add_block(&mut self, block: Block) {
        if self.check_block(&block, None) {
            println!("Adding block:\n{:?}", &block);
            self.blocks.push(block);
        } else {
            println!("Bad block found, ignoring:\n{:?}", &block);
        }
    }

    pub fn check(&self) -> bool {
        let mut prev_block = None;
        for block in self.blocks.iter() {
            if !self.check_block(block, prev_block) {
                println!("Block {:?} is bad", block);
                return false;
            }
            prev_block = Some(block);
        }
        true
    }

    fn check_block(&self, block: &Block, prev_block: Option<&Block>) -> bool {
        if !Self::check_block_hash(block) {
            return false;
        }
        if prev_block.is_none() {
            return true;
        }

        return block.prev_block_hash == prev_block.unwrap().hash;
    }

    pub fn check_block_hash(block: &Block) -> bool {
        // We need to clear Hash value to rehash it without it for check :(
        let mut copy: Block = block.clone();
        copy.hash = Key::default();
        let data = serde_json::to_string(&copy).unwrap();
        Block::hash(data.as_bytes()) == block.hash
    }
}