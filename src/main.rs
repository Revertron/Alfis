use wyrd_ns::{Blockchain, Block, Action, Transaction, Signature, Key};

fn main() {
    println!("Wyrd DNS 0.1.0");
    test_blockchain()
}

fn test_blockchain() -> () {
    let mut blockchain = Blockchain::new(42, 0);
    println!("Blockchain with genesis block has been created");
    let signature = Signature::from_file("default.key", "").unwrap();

    // Creating transaction
    let action = Action::new_domain("test.zz".to_owned(), &signature, vec!["AAAA IN 301:2925::1".to_owned()], vec![], 365);
    let mut transaction = Transaction::new(action, signature.get_public().clone());

    // Signing it with private key from Signature
    let sign_hash = signature.sign(&transaction.get_bytes());
    transaction.set_signature(Key::from_bytes(&sign_hash));

    // Creating a block with that signed transaction
    let mut block = blockchain.new_block(transaction);

    // Mining the nonce
    block.mine();

    // Our block is ready, we can print it and add to Blockchain
    let s = serde_json::to_string(&block).unwrap();
    println!("Serialized block:\n{}", s);
    blockchain.add_block(block);
    println!("Second block added");

    let block2: Block = serde_json::from_str(&s).unwrap();
    println!("DeSerialized block:\n{:?}", block2);

    // Let's check if the blockchain is valid
    if blockchain.check() {
        println!("Blockchain is correct");
    } else {
        println!("Blockchain is corrupted, aborting");
    }
}
