use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2,FheUint4,FheUint8,FheUint16,FheUint32, FheUint64, FheUint128,FheUint256, FheUint512,FheUint1024,FheUint2048};
use std::time::Instant;
use std::process;

fn main() {
    // We generate a set of client/server keys
    
  let now = Instant::now();
  let (client_key, server_key) = generate_keys(ConfigBuilder::default());
  set_server_key(server_key);
 
    let msg1: u32 = 1;
    let msg2: u32 = 3;
    // let ct_1 = FheUint2048::encrypt(msg1, &client_key);
    // let ct_2 = FheUint2048::encrypt(msg2, &client_key);
    // Change FheUint2 to FheUint4, FheUint8, FheUint16, .. FheUint2048
    // FheUint2048 run time is about 8 to 10 hours.

    let ct_1 = FheUint2::encrypt(msg1, &client_key);
    let ct_2 = FheUint2::encrypt(msg2, &client_key);
    let (mut result, mut overflowed) = (&ct_1).overflowing_add(&ct_2);
    if overflowed.decrypt(&client_key){
      let lapsed = now.elapsed();
      let f_r : u128 = result.decrypt(&client_key);
      println!("At iteration 0 and Elapsed:{:.10?} and result is {f_r} ", lapsed);
      process::exit(1)
    }
    //let mut result = ct_1 + ct_2;

    let mut i = 1;
    while i < 4500 {
      (result, overflowed) = (&result).overflowing_add(&result);
      if overflowed.decrypt(&client_key){
        let elapsed = now.elapsed();
        //let f_r : u128 = result.decrypt(&client_key);
        println!("At iteration {i} and Elapsed: {:.2?} ", elapsed);
        break;
      }
      i += 1;
    }
    let elapsed = now.elapsed();
    // elapsed provides the run time of this program.
    println!("Ran and Elapsed: {:.2?}", elapsed);
    assert!(!overflowed.decrypt(&client_key));
}
