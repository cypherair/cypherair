//! Rule E14: no error carries text. `EngineError` is `Copy`, which a type
//! holding a `String` cannot be; this file does not compile otherwise.

use cypher_engine::EngineError;

const fn assert_copy<T: Copy>() {}
const _: () = assert_copy::<EngineError>();

#[test]
fn e14_engine_error_is_copy() {
    assert_copy::<EngineError>();
}
