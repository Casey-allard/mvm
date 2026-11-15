//! Exercise returned upload credit through the actual session and TCP relay.
use super::tests::{
    gate_allowing_addr, read_flowmux_frame, run_session, tcp_echo_server, write_frame,
};
use mvm_contract::protocol::network_flow::{INITIAL_STREAM_CREDIT, Opcode};
use std::time::Duration;

#[test]
fn returned_upload_credit_keeps_the_session_validator_current() {
    const BLOCK: usize = 16 * 1024;
    let rounds = INITIAL_STREAM_CREDIT as usize / BLOCK + 4;
    let address = tcp_echo_server();
    let (mut guest, mut session, host) =
        run_session(gate_allowing_addr(address.ip(), address.port(), None));
    guest
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    guest
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        1,
        address.to_string().as_bytes(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    for index in 0..rounds {
        let expected = vec![index as u8; BLOCK];
        write_frame(&mut guest, &mut session, Opcode::Data, 1, &expected);
        let mut restored = Vec::with_capacity(BLOCK);
        let mut returned = 0usize;
        while restored.len() < BLOCK || returned < BLOCK {
            let (opcode, stream, payload) = read_flowmux_frame(&mut guest, &mut session);
            assert_eq!(
                stream,
                1,
                "round {index}, unexpected {opcode:?}: {}",
                String::from_utf8_lossy(&payload)
            );
            match opcode {
                Opcode::Data => {
                    restored.extend_from_slice(&payload);
                    assert!(restored.len() <= BLOCK);
                    write_frame(
                        &mut guest,
                        &mut session,
                        Opcode::WindowUpdate,
                        1,
                        &u32::try_from(payload.len()).unwrap().to_be_bytes(),
                    );
                }
                Opcode::WindowUpdate => {
                    let delta = u32::from_be_bytes(payload.try_into().expect("credit payload"));
                    returned += delta as usize;
                    assert!(returned <= BLOCK);
                }
                other => panic!(
                    "round {index}: expected exact echo and returned credit, got {other:?}: {}",
                    String::from_utf8_lossy(&payload)
                ),
            }
        }
        assert_eq!(restored, expected, "round {index} lost fidelity");
    }
    drop(guest);
    host.join().unwrap().unwrap();
}
