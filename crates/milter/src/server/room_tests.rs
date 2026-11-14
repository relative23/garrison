//! What the filter's room counts: the memory the messages' buffers hold,
//! which is what the unit's limit is about.

use std::sync::atomic::Ordering;

use super::*;

/// The unit's memory limit, in bytes.
fn unit_limit() -> usize {
    let unit = include_str!("../../../../deploy/systemd/garrison-milter.service");
    let limit = unit
        .lines()
        .find_map(|line| line.strip_prefix("MemoryMax="))
        .unwrap();
    let (number, unit) = limit.split_at(limit.len() - 1);
    let factor = match unit {
        "G" => 1024 * 1024 * 1024,
        "M" => 1024 * 1024,
        other => panic!("MemoryMax in {other}"),
    };
    number.parse::<usize>().unwrap() * factor
}

#[test]
fn the_units_memory_limit_lies_above_what_the_largest_setting_takes() {
    use garrison_core::config::MilterConfig;
    let largest = usize::try_from(MilterConfig::MOST_MESSAGE_MIB).unwrap() * 1024 * 1024;
    // The process itself, its threads' stacks and what the allocator keeps
    // for itself come on top of what the filter holds.
    let besides = 64 * 1024 * 1024;
    let taken = most_memory(largest);
    assert!(
        taken + besides <= unit_limit(),
        "{taken} bytes and {besides} besides against {}",
        unit_limit()
    );
    // What the unit's comment says of it.
    assert_eq!(taken, 864 * 1024 * 1024);
    // The default takes what the room alone asks for, twice, and one message.
    assert_eq!(
        most_memory(Settings::default().max_bytes),
        (256 + 256 + 64 + 96) * 1024 * 1024
    );
}

fn held(shared: &Shared) -> usize {
    shared.held.load(Ordering::SeqCst)
}

#[test]
fn the_room_counts_what_a_buffer_holds_not_what_was_written_into_it() {
    let shared = Shared::with_room(64 * 1024 * 1024);
    let limit = 5 * 1024 * 1024;
    let mut message = Message::new(&shared);
    // The pieces of a body as a mail server sends them.
    let piece = vec![b'x'; 65_535];
    while message.data.len() + piece.len() <= limit {
        message.add(&piece, limit);
        assert_eq!(held(&shared), message.data.capacity());
        // A buffer does not grow beyond what a message may hold.
        assert!(message.data.capacity() <= limit);
    }
    assert!(!message.crowded && !message.too_large);
    assert!(message.data.len() > limit - piece.len());
    drop(message);
    assert_eq!(held(&shared), 0);
}

#[test]
fn the_messages_together_never_hold_more_than_the_room() {
    let size = 1024 * 1024;
    // Three connections receive a message each, in a room for two.
    let shared = Shared::with_room(2 * size);
    let mut messages = [
        Message::new(&shared),
        Message::new(&shared),
        Message::new(&shared),
    ];
    let piece = vec![b'x'; 4096];
    for _ in 0..size / piece.len() {
        for message in &mut messages {
            message.add(&piece, size);
        }
        let buffers: usize = messages.iter().map(|message| message.data.capacity()).sum();
        assert!(buffers <= shared.room, "{buffers}");
        assert_eq!(held(&shared), buffers);
    }
    // One found no room and let go of what it had; the others are whole.
    let crowded = messages.iter().filter(|message| message.crowded).count();
    let whole = messages
        .iter()
        .filter(|message| message.data.len() == size)
        .count();
    assert_eq!((crowded, whole), (1, 2));
}

#[test]
fn a_message_of_the_largest_size_has_room_when_it_is_alone() {
    let limit = 3 * 1024 * 1024;
    // The room is exactly one such message.
    let shared = Shared::with_room(limit);
    let mut message = Message::new(&shared);
    for piece in vec![b'x'; limit].chunks(65_535) {
        message.add(piece, limit);
    }
    assert!(!message.crowded && !message.too_large);
    assert_eq!(message.data.len(), limit);
    // One byte more is more than is scanned, not a lack of room.
    message.add(b"x", limit);
    assert!(message.too_large && !message.crowded);
    assert_eq!(held(&shared), 0);
}
