use std::io::{Read, Result, Write};
use std::net::TcpStream;

pub fn read_packet_length(stream: &mut TcpStream) -> Result<u16> {
    let mut len_buffer = [0; 2];
    stream.read(&mut len_buffer)?;

    Ok(((len_buffer[0] as u16) << 8) | (len_buffer[1] as u16))
}

pub fn write_packet_length(stream: &mut TcpStream, len: usize) -> Result<()> {
    let mut len_buffer = [0; 2];
    len_buffer[0] = (len >> 8) as u8;
    len_buffer[1] = (len & 0xFF) as u8;

    stream.write(&len_buffer)?;

    Ok(())
}
