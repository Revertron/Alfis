/*
Copyright 2018 Emil Hernvall

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
*/

//! The dns module implements the DNS protocol and the related functions

pub mod authority;
pub mod buffer;
pub mod cache;
pub mod client;
pub mod context;
pub mod protocol;
pub mod resolve;
pub mod server;
pub mod filter;
pub mod hosts;

mod netutil;