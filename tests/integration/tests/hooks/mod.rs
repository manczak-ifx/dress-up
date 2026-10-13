use clap::Parser;
use std::path::PathBuf;

use dress_up::{OperatingHooks, SuitManifest};

#[derive(Parser, Debug)]
struct Args {
    file: PathBuf,
}

#[derive(Clone)]
struct OsHooks {}

impl OperatingHooks for OsHooks {
    type ReadWriteBufferSize = generic_array::typenum::U64;
    fn match_vendor_id(
        &self,
        _uuid: uuid::Uuid,
        _component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        todo!()
    }

    fn match_class_id(
        &self,
        _uuid: uuid::Uuid,
        _component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        todo!()
    }

    fn component_read(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        _offset: usize,
        _bytes: &mut [u8],
    ) -> Result<(), dress_up::error::Error> {
        todo!()
    }

    fn component_size(
        &self,
        _component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        todo!()
    }

    fn component_capacity(
        &self,
        _component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        todo!()
    }

    fn component_write(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        _offset: usize,
        _bytes: &[u8],
    ) -> Result<(), dress_up::error::Error> {
        todo!()
    }
}