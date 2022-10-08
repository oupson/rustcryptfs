use std::{collections::BTreeMap, path::PathBuf};

pub(crate) type InodeCache = BTreeMap<u64, PathBuf>;

pub(crate) trait InodeCacheExt {
    fn get_or_insert_inode(&mut self, file_path: PathBuf) -> (u64, PathBuf);

    fn get_path(&self, ino: u64) -> Option<&PathBuf>;
}

impl InodeCacheExt for InodeCache {
    // TODO Try to avoid clone
    fn get_or_insert_inode(&mut self, file_path: PathBuf) -> (u64, PathBuf) {
        if let Some((ino, path)) =
            self.iter()
                .find_map(|(i, p)| if p.eq(&file_path) { Some((i, p)) } else { None })
        {
            (*ino, path.clone())
        } else {
            let ino = self.len() as u64 + 1;
            self.insert(ino, file_path);

            (ino, self.get(&ino).unwrap().clone())
        }
    }

    fn get_path(&self, ino: u64) -> Option<&PathBuf> {
        // TODO CHECK PERM
        self.get(&ino)
    }
}
