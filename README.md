# Super Dedup-er
`dedup` tries to save hard drive space by finding identical files and
creating hard links to a single copy of the bits on disk instead each
file being its own copy.

  - Uses SHA-256 to hash the files' contents
  - hard links not supported on Windows
  - hard links not supported across devices/partitions

## Future Upgrades
  - Windows/symlink support
  - `multiprocessing` for faster hashing
