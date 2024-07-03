Lowfatfs does not allocate anything except memory for fs-instance itself over preallocated block, but it is not flexible - only static block count and sizes for all files, for filenames also.
Linkfs is more flexible and represents files as linked lists of blocks of fixed size, but block size is the option of each file, not a whole fs. Also it does quite a lot of allocations/deallocations.
Both are "plain" - no directories abstraction over files placement. 
Both allow to create binary representation of the whole "fs" and recreate fs-instance from this binary representation.
