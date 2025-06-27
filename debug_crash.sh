#!/bin/bash
source ish-env/bin/activate

echo "=== Debugging 64-bit crashes with LLDB ==="

echo "Creating fresh test database..."
rm -rf test_crash_debug
mkdir -p test_crash_debug/data
sqlite3 test_crash_debug/meta.db "$(cat << 'EOF'
create table meta (id integer unique default 0, db_inode integer);
insert into meta (db_inode) values (0);
create table stats (inode integer primary key, stat blob);
create table paths (path blob primary key, inode integer references stats(inode));
create index inode_to_path on paths (inode, path);
pragma user_version=3;
EOF
)"

echo "Running 64-bit iSH under LLDB to capture crash..."
lldb build-64bit/ish -o "run -f test_crash_debug /bin/true" -o "bt" -o "register read" -o "disassemble -c 10" -o "quit" 2>&1