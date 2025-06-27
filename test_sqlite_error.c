#include <stdio.h>
#include <sqlite3.h>

// Test the exact SQL from the migration that's failing
int main() {
    sqlite3 *db;
    int rc = sqlite3_open("e2e_out/testfs/meta.db", &db);
    if (rc) {
        printf("Can't open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    
    printf("Testing migration SQL...\n");
    
    // Test the SQL from migration version 0 (the first one)
    char *err_msg = 0;
    const char *sql = "create index inode_to_path on paths (inode, path);";
    
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        printf("Migration SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("Migration SQL succeeded\n");
    }
    
    sqlite3_close(db);
    return 0;
}