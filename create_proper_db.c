#include <stdio.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <string.h>

int main() {
    // Create a database with actual root directory entry
    sqlite3 *db;
    int rc = sqlite3_open("test_with_root.db", &db);
    if (rc) {
        printf("Can't open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    
    // Create schema
    const char *schema = 
        "create table meta (id integer unique default 0, db_inode integer);"
        "insert into meta (db_inode) values (0);"
        "create table stats (inode integer primary key, stat blob);"
        "create table paths (path blob primary key, inode integer references stats(inode));"
        "create index inode_to_path on paths (inode, path);"
        "pragma user_version=3;";
        
    char *err_msg = 0;
    rc = sqlite3_exec(db, schema, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        printf("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 1;
    }
    
    // Create a fake stat structure for root directory
    struct stat root_stat;
    memset(&root_stat, 0, sizeof(root_stat));
    root_stat.st_mode = S_IFDIR | 0755;  // Directory with 755 permissions
    root_stat.st_ino = 1;                // Inode 1 for root
    root_stat.st_nlink = 2;              // Typical for root directory
    
    // Insert root directory into database
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "INSERT INTO stats (inode, stat) VALUES (?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    
    sqlite3_bind_int64(stmt, 1, 1);  // inode 1
    sqlite3_bind_blob(stmt, 2, &root_stat, sizeof(root_stat), SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        printf("Failed to insert stat: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    sqlite3_finalize(stmt);
    
    // Insert root path entry
    rc = sqlite3_prepare_v2(db, "INSERT INTO paths (path, inode) VALUES (?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare path statement: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    
    sqlite3_bind_blob(stmt, 1, "/", 1, SQLITE_STATIC);  // root path "/"
    sqlite3_bind_int64(stmt, 2, 1);  // inode 1
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        printf("Failed to insert path: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    sqlite3_finalize(stmt);
    
    sqlite3_close(db);
    printf("Database with root directory created successfully\n");
    return 0;
}