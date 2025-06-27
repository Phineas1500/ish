#include <stdio.h>
#include <sqlite3.h>
#include <sys/stat.h>

int main() {
    printf("Testing 64-bit SQLite integration...\n");
    printf("sizeof(ino_t) = %zu\n", sizeof(ino_t));
    printf("sizeof(int) = %zu\n", sizeof(int));
    printf("sizeof(long) = %zu\n", sizeof(long));
    printf("sizeof(size_t) = %zu\n", sizeof(size_t));
    
    // Test basic SQLite operation
    sqlite3 *db;
    int rc = sqlite3_open("test.db", &db);
    if (rc) {
        printf("Can't open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    printf("SQLite opened successfully\n");
    
    // Test the problematic migration SQL
    char *err_msg = 0;
    rc = sqlite3_exec(db, "pragma user_version = 1;", 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        printf("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 1;
    }
    printf("Basic SQL operations work\n");
    
    sqlite3_close(db);
    return 0;
}