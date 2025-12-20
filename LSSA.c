#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/evp.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MAX_WATCHES 1024
#define BACKUP_DIR ".backups"
#define DEBOUNCE_SECONDS 2

// Structure to track watch descriptors and paths
typedef struct {
    int wd;
    char path[PATH_MAX];
} WatchEntry;

// Structure to track last backup time for debouncing
typedef struct {
    char filepath[PATH_MAX];
    time_t last_backup;
} DebounceEntry;

// Global variables
static int inotify_fd = -1;
static WatchEntry watches[MAX_WATCHES];
static int watch_count = 0;
static DebounceEntry debounce_table[MAX_WATCHES];
static int debounce_count = 0;

// Allowed extensions to backup
static const char *allowed_extensions[] = {
    ".c", ".h", ".cpp", ".hpp", ".py", ".js", ".java",
    ".rs", ".go", ".sh", ".txt", ".md", ".json", ".xml",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", NULL
};

// Cleanup handler
void cleanup_handler(int signum) {
    printf("\nCleaning up and exiting...\n");
    if (inotify_fd >= 0) {
        for (int i = 0; i < watch_count; i++) {
            inotify_rm_watch(inotify_fd, watches[i].wd);
        }
        close(inotify_fd);
    }
    exit(0);
}

// Check if file extension is allowed
int is_allowed_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    
    for (int i = 0; allowed_extensions[i] != NULL; i++) {
        if (strcmp(dot, allowed_extensions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Check if path should be ignored
int should_ignore(const char *name) {
    // Ignore our backup files
    if (strstr(name, ".bak_") != NULL) return 1;
    if (strstr(name, BACKUP_DIR) != NULL) return 1;
    
    // Ignore git directory
    if (strstr(name, ".git") != NULL) return 1;
    
    // Ignore compiled/binary files
    const char *ignore_extensions[] = {".o", ".so", ".a", ".pyc", ".class", NULL};
    const char *dot = strrchr(name, '.');
    if (dot) {
        for (int i = 0; ignore_extensions[i] != NULL; i++) {
            if (strcmp(dot, ignore_extensions[i]) == 0) return 1;
        }
    }
    
    return 0;
}

// Create backup directory structure
int ensure_backup_dir(const char *filepath, char *backup_path, size_t backup_path_size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_dir[64];
    
    strftime(date_dir, sizeof(date_dir), "%Y-%m-%d", tm_info);
    
    // Create .backups directory
    mkdir(BACKUP_DIR, 0755);
    
    // Create date subdirectory
    char date_path[PATH_MAX];
    snprintf(date_path, sizeof(date_path), "%s/%s", BACKUP_DIR, date_dir);
    mkdir(date_path, 0755);
    
    // Create backup filename with timestamp
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H-%M-%S", tm_info);
    
    snprintf(backup_path, backup_path_size, "%s/%s_%s", 
             date_path, timestamp, filepath);
    
    return 0;
}

// Compute SHA256 hash of file
int compute_file_hash(const char *filepath, unsigned char *hash) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(f);
        return -1;
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(f);
        return -1;
    }
    
    unsigned char buffer[8192];
    size_t bytes;
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(f);
            return -1;
        }
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(f);
        return -1;
    }
    
    EVP_MD_CTX_free(mdctx);
    fclose(f);
    return 0;
}

// Check if file content has changed using hash
int file_has_changed(const char *filepath) {
    unsigned char current_hash[EVP_MAX_MD_SIZE];
    
    if (compute_file_hash(filepath, current_hash) != 0) {
        return 1; // Assume changed if we can't read
    }
    
    // Try to find most recent backup
    char date_dir[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(date_dir, sizeof(date_dir), "%Y-%m-%d", tm_info);
    
    char search_path[PATH_MAX];
    snprintf(search_path, sizeof(search_path), "%s/%s", BACKUP_DIR, date_dir);
    
    DIR *dir = opendir(search_path);
    if (!dir) return 1; // No backups yet
    
    // Find most recent backup file
    struct dirent *entry;
    char most_recent[PATH_MAX] = "";
    time_t most_recent_time = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, filepath) != NULL) {
            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", search_path, entry->d_name);
            
            struct stat st;
            if (stat(full_path, &st) == 0) {
                if (st.st_mtime > most_recent_time) {
                    most_recent_time = st.st_mtime;
                    strncpy(most_recent, full_path, sizeof(most_recent) - 1);
                }
            }
        }
    }
    closedir(dir);
    
    if (most_recent[0] == '\0') return 1; // No backup found
    
    // Compare hashes
    unsigned char backup_hash[EVP_MAX_MD_SIZE];
    if (compute_file_hash(most_recent, backup_hash) != 0) {
        return 1;
    }
    
    return memcmp(current_hash, backup_hash, 32) != 0; // SHA256 is 32 bytes
}

// Check debounce - return 1 if should backup, 0 if too soon
int check_debounce(const char *filepath) {
    time_t now = time(NULL);
    
    for (int i = 0; i < debounce_count; i++) {
        if (strcmp(debounce_table[i].filepath, filepath) == 0) {
            if (now - debounce_table[i].last_backup < DEBOUNCE_SECONDS) {
                return 0; // Too soon
            }
            debounce_table[i].last_backup = now;
            return 1;
        }
    }
    
    // Not in table, add it
    if (debounce_count < MAX_WATCHES) {
        strncpy(debounce_table[debounce_count].filepath, filepath, PATH_MAX - 1);
        debounce_table[debounce_count].last_backup = now;
        debounce_count++;
    }
    
    return 1;
}

// Safe file copy using fork/exec (no shell injection)
int safe_copy_file(const char *src, const char *dst) {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        // Child process
        execl("/bin/cp", "cp", src, dst, NULL);
        perror("execl");
        exit(1);
    }
    
    // Parent process
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    
    return -1;
}

// Backup a file
void backup_file(const char *filepath, const char *full_path) {
    // Check if should ignore
    if (should_ignore(filepath)) return;
    
    // Check allowed extensions
    if (!is_allowed_extension(filepath)) return;
    
    // Check debounce
    if (!check_debounce(full_path)) {
        return; // Too soon since last backup
    }
    
    // Check if file actually changed
    if (!file_has_changed(filepath)) {
        printf("Skipping %s (no changes)\n", filepath);
        return;
    }
    
    char backup_path[PATH_MAX];
    ensure_backup_dir(filepath, backup_path, sizeof(backup_path));
    
    if (safe_copy_file(full_path, backup_path) == 0) {
        printf("✓ Backed up: %s -> %s\n", filepath, backup_path);
    } else {
        fprintf(stderr, "✗ Failed to backup: %s\n", filepath);
    }
}

// Add watch for a directory
int add_watch_recursive(const char *path) {
    if (watch_count >= MAX_WATCHES) {
        fprintf(stderr, "Maximum watches reached\n");
        return -1;
    }
    
    int wd = inotify_add_watch(inotify_fd, path, 
                                IN_MODIFY | IN_CREATE | IN_MOVED_TO);
    
    if (wd < 0) {
        perror("inotify_add_watch");
        return -1;
    }
    
    watches[watch_count].wd = wd;
    strncpy(watches[watch_count].path, path, PATH_MAX - 1);
    watch_count++;
    
    printf("Watching: %s\n", path);
    
    // Recursively watch subdirectories
    DIR *dir = opendir(path);
    if (!dir) return wd;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            // Skip . and .. and hidden directories
            if (entry->d_name[0] == '.') continue;
            
            char subdir[PATH_MAX];
            snprintf(subdir, sizeof(subdir), "%s/%s", path, entry->d_name);
            
            add_watch_recursive(subdir);
        }
    }
    
    closedir(dir);
    return wd;
}

// Find path for watch descriptor
const char* get_watch_path(int wd) {
    for (int i = 0; i < watch_count; i++) {
        if (watches[i].wd == wd) {
            return watches[i].path;
        }
    }
    return ".";
}

int main(int argc, char *argv[]) {
    char buffer[BUF_LEN];
    
    // Setup signal handlers
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);
    
    // Initialize inotify
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return 1;
    }
    
    // Start watching current directory
    const char *watch_path = (argc > 1) ? argv[1] : ".";
    
    if (add_watch_recursive(watch_path) < 0) {
        fprintf(stderr, "Failed to setup watches\n");
        return 1;
    }
    
    printf("\n🔍 Git Backup System Active\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Backups stored in: %s/\n", BACKUP_DIR);
    printf("Debounce: %d seconds\n", DEBOUNCE_SECONDS);
    printf("Press Ctrl+C to stop\n\n");
    
    // Main event loop
    while (1) {
        int length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }
        
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            if (event->len) {
                const char *watch_path = get_watch_path(event->wd);
                char full_path[PATH_MAX];
                
                snprintf(full_path, sizeof(full_path), "%s/%s", 
                         watch_path, event->name);
                
                if (event->mask & IN_CREATE) {
                    // Check if it's a directory
                    struct stat st;
                    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                        if (!should_ignore(event->name)) {
                            add_watch_recursive(full_path);
                        }
                    }
                } else if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
                    backup_file(event->name, full_path);
                }
            }
            
            i += EVENT_SIZE + event->len;
        }
    }
    
    cleanup_handler(0);
    return 0;
}
